using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;
using Sikkerheit.Host.Operations;
using Sikkerheit.Host.Organizations;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Assessment;

public sealed record ReleaseEntryBody(int BranchBuild, int Ubr, string Kb, DateTimeOffset ReleaseAt, string Kind, string? SecurityMonth, bool AutoOffered);

public sealed record ReleaseImportBody(string Source, string SecurityMonth, List<ReleaseEntryBody>? Entries);

public sealed record ReleaseVerificationBody(bool NoNewReleases);

public sealed record WindowsReleaseDto(
    string Product, int BranchBuild, int Ubr, string Kb, DateTimeOffset ReleaseAt, string Kind, string? SecurityMonth, bool AutoOffered,
    string State, Guid ImportedBy)
{
    public static WindowsReleaseDto From(WindowsRelease r) => new(r.Product, r.BranchBuild, r.Ubr, r.Kb, r.ReleaseAt, r.Kind, r.SecurityMonth,
        r.AutoOffered, r.State, r.ImportedBy);
}

public sealed record WindowsReleaseMonthDto(string SecurityMonth, string State, int Releases, DateTimeOffset? VerifiedAt, Guid? VerifiedBy,
    bool NoNewReleases);

/// <summary>
/// The Windows release catalog in the portal and its jobs (03 «Правило SYS-003 и каталог выпусков», RB-13): entries are
/// imported as drafts, a month is put into effect only by an Admin who verified it, and the verification queues
/// patch_level_sweep for every organization.
/// </summary>
public static class ReleaseCatalog
{
    public const int EntriesPerImport = 100;
    public static readonly TimeSpan VerificationDeadline = TimeSpan.FromDays(7);

    public static void Map(IEndpointRouteBuilder app)
    {
        var releases = app.MapGroup("/api/v1/windows-releases");
        releases.MapGet("", List).RequireStaff(StaffRoles.All);
        releases.MapPost("/imports", Import).RequireStaff(StaffRoles.AdminOnly);
        releases.MapPost("/months/{securityMonth}/verify", Verify).RequireStaff(StaffRoles.AdminOnly);
    }

    private static readonly System.Text.RegularExpressions.Regex Month = new("^[0-9]{4}-(0[1-9]|1[0-2])$");

    private static async Task<WindowsReleaseMonthDto> MonthDtoAsync(DbScope scope, string month, CancellationToken ct)
    {
        var row = await scope.Db.WindowsReleaseMonths.AsNoTracking().SingleOrDefaultAsync(m => m.SecurityMonth == month, ct);
        var releases = await scope.Db.WindowsReleases.AsNoTracking().CountAsync(r => r.CatalogMonth == month, ct);
        return new WindowsReleaseMonthDto(month, row?.State ?? "draft", releases, row?.VerifiedAt, row?.VerifiedBy, row?.NoNewReleases ?? false);
    }

    private static async Task<IResult> List(DbScopes scopes, Cursors cursors, string? cursor, string? limit, string? securityMonth,
        string? state, CancellationToken ct)
    {
        var size = OrganizationEndpoints.Limit(limit);
        if (securityMonth is not null && !Month.IsMatch(securityMonth) || state is not null and not ("draft" or "verified"))
        {
            throw new ApiProblemException(ProblemCodes.SchemaViolation, "securityMonth must be YYYY-MM and state draft or verified");
        }
        var filter = Cursors.Filter(("securityMonth", securityMonth), ("state", state));
        var position = cursors.Read(cursor, "listWindowsReleases", null, filter);
        await using var scope = await scopes.PlatformAsync(ct);
        var query = scope.Db.WindowsReleases.AsNoTracking().AsQueryable();
        if (securityMonth is not null)
        {
            query = query.Where(r => r.SecurityMonth == securityMonth);
        }
        if (state is not null)
        {
            query = query.Where(r => r.State == state);
        }
        if (position is not null)
        {
            var branch = int.Parse(position[0], CultureInfo.InvariantCulture);
            var ubr = int.Parse(position[1], CultureInfo.InvariantCulture);
            query = query.Where(r => r.BranchBuild < branch || (r.BranchBuild == branch && r.Ubr < ubr));
        }
        var rows = await query.OrderByDescending(r => r.BranchBuild).ThenByDescending(r => r.Ubr).Take(size + 1).ToListAsync(ct);
        string? next = null;
        if (rows.Count > size)
        {
            rows.RemoveAt(size);
            next = cursors.Create("listWindowsReleases", null, filter,
                [rows[^1].BranchBuild.ToString(CultureInfo.InvariantCulture), rows[^1].Ubr.ToString(CultureInfo.InvariantCulture)]);
        }
        return Results.Json(new Page<WindowsReleaseDto>(rows.Select(WindowsReleaseDto.From).ToList(), next), ApiJson.Options);
    }

    private static async Task<IResult> Import(HttpContext http, RequestBodies bodies, DbScopes scopes, TimeProvider clock, CancellationToken ct)
    {
        var actor = Actor.From(http.User);
        var body = (await bodies.ReadAsync<ReleaseImportBody>(http, "WindowsReleaseImport")).Value;
        var now = clock.GetUtcNow();
        await using var scope = await scopes.PlatformAsync(ct);
        await EnsureMonthAsync(scope, body.SecurityMonth, ct);
        if (body.Source == "manual")
        {
            await StoreDraftsAsync(scope, body.SecurityMonth, body.Entries ?? [], "manual", actor.EntraUserId, now, ct);
        }
        else
        {
            // The CVRF document of the month is fetched by the job: only api.msrc.microsoft.com at a fixed path.
            await JobQueue.EnqueueAsync(scope, "release_import", null, body.SecurityMonth, null, now, ct);
        }
        await scope.CommitAsync(ct);
        await using var read = await scopes.PlatformAsync(ct);
        return Results.Json(await MonthDtoAsync(read, body.SecurityMonth, ct), ApiJson.Options, statusCode: StatusCodes.Status202Accepted);
    }

    public static async Task EnsureMonthAsync(DbScope scope, string month, CancellationToken ct)
    {
        if (!await scope.Db.WindowsReleaseMonths.AnyAsync(m => m.SecurityMonth == month, ct))
        {
            scope.Db.WindowsReleaseMonths.Add(new WindowsReleaseMonth { SecurityMonth = month, State = "draft" });
            await scope.Db.SaveChangesAsync(ct);
        }
    }

    /// <summary>
    /// Stores the entries as drafts: an entry equal to a verified one is skipped, one that contradicts it is 422
    /// validation_failed (03: a mistaken verified entry is corrected by a new version of the service, not by an import).
    /// </summary>
    public static async Task<int> StoreDraftsAsync(DbScope scope, string month, IReadOnlyList<ReleaseEntryBody> entries, string source,
        Guid importedBy, DateTimeOffset now, CancellationToken ct)
    {
        var stored = 0;
        foreach (var entry in entries)
        {
            var existing = await scope.Db.WindowsReleases.SingleOrDefaultAsync(
                r => r.Product == "client" && r.BranchBuild == entry.BranchBuild && r.Ubr == entry.Ubr, ct);
            if (existing is { State: "verified" })
            {
                if (existing.Kb != entry.Kb || existing.Kind != entry.Kind || existing.SecurityMonth != entry.SecurityMonth
                    || existing.AutoOffered != entry.AutoOffered || existing.ReleaseAt != entry.ReleaseAt.ToUniversalTime())
                {
                    throw new ApiProblemException(ProblemCodes.ValidationFailed,
                        $"{entry.BranchBuild}.{entry.Ubr} contradicts a verified entry of the catalog");
                }
                continue;
            }
            if (existing is null)
            {
                existing = new WindowsRelease { Product = "client", BranchBuild = entry.BranchBuild, Ubr = entry.Ubr };
                scope.Db.WindowsReleases.Add(existing);
            }
            existing.Kb = entry.Kb;
            existing.ReleaseAt = entry.ReleaseAt.ToUniversalTime();
            existing.Kind = entry.Kind;
            existing.SecurityMonth = entry.SecurityMonth;
            existing.CatalogMonth = month;
            existing.AutoOffered = entry.AutoOffered;
            existing.State = "draft";
            existing.Source = source;
            existing.ImportedBy = importedBy;
            existing.ImportedAt = now;
            stored++;
        }
        await scope.Db.SaveChangesAsync(ct);
        return stored;
    }

    private static async Task<IResult> Verify(string securityMonth, HttpContext http, RequestBodies bodies, DbScopes scopes,
        TimeProvider clock, CancellationToken ct)
    {
        var actor = Actor.From(http.User);
        if (!Month.IsMatch(securityMonth))
        {
            throw new ApiProblemException(ProblemCodes.SchemaViolation, "securityMonth must be YYYY-MM");
        }
        var body = (await bodies.ReadAsync<ReleaseVerificationBody>(http, "WindowsReleaseMonthVerification")).Value;
        var now = clock.GetUtcNow();
        await using (var scope = await scopes.PlatformAsync(ct))
        {
            var month = await scope.Db.WindowsReleaseMonths.SingleOrDefaultAsync(m => m.SecurityMonth == securityMonth, ct);
            var count = await scope.Db.WindowsReleases.CountAsync(r => r.CatalogMonth == securityMonth, ct);
            if (count == 0 && !body.NoNewReleases)
            {
                throw new ApiProblemException(ProblemCodes.ValidationFailed, "a month without entries is verified only with noNewReleases=true");
            }
            if (month is null)
            {
                month = new WindowsReleaseMonth { SecurityMonth = securityMonth };
                scope.Db.WindowsReleaseMonths.Add(month);
            }
            var promoted = await scope.Db.WindowsReleases.Where(r => r.CatalogMonth == securityMonth && r.State == "draft")
                .ExecuteUpdateAsync(u => u.SetProperty(r => r.State, "verified"), ct);
            if (month.State != "verified" || promoted > 0)
            {
                // New entries put into effect later count as a new verification: the scheduler sweeps the devices again.
                month.State = "verified";
                month.VerifiedAt = now;
                month.VerifiedBy = actor.EntraUserId;
            }
            month.NoNewReleases = count == 0;
            await scope.CommitAsync(ct);
        }
        // The next tick of the scheduler queues patch_level_sweep for every organization (periodKey = month, see Scheduler).
        await using var read = await scopes.PlatformAsync(ct);
        return Results.Json(await MonthDtoAsync(read, securityMonth, ct), ApiJson.Options);
    }
}

/// <summary>
/// release_import: the CVRF document of a month from api.msrc.microsoft.com (fixed host and path) becomes draft entries.
/// The documents change after the release and the data is sometimes imprecise, so Admin checks the draft against the Windows
/// release information page before the month is verified (RB-13).
/// </summary>
public sealed class ReleaseImportJob(DbScopes scopes, IHttpClientFactory http, TimeProvider clock, ILogger<ReleaseImportJob> logger)
    : IJobHandler
{
    public const string HttpClientName = "msrc";
    public const string Host = "api.msrc.microsoft.com";

    public string Type => "release_import";

    public static Uri Address(string month)
    {
        var date = DateTime.ParseExact(month + "-01", "yyyy-MM-dd", CultureInfo.InvariantCulture);
        return new Uri($"https://{Host}/cvrf/v3.0/cvrf/{date.ToString("yyyy-MMM", CultureInfo.InvariantCulture)}");
    }

    public async Task ExecuteAsync(JobLease lease, CancellationToken ct)
    {
        var month = lease.InputId ?? throw new InvalidOperationException("release_import needs a month");
        var client = http.CreateClient(HttpClientName);
        using var request = new HttpRequestMessage(HttpMethod.Get, Address(month));
        request.Headers.Accept.ParseAdd("application/json");
        using var response = await client.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
        using var document = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
        var now = clock.GetUtcNow();
        var entries = Parse(document.RootElement, month);
        await using var scope = await scopes.PlatformAsync(ct);
        if (!await lease.HoldAsync(scope, ct))
        {
            throw new JobLeaseLostException();
        }
        await ReleaseCatalog.EnsureMonthAsync(scope, month, ct);
        try
        {
            var stored = await ReleaseCatalog.StoreDraftsAsync(scope, month, entries, "msrc_cvrf", Guid.Empty, now, ct);
            logger.LogInformation("Windows release import {Month}: {Stored} draft entries from {Count}", month, stored, entries.Count);
        }
        catch (ApiProblemException error) when (error.Code == ProblemCodes.ValidationFailed)
        {
            // The document contradicts a verified entry: nothing is stored, the month stays as it was (RB-13).
            logger.LogError("Windows release import {Month} contradicts the verified catalog: {Detail}", month, error.Detail);
        }
        await lease.CompleteAsync(scope, ct);
        await scope.CommitAsync(ct);
    }

    /// <summary>
    /// Entries of the client products from the CVRF remediations: FixedBuild "10.0.&lt;branch&gt;.&lt;ubr&gt;", the KB from the
    /// description. The month is the one of the request; kind security_monthly.
    /// </summary>
    public static List<ReleaseEntryBody> Parse(JsonElement cvrf, string month)
    {
        var released = cvrf.TryGetProperty("DocumentTracking", out var tracking) && tracking.TryGetProperty("InitialReleaseDate", out var date)
            && DateTimeOffset.TryParse(date.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed)
            ? parsed : DateTimeOffset.Parse(month + "-01T00:00:00Z", CultureInfo.InvariantCulture);
        var clientProducts = new HashSet<string>(StringComparer.Ordinal);
        if (cvrf.TryGetProperty("ProductTree", out var tree) && tree.TryGetProperty("FullProductName", out var names))
        {
            foreach (var name in names.EnumerateArray())
            {
                var text = name.GetProperty("Value").GetString() ?? "";
                if ((text.StartsWith("Windows 10", StringComparison.Ordinal) || text.StartsWith("Windows 11", StringComparison.Ordinal))
                    && !text.Contains("Server", StringComparison.Ordinal))
                {
                    clientProducts.Add(name.GetProperty("ProductID").GetString()!);
                }
            }
        }
        var found = new Dictionary<(int, int), ReleaseEntryBody>();
        if (cvrf.TryGetProperty("Vulnerability", out var vulnerabilities))
        {
            foreach (var vulnerability in vulnerabilities.EnumerateArray())
            {
                if (!vulnerability.TryGetProperty("Remediations", out var remediations))
                {
                    continue;
                }
                foreach (var remediation in remediations.EnumerateArray())
                {
                    if (!remediation.TryGetProperty("FixedBuild", out var fixedBuild) || fixedBuild.GetString() is not { } build
                        || !remediation.TryGetProperty("ProductID", out var ids)
                        || !ids.EnumerateArray().Any(p => clientProducts.Contains(p.GetString() ?? "")))
                    {
                        continue;
                    }
                    var parts = build.Split('.');
                    if (parts.Length != 4 || !int.TryParse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture, out var branch)
                        || !int.TryParse(parts[3], NumberStyles.None, CultureInfo.InvariantCulture, out var ubr) || branch < 10000)
                    {
                        continue;
                    }
                    var kb = remediation.TryGetProperty("Description", out var description) ? description.GetProperty("Value").GetString() ?? "" : "";
                    kb = new string(kb.Where(char.IsDigit).ToArray());
                    if (kb.Length is < 6 or > 8)
                    {
                        continue;
                    }
                    found.TryAdd((branch, ubr), new ReleaseEntryBody(branch, ubr, kb, released, "security_monthly", month, true));
                }
            }
        }
        return found.Values.OrderBy(e => e.BranchBuild).ThenBy(e => e.Ubr).Take(ReleaseCatalog.EntriesPerImport * 10).ToList();
    }
}

/// <summary>
/// release_catalog_check (daily): a month of the catalog that is not verified 7 days after Patch Tuesday raises the alert of
/// 06 «Наблюдаемость и оповещения»; with graceDays 14 that leaves a week before SYS-003 turns unknown (03).
/// </summary>
public sealed class ReleaseCatalogCheckJob(DbScopes scopes, TimeProvider clock, ILogger<ReleaseCatalogCheckJob> logger) : IJobHandler
{
    public string Type => "release_catalog_check";

    /// <summary>The month that has to be verified by now, or null; the latest month whose deadline has passed.</summary>
    public static string? DueMonth(DateTimeOffset now)
    {
        var date = now.UtcDateTime.Date;
        var month = new DateTime(date.Year, date.Month, 1, 0, 0, 0, DateTimeKind.Utc);
        return ServerRules.SecondTuesday(month.Year, month.Month).Add(ReleaseCatalog.VerificationDeadline) <= date
            ? month.ToString("yyyy-MM", CultureInfo.InvariantCulture)
            : month.AddMonths(-1).ToString("yyyy-MM", CultureInfo.InvariantCulture);
    }

    /// <summary>The state of the catalog for the alert and the Teams digest: the month that is due and whether it is verified.</summary>
    public static async Task<(string Month, bool Verified)?> StateAsync(DbScope scope, DateTimeOffset now, CancellationToken ct)
    {
        // A catalog that was never filled is not monitored (a deployment without Windows agents).
        if (!await scope.Db.WindowsReleaseMonths.AnyAsync(ct))
        {
            return null;
        }
        var due = DueMonth(now)!;
        var verified = await scope.Db.WindowsReleaseMonths.AnyAsync(m => m.SecurityMonth == due && m.State == "verified", ct);
        return (due, verified);
    }

    public async Task ExecuteAsync(JobLease lease, CancellationToken ct)
    {
        await using var scope = await scopes.PlatformAsync(ct);
        if (!await lease.HoldAsync(scope, ct))
        {
            throw new JobLeaseLostException();
        }
        if (await StateAsync(scope, clock.GetUtcNow(), ct) is { Verified: false } due)
        {
            logger.LogError("Windows release catalog month {Month} is not verified 7 days after Patch Tuesday (RB-13)", due.Month);
        }
        await lease.CompleteAsync(scope, ct);
        await scope.CommitAsync(ct);
    }
}
