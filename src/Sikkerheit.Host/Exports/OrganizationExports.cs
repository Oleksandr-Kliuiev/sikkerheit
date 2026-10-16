using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;
using Sikkerheit.Host.Operations;
using Sikkerheit.Host.Organizations;
using Sikkerheit.Host.Platform;
using Sikkerheit.Host.Reports;

namespace Sikkerheit.Host.Exports;

public sealed record OrganizationExportDto(Guid Id, string State, DateTimeOffset CreatedAt, DateTimeOffset? ExpiresAt, Guid RequestedBy)
{
    /// <summary>A ready export past its 7 days is shown as expired before the purge removes the file.</summary>
    public static OrganizationExportDto From(OrganizationExport e, DateTimeOffset now) =>
        new(e.Id, e.State == "ready" && e.ExpiresAt <= now ? "expired" : e.State, e.CreatedAt, e.ExpiresAt, e.RequestedBy);
}

public sealed record OrganizationExportCreateBody(Guid IdempotencyKey);

/// <summary>
/// Export of all data of one organization (FR-01, 05 «Жизненный цикл организации»): a ZIP with one JSON Lines file per
/// table from one consistent snapshot, the HTML of ready reports and a manifest. Admin only; every download is audited;
/// the file is kept 7 days (04 «Сроки хранения»).
/// </summary>
public static class OrganizationExports
{
    public const int FormatVersion = 1;
    public static readonly TimeSpan Lifetime = TimeSpan.FromDays(7);

    /// <summary>Tables in the export with their stable order; only fixed identifiers reach the SQL text.</summary>
    private static readonly (string Table, string Order)[] Tables =
    [
        ("organization", "id"), ("policy_revision", "version"), ("tenant_connection", "organization_id"),
        ("collection_run", "queued_at, id"), ("subject", "first_seen_at, id"), ("observation", "observed_at, id"),
        ("assessment", "evaluated_at, id"), ("finding", "opened_at, id"), ("finding_event", "occurred_at, id"),
        ("risk_decision", "decided_at, id"), ("report", "period_start, id"), ("audit_event", "occurred_at, id"),
    ];

    public static string FileKey(Guid organizationId, Guid exportId) => $"{organizationId}/{exportId}.zip";

    public static void Map(IEndpointRouteBuilder app)
    {
        var org = app.MapGroup("/api/v1/organizations/{organizationId:guid}");
        org.MapPost("/exports", Create).RequireStaff(StaffRoles.AdminOnly);
        org.MapGet("/exports/{exportId:guid}", Get).RequireStaff(StaffRoles.AdminOnly);
        org.MapGet("/exports/{exportId:guid}/download", Download).RequireStaff(StaffRoles.AdminOnly);
    }

    private static async Task<IResult> Create(Guid organizationId, HttpContext http, RequestBodies bodies, DbScopes scopes,
        TimeProvider clock, CancellationToken ct)
    {
        const string operation = "createOrganizationExport";
        var actor = Actor.From(http.User);
        var request = await bodies.ReadAsync<OrganizationExportCreateBody>(http, "OrganizationExportCreate");
        var now = clock.GetUtcNow();
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        // Allowed in every lifecycle state: an export is the condition for scheduling deletion.
        await OrganizationEndpoints.RequireOrganizationAsync(scope, forUpdate: true, ct);
        var replay = await Idempotency.FindReplayAsync(scope, operation, request.Value.IdempotencyKey, request.RawHash, now, ct);
        if (replay is not null)
        {
            return Results.Text(replay.ResponseBody!, "application/json", statusCode: replay.ResponseStatus);
        }
        var export = new OrganizationExport
        {
            OrganizationId = organizationId, Id = Guid.CreateVersion7(), State = "queued", CreatedAt = now,
            RequestedBy = actor.EntraUserId,
        };
        scope.Db.OrganizationExports.Add(export);
        await scope.Db.SaveChangesAsync(ct);
        await JobQueue.EnqueueAsync(scope, "organization_export", organizationId, export.Id.ToString(), null, now, ct);
        var response = ApiJson.Serialize(OrganizationExportDto.From(export, now));
        await Idempotency.RecordAsync(scope, operation, request.Value.IdempotencyKey, request.RawHash, 202,
            export.Id.ToString(), response, now, ct);
        AuditLog.Staff(scope, actor, "organization_export.create", "organization_export", export.Id.ToString(), http.TraceIdentifier);
        await scope.CommitAsync(ct);
        return Results.Text(response, "application/json", statusCode: StatusCodes.Status202Accepted);
    }

    private static async Task<IResult> Get(Guid organizationId, Guid exportId, DbScopes scopes, TimeProvider clock,
        CancellationToken ct)
    {
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        await OrganizationEndpoints.RequireOrganizationAsync(scope, forUpdate: false, ct);
        var export = await FindAsync(scope, organizationId, exportId, ct);
        return Results.Json(OrganizationExportDto.From(export, clock.GetUtcNow()), ApiJson.Options);
    }

    private static async Task Download(Guid organizationId, Guid exportId, HttpContext http, DbScopes scopes,
        IFileStore files, TimeProvider clock, CancellationToken ct)
    {
        var actor = Actor.From(http.User);
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        await OrganizationEndpoints.RequireOrganizationAsync(scope, forUpdate: false, ct);
        var export = await FindAsync(scope, organizationId, exportId, ct);
        if (OrganizationExportDto.From(export, clock.GetUtcNow()).State != "ready"
            || await files.GetAsync(FileContainers.Exports, export.BlobKey!, ct) is not { } content)
        {
            throw new ApiProblemException(ProblemCodes.ResourceNotReady, "export is not available");
        }
        AuditLog.Staff(scope, actor, "organization_export.download", "organization_export", export.Id.ToString(),
            http.TraceIdentifier);
        await scope.CommitAsync(ct);
        var headers = http.Response.Headers;
        headers.ContentType = "application/zip";
        headers.ContentDisposition = $"attachment; filename=\"export-{export.Id}.zip\"";
        headers.XContentTypeOptions = "nosniff";
        headers.CacheControl = "private, no-store";
        http.Response.ContentLength = content.Length;
        await http.Response.Body.WriteAsync(content, ct);
    }

    private static async Task<OrganizationExport> FindAsync(DbScope scope, Guid organizationId, Guid exportId, CancellationToken ct) =>
        await scope.Db.OrganizationExports.AsNoTracking()
            .SingleOrDefaultAsync(e => e.OrganizationId == organizationId && e.Id == exportId, ct)
        ?? throw new ApiProblemException(ProblemCodes.NotFound);

    /// <summary>
    /// Writes the archive of the organization from the snapshot of the scope's transaction. The manifest lists every
    /// file with its SHA-256 and row count, the contract version and the database migrations of the service.
    /// </summary>
    public static async Task<(byte[] Content, IReadOnlyDictionary<string, int> Counts)> BuildAsync(DbScope scope,
        Organization organization, Guid exportId, ReportService reports, DateTimeOffset now, CancellationToken ct)
    {
        var counts = new SortedDictionary<string, int>(StringComparer.Ordinal);
        var files = new List<object>();
        using var buffer = new MemoryStream();
        using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            async Task AddAsync(string path, byte[] content, int? rows)
            {
                var entry = zip.CreateEntry(path, CompressionLevel.Optimal);
                await using (var stream = await entry.OpenAsync(ct))
                {
                    await stream.WriteAsync(content, ct);
                }
                files.Add(new { path, sha256 = Convert.ToHexStringLower(SHA256.HashData(content)), bytes = content.Length, rows });
            }

            await using (var utc = new NpgsqlCommand("set local timezone = 'UTC'", scope.Connection, scope.Transaction))
            {
                await utc.ExecuteNonQueryAsync(ct);
            }
            foreach (var (table, order) in Tables)
            {
                var column = table == "organization" ? "id" : "organization_id";
                await using var command = new NpgsqlCommand(
                    $"select to_jsonb(t)::text from {table} t where t.{column} = @org order by {order}",
                    scope.Connection, scope.Transaction);
                command.Parameters.AddWithValue("org", organization.Id);
                using var lines = new MemoryStream();
                var count = 0;
                await using (var reader = await command.ExecuteReaderAsync(ct))
                {
                    while (await reader.ReadAsync(ct))
                    {
                        lines.Write(Encoding.UTF8.GetBytes(reader.GetString(0)));
                        lines.WriteByte((byte)'\n');
                        count++;
                    }
                }
                counts[table] = count;
                await AddAsync($"data/{table}.jsonl", lines.ToArray(), count);
            }
            var ready = await scope.Db.Reports.AsNoTracking()
                .Where(r => r.OrganizationId == organization.Id && r.State == "ready").OrderBy(r => r.PeriodStart).ToListAsync(ct);
            foreach (var report in ready)
            {
                await AddAsync($"reports/report-{report.Id}.html", await reports.ContentAsync(report, ct), null);
            }
            counts["report_files"] = ready.Count;
            var manifest = JsonSerializer.SerializeToUtf8Bytes(new
            {
                formatVersion = FormatVersion, exportId, organizationId = organization.Id, organizationName = organization.Name,
                generatedAt = now, contractVersion = Catalog.Version,
                databaseMigrations = SchemaMigrator.Scripts().Select(s => s.Name).ToArray(),
                format = "data/<table>.jsonl: one JSON object per row with database column names, timestamps in UTC; "
                         + "reports/: HTML of ready reports",
                files,
            }, ApiJson.Options);
            var manifestEntry = zip.CreateEntry("manifest.json", CompressionLevel.Optimal);
            await using (var stream = await manifestEntry.OpenAsync(ct))
            {
                await stream.WriteAsync(manifest, ct);
            }
        }
        return (buffer.ToArray(), counts);
    }
}

/// <summary>organization_export: builds the archive, stores it in the exports container and marks the export ready.</summary>
public sealed class OrganizationExportJob(DbScopes scopes, IFileStore files, ReportService reports, TimeProvider clock,
    ILogger<OrganizationExportJob> logger) : IJobHandler
{
    public string Type => "organization_export";

    public async Task ExecuteAsync(JobLease lease, CancellationToken ct)
    {
        var organizationId = lease.OrganizationId ?? throw new InvalidOperationException("organization_export needs an organization");
        var exportId = Guid.Parse(lease.InputId!);
        try
        {
            await using var scope = await scopes.OrganizationSnapshotAsync(organizationId, ct);
            if (!await lease.HoldAsync(scope, ct))
            {
                throw new JobLeaseLostException();
            }
            var export = await scope.Db.OrganizationExports.SingleOrDefaultAsync(e => e.OrganizationId == organizationId && e.Id == exportId, ct);
            var organization = await scope.Db.Organizations.AsNoTracking().SingleOrDefaultAsync(o => o.Id == organizationId, ct);
            if (export is { State: "queued" } && organization is not null)
            {
                var now = clock.GetUtcNow();
                var (content, counts) = await OrganizationExports.BuildAsync(scope, organization, exportId, reports, now, ct);
                var key = OrganizationExports.FileKey(organizationId, exportId);
                await files.PutAsync(FileContainers.Exports, key, content, "application/zip", ct);
                export.State = "ready";
                export.BlobKey = key;
                export.ExpiresAt = now + OrganizationExports.Lifetime;
                logger.LogInformation("Export {ExportId} ready: {Bytes} bytes, {Rows} rows", exportId, content.Length,
                    counts.Values.Sum().ToString(CultureInfo.InvariantCulture));
            }
            await scope.Db.SaveChangesAsync(ct);
            await lease.CompleteAsync(scope, ct);
            await scope.CommitAsync(ct);
        }
        catch (Exception error) when (error is not (JobLeaseLostException or OperationCanceledException) && lease.IsLastAttempt)
        {
            logger.LogError(error, "Export {ExportId} failed", exportId);
            await using var scope = await scopes.OrganizationAsync(organizationId, ct);
            if (!await lease.HoldAsync(scope, ct))
            {
                throw new JobLeaseLostException();
            }
            await scope.Db.OrganizationExports.Where(e => e.OrganizationId == organizationId && e.Id == exportId && e.State == "queued")
                .ExecuteUpdateAsync(u => u.SetProperty(e => e.State, "failed"), ct);
            await lease.CompleteAsync(scope, ct);
            await scope.CommitAsync(ct);
        }
    }
}
