using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Assessment;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;
using Sikkerheit.Host.Operations;
using Sikkerheit.Host.Organizations;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.M365;

public sealed record CapabilityDto(string Module, string Status);

public sealed record TenantConnectionDto(
    string Status, Guid? EntraTenantId, string? TenantDisplayName, string? PrimaryDomain, Guid? PendingTenantId,
    DateTimeOffset? PendingExpiresAt, DateTimeOffset? ConnectedAt, DateTimeOffset? LastCollectedAt,
    string? LastCollectionState, bool? EntraP1, IReadOnlyList<CapabilityDto> Capabilities)
{
    public static TenantConnectionDto From(TenantConnection c, DateTimeOffset now)
    {
        var pendingValid = c.PendingTenantId is not null && c.PendingExpiresAt > now;
        var status = c.Status == "consent_pending" && !pendingValid
            ? (c.EntraTenantId is null ? "not_connected" : "disconnected")
            : c.Status;
        return new TenantConnectionDto(status, c.EntraTenantId, c.TenantDisplayName, c.PrimaryDomain,
            pendingValid ? c.PendingTenantId : null, pendingValid ? c.PendingExpiresAt : null, c.ConnectedAt,
            c.LastCollectedAt, c.LastCollectionState, c.EntraP1,
            JsonSerializer.Deserialize<List<CapabilityDto>>(c.Capabilities, ApiJson.Options) ?? []);
    }
}

public sealed record TenantConsentStartBody(string TenantHint, bool? AllowCompanyTenant);

public sealed record ConsentStartDto(string ConsentUrl, Guid ExpectedTenantId, DateTimeOffset ExpiresAt);

public sealed record CollectionRunCreateBody(Guid IdempotencyKey);

public sealed record CollectionRunDto(
    Guid Id, string Trigger, string State, DateTimeOffset QueuedAt, DateTimeOffset? StartedAt, DateTimeOffset? CompletedAt,
    string? FailureCode, IReadOnlyList<CapabilityDto> Capabilities)
{
    public static CollectionRunDto From(CollectionRun r) => new(r.Id, r.Trigger, r.State, r.QueuedAt, r.StartedAt,
        r.CompletedAt, r.FailureCode, JsonSerializer.Deserialize<List<CapabilityDto>>(r.Capabilities, ApiJson.Options) ?? []);
}

/// <summary>Microsoft 365 connection and collection runs (FR-04, FR-05; 05 «Подключение M365 и сбор»).</summary>
public static class ConnectionEndpoints
{
    public static readonly TimeSpan ConsentWindow = TimeSpan.FromDays(7);

    public static void Map(IEndpointRouteBuilder app)
    {
        var org = app.MapGroup("/api/v1/organizations/{organizationId:guid}");
        org.MapGet("/m365-connection", Get).RequireStaff(StaffRoles.All);
        org.MapPost("/m365-connection/consent", StartConsent).RequireStaff(StaffRoles.AdminOnly);
        org.MapPost("/m365-connection/verify", Verify).RequireStaff(StaffRoles.AdminOnly);
        org.MapPost("/m365-connection/disconnect", Disconnect).RequireStaff(StaffRoles.AdminOnly);
        org.MapGet("/collection-runs", ListRuns).RequireStaff(StaffRoles.All);
        org.MapPost("/collection-runs", RequestRun).RequireStaff(StaffRoles.Work);
    }

    private static async Task<TenantConnection> ConnectionAsync(DbScope scope, bool forUpdate, CancellationToken ct)
    {
        var id = scope.OrganizationId!.Value;
        var query = forUpdate
            ? scope.Db.TenantConnections.FromSqlInterpolated($"select * from tenant_connection where organization_id = {id} for update")
            : scope.Db.TenantConnections.Where(c => c.OrganizationId == id);
        return await query.SingleAsync(ct);
    }

    private static async Task<IResult> Get(Guid organizationId, DbScopes scopes, TimeProvider clock, CancellationToken ct)
    {
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        await OrganizationEndpoints.RequireOrganizationAsync(scope, forUpdate: false, ct);
        var connection = await ConnectionAsync(scope, forUpdate: false, ct);
        return Results.Json(TenantConnectionDto.From(connection, clock.GetUtcNow()), ApiJson.Options);
    }

    private static async Task<IResult> StartConsent(Guid organizationId, HttpContext http, RequestBodies bodies,
        DbScopes scopes, ITenantResolver resolver, M365Options options, TimeProvider clock, CancellationToken ct)
    {
        var actor = Actor.From(http.User);
        var body = (await bodies.ReadAsync<TenantConsentStartBody>(http, "TenantConsentStart")).Value;
        var tenant = await resolver.ResolveAsync(body.TenantHint.Trim(), ct)
            ?? throw new ApiProblemException(ProblemCodes.ValidationFailed, "tenantHint is not a tenant ID or a known domain");
        if (tenant == options.CompanyTenantId && body.AllowCompanyTenant != true)
        {
            throw new ApiProblemException(ProblemCodes.ValidationFailed, "the company tenant needs allowCompanyTenant=true");
        }
        var now = clock.GetUtcNow();
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        var organization = await OrganizationEndpoints.RequireOrganizationAsync(scope, forUpdate: true, ct);
        OrganizationEndpoints.RequireActive(organization);
        var connection = await ConnectionAsync(scope, forUpdate: true, ct);
        var owner = await ActiveOwnerAsync(scope, tenant, ct);
        if ((owner is not null && owner != organizationId)
            || (connection.Status == "active" && connection.EntraTenantId != tenant))
        {
            throw new ApiProblemException(ProblemCodes.TenantConflict);
        }
        var expires = now + ConsentWindow;
        if (connection.Status != "active")
        {
            connection.Status = "consent_pending";
        }
        connection.PendingTenantId = tenant;
        connection.PendingExpiresAt = expires;
        connection.AllowCompanyTenant = body.AllowCompanyTenant == true;
        AuditLog.Staff(scope, actor, "m365.consent_start", "tenant_connection", organizationId.ToString(), http.TraceIdentifier);
        await scope.CommitAsync(ct);
        var url = $"https://login.microsoftonline.com/{tenant}/v2.0/adminconsent?client_id={Uri.EscapeDataString(options.ClientId ?? "")}"
                  + $"&scope={Uri.EscapeDataString("https://graph.microsoft.com/.default")}"
                  + $"&redirect_uri={Uri.EscapeDataString(options.ConsentRedirectUri ?? "")}";
        return Results.Json(new ConsentStartDto(url, tenant, expires), ApiJson.Options, statusCode: StatusCodes.Status201Created);
    }

    private static async Task<IResult> Verify(Guid organizationId, HttpContext http, DbScopes scopes, GraphClient graph,
        TimeProvider clock, CancellationToken ct)
    {
        var actor = Actor.From(http.User);
        var now = clock.GetUtcNow();
        Guid tenant;
        await using (var check = await scopes.OrganizationAsync(organizationId, ct))
        {
            var organization = await OrganizationEndpoints.RequireOrganizationAsync(check, forUpdate: false, ct);
            OrganizationEndpoints.RequireActive(organization);
            var current = await ConnectionAsync(check, forUpdate: false, ct);
            tenant = current.PendingTenantId is { } pending && current.PendingExpiresAt > now ? pending
                : current.Status == "active" && current.EntraTenantId is { } active ? active
                : throw new ApiProblemException(ProblemCodes.ConnectionStateConflict, "no tenant to verify");
            var owner = await ActiveOwnerAsync(check, tenant, ct);
            if (owner is not null && owner != organizationId)
            {
                throw new ApiProblemException(ProblemCodes.TenantConflict);
            }
        }

        // The service trusts only its own token and /organization, not browser parameters.
        string? displayName = null;
        string? primaryDomain = null;
        try
        {
            var body = await graph.GetAsync(tenant, "v1.0/organization?$select=id,displayName,verifiedDomains", GraphLimit.Default, ct);
            var organization = body.GetProperty("value").EnumerateArray().FirstOrDefault();
            if (organization.ValueKind != JsonValueKind.Object || organization.GetProperty("id").GetString() is not { } id
                || !Guid.TryParse(id, out var actual) || actual != tenant)
            {
                throw new ApiProblemException(ProblemCodes.ConsentNotGranted, "/organization returned another tenant");
            }
            displayName = M365Collector.Clean(organization.TryGetProperty("displayName", out var name) ? name.GetString() : null);
            primaryDomain = organization.TryGetProperty("verifiedDomains", out var domains)
                ? M365Collector.Clean(domains.EnumerateArray().FirstOrDefault(d => d.TryGetProperty("isDefault", out var isDefault)
                    && isDefault.GetBoolean()).TryGetProperty("name", out var domain) ? domain.GetString() : null)
                : null;
        }
        catch (GraphTokenException)
        {
            throw new ApiProblemException(ProblemCodes.ConsentNotGranted, "no token for the expected tenant");
        }
        catch (GraphException error) when (error.Failure is GraphFailure.Forbidden or GraphFailure.Unauthorized)
        {
            throw new ApiProblemException(ProblemCodes.ConsentNotGranted, "Graph refused the request");
        }

        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        var org = await OrganizationEndpoints.RequireOrganizationAsync(scope, forUpdate: true, ct);
        OrganizationEndpoints.RequireActive(org);
        var connection = await ConnectionAsync(scope, forUpdate: true, ct);
        var previousTenant = connection.EntraTenantId;
        var wasActive = connection.Status == "active" && previousTenant == tenant;
        connection.Status = "active";
        connection.EntraTenantId = tenant;
        connection.TenantDisplayName = displayName;
        connection.PrimaryDomain = primaryDomain;
        connection.PendingTenantId = null;
        connection.PendingExpiresAt = null;
        if (!wasActive)
        {
            connection.ConnectedAt = now;
            connection.ConnectedBy = actor.EntraUserId;
            connection.DisconnectedAt = null;
        }
        if (previousTenant is { } old && old != tenant)
        {
            await SubjectRetirement.RetireTenantAsync(scope, actor.EntraUserId, now, ct);
        }
        if (!wasActive)
        {
            AuditLog.Staff(scope, actor, "m365.connect", "tenant_connection", organizationId.ToString(), http.TraceIdentifier);
            await QueueRunAsync(scope, "manual", now, ct);
        }
        try
        {
            await scope.CommitAsync(ct);
        }
        catch (DbUpdateException error) when (error.InnerException is Npgsql.PostgresException { SqlState: "23505" })
        {
            throw new ApiProblemException(ProblemCodes.TenantConflict);
        }
        return Results.Json(TenantConnectionDto.From(connection, now), ApiJson.Options);
    }

    private static async Task<IResult> Disconnect(Guid organizationId, HttpContext http, DbScopes scopes,
        ISecurityLog securityLog, TimeProvider clock, CancellationToken ct)
    {
        var actor = Actor.From(http.User);
        var now = clock.GetUtcNow();
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        await OrganizationEndpoints.RequireOrganizationAsync(scope, forUpdate: true, ct);
        var connection = await ConnectionAsync(scope, forUpdate: true, ct);
        if (connection.Status is "active" or "consent_pending")
        {
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeout.CancelAfter(TimeSpan.FromSeconds(5));
                await securityLog.AppendAsync(new SecurityLogRecord(Guid.CreateVersion7(), "m365.disconnect", organizationId,
                    "tenant_connection", organizationId.ToString(), now, http.TraceIdentifier, actor.EntraUserId), timeout.Token);
            }
            catch (Exception error) when (error is SecurityLogUnavailableException or OperationCanceledException
                                          && !ct.IsCancellationRequested)
            {
                // The restrictive action is refused; operations are alerted by the error (06 «Наблюдаемость»).
                http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Sikkerheit.SecurityLog")
                    .LogError(error, "Security log record {Action} was not created; the action is refused with 503", "m365.disconnect");
                throw new ApiProblemException(ProblemCodes.TemporarilyUnavailable, "security log is unavailable");
            }
            await TenantConnections.DisconnectAsync(scope, now, ct);
            AuditLog.Staff(scope, actor, "m365.disconnect", "tenant_connection", organizationId.ToString(), http.TraceIdentifier);
        }
        await scope.CommitAsync(ct);
        return Results.Json(TenantConnectionDto.From(connection, now), ApiJson.Options);
    }

    private static async Task<IResult> ListRuns(Guid organizationId, DbScopes scopes, Cursors cursors, string? cursor,
        string? limit, CancellationToken ct)
    {
        var size = OrganizationEndpoints.Limit(limit);
        var position = cursors.Read(cursor, "listCollectionRuns", organizationId, "");
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        await OrganizationEndpoints.RequireOrganizationAsync(scope, forUpdate: false, ct);
        var query = scope.Db.CollectionRuns.AsNoTracking().Where(r => r.OrganizationId == organizationId);
        if (position is not null)
        {
            var before = DateTimeOffset.Parse(position[0], CultureInfo.InvariantCulture);
            query = query.Where(r => r.QueuedAt < before);
        }
        var rows = await query.OrderByDescending(r => r.QueuedAt).Take(size + 1).ToListAsync(ct);
        string? next = null;
        if (rows.Count > size)
        {
            rows.RemoveAt(size);
            next = cursors.Create("listCollectionRuns", organizationId, "", [rows[^1].QueuedAt.ToString("O", CultureInfo.InvariantCulture)]);
        }
        return Results.Json(new Page<CollectionRunDto>(rows.Select(CollectionRunDto.From).ToList(), next), ApiJson.Options);
    }

    private static async Task<IResult> RequestRun(Guid organizationId, HttpContext http, RequestBodies bodies,
        DbScopes scopes, TimeProvider clock, CancellationToken ct)
    {
        const string operation = "requestCollection";
        var actor = Actor.From(http.User);
        var request = await bodies.ReadAsync<CollectionRunCreateBody>(http, "CollectionRunCreate");
        var now = clock.GetUtcNow();
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        var organization = await OrganizationEndpoints.RequireOrganizationAsync(scope, forUpdate: true, ct);
        var replay = await Idempotency.FindReplayAsync(scope, operation, request.Value.IdempotencyKey, request.RawHash, now, ct);
        if (replay is not null)
        {
            var previous = await scope.Db.CollectionRuns.AsNoTracking()
                .SingleAsync(r => r.OrganizationId == organizationId && r.Id == Guid.Parse(replay.ResultId!), ct);
            return Results.Json(CollectionRunDto.From(previous), ApiJson.Options, statusCode: StatusCodes.Status202Accepted);
        }
        OrganizationEndpoints.RequireActive(organization);
        var connection = await ConnectionAsync(scope, forUpdate: true, ct);
        if (connection.Status != "active")
        {
            throw new ApiProblemException(ProblemCodes.ConnectionStateConflict, "the connection is not active");
        }
        var run = await QueueRunAsync(scope, "manual", now, ct);
        await Idempotency.RecordAsync(scope, operation, request.Value.IdempotencyKey, request.RawHash, 202, run.Id.ToString(),
            null, now, ct);
        AuditLog.Staff(scope, actor, "m365.collection_request", "collection_run", run.Id.ToString(), http.TraceIdentifier);
        await scope.CommitAsync(ct);
        return Results.Json(CollectionRunDto.From(run), ApiJson.Options, statusCode: StatusCodes.Status202Accepted);
    }

    /// <summary>Queues a run or returns the open one: one queued or running run per organization.</summary>
    public static async Task<CollectionRun> QueueRunAsync(DbScope scope, string trigger, DateTimeOffset now, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        var open = await scope.Db.CollectionRuns
            .SingleOrDefaultAsync(r => r.OrganizationId == org && (r.State == "queued" || r.State == "running"), ct);
        if (open is not null)
        {
            return open;
        }
        var run = new CollectionRun
        {
            OrganizationId = org, Id = Guid.CreateVersion7(), Trigger = trigger, State = "queued", QueuedAt = now,
            Capabilities = "[]",
        };
        scope.Db.CollectionRuns.Add(run);
        await JobQueue.EnqueueAsync(scope, "m365_collect", org, run.Id.ToString(), null, now, ct);
        return run;
    }

    private static async Task<Guid?> ActiveOwnerAsync(DbScope scope, Guid tenant, CancellationToken ct) =>
        await scope.Db.Database.SqlQuery<Guid?>($"select app.active_tenant_owner({tenant}) as \"Value\"").SingleAsync(ct);
}
