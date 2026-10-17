using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Assessment;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Exports;
using Sikkerheit.Host.Jobs;
using Sikkerheit.Host.M365;
using Sikkerheit.Host.Operations;
using Sikkerheit.Host.Platform;
using Sikkerheit.Host.Reports;

namespace Sikkerheit.Host.Organizations;

/// <summary>Organizations, lifecycle, policy revisions and the audit journal (FR-01, FR-02, FR-03; 05).</summary>
public static class OrganizationEndpoints
{
    public static readonly TimeSpan DeletionDelay = TimeSpan.FromDays(30);

    public static void Map(IEndpointRouteBuilder app)
    {
        var api = app.MapGroup("/api/v1");
        api.MapGet("/organizations", List).RequireStaff(StaffRoles.All);
        api.MapPost("/organizations", Create).RequireStaff(StaffRoles.AdminOnly);
        var org = api.MapGroup("/organizations/{organizationId:guid}");
        org.MapGet("", Get).RequireStaff(StaffRoles.All);
        org.MapPatch("", Update).RequireStaff(StaffRoles.AdminOnly);
        org.MapPost("/lifecycle", ChangeLifecycle).RequireStaff(StaffRoles.AdminOnly);
        org.MapGet("/policy-revisions", ListPolicies).RequireStaff(StaffRoles.All);
        org.MapPost("/policy-revisions", CreatePolicy).RequireStaff(StaffRoles.AdminOnly);
        org.MapGet("/audit-events", ListAudit).RequireStaff(StaffRoles.AdminOnly);
    }

    public static int Limit(string? value)
    {
        if (value is null)
        {
            return 50;
        }
        if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var limit) || limit is < 1 or > 100)
        {
            throw new ApiProblemException(ProblemCodes.SchemaViolation, "limit must be an integer 1..100");
        }
        return limit;
    }

    /// <summary>Loads the organization of the path in its scope; deleted or foreign organizations are 404.</summary>
    public static async Task<Organization> RequireOrganizationAsync(DbScope scope, bool forUpdate, CancellationToken ct) =>
        await OrganizationLifecycle.FindAsync(scope, forUpdate, ct) ?? throw new ApiProblemException(ProblemCodes.NotFound);

    /// <summary>Changes other than lifecycle, export and disconnect are refused while the organization is inactive.</summary>
    public static void RequireActive(Organization organization)
    {
        if (organization.Status != "active")
        {
            throw new ApiProblemException(ProblemCodes.LifecycleTransitionForbidden, "organization is " + organization.Status);
        }
    }

    private static async Task<IResult> List(HttpContext http, DbScopes scopes, Cursors cursors, TimeProvider clock,
        string? cursor, string? limit, CancellationToken ct)
    {
        var size = Limit(limit);
        var position = cursors.Read(cursor, "listOrganizations", null, "");
        await using var scope = await scopes.ReadAllAsync(ct);
        await using var command = new NpgsqlCommand("""
            select o.id, o.name, o.timezone, o.report_language, o.status, o.deletion_due_at, o.created_at
            from organization o
            where @after_name::text is null or (o.name, o.id) > (@after_name::text, @after_id::uuid)
            order by o.name, o.id
            limit @take
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("after_name", (object?)position?[0] ?? DBNull.Value);
        command.Parameters.AddWithValue("after_id", position is null ? DBNull.Value : Guid.Parse(position[1]));
        command.Parameters.AddWithValue("take", size + 1);
        var items = new List<OrganizationOverviewDto>();
        await using (var reader = await command.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
            {
                var organization = new OrganizationDto(
                    reader.GetGuid(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetString(4),
                    reader.IsDBNull(5) ? null : reader.GetFieldValue<DateTimeOffset>(5), reader.GetFieldValue<DateTimeOffset>(6));
                items.Add(new OrganizationOverviewDto(organization, "not_connected", null, 0, 0, 0, null));
            }
        }
        var connections = await TenantConnections.StatesAsync(scope, ct);
        var open = await FindingHistory.OpenCountsAsync(scope, ct);
        for (var i = 0; i < items.Count; i++)
        {
            var id = items[i].Organization.Id;
            var connection = connections.GetValueOrDefault(id);
            var counts = open.GetValueOrDefault(id);
            items[i] = items[i] with
            {
                M365Status = connection?.Status ?? "not_connected", LastCollectedAt = connection?.LastCollectedAt,
                OpenCritical = counts?.Critical ?? 0, OpenWarning = counts?.Warning ?? 0,
            };
        }
        string? next = null;
        var hasMore = items.Count > size;
        if (hasMore)
        {
            items.RemoveAt(size);
        }
        // coverageAt now — the same calculation as the report (05 «Отчёт и покрытие»).
        var now = clock.GetUtcNow();
        for (var i = 0; i < items.Count; i++)
        {
            var coverage = await Coverage.AtAsync(scope, items[i].Organization.Id, now, ct);
            items[i] = items[i] with { CoverageAt = coverage.CoverageAt };
        }
        if (hasMore)
        {
            var last = items[^1].Organization;
            next = cursors.Create("listOrganizations", null, "", [last.Name, last.Id.ToString()]);
        }
        return Results.Json(new Page<OrganizationOverviewDto>(items, next), ApiJson.Options);
    }

    private static async Task<IResult> Create(HttpContext http, RequestBodies bodies, DbScopes scopes,
        PolicyRules policy, TimeProvider clock, CancellationToken ct)
    {
        var actor = Actor.From(http.User);
        var body = (await bodies.ReadAsync<OrganizationCreateBody>(http, "OrganizationCreate")).Value;
        RequireTimezone(body.Timezone);
        var now = clock.GetUtcNow();
        var organization = new Organization
        {
            Id = Guid.CreateVersion7(), Name = body.Name, Timezone = body.Timezone, ReportLanguage = body.ReportLanguage,
            Status = "active", CreatedAt = now, NextPolicyVersion = 2,
        };
        await using var scope = await scopes.OrganizationAsync(organization.Id, ct);
        scope.Db.Organizations.Add(organization);
        scope.Db.PolicyRevisions.Add(new PolicyRevision
        {
            OrganizationId = organization.Id, Version = 1, EffectiveFrom = now, CreatedAt = now,
            CreatedBy = actor.EntraUserId, Configuration = policy.DefaultConfiguration,
        });
        TenantConnections.Create(scope);
        AuditLog.Staff(scope, actor, "organization.create", "organization", organization.Id.ToString(), http.TraceIdentifier);
        await scope.CommitAsync(ct);
        return Results.Json(OrganizationDto.From(organization), ApiJson.Options, statusCode: StatusCodes.Status201Created);
    }

    private static async Task<IResult> Get(Guid organizationId, DbScopes scopes, CancellationToken ct)
    {
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        var organization = await RequireOrganizationAsync(scope, forUpdate: false, ct);
        return Results.Json(OrganizationDto.From(organization), ApiJson.Options);
    }

    private static async Task<IResult> Update(Guid organizationId, HttpContext http, RequestBodies bodies,
        DbScopes scopes, CancellationToken ct)
    {
        var actor = Actor.From(http.User);
        var body = (await bodies.ReadAsync<OrganizationUpdateBody>(http, "OrganizationUpdate")).Value;
        if (body.Timezone is not null)
        {
            RequireTimezone(body.Timezone);
        }
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        var organization = await RequireOrganizationAsync(scope, forUpdate: true, ct);
        RequireActive(organization);
        organization.Name = body.Name ?? organization.Name;
        organization.Timezone = body.Timezone ?? organization.Timezone;
        organization.ReportLanguage = body.ReportLanguage ?? organization.ReportLanguage;
        AuditLog.Staff(scope, actor, "organization.update", "organization", organizationId.ToString(), http.TraceIdentifier);
        await scope.CommitAsync(ct);
        return Results.Json(OrganizationDto.From(organization), ApiJson.Options);
    }

    private static async Task<IResult> ChangeLifecycle(Guid organizationId, HttpContext http, RequestBodies bodies,
        DbScopes scopes, ISecurityLog securityLog, TimeProvider clock, CancellationToken ct)
    {
        const string operation = "changeOrganizationLifecycle";
        var actor = Actor.From(http.User);
        var request = await bodies.ReadAsync<LifecycleChangeBody>(http, "OrganizationLifecycleChange");
        var body = request.Value;
        var now = clock.GetUtcNow();
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        var organization = await RequireOrganizationAsync(scope, forUpdate: true, ct);
        var replay = await Idempotency.FindReplayAsync(scope, operation, body.IdempotencyKey, request.RawHash, now, ct);
        if (replay is not null)
        {
            return Results.Text(replay.ResponseBody!, "application/json", statusCode: replay.ResponseStatus);
        }

        string? logAction = null;
        switch (body.Action, organization.Status)
        {
            case ("disable", "active"):
                logAction = "organization.disable";
                break;
            case ("enable", "disabled"):
                break;
            case ("schedule_deletion", "disabled"):
                if (body.ExportWaived != true && !await HasExportSinceDisableAsync(scope, organization, ct))
                {
                    throw new ApiProblemException(ProblemCodes.LifecycleTransitionForbidden,
                        "an export after disabling or exportWaived=true is required");
                }
                logAction = "organization.schedule_deletion";
                break;
            case ("cancel_deletion", "deletion_scheduled") when organization.DeletionDueAt > now:
                logAction = "organization.cancel_deletion";
                break;
            default:
                throw new ApiProblemException(ProblemCodes.LifecycleTransitionForbidden,
                    $"{body.Action} is not allowed from {organization.Status}");
        }

        var dueAt = body.Action == "schedule_deletion" ? now + DeletionDelay : (DateTimeOffset?)null;
        if (logAction is not null)
        {
            // The record is created before the state changes; without it the restrictive action does not happen.
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeout.CancelAfter(TimeSpan.FromSeconds(5));
                await securityLog.AppendAsync(new SecurityLogRecord(
                    Guid.CreateVersion7(), logAction, organizationId, "organization", organizationId.ToString(), now,
                    http.TraceIdentifier, actor.EntraUserId, DeletionDueAt: dueAt), timeout.Token);
            }
            catch (Exception error) when (error is SecurityLogUnavailableException or OperationCanceledException
                                          && !ct.IsCancellationRequested)
            {
                // The restrictive action is refused; operations are alerted by the error (06 «Наблюдаемость»).
                http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Sikkerheit.SecurityLog")
                    .LogError(error, "Security log record {Action} was not created; the action is refused with 503", logAction);
                throw new ApiProblemException(ProblemCodes.TemporarilyUnavailable, "security log is unavailable");
            }
        }

        switch (body.Action)
        {
            case "disable":
                OrganizationLifecycle.Disable(organization, now);
                break;
            case "enable":
                OrganizationLifecycle.Enable(organization);
                break;
            case "schedule_deletion":
                OrganizationLifecycle.ScheduleDeletion(organization, dueAt!.Value);
                break;
            case "cancel_deletion":
                OrganizationLifecycle.CancelDeletion(organization);
                break;
        }
        var response = ApiJson.Serialize(OrganizationDto.From(organization));
        await Idempotency.RecordAsync(scope, operation, body.IdempotencyKey, request.RawHash, 200,
            organizationId.ToString(), response, now, ct);
        AuditLog.Staff(scope, actor, "organization.lifecycle_change", "organization", organizationId.ToString(),
            http.TraceIdentifier, new LifecycleAuditDetails(body.Action, body.Reason, body.ExportWaived == true));
        await scope.CommitAsync(ct);
        return Results.Text(response, "application/json", statusCode: StatusCodes.Status200OK);
    }

    private static Task<bool> HasExportSinceDisableAsync(DbScope scope, Organization organization, CancellationToken ct) =>
        OrganizationExports.HasExportSinceAsync(scope, organization.DisabledAt ?? DateTimeOffset.MaxValue, ct);

    private static async Task<IResult> ListPolicies(Guid organizationId, DbScopes scopes, Cursors cursors,
        string? cursor, string? limit, CancellationToken ct)
    {
        var size = Limit(limit);
        var position = cursors.Read(cursor, "listPolicyRevisions", organizationId, "");
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        await RequireOrganizationAsync(scope, forUpdate: false, ct);
        var query = scope.Db.PolicyRevisions.AsNoTracking().Where(p => p.OrganizationId == organizationId);
        if (position is not null)
        {
            var before = int.Parse(position[0], CultureInfo.InvariantCulture);
            query = query.Where(p => p.Version < before);
        }
        var rows = await query.OrderByDescending(p => p.Version).Take(size + 1).ToListAsync(ct);
        string? next = null;
        if (rows.Count > size)
        {
            rows.RemoveAt(size);
            next = cursors.Create("listPolicyRevisions", organizationId, "",
                [rows[^1].Version.ToString(CultureInfo.InvariantCulture)]);
        }
        return Results.Json(new Page<PolicyRevisionDto>(rows.Select(PolicyRevisionDto.From).ToList(), next), ApiJson.Options);
    }

    private static async Task<IResult> CreatePolicy(Guid organizationId, HttpContext http, RequestBodies bodies,
        DbScopes scopes, TimeProvider clock, CancellationToken ct)
    {
        var actor = Actor.From(http.User);
        var ifMatch = http.Request.Headers.IfMatch.ToString();
        if (ifMatch.Length == 0)
        {
            throw new ApiProblemException(ProblemCodes.IfMatchRequired);
        }
        var body = (await bodies.ReadAsync<PolicyRevisionCreateBody>(http, "PolicyRevisionCreate")).Value;
        PolicyRules.Validate(body.Configuration);
        var now = clock.GetUtcNow();
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        var organization = await RequireOrganizationAsync(scope, forUpdate: true, ct);
        RequireActive(organization);
        var revision = await PolicyWriting.CreateAsync(scope, organization, ifMatch, body.Configuration, actor,
            http.TraceIdentifier, now, ct);
        await scope.CommitAsync(ct);
        http.Response.Headers.ETag = $"\"{revision.Version}\"";
        return Results.Json(PolicyRevisionDto.From(revision), ApiJson.Options, statusCode: StatusCodes.Status201Created);
    }

    private static async Task<IResult> ListAudit(Guid organizationId, HttpContext http, DbScopes scopes,
        Cursors cursors, string? cursor, string? limit, CancellationToken ct)
    {
        var actor = Actor.From(http.User);
        var size = Limit(limit);
        var position = cursors.Read(cursor, "listAuditEvents", organizationId, "");
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        await RequireOrganizationAsync(scope, forUpdate: false, ct);
        var before = position is null
            ? ((DateTimeOffset, Guid)?)null
            : (DateTimeOffset.Parse(position[0], CultureInfo.InvariantCulture), Guid.Parse(position[1]));
        var rows = await AuditLog.ListAsync(scope, before, size + 1, ct);
        string? next = null;
        if (rows.Count > size)
        {
            rows.RemoveAt(size);
            next = cursors.Create("listAuditEvents", organizationId, "",
                [rows[^1].OccurredAt.ToString("O", CultureInfo.InvariantCulture), rows[^1].Id.ToString()]);
        }
        // Every read of the journal is itself audited (x-audit-read).
        AuditLog.Staff(scope, actor, "audit_events.read", "organization", organizationId.ToString(), http.TraceIdentifier);
        await scope.CommitAsync(ct);
        return Results.Json(new Page<AuditEventDto>(rows.Select(AuditEventDto.From).ToList(), next), ApiJson.Options);
    }

    private static void RequireTimezone(string timezone)
    {
        var known = timezone is "UTC" or "Etc/UTC"
                    || (timezone.Contains('/', StringComparison.Ordinal)
                        && TimeZoneInfo.TryConvertIanaIdToWindowsId(timezone, out _)
                        && TimeZoneInfo.TryFindSystemTimeZoneById(timezone, out _));
        if (!known)
        {
            throw new ApiProblemException(ProblemCodes.ValidationFailed, "timezone must be an IANA time zone");
        }
    }
}
