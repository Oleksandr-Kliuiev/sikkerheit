using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using NpgsqlTypes;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Operations;
using Sikkerheit.Host.Organizations;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Assessment;

public sealed record SubjectDto(string Type, string Key, string? DisplayName, Guid? DeviceId);

public sealed record FindingDto(
    Guid Id, Guid OrganizationId, string CheckId, SubjectDto Subject, string TechnicalState, string WorkflowState,
    string AssessmentResult, string Freshness, string Severity, int Revision, string Title, string Recommendation,
    DateTimeOffset OpenedAt, DateTimeOffset LatestObservedAt, Guid? AssigneeId, DateTimeOffset? DueAt,
    string? WorkflowReason, DateTimeOffset? ReviewAt, Guid? WorkflowDecidedBy);

public sealed record FindingEventDto(Guid Id, DateTimeOffset OccurredAt, string EventType, string Cause, Guid? AssessmentId,
    Guid? ActorId, string? FromWorkflowState, string? ToWorkflowState);

public sealed record AssessmentDto(
    Guid Id, SubjectDto Subject, string CheckId, string RuleId, string RuleVersion, int SourcePolicyVersion,
    int EvaluatedPolicyVersion, string AssessmentScope, string AssessmentMode, string? Result, string? Severity,
    string Freshness, string? ReasonCode, DateTimeOffset ObservedAt, DateTimeOffset ReceivedAt, JsonElement? Evidence,
    string EvidenceAvailability, string Explanation);

public sealed record FindingPatchBody(string? WorkflowState, Guid? AssigneeId, DateTimeOffset? DueAt);

public sealed record RiskDecisionBody(string Decision, string? Reason, DateTimeOffset? ReviewAt);

public sealed record AssignmentChange<T>(T From, T To);

/// <summary>Findings, workflow, risk decisions, events and assessments (FR-06, FR-07, FR-09; 05).</summary>
public static class FindingEndpoints
{
    private static readonly string[] TechnicalStates = ["open", "resolved"];
    private static readonly string[] Freshnesses = ["fresh", "stale"];
    private static readonly string[] Severities = ["critical", "warning"];
    private static readonly string[] WorkflowStates = ["new", "in_progress", "risk_accepted", "suppressed"];

    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapGet("/api/v1/findings", ListAcross).RequireStaff(StaffRoles.All);
        var org = app.MapGroup("/api/v1/organizations/{organizationId:guid}");
        org.MapGet("/findings", List).RequireStaff(StaffRoles.All);
        org.MapGet("/findings/{findingId:guid}", Get).RequireStaff(StaffRoles.All);
        org.MapPatch("/findings/{findingId:guid}", Patch).RequireStaff(StaffRoles.Work);
        org.MapPost("/findings/{findingId:guid}/risk-decisions", Decide).RequireStaff(StaffRoles.AdminOnly);
        org.MapGet("/findings/{findingId:guid}/events", Events).RequireStaff(StaffRoles.All);
        org.MapGet("/assessments", Assessments).RequireStaff(StaffRoles.All);
    }

    private sealed record Filters(string[]? TechnicalState, string[]? Freshness, string[]? Severity, string[]? CheckId,
        string[]? WorkflowState)
    {
        public string Key => Cursors.Filter(("t", Join(TechnicalState)), ("f", Join(Freshness)), ("s", Join(Severity)),
            ("c", Join(CheckId)), ("w", Join(WorkflowState)));

        private static string? Join(string[]? values) => values is null ? null : string.Join(',', values);
    }

    private static string[]? Values(string? raw, IReadOnlyCollection<string> allowed)
    {
        if (raw is null)
        {
            return null;
        }
        var values = raw.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Distinct().Order().ToArray();
        if (values.Length == 0 || values.Any(v => !allowed.Contains(v)))
        {
            throw new ApiProblemException(ProblemCodes.SchemaViolation, "unknown filter value");
        }
        return values;
    }

    private static Filters Parse(string? technicalState, string? freshness, string? severity, string? checkId, string? workflowState) =>
        new(Values(technicalState, TechnicalStates), Values(freshness, Freshnesses), Values(severity, Severities),
            Values(checkId, Catalog.Checks.Select(c => c.CheckId).ToArray()), Values(workflowState, WorkflowStates));

    private static async Task<IResult> List(Guid organizationId, HttpContext http, DbScopes scopes, Cursors cursors,
        TimeProvider clock, string? cursor, string? limit, string? technicalState, string? freshness, string? severity,
        string? checkId, string? workflowState, CancellationToken ct)
    {
        var filters = Parse(technicalState, freshness, severity, checkId, workflowState);
        var size = OrganizationEndpoints.Limit(limit);
        var position = cursors.Read(cursor, "listFindings", organizationId, filters.Key);
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        await OrganizationEndpoints.RequireOrganizationAsync(scope, forUpdate: false, ct);
        var (items, next) = await QueryAsync(scope, http, cursors, clock, "listFindings", organizationId, filters, position, size, ct);
        return Localized(http, new Page<FindingDto>(items, next));
    }

    private static async Task<IResult> ListAcross(HttpContext http, DbScopes scopes, Cursors cursors, TimeProvider clock,
        string? cursor, string? limit, string? technicalState, string? freshness, string? severity, string? checkId,
        string? workflowState, CancellationToken ct)
    {
        var filters = Parse(technicalState, freshness, severity, checkId, workflowState);
        var size = OrganizationEndpoints.Limit(limit);
        var position = cursors.Read(cursor, "listFindingsAcrossOrganizations", null, filters.Key);
        await using var scope = await scopes.ReadAllAsync(ct);
        var (items, next) = await QueryAsync(scope, http, cursors, clock, "listFindingsAcrossOrganizations", null, filters,
            position, size, ct);
        return Localized(http, new Page<FindingDto>(items, next));
    }

    private static async Task<(List<FindingDto>, string?)> QueryAsync(DbScope scope, HttpContext http, Cursors cursors,
        TimeProvider clock, string operation, Guid? organizationId, Filters filters, IReadOnlyList<string>? position, int size,
        CancellationToken ct)
    {
        var language = Texts.Language(http.Request.Headers.AcceptLanguage);
        var windows = await WindowsAsync(scope, ct);
        await using var command = new NpgsqlCommand($"""
            with latest as (
                select w.key::uuid as organization_id, w.value as windows from jsonb_each(@windows) w)
            select {Columns},
                   case f.severity when 'critical' then 0 else 1 end as rank
            from finding f
            join subject s on s.organization_id = f.organization_id and s.id = f.subject_id
            join latest l on l.organization_id = f.organization_id
            where (@org::uuid is null or f.organization_id = @org)
              and (@technical::text[] is null or f.technical_state = any(@technical))
              and (@severity::text[] is null or f.severity = any(@severity))
              and (@check::text[] is null or f.check_id = any(@check))
              and (@workflow::text[] is null or f.workflow_state = any(@workflow))
              and (@fresh::boolean is null or ({FreshExpression}) = @fresh)
              and (@rank::int is null
                   or (case f.severity when 'critical' then 0 else 1 end) > @rank
                   or ((case f.severity when 'critical' then 0 else 1 end) = @rank
                       and (f.opened_at < @opened or (f.opened_at = @opened and f.id < @id))))
            order by rank, f.opened_at desc, f.id desc
            limit @take
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("windows", NpgsqlDbType.Jsonb, windows);
        command.Parameters.AddWithValue("org", NpgsqlDbType.Uuid, (object?)organizationId ?? DBNull.Value);
        AddArray(command, "technical", filters.TechnicalState);
        AddArray(command, "severity", filters.Severity);
        AddArray(command, "check", filters.CheckId);
        AddArray(command, "workflow", filters.WorkflowState);
        command.Parameters.AddWithValue("fresh", NpgsqlDbType.Boolean,
            filters.Freshness is { Length: 1 } f ? f[0] == "fresh" : DBNull.Value);
        command.Parameters.AddWithValue("now", clock.GetUtcNow());
        command.Parameters.AddWithValue("rank", NpgsqlDbType.Integer,
            position is null ? DBNull.Value : int.Parse(position[0], CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("opened", NpgsqlDbType.TimestampTz,
            position is null ? DBNull.Value : DateTimeOffset.Parse(position[1], CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("id", NpgsqlDbType.Uuid, position is null ? DBNull.Value : Guid.Parse(position[2]));
        command.Parameters.AddWithValue("take", size + 1);
        var items = new List<(FindingDto Dto, int Rank)>();
        await using (var reader = await command.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
            {
                items.Add((Read(reader, language), reader.GetInt32(reader.GetOrdinal("rank"))));
            }
        }
        string? next = null;
        if (items.Count > size)
        {
            items.RemoveAt(size);
            var last = items[^1];
            next = cursors.Create(operation, organizationId, filters.Key,
                [last.Rank.ToString(CultureInfo.InvariantCulture), last.Dto.OpenedAt.ToString("O", CultureInfo.InvariantCulture),
                 last.Dto.Id.ToString()]);
        }
        return (items.Select(i => i.Dto).ToList(), next);
    }

    /// <summary>
    /// freshnessWindowHours of every check by the newest policy revision of each organization the scope sees, keyed by
    /// organization and check id: the input of the freshness expression in the SQL.
    /// </summary>
    private static async Task<string> WindowsAsync(DbScope scope, CancellationToken ct)
    {
        var windows = new JsonObject();
        foreach (var (organizationId, policy) in await Policies.CurrentByOrganizationAsync(scope, ct))
        {
            windows[organizationId.ToString()] = Windows(policy);
        }
        return windows.ToJsonString();
    }

    /// <summary>freshnessWindowHours of every check of a revision, as the configuration states it.</summary>
    private static JsonObject Windows(PolicyRevision policy)
    {
        var windows = new JsonObject();
        using var configuration = JsonDocument.Parse(policy.Configuration);
        if (configuration.RootElement.TryGetProperty("checks", out var checks) && checks.ValueKind == JsonValueKind.Object)
        {
            foreach (var check in checks.EnumerateObject())
            {
                if (check.Value.ValueKind == JsonValueKind.Object && check.Value.TryGetProperty("freshnessWindowHours", out var hours))
                {
                    windows[check.Name] = JsonNode.Parse(hours.GetRawText());
                }
            }
        }
        return windows;
    }

    private const string FreshExpression =
        "coalesce(f.latest_observed_at, f.opened_at) > @now - make_interval(hours => (l.windows ->> f.check_id)::int)";

    private const string Columns = """
        f.id, f.organization_id, f.check_id, s.type, s.key, s.display_name, s.device_id, f.technical_state, f.workflow_state,
        f.assessment_result, (coalesce(f.latest_observed_at, f.opened_at) > @now - make_interval(hours =>
            (l.windows ->> f.check_id)::int)) as fresh,
        f.severity, f.revision, f.opened_at, coalesce(f.latest_observed_at, f.opened_at) as latest_observed_at, f.assignee_id,
        f.due_at, f.workflow_reason, f.review_at, f.workflow_decided_by
        """;

    private static FindingDto Read(NpgsqlDataReader reader, string language)
    {
        DateTimeOffset? Time(string name) => reader.IsDBNull(reader.GetOrdinal(name)) ? null
            : reader.GetFieldValue<DateTimeOffset>(reader.GetOrdinal(name));
        Guid? Id(string name) => reader.IsDBNull(reader.GetOrdinal(name)) ? null : reader.GetGuid(reader.GetOrdinal(name));
        string? Text(string name) => reader.IsDBNull(reader.GetOrdinal(name)) ? null : reader.GetString(reader.GetOrdinal(name));
        var checkId = reader.GetString(reader.GetOrdinal("check_id"));
        return new FindingDto(
            reader.GetGuid(reader.GetOrdinal("id")), reader.GetGuid(reader.GetOrdinal("organization_id")), checkId,
            new SubjectDto(Text("type")!, Text("key")!, Text("display_name"), Id("device_id")),
            Text("technical_state")!, Text("workflow_state")!, Text("assessment_result")!,
            reader.GetBoolean(reader.GetOrdinal("fresh")) ? "fresh" : "stale", Text("severity")!,
            reader.GetInt32(reader.GetOrdinal("revision")), Texts.Title(checkId, language), Texts.Recommendation(checkId, language),
            Time("opened_at")!.Value, Time("latest_observed_at")!.Value, Id("assignee_id"), Time("due_at"),
            Text("workflow_reason"), Time("review_at"), Id("workflow_decided_by"));
    }

    private static async Task<FindingDto> LoadAsync(DbScope scope, HttpContext http, TimeProvider clock, Guid findingId,
        CancellationToken ct)
    {
        var language = Texts.Language(http.Request.Headers.AcceptLanguage);
        var windows = await WindowsAsync(scope, ct);
        await using var command = new NpgsqlCommand($"""
            with latest as (
                select w.key::uuid as organization_id, w.value as windows from jsonb_each(@windows) w)
            select {Columns}
            from finding f
            join subject s on s.organization_id = f.organization_id and s.id = f.subject_id
            join latest l on l.organization_id = f.organization_id
            where f.id = @finding
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("windows", NpgsqlDbType.Jsonb, windows);
        command.Parameters.AddWithValue("finding", findingId);
        command.Parameters.AddWithValue("now", clock.GetUtcNow());
        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
        {
            throw new ApiProblemException(ProblemCodes.NotFound);
        }
        return Read(reader, language);
    }

    private static async Task<IResult> Get(Guid organizationId, Guid findingId, HttpContext http, DbScopes scopes,
        TimeProvider clock, CancellationToken ct)
    {
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        var finding = await LoadAsync(scope, http, clock, findingId, ct);
        http.Response.Headers.ETag = $"\"{finding.Revision}\"";
        return Localized(http, finding);
    }

    private static async Task<Finding> LockAsync(DbScope scope, HttpContext http, Guid findingId, CancellationToken ct)
    {
        var finding = await scope.Db.Findings
            .FromSqlInterpolated($"select * from finding where id = {findingId} for update").SingleOrDefaultAsync(ct)
            ?? throw new ApiProblemException(ProblemCodes.NotFound);
        var ifMatch = http.Request.Headers.IfMatch.ToString();
        if (ifMatch.Length == 0)
        {
            throw new ApiProblemException(ProblemCodes.IfMatchRequired);
        }
        if (ifMatch != $"\"{finding.Revision}\"")
        {
            throw new ApiProblemException(ProblemCodes.RevisionMismatch, $"current revision is {finding.Revision}");
        }
        return finding;
    }

    private static async Task<IResult> Patch(Guid organizationId, Guid findingId, HttpContext http, RequestBodies bodies,
        DbScopes scopes, TimeProvider clock, CancellationToken ct)
    {
        var actor = Actor.From(http.User);
        var request = await bodies.ReadAsync<FindingPatchBody>(http, "FindingPatch");
        var present = request.Json.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
        var body = request.Value;
        var now = clock.GetUtcNow();
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        var organization = await OrganizationEndpoints.RequireOrganizationAsync(scope, forUpdate: false, ct);
        OrganizationEndpoints.RequireActive(organization);
        var finding = await LockAsync(scope, http, findingId, ct);
        if (present.Contains("workflowState") && body.WorkflowState != finding.WorkflowState)
        {
            if (finding.WorkflowState is not ("new" or "in_progress"))
            {
                throw new ApiProblemException(ProblemCodes.WorkflowTransitionForbidden, "decide the risk decision first");
            }
            Event(scope, finding, "workflow_changed", "manual_action", actor.EntraUserId, finding.WorkflowState,
                body.WorkflowState!, now);
            finding.WorkflowState = body.WorkflowState!;
        }
        var changes = new Dictionary<string, object>();
        if (present.Contains("assigneeId") && body.AssigneeId != finding.AssigneeId)
        {
            if (body.AssigneeId is { } assignee && !await Access.StaffDirectory.CanBeAssignedAsync(scope, assignee, now, ct))
            {
                throw new ApiProblemException(ProblemCodes.ValidationFailed, "assignee must be an active Admin or Technician");
            }
            changes["assigneeId"] = new AssignmentChange<Guid?>(finding.AssigneeId, body.AssigneeId);
            finding.AssigneeId = body.AssigneeId;
        }
        if (present.Contains("dueAt") && body.DueAt != finding.DueAt)
        {
            changes["dueAt"] = new AssignmentChange<DateTimeOffset?>(finding.DueAt, body.DueAt);
            finding.DueAt = body.DueAt;
        }
        if (changes.Count > 0)
        {
            AuditLog.Staff(scope, actor, "finding.assignment_change", "finding", findingId.ToString(), http.TraceIdentifier, changes);
        }
        finding.Revision++;
        await scope.CommitAsync(ct);
        await using var read = await scopes.OrganizationAsync(organizationId, ct);
        var dto = await LoadAsync(read, http, clock, findingId, ct);
        http.Response.Headers.ETag = $"\"{dto.Revision}\"";
        return Localized(http, dto);
    }

    private static async Task<IResult> Decide(Guid organizationId, Guid findingId, HttpContext http, RequestBodies bodies,
        DbScopes scopes, TimeProvider clock, CancellationToken ct)
    {
        var actor = Actor.From(http.User);
        var body = (await bodies.ReadAsync<RiskDecisionBody>(http, "RiskDecision")).Value;
        var now = clock.GetUtcNow();
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        var organization = await OrganizationEndpoints.RequireOrganizationAsync(scope, forUpdate: false, ct);
        OrganizationEndpoints.RequireActive(organization);
        var finding = await LockAsync(scope, http, findingId, ct);
        string to;
        if (body.Decision == "withdrawn")
        {
            if (finding.WorkflowState is not ("risk_accepted" or "suppressed"))
            {
                throw new ApiProblemException(ProblemCodes.WorkflowTransitionForbidden, "nothing to withdraw");
            }
            to = "new";
        }
        else
        {
            if (finding.TechnicalState != "open")
            {
                throw new ApiProblemException(ProblemCodes.WorkflowTransitionForbidden, "the finding is resolved");
            }
            if (body.ReviewAt is not { } review || review <= now || review > now.AddDays(365))
            {
                throw new ApiProblemException(ProblemCodes.ValidationFailed, "reviewAt must be within the next 365 days");
            }
            to = body.Decision;
        }
        var from = finding.WorkflowState;
        var eventId = Event(scope, finding, "workflow_changed", "manual_action", actor.EntraUserId, from, to, now);
        // Every decision is kept as an immutable record so later changes do not erase its reason (external review F07).
        scope.Db.RiskDecisions.Add(new RiskDecision
        {
            OrganizationId = organizationId, Id = Guid.CreateVersion7(), FindingId = findingId, Decision = body.Decision,
            Reason = body.Reason, ReviewAt = body.Decision == "withdrawn" ? null : body.ReviewAt, DecidedBy = actor.EntraUserId,
            DecidedAt = now, FindingEventId = eventId,
        });
        finding.WorkflowState = to;
        finding.WorkflowReason = body.Decision == "withdrawn" ? null : body.Reason;
        finding.ReviewAt = body.Decision == "withdrawn" ? null : body.ReviewAt;
        finding.WorkflowDecidedBy = actor.EntraUserId;
        finding.Revision++;
        await scope.CommitAsync(ct);
        await using var read = await scopes.OrganizationAsync(organizationId, ct);
        var dto = await LoadAsync(read, http, clock, findingId, ct);
        http.Response.Headers.ETag = $"\"{dto.Revision}\"";
        return Localized(http, dto);
    }

    private static Guid Event(DbScope scope, Finding finding, string type, string cause, Guid actorId, string from, string to,
        DateTimeOffset now)
    {
        var id = Guid.CreateVersion7();
        scope.Db.FindingEvents.Add(new FindingEvent
        {
            OrganizationId = finding.OrganizationId, FindingId = finding.Id, Id = id, EventType = type, Cause = cause,
            ActorId = actorId, FromWorkflowState = from, ToWorkflowState = to, OccurredAt = now,
        });
        return id;
    }

    private static async Task<IResult> Events(Guid organizationId, Guid findingId, DbScopes scopes, Cursors cursors,
        string? cursor, string? limit, CancellationToken ct)
    {
        var size = OrganizationEndpoints.Limit(limit);
        var position = cursors.Read(cursor, "listFindingEvents", organizationId, findingId.ToString());
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        if (!await scope.Db.Findings.AnyAsync(f => f.Id == findingId, ct))
        {
            throw new ApiProblemException(ProblemCodes.NotFound);
        }
        var query = scope.Db.FindingEvents.AsNoTracking().Where(e => e.FindingId == findingId);
        if (position is not null)
        {
            var after = DateTimeOffset.Parse(position[0], CultureInfo.InvariantCulture);
            query = query.Where(e => e.OccurredAt > after);
        }
        var rows = await query.OrderBy(e => e.OccurredAt).Take(size + 1).ToListAsync(ct);
        string? next = null;
        if (rows.Count > size)
        {
            rows.RemoveAt(size);
            next = cursors.Create("listFindingEvents", organizationId, findingId.ToString(),
                [rows[^1].OccurredAt.ToString("O", CultureInfo.InvariantCulture)]);
        }
        var items = rows.Select(e => new FindingEventDto(e.Id, e.OccurredAt, e.EventType, e.Cause, e.AssessmentId, e.ActorId,
            e.FromWorkflowState, e.ToWorkflowState)).ToList();
        return Results.Json(new Page<FindingEventDto>(items, next), ApiJson.Options);
    }

    private static async Task<IResult> Assessments(Guid organizationId, HttpContext http, DbScopes scopes, Cursors cursors,
        TimeProvider clock, string? cursor, string? limit, string? subjectType, string? subjectKey, string? checkId,
        string? scope, CancellationToken ct)
    {
        if (subjectType is not (null or "tenant" or "user" or "device" or "volume") || scope is not (null or "current" or "all")
            || (checkId is not null && Catalog.Checks.All(c => c.CheckId != checkId)))
        {
            throw new ApiProblemException(ProblemCodes.SchemaViolation, "unknown filter value");
        }
        var size = OrganizationEndpoints.Limit(limit);
        var filter = Cursors.Filter(("t", subjectType), ("k", subjectKey), ("c", checkId), ("s", scope));
        var position = cursors.Read(cursor, "listAssessments", organizationId, filter);
        var language = Texts.Language(http.Request.Headers.AcceptLanguage);
        await using var db = await scopes.OrganizationAsync(organizationId, ct);
        await OrganizationEndpoints.RequireOrganizationAsync(db, forUpdate: false, ct);
        var policy = await Policies.CurrentAsync(db, ct);
        await using var command = new NpgsqlCommand("""
            with picked as (
                select a.*, row_number() over (partition by a.subject_id, a.check_id order by a.evaluated_at desc, a.id desc) as n
                from assessment a where a.organization_id = @org and a.assessment_scope = 'current')
            select a.id, s.type, s.key, s.display_name, s.device_id, a.check_id, a.rule_id, a.rule_version,
                   a.source_policy_version, a.evaluated_policy_version, a.assessment_scope, a.assessment_mode, a.result,
                   a.severity, a.reason_code, a.observed_at, a.received_at, o.evidence::text, a.evidence_availability,
                   a.basis_snapshot::text, a.evaluated_at,
                   (a.observed_at > @now - make_interval(hours => (@windows ->> a.check_id)::int)) as fresh
            from picked a
            join subject s on s.organization_id = a.organization_id and s.id = a.subject_id
            left join observation o on o.organization_id = a.organization_id and o.id = a.observation_id
            where (@all or a.n = 1)
              and (@type::text is null or s.type = @type)
              and (@key::text is null or s.key = @key)
              and (@check::text is null or a.check_id = @check)
              and (@after_at::timestamptz is null or (a.evaluated_at, a.id) < (@after_at, @after_id::uuid))
            order by a.evaluated_at desc, a.id desc
            limit @take
            """, db.Connection, db.Transaction);
        command.Parameters.AddWithValue("windows", NpgsqlDbType.Jsonb,
            policy is null ? DBNull.Value : (object)Windows(policy).ToJsonString());
        command.Parameters.AddWithValue("org", organizationId);
        command.Parameters.AddWithValue("now", clock.GetUtcNow());
        command.Parameters.AddWithValue("all", scope == "all");
        command.Parameters.AddWithValue("type", NpgsqlDbType.Text, (object?)subjectType ?? DBNull.Value);
        command.Parameters.AddWithValue("key", NpgsqlDbType.Text, (object?)subjectKey ?? DBNull.Value);
        command.Parameters.AddWithValue("check", NpgsqlDbType.Text, (object?)checkId ?? DBNull.Value);
        command.Parameters.AddWithValue("after_at", NpgsqlDbType.TimestampTz,
            position is null ? DBNull.Value : DateTimeOffset.Parse(position[0], CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("after_id", NpgsqlDbType.Uuid, position is null ? DBNull.Value : Guid.Parse(position[1]));
        command.Parameters.AddWithValue("take", size + 1);
        var items = new List<(AssessmentDto Dto, DateTimeOffset EvaluatedAt)>();
        await using (var reader = await command.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
            {
                var expired = reader.GetString(18) == "expired";
                JsonElement? evidence = reader.IsDBNull(17) || expired ? null : JsonDocument.Parse(reader.GetString(17)).RootElement.Clone();
                items.Add((new AssessmentDto(
                    reader.GetGuid(0), new SubjectDto(reader.GetString(1), reader.GetString(2),
                        reader.IsDBNull(3) ? null : reader.GetString(3), reader.IsDBNull(4) ? null : reader.GetGuid(4)),
                    reader.GetString(5), reader.GetString(6), reader.GetString(7), reader.GetInt32(8), reader.GetInt32(9),
                    reader.GetString(10), reader.GetString(11), reader.IsDBNull(12) ? null : reader.GetString(12),
                    reader.IsDBNull(13) ? null : reader.GetString(13), reader.GetBoolean(21) ? "fresh" : "stale",
                    reader.IsDBNull(14) ? null : reader.GetString(14), reader.GetFieldValue<DateTimeOffset>(15),
                    reader.GetFieldValue<DateTimeOffset>(16), evidence, reader.GetString(18),
                    Texts.Explanation(reader.GetString(19), language)), reader.GetFieldValue<DateTimeOffset>(20)));
            }
        }
        string? next = null;
        if (items.Count > size)
        {
            items.RemoveAt(size);
            next = cursors.Create("listAssessments", organizationId, filter,
                [items[^1].EvaluatedAt.ToString("O", CultureInfo.InvariantCulture), items[^1].Dto.Id.ToString()]);
        }
        return Localized(http, new Page<AssessmentDto>(items.Select(i => i.Dto).ToList(), next));
    }

    private static void AddArray(NpgsqlCommand command, string name, string[]? values) =>
        command.Parameters.AddWithValue(name, NpgsqlDbType.Array | NpgsqlDbType.Text, (object?)values ?? DBNull.Value);

    private static IResult Localized<T>(HttpContext http, T body)
    {
        http.Response.Headers.ContentLanguage = Texts.Language(http.Request.Headers.AcceptLanguage);
        return Results.Json(body, ApiJson.Options);
    }
}
