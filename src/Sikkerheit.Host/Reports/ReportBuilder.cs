using System.Text.Json;
using Npgsql;
using Sikkerheit.Host.Data;

namespace Sikkerheit.Host.Reports;

public sealed record ReportSubject(string Type, string Key, string? Name);

public sealed record ReportEvent(Guid FindingId, string CheckId, ReportSubject Subject, string EventType, string Cause,
    string Severity, DateTimeOffset OccurredAt);

public sealed record ReportOpenFinding(Guid FindingId, string CheckId, ReportSubject Subject, string Severity,
    string WorkflowState, DateTimeOffset OpenedAt, bool NewInPeriod);

public sealed record ReportDecision(Guid FindingId, string CheckId, ReportSubject Subject, string Decision, string? Reason,
    DateTimeOffset? ReviewAt, string? DecidedBy, DateTimeOffset DecidedAt, bool InPeriod);

public sealed record ReportConnection(string Status, Guid? TenantId, string? DisplayName, string? PrimaryDomain, bool? EntraP1,
    DateTimeOffset? LastCollectedAt);

public sealed record ReportModule(string Module, string Status);

public sealed record ReportLastRun(string State, string? FailureCode, DateTimeOffset? CompletedAt, IReadOnlyList<ReportModule> Modules);

public sealed record ReportRunCount(string State, string? FailureCode, int Count);

public sealed record ReportUnavailable(string CheckId, string? ReasonCode, int Count);

/// <summary>
/// Immutable basis of a report (external review F08): pairs and results, events, decisions, policy versions and the
/// connection state at generation. The HTML is rendered from it; a ready report is never rebuilt.
/// </summary>
public sealed record ReportSnapshot(
    int SnapshotVersion, Guid ReportId, Guid OrganizationId, string OrganizationName, string Timezone, string Language,
    string IsoWeek, DateTimeOffset PeriodStart, DateTimeOffset PeriodEnd, DateTimeOffset GeneratedAt,
    IReadOnlyList<int> PolicyVersions, ReportConnection Connection, ReportLastRun? LastRun, IReadOnlyList<ReportRunCount> Runs,
    IReadOnlyList<ReportEvent> Events, IReadOnlyList<ReportOpenFinding> OpenAtEnd, IReadOnlyList<ReportDecision> Decisions,
    IReadOnlyList<ReportUnavailable> Unavailable, CoverageResult Coverage, bool DetailsExpired)
{
    public const int CurrentVersion = 1;

    public IEnumerable<string> CheckIds =>
        Events.Select(e => e.CheckId).Concat(OpenAtEnd.Select(o => o.CheckId)).Concat(Decisions.Select(d => d.CheckId))
            .Concat(Unavailable.Select(u => u.CheckId)).Distinct(StringComparer.Ordinal);
}

/// <summary>Reads everything a weekly report needs for [periodStart, periodEnd) in the organization scope.</summary>
public static class ReportBuilder
{
    private static readonly string[] StateEvents = ["opened", "reopened", "resolved", "policy_changed", "subject_retired"];
    public static readonly TimeSpan EvidenceRetention = TimeSpan.FromDays(90);

    public static async Task<ReportSnapshot> BuildAsync(DbScope scope, Organization organization, Report report,
        DateTimeOffset now, CancellationToken ct)
    {
        var org = organization.Id;
        var start = report.PeriodStart;
        var end = report.PeriodEnd;
        var zone = TimeZoneInfo.FindSystemTimeZoneById(report.Timezone);
        var (year, week) = ReportPeriod.WeekOf(zone, start);
        var coverage = await Coverage.PeriodAsync(scope, org, start, end, ct);
        var connection = await ConnectionAsync(scope, org, end, ct);
        var events = await EventsAsync(scope, org, start, end, ct);
        var open = await OpenAtEndAsync(scope, org, start, end, ct);
        var decisions = await DecisionsAsync(scope, org, start, end, open, ct);
        var unavailable = coverage.Rows
            .Where(r => r.ActiveAtEnd && ((r.Category == "required" && r.Result is null or "unknown")
                                          || (r.Category == "informational" && r.ReasonCode is not null)))
            .GroupBy(r => (r.CheckId, r.ReasonCode))
            .Select(g => new ReportUnavailable(g.Key.CheckId, g.Key.ReasonCode, g.Count()))
            .OrderBy(u => u.CheckId, StringComparer.Ordinal).ThenBy(u => u.ReasonCode, StringComparer.Ordinal).ToList();
        return new ReportSnapshot(ReportSnapshot.CurrentVersion, report.Id, org, organization.Name, report.Timezone,
            report.Language, ReportPeriod.Key(year, week), start, end, now,
            await PolicyVersionsAsync(scope, org, start, end, ct), connection, await LastRunAsync(scope, org, end, ct),
            await RunsAsync(scope, org, start, end, ct), events, open, decisions, unavailable, coverage,
            now - end > EvidenceRetention);
    }

    private static NpgsqlCommand Command(DbScope scope, string sql, Guid org, DateTimeOffset start, DateTimeOffset end)
    {
        var command = new NpgsqlCommand(sql, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("org", org);
        command.Parameters.AddWithValue("start", start);
        command.Parameters.AddWithValue("end", end);
        command.Parameters.AddWithValue("state_events", StateEvents);
        return command;
    }

    private static ReportSubject Subject(NpgsqlDataReader reader, int first) =>
        new(reader.GetString(first), reader.GetString(first + 1), reader.IsDBNull(first + 2) ? null : reader.GetString(first + 2));

    private static async Task<IReadOnlyList<int>> PolicyVersionsAsync(DbScope scope, Guid org, DateTimeOffset start,
        DateTimeOffset end, CancellationToken ct)
    {
        var (atStart, _) = await Coverage.PolicyAtAsync(scope, org, start, ct);
        await using var command = Command(scope, """
            select version from policy_revision
            where organization_id = @org and effective_from >= @start and effective_from < @end
            order by version
            """, org, start, end);
        var versions = new List<int> { atStart };
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            if (!versions.Contains(reader.GetInt32(0)))
            {
                versions.Add(reader.GetInt32(0));
            }
        }
        return versions;
    }

    private static async Task<ReportConnection> ConnectionAsync(DbScope scope, Guid org, DateTimeOffset end, CancellationToken ct)
    {
        await using var command = Command(scope, """
            select status, entra_tenant_id, tenant_display_name, primary_domain, entra_p1,
                   (select max(completed_at) from collection_run r
                    where r.organization_id = @org and r.completed_at < @end and r.state in ('completed', 'partial'))
            from tenant_connection where organization_id = @org
            """, org, end, end);
        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
        {
            return new ReportConnection("not_connected", null, null, null, null, null);
        }
        return new ReportConnection(reader.GetString(0), reader.IsDBNull(1) ? null : reader.GetGuid(1),
            reader.IsDBNull(2) ? null : reader.GetString(2), reader.IsDBNull(3) ? null : reader.GetString(3),
            reader.IsDBNull(4) ? null : reader.GetBoolean(4),
            reader.IsDBNull(5) ? null : reader.GetFieldValue<DateTimeOffset>(5));
    }

    private static async Task<ReportLastRun?> LastRunAsync(DbScope scope, Guid org, DateTimeOffset end, CancellationToken ct)
    {
        await using var command = Command(scope, """
            select state, failure_code, completed_at, capabilities::text from collection_run
            where organization_id = @org and completed_at < @end and state in ('completed', 'partial', 'failed')
            order by completed_at desc, id desc limit 1
            """, org, end, end);
        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
        {
            return null;
        }
        using var capabilities = JsonDocument.Parse(reader.GetString(3));
        var modules = capabilities.RootElement.EnumerateArray()
            .Select(m => new ReportModule(m.GetProperty("module").GetString()!, m.GetProperty("status").GetString()!)).ToList();
        return new ReportLastRun(reader.GetString(0), reader.IsDBNull(1) ? null : reader.GetString(1),
            reader.GetFieldValue<DateTimeOffset>(2), modules);
    }

    private static async Task<IReadOnlyList<ReportRunCount>> RunsAsync(DbScope scope, Guid org, DateTimeOffset start,
        DateTimeOffset end, CancellationToken ct)
    {
        await using var command = Command(scope, """
            select state, failure_code, count(*)::int from collection_run
            where organization_id = @org and queued_at >= @start and queued_at < @end
            group by state, failure_code order by state, failure_code
            """, org, start, end);
        var runs = new List<ReportRunCount>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            runs.Add(new ReportRunCount(reader.GetString(0), reader.IsDBNull(1) ? null : reader.GetString(1), reader.GetInt32(2)));
        }
        return runs;
    }

    private static async Task<IReadOnlyList<ReportEvent>> EventsAsync(DbScope scope, Guid org, DateTimeOffset start,
        DateTimeOffset end, CancellationToken ct)
    {
        await using var command = Command(scope, """
            select e.finding_id, f.check_id, s.type, s.key, s.display_name, e.event_type, e.cause, e.occurred_at,
                   coalesce(a.severity,
                       (select p.severity from assessment p
                        where p.organization_id = f.organization_id and p.subject_id = f.subject_id
                          and p.check_id = f.check_id and p.result = 'fail' and p.evaluated_at <= e.occurred_at
                        order by p.evaluated_at desc, p.id desc limit 1),
                       f.severity)
            from finding_event e
            join finding f on f.organization_id = e.organization_id and f.id = e.finding_id
            join subject s on s.organization_id = f.organization_id and s.id = f.subject_id
            left join assessment a on a.organization_id = e.organization_id and a.id = e.assessment_id
            where e.organization_id = @org and e.occurred_at >= @start and e.occurred_at < @end
              and e.event_type = any(@state_events)
            order by e.occurred_at, e.id
            """, org, start, end);
        var events = new List<ReportEvent>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            events.Add(new ReportEvent(reader.GetGuid(0), reader.GetString(1), Subject(reader, 2), reader.GetString(5),
                reader.GetString(6), reader.GetString(8), reader.GetFieldValue<DateTimeOffset>(7)));
        }
        return events;
    }

    /// <summary>Findings open at periodEnd, reconstructed from events: state, workflow and severity before the end.</summary>
    private static async Task<IReadOnlyList<ReportOpenFinding>> OpenAtEndAsync(DbScope scope, Guid org, DateTimeOffset start,
        DateTimeOffset end, CancellationToken ct)
    {
        await using var command = Command(scope, """
            with state_at_end as (
                select distinct on (e.finding_id) e.finding_id, e.event_type, e.occurred_at
                from finding_event e
                where e.organization_id = @org and e.occurred_at < @end and e.event_type = any(@state_events)
                order by e.finding_id, e.occurred_at desc, e.id desc),
            workflow_at_end as (
                select distinct on (e.finding_id) e.finding_id, e.to_workflow_state
                from finding_event e
                where e.organization_id = @org and e.occurred_at < @end and e.to_workflow_state is not null
                order by e.finding_id, e.occurred_at desc, e.id desc)
            select f.id, f.check_id, s.type, s.key, s.display_name,
                   coalesce((select p.severity from assessment p
                             where p.organization_id = f.organization_id and p.subject_id = f.subject_id
                               and p.check_id = f.check_id and p.result = 'fail' and p.evaluated_at < @end
                             order by p.evaluated_at desc, p.id desc limit 1), f.severity),
                   coalesce(w.to_workflow_state, 'new'), st.occurred_at
            from finding f
            join state_at_end st on st.finding_id = f.id and st.event_type in ('opened', 'reopened')
            join subject s on s.organization_id = f.organization_id and s.id = f.subject_id
            left join workflow_at_end w on w.finding_id = f.id
            where f.organization_id = @org
            order by f.check_id, s.display_name, s.key
            """, org, start, end);
        var open = new List<ReportOpenFinding>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var openedAt = reader.GetFieldValue<DateTimeOffset>(7);
            open.Add(new ReportOpenFinding(reader.GetGuid(0), reader.GetString(1), Subject(reader, 2), reader.GetString(5),
                reader.GetString(6), openedAt, openedAt >= start));
        }
        return open;
    }

    /// <summary>Risk decisions in force at periodEnd for findings open at the end (accepted and suppressed apart).</summary>
    private static async Task<IReadOnlyList<ReportDecision>> DecisionsAsync(DbScope scope, Guid org, DateTimeOffset start,
        DateTimeOffset end, IReadOnlyList<ReportOpenFinding> open, CancellationToken ct)
    {
        var workflow = open.ToDictionary(o => o.FindingId, o => o.WorkflowState);
        await using var command = Command(scope, """
            select distinct on (d.finding_id) d.finding_id, f.check_id, s.type, s.key, s.display_name, d.decision, d.reason,
                   d.review_at, u.display_name, d.decided_at
            from risk_decision d
            join finding f on f.organization_id = d.organization_id and f.id = d.finding_id
            join subject s on s.organization_id = f.organization_id and s.id = f.subject_id
            left join staff_user u on u.entra_user_id = d.decided_by
            where d.organization_id = @org and d.decided_at < @end
            order by d.finding_id, d.decided_at desc, d.id desc
            """, org, start, end);
        var decisions = new List<ReportDecision>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var findingId = reader.GetGuid(0);
            var decision = reader.GetString(5);
            DateTimeOffset? reviewAt = reader.IsDBNull(7) ? null : reader.GetFieldValue<DateTimeOffset>(7);
            if (decision is not ("risk_accepted" or "suppressed") || workflow.GetValueOrDefault(findingId) != decision
                || reviewAt <= end)
            {
                continue;
            }
            var decidedAt = reader.GetFieldValue<DateTimeOffset>(9);
            decisions.Add(new ReportDecision(findingId, reader.GetString(1), Subject(reader, 2), decision,
                reader.IsDBNull(6) ? null : reader.GetString(6), reviewAt, reader.IsDBNull(8) ? null : reader.GetString(8),
                decidedAt, decidedAt >= start));
        }
        return decisions.OrderBy(d => d.CheckId, StringComparer.Ordinal).ThenBy(d => d.Subject.Name ?? d.Subject.Key,
            StringComparer.Ordinal).ToList();
    }
}
