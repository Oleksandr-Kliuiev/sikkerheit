using Npgsql;
using Sikkerheit.Host.Data;

namespace Sikkerheit.Host.Assessment;

/// <summary>The subject of a finding as reports name it.</summary>
public sealed record FindingSubject(string Type, string Key, string? Name);

/// <summary>An event that changed the technical state of a finding, with the severity of the finding at that moment.</summary>
public sealed record FindingStateEvent(Guid FindingId, string CheckId, FindingSubject Subject, string EventType, string Cause,
    string Severity, DateTimeOffset OccurredAt);

/// <summary>A finding open at a moment: its severity and workflow state then, and when it was opened last.</summary>
public sealed record OpenFinding(Guid FindingId, string CheckId, FindingSubject Subject, string Severity, string WorkflowState,
    DateTimeOffset OpenedAt);

/// <summary>The last risk decision of a finding before a moment.</summary>
public sealed record LatestDecision(Guid FindingId, string CheckId, FindingSubject Subject, string Decision, string? Reason,
    DateTimeOffset? ReviewAt, Guid DecidedBy, DateTimeOffset DecidedAt);

/// <summary>Critical findings of an organization and a check opened or reopened by the source.</summary>
public sealed record CriticalCount(Guid OrganizationId, string CheckId, int Count);

/// <summary>Open findings of an organization by severity.</summary>
public sealed record OpenCounts(int Critical, int Warning);

/// <summary>A subject seen in a period; ActiveAtEnd is false for subjects active only earlier in it.</summary>
public sealed record SubjectInPeriod(Guid Id, string Type, string Key, string? Name, bool ActiveAtEnd, Guid? DeviceId = null);

/// <summary>The latest current assessment of a pair at a moment.</summary>
public sealed record CurrentAssessment(Guid SubjectId, string CheckId, string Mode, string? Result, string? Severity,
    string? ReasonCode, DateTimeOffset ObservedAt);

/// <summary>
/// History of findings for reports and summaries. The finding, finding_event and risk_decision tables belong to this
/// module; other modules read them only here.
/// </summary>
public static class FindingHistory
{
    /// <summary>Event types that change the technical state of a finding.</summary>
    public static readonly string[] StateEvents = ["opened", "reopened", "resolved", "policy_changed", "subject_retired"];

    /// <summary>State events of [start, end) in time order.</summary>
    public static async Task<IReadOnlyList<FindingStateEvent>> StateEventsAsync(DbScope scope, Guid organizationId,
        DateTimeOffset start, DateTimeOffset end, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
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
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("org", organizationId);
        command.Parameters.AddWithValue("start", start);
        command.Parameters.AddWithValue("end", end);
        command.Parameters.AddWithValue("state_events", StateEvents);
        var events = new List<FindingStateEvent>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            events.Add(new FindingStateEvent(reader.GetGuid(0), reader.GetString(1), Subject(reader, 2), reader.GetString(5),
                reader.GetString(6), reader.GetString(8), reader.GetFieldValue<DateTimeOffset>(7)));
        }
        return events;
    }

    /// <summary>
    /// Findings open at the moment, reconstructed from events: state, workflow and severity before it; by check id, subject
    /// name and key.
    /// </summary>
    public static async Task<IReadOnlyList<OpenFinding>> OpenAtAsync(DbScope scope, Guid organizationId, DateTimeOffset end,
        CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
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
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("org", organizationId);
        command.Parameters.AddWithValue("end", end);
        command.Parameters.AddWithValue("state_events", StateEvents);
        var open = new List<OpenFinding>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            open.Add(new OpenFinding(reader.GetGuid(0), reader.GetString(1), Subject(reader, 2), reader.GetString(5),
                reader.GetString(6), reader.GetFieldValue<DateTimeOffset>(7)));
        }
        return open;
    }

    /// <summary>
    /// Critical findings opened or reopened by the source in [since, until), by organization and check, ordered by check;
    /// only for the read-all scope.
    /// </summary>
    public static async Task<IReadOnlyList<CriticalCount>> NewCriticalAsync(DbScope all, DateTimeOffset since,
        DateTimeOffset until, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            select e.organization_id, f.check_id, count(*)::int
            from finding_event e
            join finding f on f.organization_id = e.organization_id and f.id = e.finding_id
            where e.occurred_at >= @since and e.occurred_at < @until and e.event_type in ('opened', 'reopened')
              and e.cause = 'source_change' and f.severity = 'critical'
            group by e.organization_id, f.check_id order by f.check_id
            """, all.Connection, all.Transaction);
        command.Parameters.AddWithValue("since", since);
        command.Parameters.AddWithValue("until", until);
        var counts = new List<CriticalCount>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            counts.Add(new CriticalCount(reader.GetGuid(0), reader.GetString(1), reader.GetInt32(2)));
        }
        return counts;
    }

    /// <summary>Open findings by severity of every organization that has one; only for the read-all scope.</summary>
    public static async Task<IReadOnlyDictionary<Guid, OpenCounts>> OpenCountsAsync(DbScope all, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            select organization_id, (count(*) filter (where severity = 'critical'))::int,
                   (count(*) filter (where severity = 'warning'))::int
            from finding where technical_state = 'open'
            group by organization_id
            """, all.Connection, all.Transaction);
        var counts = new Dictionary<Guid, OpenCounts>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            counts[reader.GetGuid(0)] = new OpenCounts(reader.GetInt32(1), reader.GetInt32(2));
        }
        return counts;
    }

    internal static FindingSubject Subject(NpgsqlDataReader reader, int first) =>
        new(reader.GetString(first), reader.GetString(first + 1), reader.IsDBNull(first + 2) ? null : reader.GetString(first + 2));
}

/// <summary>Risk decisions for reports; the risk_decision table belongs to this module.</summary>
public static class RiskDecisions
{
    /// <summary>The last decision of every finding made before the moment.</summary>
    public static async Task<IReadOnlyList<LatestDecision>> LatestBeforeAsync(DbScope scope, Guid organizationId,
        DateTimeOffset end, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            select distinct on (d.finding_id) d.finding_id, f.check_id, s.type, s.key, s.display_name, d.decision, d.reason,
                   d.review_at, d.decided_by, d.decided_at
            from risk_decision d
            join finding f on f.organization_id = d.organization_id and f.id = d.finding_id
            join subject s on s.organization_id = f.organization_id and s.id = f.subject_id
            where d.organization_id = @org and d.decided_at < @end
            order by d.finding_id, d.decided_at desc, d.id desc
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("org", organizationId);
        command.Parameters.AddWithValue("end", end);
        var decisions = new List<LatestDecision>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            decisions.Add(new LatestDecision(reader.GetGuid(0), reader.GetString(1), FindingHistory.Subject(reader, 2),
                reader.GetString(5), reader.IsDBNull(6) ? null : reader.GetString(6),
                reader.IsDBNull(7) ? null : reader.GetFieldValue<DateTimeOffset>(7), reader.GetGuid(8),
                reader.GetFieldValue<DateTimeOffset>(9)));
        }
        return decisions;
    }
}

/// <summary>Assessments for the coverage of 05 «Отчёт и покрытие»; the assessment table belongs to this module.</summary>
public static class Assessments
{
    /// <summary>The latest current assessment of every pair evaluated at the moment or earlier.</summary>
    public static async Task<IReadOnlyList<CurrentAssessment>> LatestAsync(DbScope scope, Guid organizationId,
        DateTimeOffset at, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            select distinct on (a.subject_id, a.check_id) a.subject_id, a.check_id, a.assessment_mode, a.result,
                   a.severity, a.reason_code, a.observed_at
            from assessment a
            where a.organization_id = @org and a.assessment_scope = 'current' and a.evaluated_at <= @at
            order by a.subject_id, a.check_id, a.evaluated_at desc, a.id desc
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("org", organizationId);
        command.Parameters.AddWithValue("at", at);
        var latest = new List<CurrentAssessment>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            latest.Add(new CurrentAssessment(reader.GetGuid(0), reader.GetString(1), reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetString(3), reader.IsDBNull(4) ? null : reader.GetString(4),
                reader.IsDBNull(5) ? null : reader.GetString(5), reader.GetFieldValue<DateTimeOffset>(6)));
        }
        return latest;
    }

    /// <summary>Pairs with a current pass or fail observed in [start, end).</summary>
    public static async Task<IReadOnlyList<(Guid SubjectId, string CheckId)>> DeterminedAsync(DbScope scope,
        Guid organizationId, DateTimeOffset start, DateTimeOffset end, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            select distinct subject_id, check_id from assessment
            where organization_id = @org and assessment_scope = 'current' and result in ('pass', 'fail')
              and observed_at >= @start and observed_at < @end
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("org", organizationId);
        command.Parameters.AddWithValue("start", start);
        command.Parameters.AddWithValue("end", end);
        var pairs = new List<(Guid, string)>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            pairs.Add((reader.GetGuid(0), reader.GetString(1)));
        }
        return pairs;
    }
}

/// <summary>Subjects for the coverage; the subject table belongs to this module.</summary>
public static class Subjects
{
    /// <summary>Subjects of the types seen by the moment and not retired before the start of the period.</summary>
    public static async Task<IReadOnlyList<SubjectInPeriod>> InPeriodAsync(DbScope scope, Guid organizationId,
        IReadOnlyList<string> types, DateTimeOffset from, DateTimeOffset at, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            select id, type, key, display_name, (retired_at is null or retired_at > @at) and first_seen_at <= @at, device_id
            from subject
            where organization_id = @org and type = any(@types)
              and first_seen_at <= @at and (retired_at is null or retired_at > @from)
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("org", organizationId);
        command.Parameters.AddWithValue("types", types.ToArray());
        command.Parameters.AddWithValue("at", at);
        command.Parameters.AddWithValue("from", from);
        var subjects = new List<SubjectInPeriod>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            subjects.Add(new SubjectInPeriod(reader.GetGuid(0), reader.GetString(1), reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetString(3), reader.GetBoolean(4), reader.IsDBNull(5) ? null : reader.GetGuid(5)));
        }
        return subjects;
    }
}
