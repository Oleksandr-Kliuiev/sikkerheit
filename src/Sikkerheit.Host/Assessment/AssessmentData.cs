using Npgsql;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;

namespace Sikkerheit.Host.Assessment;

/// <summary>
/// Operations on all data of an organization in the tables of this module — subject, observation, assessment, finding,
/// finding_event, risk_decision: its deletion, the terms of 04 «Сроки хранения» and the organization export.
/// </summary>
public static class AssessmentData
{
    /// <summary>Tables of this module in the organization export, with their stable order.</summary>
    private static readonly (string Table, string Order)[] ExportTables =
    [
        ("subject", "first_seen_at, id"), ("observation", "observed_at, id"), ("assessment", "evaluated_at, id"),
        ("finding", "opened_at, id"), ("finding_event", "occurred_at, id"), ("risk_decision", "decided_at, id"),
    ];

    /// <summary>Removes every row of the scope's organization from the tables of this module, in the order of the foreign keys.</summary>
    public static Task DeleteOrganizationDataAsync(DbScope scope, CancellationToken ct) =>
        OrganizationRows.DeleteAsync(scope, ["risk_decision", "finding_event", "finding", "assessment", "observation", "subject"], ct);

    /// <summary>The rows of this module for the organization export.</summary>
    public static Task ExportAsync(DbScope scope, TableRowsWriter write, CancellationToken ct) =>
        OrganizationRows.ExportAsync(scope, ExportTables, write, ct);

    /// <summary>Evidence older than its term gives way to the basis snapshot: the assessment stops referring to its observation.</summary>
    public static Task<int> ExpireEvidenceAsync(DbScope scope, RetentionCuts cuts, CancellationToken ct) => RunAsync(scope, cuts, """
        update assessment a set observation_id = null, evidence_availability = 'expired'
        from observation o
        where a.organization_id = @org and o.organization_id = a.organization_id and o.id = a.observation_id
          and o.observed_at < @evidence_cut
        """, ct);

    /// <summary>Decisions of closed findings older than 12 months; active decisions stay with their events.</summary>
    public static Task<int> PurgeRiskDecisionsAsync(DbScope scope, RetentionCuts cuts, CancellationToken ct) => RunAsync(scope, cuts, """
        delete from risk_decision d using finding f
        where d.organization_id = @org and f.organization_id = d.organization_id and f.id = d.finding_id
          and d.decided_at < @history_cut and f.technical_state = 'resolved'
        """, ct);

    /// <summary>Events older than 12 months, except those of a decision and the last opening of an open finding.</summary>
    public static Task<int> PurgeFindingEventsAsync(DbScope scope, RetentionCuts cuts, CancellationToken ct) => RunAsync(scope, cuts, """
        delete from finding_event e
        where e.organization_id = @org and e.occurred_at < @history_cut
          and not exists (select 1 from risk_decision d where d.organization_id = e.organization_id and d.finding_event_id = e.id)
          and e.id not in (
              select distinct on (x.finding_id) x.id from finding_event x
              join finding f on f.organization_id = x.organization_id and f.id = x.finding_id and f.technical_state = 'open'
              where x.organization_id = @org and x.event_type in ('opened', 'reopened')
              order by x.finding_id, x.occurred_at desc, x.id desc)
        """, ct);

    /// <summary>Assessments older than 12 months that no event and no finding refers to.</summary>
    public static Task<int> PurgeAssessmentsAsync(DbScope scope, RetentionCuts cuts, CancellationToken ct) => RunAsync(scope, cuts, """
        delete from assessment a
        where a.organization_id = @org and a.evaluated_at < @history_cut
          and not exists (select 1 from finding_event e where e.organization_id = a.organization_id and e.assessment_id = a.id)
          and not exists (select 1 from finding f where f.organization_id = a.organization_id and f.latest_assessment_id = a.id)
        """, ct);

    /// <summary>Resolved findings left without events and decisions.</summary>
    public static Task<int> PurgeFindingsAsync(DbScope scope, RetentionCuts cuts, CancellationToken ct) => RunAsync(scope, cuts, """
        delete from finding f
        where f.organization_id = @org and f.technical_state = 'resolved'
          and not exists (select 1 from finding_event e where e.organization_id = f.organization_id and e.finding_id = f.id)
          and not exists (select 1 from risk_decision d where d.organization_id = f.organization_id and d.finding_id = f.id)
        """, ct);

    /// <summary>Observations older than 90 days that no assessment refers to.</summary>
    public static Task<int> PurgeObservationsAsync(DbScope scope, RetentionCuts cuts, CancellationToken ct) => RunAsync(scope, cuts, """
        delete from observation o
        where o.organization_id = @org and o.observed_at < @evidence_cut
          and not exists (select 1 from assessment a where a.organization_id = o.organization_id and a.observation_id = o.id)
        """, ct);

    /// <summary>Subjects retired more than 12 months ago that no finding, assessment or observation refers to.</summary>
    public static Task<int> PurgeSubjectsAsync(DbScope scope, RetentionCuts cuts, CancellationToken ct) => RunAsync(scope, cuts, """
        delete from subject s
        where s.organization_id = @org and s.retired_at < @history_cut
          and not exists (select 1 from finding f where f.organization_id = s.organization_id and f.subject_id = s.id)
          and not exists (select 1 from assessment a where a.organization_id = s.organization_id and a.subject_id = s.id)
          and not exists (select 1 from observation o where o.organization_id = s.organization_id and o.subject_id = s.id)
        """, ct);

    /// <summary>Collection runs that observations of the scope's organization still refer to.</summary>
    public static async Task<IReadOnlyList<Guid>> ObservedRunsAsync(DbScope scope, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(
            "select distinct collection_run_id from observation where organization_id = @org and collection_run_id is not null",
            scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("org", scope.OrganizationId!.Value);
        var runs = new List<Guid>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            runs.Add(reader.GetGuid(0));
        }
        return runs;
    }

    /// <summary>Scan batches that observations of the scope's organization still refer to (the batch stays while they do).</summary>
    public static async Task<IReadOnlyList<Guid>> ObservedBatchesAsync(DbScope scope, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(
            "select distinct scan_batch_id from observation where organization_id = @org and scan_batch_id is not null",
            scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("org", scope.OrganizationId!.Value);
        var batches = new List<Guid>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            batches.Add(reader.GetGuid(0));
        }
        return batches;
    }

    private static async Task<int> RunAsync(DbScope scope, RetentionCuts cuts, string sql, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(sql, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("org", scope.OrganizationId!.Value);
        command.Parameters.AddWithValue("evidence_cut", cuts.Evidence);
        command.Parameters.AddWithValue("history_cut", cuts.History);
        return await command.ExecuteNonQueryAsync(ct);
    }
}
