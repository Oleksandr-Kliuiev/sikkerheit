using Microsoft.EntityFrameworkCore;
using Npgsql;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;

namespace Sikkerheit.Host.M365;

/// <summary>A completed or partial run: its observations form the current projection (05 «Выбор текущего состояния»).</summary>
public sealed record ProjectionRun(Guid Id, DateTimeOffset? CompletedAt, int? PolicyVersion);

/// <summary>Runs of an organization with one state and failure code.</summary>
public sealed record CollectionRunCount(string State, string? FailureCode, int Count);

/// <summary>Failed runs of an organization with one failure code.</summary>
public sealed record FailedRunCount(Guid OrganizationId, string? FailureCode, int Count);

/// <summary>Reads of collection runs for other modules; the collection_run table belongs to this module.</summary>
public static class CollectionRuns
{
    /// <summary>The completed and partial runs of the scope's organization.</summary>
    public static async Task<IReadOnlyList<ProjectionRun>> ProjectionRunsAsync(DbScope scope, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        return await scope.Db.CollectionRuns.AsNoTracking()
            .Where(r => r.OrganizationId == org && (r.State == "completed" || r.State == "partial"))
            .Select(r => new ProjectionRun(r.Id, r.CompletedAt, r.PolicyVersion)).ToListAsync(ct);
    }

    /// <summary>The end of the last completed or partial run before the moment.</summary>
    public static async Task<DateTimeOffset?> LastCollectedBeforeAsync(DbScope scope, Guid organizationId, DateTimeOffset end,
        CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            select max(completed_at) from collection_run
            where organization_id = @org and completed_at < @end and state in ('completed', 'partial')
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("org", organizationId);
        command.Parameters.AddWithValue("end", end);
        await using var reader = await command.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) && !reader.IsDBNull(0) ? reader.GetFieldValue<DateTimeOffset>(0) : null;
    }

    /// <summary>The last run that finished before the moment: completed, partial or failed.</summary>
    public static async Task<CollectionRun?> LastFinishedBeforeAsync(DbScope scope, Guid organizationId, DateTimeOffset end,
        CancellationToken ct) =>
        await scope.Db.CollectionRuns.FromSql($"""
            select * from collection_run
            where organization_id = {organizationId} and completed_at < {end} and state in ('completed', 'partial', 'failed')
            order by completed_at desc, id desc limit 1
            """).AsNoTracking().SingleOrDefaultAsync(ct);

    /// <summary>Runs queued in [start, end) by state and failure code.</summary>
    public static async Task<IReadOnlyList<CollectionRunCount>> CountsAsync(DbScope scope, Guid organizationId,
        DateTimeOffset start, DateTimeOffset end, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            select state, failure_code, count(*)::int from collection_run
            where organization_id = @org and queued_at >= @start and queued_at < @end
            group by state, failure_code order by state, failure_code
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("org", organizationId);
        command.Parameters.AddWithValue("start", start);
        command.Parameters.AddWithValue("end", end);
        var counts = new List<CollectionRunCount>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            counts.Add(new CollectionRunCount(reader.GetString(0), reader.IsDBNull(1) ? null : reader.GetString(1), reader.GetInt32(2)));
        }
        return counts;
    }

    /// <summary>
    /// Finished runs older than 90 days (04 «Сроки хранения») except the observed ones, which observations still refer to.
    /// Returns the number of deleted runs.
    /// </summary>
    public static async Task<int> PurgeAsync(DbScope scope, RetentionCuts cuts, IReadOnlyCollection<Guid> observed,
        CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            delete from collection_run r
            where r.organization_id = @org and r.queued_at < @evidence_cut and r.state not in ('queued', 'running')
              and not (r.id = any(@observed))
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("org", scope.OrganizationId!.Value);
        command.Parameters.AddWithValue("evidence_cut", cuts.Evidence);
        command.Parameters.AddWithValue("observed", observed.ToArray());
        return await command.ExecuteNonQueryAsync(ct);
    }

    /// <summary>Runs that failed in [since, until) by organization and failure code; only for the read-all scope.</summary>
    public static async Task<IReadOnlyList<FailedRunCount>> FailedAsync(DbScope all, DateTimeOffset since, DateTimeOffset until,
        CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            select organization_id, failure_code, count(*)::int from collection_run
            where completed_at >= @since and completed_at < @until and state = 'failed'
            group by organization_id, failure_code order by failure_code
            """, all.Connection, all.Transaction);
        command.Parameters.AddWithValue("since", since);
        command.Parameters.AddWithValue("until", until);
        var counts = new List<FailedRunCount>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            counts.Add(new FailedRunCount(reader.GetGuid(0), reader.IsDBNull(1) ? null : reader.GetString(1), reader.GetInt32(2)));
        }
        return counts;
    }
}
