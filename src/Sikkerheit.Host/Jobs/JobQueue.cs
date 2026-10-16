using Npgsql;
using Sikkerheit.Host.Data;

namespace Sikkerheit.Host.Jobs;

/// <summary>
/// The job table belongs to this module: other modules create and mark jobs only through these methods. Jobs are
/// identified by (type, organizationId, inputId or periodKey) — 02 «Фоновые задания».
/// </summary>
public static class JobQueue
{
    public static async Task EnqueueAsync(DbScope scope, string type, Guid? organizationId, string? inputId,
        string? periodKey, DateTimeOffset now, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            insert into job (id, type, organization_id, input_id, period_key, state, next_attempt_at, created_at)
            values (@id, @type, @org, @input, @period, 'queued', @now, @now)
            on conflict do nothing
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("id", Guid.CreateVersion7());
        command.Parameters.AddWithValue("type", type);
        command.Parameters.AddWithValue("org", (object?)organizationId ?? DBNull.Value);
        command.Parameters.AddWithValue("input", (object?)inputId ?? DBNull.Value);
        command.Parameters.AddWithValue("period", (object?)periodKey ?? DBNull.Value);
        command.Parameters.AddWithValue("now", now);
        await command.ExecuteNonQueryAsync(ct);
    }

    /// <summary>Queues the job again when its earlier run has finished (a failed report is retried, external review F09).</summary>
    public static async Task RequeueAsync(DbScope scope, string type, Guid organizationId, string inputId, DateTimeOffset now,
        CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            insert into job (id, type, organization_id, input_id, period_key, state, next_attempt_at, created_at)
            values (@id, @type, @org, @input, null, 'queued', @now, @now)
            on conflict (type, organization_id, (coalesce(input_id, period_key))) do update
                set state = 'queued', attempts = 0, next_attempt_at = excluded.next_attempt_at, completed_at = null,
                    lease_until = null, last_error = null
                where job.state in ('succeeded', 'failed')
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("id", Guid.CreateVersion7());
        command.Parameters.AddWithValue("type", type);
        command.Parameters.AddWithValue("org", organizationId);
        command.Parameters.AddWithValue("input", inputId);
        command.Parameters.AddWithValue("now", now);
        await command.ExecuteNonQueryAsync(ct);
    }

    /// <summary>
    /// Marks a periodic job done without running it, so the scheduler does not create it again (restore, 06 step 5:
    /// a week whose report already reached the client). A running job is left alone. True when a row changed.
    /// </summary>
    public static async Task<bool> MarkDoneAsync(DbScope platform, string type, Guid? organizationId, string periodKey,
        DateTimeOffset now, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            insert into job (id, type, organization_id, input_id, period_key, state, next_attempt_at, created_at, completed_at)
            values (@id, @type, @org, null, @period, 'succeeded', @now, @now, @now)
            on conflict (type, organization_id, (coalesce(input_id, period_key))) do update
                set state = 'succeeded', completed_at = excluded.completed_at, lease_until = null, last_error = null
                where job.state in ('queued', 'failed')
            """, platform.Connection, platform.Transaction);
        command.Parameters.AddWithValue("id", Guid.CreateVersion7());
        command.Parameters.AddWithValue("type", type);
        command.Parameters.AddWithValue("org", (object?)organizationId ?? DBNull.Value);
        command.Parameters.AddWithValue("period", periodKey);
        command.Parameters.AddWithValue("now", now);
        return await command.ExecuteNonQueryAsync(ct) > 0;
    }

    /// <summary>
    /// Drops every lease (restore, 06 step 6): a job that was running at the restore point runs again from the start;
    /// its effects are idempotent. Returns the number of released jobs.
    /// </summary>
    public static async Task<int> ResetLeasesAsync(DbScope platform, DateTimeOffset now, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            update job set state = case when state = 'running' then 'queued' else state end,
                           next_attempt_at = case when state = 'running' then least(next_attempt_at, @now) else next_attempt_at end,
                           lease_owner = null, lease_until = null
            where state = 'running' or lease_until is not null
            """, platform.Connection, platform.Transaction);
        command.Parameters.AddWithValue("now", now);
        return await command.ExecuteNonQueryAsync(ct);
    }

    /// <summary>Jobs that still hold a lease; zero after ResetLeasesAsync.</summary>
    public static async Task<long> LeasedCountAsync(DbScope platform, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(
            "select count(*) from job where state = 'running' or lease_until is not null", platform.Connection, platform.Transaction);
        return (long)(await command.ExecuteScalarAsync(ct))!;
    }
}
