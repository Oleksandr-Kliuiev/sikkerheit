using Npgsql;
using Sikkerheit.Host.Data;

namespace Sikkerheit.Host.Operations;

/// <summary>Creates jobs idempotently by (type, organizationId, inputId or periodKey) — 02 «Фоновые задания».</summary>
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
}
