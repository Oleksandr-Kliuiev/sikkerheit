using Npgsql;
using Sikkerheit.Host.Data;

namespace Sikkerheit.Host.Jobs;

/// <summary>Claims are coordinated in PostgreSQL, including across application instances.</summary>
internal static class JobClaims
{
    private const long ClaimLock = 0x534B_4A4F_4253; // "SKJOBS"; held only for the short claim transaction.

    public static async Task<JobLease?> CaptureAsync(DbScopes scopes, TimeProvider clock, string owner,
        JobExecutionOptions options, bool? collectionLane, CancellationToken ct)
    {
        await using var scope = await scopes.PlatformAsync(ct);
        await using (var gate = new NpgsqlCommand("select pg_advisory_xact_lock(@key)", scope.Connection, scope.Transaction))
        {
            gate.Parameters.AddWithValue("key", ClaimLock);
            await gate.ExecuteNonQueryAsync(ct);
        }
        // The gate serializes admission, not execution. An expired lease being reclaimed does not count itself.
        await using var command = new NpgsqlCommand("""
            update job set state = 'running', lease_owner = @owner, lease_token = lease_token + 1,
                           lease_until = @until, attempts = attempts + 1
            where id = (
                select j.id from job j
                where ((j.state = 'queued' and j.next_attempt_at <= @now)
                    or (j.state = 'running' and j.lease_until < @now))
                  and (@lane::boolean is null or (j.type = 'm365_collect') = @lane)
                  and (select count(*) from job active
                       where active.state = 'running' and active.lease_until >= @now and active.id <> j.id
                         and (active.type = 'm365_collect') = (j.type = 'm365_collect'))
                      < case when j.type = 'm365_collect' then @collections else @maintenance end
                  and (j.type <> 'm365_collect' or j.organization_id is null or not exists (
                      select 1 from job active where active.type = 'm365_collect' and active.state = 'running'
                        and active.lease_until >= @now and active.organization_id = j.organization_id and active.id <> j.id))
                order by j.next_attempt_at, j.created_at, j.id
                for update of j skip locked limit 1)
            returning id, lease_token, type, organization_id, input_id, period_key, attempts, next_attempt_at, created_at
            """, scope.Connection, scope.Transaction);
        var now = clock.GetUtcNow();
        command.Parameters.AddWithValue("owner", owner);
        command.Parameters.AddWithValue("until", now + JobRunner.Lease);
        command.Parameters.AddWithValue("now", now);
        command.Parameters.AddWithValue("lane", (object?)collectionLane ?? DBNull.Value);
        command.Parameters.AddWithValue("collections", options.CollectionConcurrency);
        command.Parameters.AddWithValue("maintenance", options.MaintenanceConcurrency);
        JobLease? lease = null;
        await using (var reader = await command.ExecuteReaderAsync(ct))
        {
            if (await reader.ReadAsync(ct))
            {
                lease = new JobLease(reader.GetGuid(0), reader.GetInt64(1), reader.GetString(2),
                    reader.IsDBNull(3) ? null : reader.GetGuid(3), reader.IsDBNull(4) ? null : reader.GetString(4),
                    reader.IsDBNull(5) ? null : reader.GetString(5), reader.GetInt32(6), reader.GetFieldValue<DateTimeOffset>(8));
                JobMetrics.Queued(lease.Type, now - reader.GetFieldValue<DateTimeOffset>(7));
            }
        }
        await scope.CommitAsync(ct);
        return lease;
    }
}
