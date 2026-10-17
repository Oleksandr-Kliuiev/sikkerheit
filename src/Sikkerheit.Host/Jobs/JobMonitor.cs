using Npgsql;
using Sikkerheit.Host.Data;

namespace Sikkerheit.Host.Jobs;

public sealed record JobLaneSnapshot(string Lane, long Ready, double OldestReadySeconds);

/// <summary>Observe backlog independently of execution, including when every worker is occupied.</summary>
public sealed class JobMonitor(DbScopes scopes, TimeProvider clock, ILogger<JobMonitor> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                JobMetrics.PublishQueue(await ReadAsync(scopes, clock.GetUtcNow(), stoppingToken));
            }
            catch (Exception error) when (error is not OperationCanceledException)
            {
                logger.LogWarning(error, "Cannot measure the job backlog");
            }
            await Task.Delay(TimeSpan.FromSeconds(30), clock, stoppingToken);
        }
    }

    internal static async Task<IReadOnlyList<JobLaneSnapshot>> ReadAsync(DbScopes scopes, DateTimeOffset now, CancellationToken ct)
    {
        await using var scope = await scopes.PlatformAsync(ct);
        await using var read = new NpgsqlCommand("""
            select case when type = 'm365_collect' then 'collection' else 'maintenance' end as lane,
                   count(*), greatest(0, extract(epoch from (@now - min(next_attempt_at))))::double precision
            from job where (state = 'queued' and next_attempt_at <= @now)
                        or (state = 'running' and lease_until < @now)
            group by lane
            """, scope.Connection, scope.Transaction);
        read.Parameters.AddWithValue("now", now);
        var snapshots = new Dictionary<string, JobLaneSnapshot>(StringComparer.Ordinal)
        {
            ["collection"] = new("collection", 0, 0), ["maintenance"] = new("maintenance", 0, 0),
        };
        await using var reader = await read.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            snapshots[reader.GetString(0)] = new(reader.GetString(0), reader.GetInt64(1), reader.GetDouble(2));
        }
        return snapshots.Values.ToArray();
    }
}
