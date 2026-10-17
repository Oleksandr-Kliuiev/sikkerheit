using System.Diagnostics;
using Npgsql;
using Sikkerheit.Host.Data;

namespace Sikkerheit.Host.Jobs;

/// <summary>
/// Bounded collection and maintenance lanes, with shared PostgreSQL admission, renewable leases and fenced effects.
/// Runs only where Jobs:Enabled is set. A failed job is retried up to ten times.
/// </summary>
public sealed class JobRunner(DbScopes scopes, IEnumerable<IJobHandler> handlers, TimeProvider clock, ILogger<JobRunner> logger,
    JobExecutionOptions? options = null) : BackgroundService
{
    public static readonly TimeSpan Lease = TimeSpan.FromMinutes(5);
    public const int MaxAttempts = 10;
    private static readonly TimeSpan[] Retries =
        [TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(60)];
    private readonly JobExecutionOptions _options = Validated(options ?? new());
    private readonly Dictionary<string, IJobHandler> _handlers = handlers.ToDictionary(h => h.Type, StringComparer.Ordinal);
    private readonly string _owner = Environment.MachineName + ":" + Guid.NewGuid().ToString("N")[..8];

    private static JobExecutionOptions Validated(JobExecutionOptions value)
    {
        value.Validate();
        return value;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken) => Task.WhenAll(
        Enumerable.Range(0, _options.CollectionConcurrency).Select(_ => WorkerAsync(true, stoppingToken))
            .Concat(Enumerable.Range(0, _options.MaintenanceConcurrency).Select(_ => WorkerAsync(false, stoppingToken))));

    private async Task WorkerAsync(bool collectionLane, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (!await RunOnceAsync(collectionLane, ct))
                {
                    await Task.Delay(TimeSpan.FromSeconds(1), clock, ct);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (Exception error)
            {
                logger.LogError(error, "Job runner iteration failed");
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(5), clock, ct);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    break;
                }
            }
        }
    }

    /// <summary>Captures and runs one ready job; false when both shared lanes are full or none is ready.</summary>
    public Task<bool> RunOnceAsync(CancellationToken ct) => RunOnceAsync(null, ct);

    private async Task<bool> RunOnceAsync(bool? collectionLane, CancellationToken ct)
    {
        var lease = await JobClaims.CaptureAsync(scopes, clock, _owner, _options, collectionLane, ct);
        if (lease is null)
        {
            return false;
        }
        using var execution = CancellationTokenSource.CreateLinkedTokenSource(ct);
        using var renewal = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var renewing = RenewAsync(lease, execution, renewal.Token);
        var started = Stopwatch.GetTimestamp();
        var outcome = "completed";
        JobMetrics.Started(lease.Type);
        try
        {
            if (!_handlers.TryGetValue(lease.Type, out var handler))
            {
                throw new InvalidOperationException($"No handler for job type {lease.Type}");
            }
            await handler.ExecuteAsync(lease, execution.Token);
        }
        catch (JobLeaseLostException)
        {
            outcome = "lease_lost";
            logger.LogWarning("Job {JobId} lost its lease; another worker owns it", lease.JobId);
        }
        catch (OperationCanceledException) when (execution.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            // Renewal failed or the lease was taken over. No further business effects may be written.
            outcome = "lease_lost";
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            outcome = "cancelled";
            throw;
        }
        catch (Exception error)
        {
            outcome = "failed";
            logger.LogError(error, "Job {JobId} of type {Type} failed", lease.JobId, lease.Type);
            await FailAsync(lease, error.Message, ct);
        }
        finally
        {
            await renewal.CancelAsync();
            try
            {
                await renewing;
            }
            catch (OperationCanceledException) when (renewal.IsCancellationRequested)
            {
                // Renewal stops with the job.
            }
            catch (Exception error)
            {
                outcome = "lease_lost";
                logger.LogWarning(error, "Lease renewal stopped job {JobId}", lease.JobId);
            }
            JobMetrics.Finished(lease.Type, outcome, Stopwatch.GetElapsedTime(started));
        }
        return true;
    }

    private async Task RenewAsync(JobLease lease, CancellationTokenSource execution, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromMinutes(1), clock, ct);
                await using var scope = await scopes.PlatformAsync(ct);
                await using var command = new NpgsqlCommand(
                    "update job set lease_until = @until where id = @id and lease_token = @token and state = 'running'",
                    scope.Connection, scope.Transaction);
                command.Parameters.AddWithValue("until", clock.GetUtcNow() + Lease);
                command.Parameters.AddWithValue("id", lease.JobId);
                command.Parameters.AddWithValue("token", lease.Token);
                if (await command.ExecuteNonQueryAsync(ct) != 1)
                {
                    throw new JobLeaseLostException();
                }
                await scope.CommitAsync(ct);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            await execution.CancelAsync();
            throw;
        }
    }

    private async Task FailAsync(JobLease lease, string error, CancellationToken ct)
    {
        await using var scope = await scopes.PlatformAsync(ct);
        await using var command = new NpgsqlCommand("""
            update job set
                state = case when attempts >= @max then 'failed' else 'queued' end,
                next_attempt_at = @now + (case attempts when 1 then @r1 when 2 then @r2 when 3 then @r3 else @r4 end),
                lease_until = null, last_error = left(@error, 1000),
                completed_at = case when attempts >= @max then @now else null end
            where id = @id and lease_token = @token and state = 'running'
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("now", clock.GetUtcNow());
        command.Parameters.AddWithValue("max", MaxAttempts);
        command.Parameters.AddWithValue("r1", Retries[0]);
        command.Parameters.AddWithValue("r2", Retries[1]);
        command.Parameters.AddWithValue("r3", Retries[2]);
        command.Parameters.AddWithValue("r4", Retries[3]);
        command.Parameters.AddWithValue("error", error);
        command.Parameters.AddWithValue("id", lease.JobId);
        command.Parameters.AddWithValue("token", lease.Token);
        await command.ExecuteNonQueryAsync(ct);
        await scope.CommitAsync(ct);
    }
}
