using Npgsql;
using Sikkerheit.Host.Data;

namespace Sikkerheit.Host.Jobs;

/// <summary>A captured job. The lease token fences effects: a transaction holds the lease before it writes.</summary>
public sealed record JobLease(Guid JobId, long Token, string Type, Guid? OrganizationId, string? InputId, string? PeriodKey,
    int Attempts = 1)
{
    /// <summary>Locks the job row in the transaction of the effect; false if the lease was lost (external review F14).</summary>
    public async Task<bool> HoldAsync(DbScope scope, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(
            "select 1 from job where id = @id and lease_token = @token and state = 'running' for update",
            scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("id", JobId);
        command.Parameters.AddWithValue("token", Token);
        return await command.ExecuteScalarAsync(ct) is not null;
    }

    /// <summary>The last attempt before the job turns failed: handlers record a business failure instead of retrying.</summary>
    public bool IsLastAttempt => Attempts >= JobRunner.MaxAttempts;

    /// <summary>Marks the job succeeded in the same transaction as its effect.</summary>
    public async Task CompleteAsync(DbScope scope, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(
            "update job set state = 'succeeded', completed_at = now(), lease_until = null where id = @id and lease_token = @token",
            scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("id", JobId);
        command.Parameters.AddWithValue("token", Token);
        if (await command.ExecuteNonQueryAsync(ct) != 1)
        {
            throw new JobLeaseLostException();
        }
    }
}

public sealed class JobLeaseLostException : Exception;

public interface IJobHandler
{
    string Type { get; }

    /// <summary>Runs the job; completes it with lease.CompleteAsync inside the transaction of its last effect.</summary>
    Task ExecuteAsync(JobLease lease, CancellationToken ct);
}

/// <summary>
/// Executes jobs from the job table (02 «Фоновые задания»): FOR UPDATE SKIP LOCKED capture with a 5-minute lease,
/// renewal while running, retries after 1, 5, 15 and 60 minutes and then hourly, failed after 10 attempts.
/// Runs only where Jobs:Enabled is set (the production slot).
/// </summary>
public sealed class JobRunner(DbScopes scopes, IEnumerable<IJobHandler> handlers, TimeProvider clock, ILogger<JobRunner> logger)
    : BackgroundService
{
    public static readonly TimeSpan Lease = TimeSpan.FromMinutes(5);
    public const int MaxAttempts = 10;
    private static readonly TimeSpan[] Retries =
        [TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(60)];
    private readonly Dictionary<string, IJobHandler> _handlers = handlers.ToDictionary(h => h.Type, StringComparer.Ordinal);
    private readonly string _owner = Environment.MachineName + ":" + Guid.NewGuid().ToString("N")[..8];

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            bool worked;
            try
            {
                worked = await RunOnceAsync(stoppingToken);
            }
            catch (Exception error) when (error is not OperationCanceledException)
            {
                logger.LogError(error, "Job runner iteration failed");
                worked = false;
            }
            if (!worked)
            {
                await Task.Delay(TimeSpan.FromSeconds(5), clock, stoppingToken);
            }
        }
    }

    /// <summary>Captures and runs one ready job; false when none is ready.</summary>
    public async Task<bool> RunOnceAsync(CancellationToken ct)
    {
        var lease = await CaptureAsync(ct);
        if (lease is null)
        {
            return false;
        }
        using var renewal = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var renewing = RenewAsync(lease, renewal.Token);
        try
        {
            if (!_handlers.TryGetValue(lease.Type, out var handler))
            {
                throw new InvalidOperationException($"No handler for job type {lease.Type}");
            }
            await handler.ExecuteAsync(lease, ct);
        }
        catch (JobLeaseLostException)
        {
            logger.LogWarning("Job {JobId} lost its lease; another worker owns it", lease.JobId);
        }
        catch (Exception error) when (error is not OperationCanceledException || !ct.IsCancellationRequested)
        {
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
            catch (OperationCanceledException)
            {
                // Renewal stops with the job.
            }
        }
        return true;
    }

    private async Task<JobLease?> CaptureAsync(CancellationToken ct)
    {
        await using var scope = await scopes.PlatformAsync(ct);
        await using var command = new NpgsqlCommand("""
            update job set state = 'running', lease_owner = @owner, lease_token = lease_token + 1,
                           lease_until = @until, attempts = attempts + 1
            where id = (
                select id from job
                where (state = 'queued' and next_attempt_at <= @now) or (state = 'running' and lease_until < @now)
                order by next_attempt_at
                for update skip locked
                limit 1)
            returning id, lease_token, type, organization_id, input_id, period_key, attempts
            """, scope.Connection, scope.Transaction);
        var now = clock.GetUtcNow();
        command.Parameters.AddWithValue("owner", _owner);
        command.Parameters.AddWithValue("until", now + Lease);
        command.Parameters.AddWithValue("now", now);
        JobLease? lease = null;
        await using (var reader = await command.ExecuteReaderAsync(ct))
        {
            if (await reader.ReadAsync(ct))
            {
                lease = new JobLease(reader.GetGuid(0), reader.GetInt64(1), reader.GetString(2),
                    reader.IsDBNull(3) ? null : reader.GetGuid(3), reader.IsDBNull(4) ? null : reader.GetString(4),
                    reader.IsDBNull(5) ? null : reader.GetString(5), reader.GetInt32(6));
            }
        }
        await scope.CommitAsync(ct);
        return lease;
    }

    private async Task RenewAsync(JobLease lease, CancellationToken ct)
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
            await command.ExecuteNonQueryAsync(ct);
            await scope.CommitAsync(ct);
        }
    }

    private async Task FailAsync(JobLease lease, string error, CancellationToken ct)
    {
        await using var scope = await scopes.PlatformAsync(CancellationToken.None);
        await using var command = new NpgsqlCommand("""
            update job set
                state = case when attempts >= @max then 'failed' else 'queued' end,
                next_attempt_at = @now + (case attempts when 1 then @r1 when 2 then @r2 when 3 then @r3 else @r4 end),
                lease_until = null, last_error = left(@error, 1000),
                completed_at = case when attempts >= @max then @now else null end
            where id = @id and lease_token = @token
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
        await command.ExecuteNonQueryAsync(CancellationToken.None);
        await scope.CommitAsync(CancellationToken.None);
        _ = ct;
    }
}
