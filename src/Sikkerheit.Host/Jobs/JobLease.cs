using Npgsql;
using Sikkerheit.Host.Data;

namespace Sikkerheit.Host.Jobs;

/// <summary>A captured job. The lease token fences effects: a transaction holds the lease before it writes.</summary>
public sealed record JobLease(Guid JobId, long Token, string Type, Guid? OrganizationId, string? InputId, string? PeriodKey,
    int Attempts = 1, DateTimeOffset? EnqueuedAt = null)
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
