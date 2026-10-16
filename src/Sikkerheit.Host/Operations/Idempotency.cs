using Microsoft.EntityFrameworkCore;
using Npgsql;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Operations;

/// <summary>
/// Repeat of a portal operation with the same idempotencyKey: same request hash within 24 hours returns the
/// recorded response, another body gives 409 idempotency_conflict (05 «Сущности и ограничения»).
/// </summary>
public static class Idempotency
{
    public static readonly TimeSpan Window = TimeSpan.FromHours(24);
    public static readonly TimeSpan Retention = TimeSpan.FromDays(7);

    /// <summary>Removes the records of the scope's organization (its deletion).</summary>
    public static Task DeleteOrganizationDataAsync(DbScope scope, CancellationToken ct) =>
        OrganizationRows.DeleteAsync(scope, ["idempotency_record"], ct);

    /// <summary>Records older than 7 days (04 «Сроки хранения»).</summary>
    public static async Task PurgeAsync(DbScope scope, RetentionCuts cuts, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(
            "delete from idempotency_record where organization_id = @org and created_at < @now - interval '7 days'",
            scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("org", scope.OrganizationId!.Value);
        command.Parameters.AddWithValue("now", cuts.Now);
        await command.ExecuteNonQueryAsync(ct);
    }

    public static async Task<IdempotencyRecord?> FindReplayAsync(DbScope scope, string operationId, Guid key,
        string requestHash, DateTimeOffset now, CancellationToken ct)
    {
        var organizationId = scope.OrganizationId!.Value;
        var record = await scope.Db.IdempotencyRecords.SingleOrDefaultAsync(
            r => r.OrganizationId == organizationId && r.OperationId == operationId && r.Key == key, ct);
        if (record is null || record.CreatedAt + Window <= now)
        {
            return null;
        }
        if (record.RequestHash != requestHash)
        {
            throw new ApiProblemException(ProblemCodes.IdempotencyConflict);
        }
        return record;
    }

    public static async Task RecordAsync(DbScope scope, string operationId, Guid key, string requestHash, int status,
        string? resultId, string? responseBody, DateTimeOffset now, CancellationToken ct)
    {
        var organizationId = scope.OrganizationId!.Value;
        // A stale record past the window is replaced by the new one.
        await scope.Db.IdempotencyRecords
            .Where(r => r.OrganizationId == organizationId && r.OperationId == operationId && r.Key == key)
            .ExecuteDeleteAsync(ct);
        scope.Db.IdempotencyRecords.Add(new IdempotencyRecord
        {
            OrganizationId = organizationId, OperationId = operationId, Key = key, RequestHash = requestHash,
            ResponseStatus = status, ResultId = resultId, ResponseBody = responseBody, CreatedAt = now,
            ExpiresAt = now + Retention,
        });
    }
}
