using Microsoft.EntityFrameworkCore;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Data;
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
