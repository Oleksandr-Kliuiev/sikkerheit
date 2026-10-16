using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Sikkerheit.Host.Data;

namespace Sikkerheit.Host.Agents;

public sealed record IdentityConflictDto(DateTimeOffset At, string Kind, string? ReportedDisplayName);

public sealed record DeviceDto(
    Guid Id, string DisplayName, string Status, bool Dormant, string IdentityState, IdentityConflictDto? IdentityConflict,
    string ClockStatus, string KeyProtection, string? AgentVersion, DateTimeOffset EnrolledAt, DateTimeOffset? LastSeenAt,
    DateTimeOffset? LastFullScanAt, Guid? EnrollmentKeyId)
{
    public static DeviceDto From(Device d, DateTimeOffset now) => new(d.Id, d.DisplayName, d.Status, Devices.IsDormant(d, now),
        d.IdentityState,
        d.IdentityState == "identity_conflict"
            ? new IdentityConflictDto(d.IdentityConflictAt!.Value, d.ConflictKind ?? "fingerprint", d.ConflictDisplayName)
            : null,
        d.ClockStatus, d.KeyProtection, d.AgentVersion, d.EnrolledAt, d.LastSeenAt, d.LastFullScanAt, d.EnrollmentKeyId);
}

/// <summary>A device as the other modules read it: what the assessment of its subjects needs.</summary>
public sealed record DeviceState(
    Guid Id, string DisplayName, string Status, DateTimeOffset EnrolledAt, DateTimeOffset? LastSeenAt, DateTimeOffset? LastFullScanAt,
    long? ProjectionSequence, DateTimeOffset? ProjectionCompletedAt, DateTimeOffset? RebootEpisodeSince, DateTimeOffset? RebootEpisodeBootAt);

/// <summary>
/// The device table and the reads of it that other modules use (the table belongs to this module): the dormant limits of
/// 05 «Сущности и ограничения», row locks as the serialization point of batches and jobs, and the batches of the
/// projection.
/// </summary>
public static class Devices
{
    public static readonly TimeSpan DormantAfter = TimeSpan.FromDays(14);
    public static readonly TimeSpan RetireAfter = TimeSpan.FromDays(90);
    public static readonly TimeSpan ConflictRecovery = TimeSpan.FromDays(7);

    /// <summary>No check-in for more than 14 days; a device that never checked in counts from its enrollment.</summary>
    public static bool IsDormant(Device device, DateTimeOffset now) => (device.LastSeenAt ?? device.EnrolledAt) < now - DormantAfter;

    public static DeviceState State(Device d) => new(d.Id, d.DisplayName, d.Status, d.EnrolledAt, d.LastSeenAt,
        d.LastFullScanAt, d.ProjectionSequence, d.ProjectionCompletedAt, d.RebootEpisodeSince, d.RebootEpisodeBootAt);

    /// <summary>The device of the scope's organization, locked for update when asked.</summary>
    public static async Task<Device?> FindAsync(DbScope scope, Guid deviceId, bool forUpdate, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        var query = forUpdate
            ? scope.Db.Devices.FromSqlInterpolated($"select * from device where organization_id = {org} and id = {deviceId} for update")
            : scope.Db.Devices.Where(d => d.OrganizationId == org && d.Id == deviceId);
        return await query.SingleOrDefaultAsync(ct);
    }

    /// <summary>
    /// Locks the row of the device and returns its state: the point where batches and the jobs that change the problems of
    /// the device's subjects take turns (05 «Фоновые задания и планировщик»). Null when there is no such device.
    /// </summary>
    public static async Task<DeviceState?> LockAsync(DbScope scope, Guid deviceId, CancellationToken ct) =>
        await FindAsync(scope, deviceId, forUpdate: true, ct) is { } device ? State(device) : null;

    /// <summary>Devices of the organization that have not been revoked, oldest first (also in the read-all scope).</summary>
    public static async Task<IReadOnlyList<DeviceState>> ActiveAsync(DbScope scope, Guid org, CancellationToken ct)
    {
        var devices = await scope.Db.Devices.AsNoTracking().Where(d => d.OrganizationId == org && d.Status == "active")
            .OrderBy(d => d.EnrolledAt).ThenBy(d => d.Id).ToListAsync(ct);
        return devices.Select(State).ToList();
    }

    /// <summary>Active devices with no check-in for 90 days (freshness_sweep retires their subjects).</summary>
    public static async Task<IReadOnlyList<Guid>> UnseenSinceAsync(DbScope scope, DateTimeOffset now, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        var cut = now - RetireAfter;
        return await scope.Db.Devices.AsNoTracking()
            .Where(d => d.OrganizationId == org && d.Status == "active" && (d.LastSeenAt ?? d.EnrolledAt) < cut)
            .Select(d => d.Id).ToListAsync(ct);
    }

    /// <summary>
    /// The batches that could change the projection of the device, newest first (by completedAt, then sequence): the input
    /// of SYS-002 and SYS-003 is the last collected WIN-011 among them (05 «Выбор текущего состояния», step 7).
    /// </summary>
    public static async Task<IReadOnlyList<Guid>> ProjectionBatchesAsync(DbScope scope, Guid deviceId, int take, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        return await scope.Db.ScanBatches.AsNoTracking()
            .Where(b => b.OrganizationId == org && b.DeviceId == deviceId && b.ReplacedProjection)
            .OrderByDescending(b => b.CompletedAt).ThenByDescending(b => b.Sequence).Take(take).Select(b => b.Id).ToListAsync(ct);
    }

    /// <summary>The batch that holds the current projection of the device, or null before the first one.</summary>
    public static async Task<Guid?> ProjectionBatchAsync(DbScope scope, Guid deviceId, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        var sequence = await scope.Db.Devices.AsNoTracking().Where(d => d.OrganizationId == org && d.Id == deviceId)
            .Select(d => d.ProjectionSequence).SingleOrDefaultAsync(ct);
        return sequence is null ? null : await scope.Db.ScanBatches.AsNoTracking()
            .Where(b => b.OrganizationId == org && b.DeviceId == deviceId && b.Sequence == sequence)
            .Select(b => (Guid?)b.Id).SingleOrDefaultAsync(ct);
    }

    /// <summary>The policyVersion the batch was collected under.</summary>
    public static async Task<int> BatchPolicyVersionAsync(DbScope scope, Guid batchId, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        return await scope.Db.ScanBatches.AsNoTracking().Where(b => b.OrganizationId == org && b.Id == batchId)
            .Select(b => b.PolicyVersion).SingleAsync(ct);
    }

    /// <summary>Days (UTC) of the period with a check-in or an accepted batch, per device (the denominator of coveragePeriod).</summary>
    public static async Task<IReadOnlyDictionary<Guid, int>> PresenceDaysAsync(DbScope scope, Guid org, DateTimeOffset start,
        DateTimeOffset end, CancellationToken ct)
    {
        var from = DateOnly.FromDateTime(start.UtcDateTime);
        var to = DateOnly.FromDateTime(end.UtcDateTime.AddTicks(-1));
        var rows = await scope.Db.DevicePresences.AsNoTracking()
            .Where(p => p.OrganizationId == org && p.Day >= from && p.Day <= to)
            .GroupBy(p => p.DeviceId).Select(g => new { Id = g.Key, Days = g.Count() }).ToListAsync(ct);
        return rows.ToDictionary(r => r.Id, r => r.Days);
    }

    /// <summary>Marks a UTC day as present (check-in or accepted batch); repeats on the same day do nothing.</summary>
    public static async Task MarkPresentAsync(DbScope scope, Guid deviceId, DateTimeOffset at, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            insert into device_presence (organization_id, device_id, day) values (@org, @device, @day)
            on conflict do nothing
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("org", scope.OrganizationId!.Value);
        command.Parameters.AddWithValue("device", deviceId);
        command.Parameters.AddWithValue("day", NpgsqlTypes.NpgsqlDbType.Date, DateOnly.FromDateTime(at.UtcDateTime));
        await command.ExecuteNonQueryAsync(ct);
    }

    /// <summary>The identity returns to ok after 7 days without a mismatch (05 «Субъекты и идентичность устройства»).</summary>
    public static void RecoverIdentity(Device device, DateTimeOffset now)
    {
        if (device.IdentityState == "identity_conflict" && device.IdentityConflictAt + ConflictRecovery <= now)
        {
            ClearConflict(device);
        }
    }

    /// <summary>Identities without a mismatch for 7 days return to ok (hourly, with the scan request expiry).</summary>
    public static async Task RecoverIdentitiesAsync(DbScope scope, DateTimeOffset now, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        var cut = now - ConflictRecovery;
        var due = await scope.Db.Devices.Where(d => d.OrganizationId == org && d.IdentityState == "identity_conflict"
                                                    && d.IdentityConflictAt <= cut).ToListAsync(ct);
        foreach (var device in due)
        {
            ClearConflict(device);
        }
    }

    public static void ClearConflict(Device device)
    {
        device.IdentityState = "ok";
        device.IdentityConflictAt = null;
        device.ConflictKind = null;
        device.ConflictFingerprintHash = null;
        device.ConflictPublicKeyJwk = null;
        device.ConflictDisplayName = null;
    }

    /// <summary>Records a mismatch of the machine fingerprint or of the key (the data stays for the technician to decide).</summary>
    public static void MarkConflict(Device device, string kind, DateTimeOffset now, string? fingerprintHash, string? publicKeyJwk,
        string? displayName)
    {
        device.IdentityState = "identity_conflict";
        device.IdentityConflictAt = now;
        device.ConflictKind = kind;
        device.ConflictFingerprintHash = fingerprintHash;
        device.ConflictPublicKeyJwk = publicKeyJwk;
        device.ConflictDisplayName = displayName ?? device.ConflictDisplayName;
    }

    /// <summary>The sessions of the device are removed with a replaced key or a revocation.</summary>
    public static async Task DeleteSessionsAsync(DbScope scope, Guid deviceId, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("delete from agent_session where device_id = @device and organization_id = @org",
            scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("device", deviceId);
        command.Parameters.AddWithValue("org", scope.OrganizationId!.Value);
        await command.ExecuteNonQueryAsync(ct);
    }

    public static string? Telemetry(JsonElement checkIn)
    {
        var keys = new[] { "queueDepth", "bufferBytes", "droppedBatchCount", "rejectedBatchCount", "configRejected", "serviceStarts",
            "lastCrashAt", "workingSetMb", "cpuSeconds", "abandonedCollectors" };
        var node = new System.Text.Json.Nodes.JsonObject();
        foreach (var key in keys)
        {
            if (checkIn.TryGetProperty(key, out var value))
            {
                node[key] = System.Text.Json.Nodes.JsonNode.Parse(value.GetRawText());
            }
        }
        return node.ToJsonString();
    }
}
