using Microsoft.EntityFrameworkCore;
using Sikkerheit.Host.Assessment;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Operations;

namespace Sikkerheit.Host.Agents;

/// <summary>
/// The security log records of the agent module applied after a database restore (04 «Журнал безопасности», 06 «Резервное
/// копирование и восстановление», step 3): revocations are only made stricter, never undone, and the revocation of a device
/// that the restored database does not know still writes the installation to revoked_installation.
/// </summary>
public static class AgentReplay
{
    /// <summary>device.revoke: the device is revoked and its installation recorded. False when both were already so.</summary>
    public static async Task<bool> RevokeDeviceAsync(DbScope scope, SecurityLogRecord record, DateTimeOffset now, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        if (!Guid.TryParse(record.TargetId, out var deviceId))
        {
            return false;
        }
        var changed = false;
        var device = await Devices.FindAsync(scope, deviceId, forUpdate: true, ct);
        var installation = device?.InstallationId ?? record.InstallationId;
        if (device is { Status: "active" })
        {
            DeviceEndpoints.MarkRevoked(device, record.OccurredAt);
            await DeviceSubjects.RetireAsync(scope, [deviceId], record.EntraUserId is null ? "source_change" : "manual_action",
                record.EntraUserId, now, ct);
            changed = true;
        }
        if (installation is { } id && !await scope.Db.RevokedInstallations.AnyAsync(r => r.OrganizationId == org && r.InstallationId == id, ct))
        {
            scope.Db.RevokedInstallations.Add(new RevokedInstallation
            {
                OrganizationId = org, InstallationId = id, KeyThumbprint = device?.KeyThumbprint ?? record.KeyThumbprint,
                DeviceId = deviceId, RevokedAt = record.OccurredAt, Source = "restore_replay",
            });
            changed = true;
        }
        return changed;
    }

    /// <summary>enrollment_key.revoke: an active key is revoked; a key the restored database does not have needs nothing.</summary>
    public static async Task<bool> RevokeKeyAsync(DbScope scope, SecurityLogRecord record, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        if (!Guid.TryParse(record.TargetId, out var keyId))
        {
            return false;
        }
        var key = await scope.Db.EnrollmentKeys.SingleOrDefaultAsync(k => k.OrganizationId == org && k.Id == keyId, ct);
        if (key is not { RevokedAt: null })
        {
            return false;
        }
        key.RevokedAt = record.OccurredAt;
        return true;
    }

    /// <summary>The installation of a device.revoke record is in revoked_installation (the check after the replay).</summary>
    public static Task<bool> InstallationRevokedAsync(DbScope scope, SecurityLogRecord record, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        return record.InstallationId is { } id
            ? scope.Db.RevokedInstallations.AnyAsync(r => r.OrganizationId == org && r.InstallationId == id, ct)
            : Task.FromResult(true);
    }

    /// <summary>No active key with the id of the record remains (a key the restored database never had needs nothing).</summary>
    public static async Task<bool> KeyRevokedAsync(DbScope scope, SecurityLogRecord record, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        return !Guid.TryParse(record.TargetId, out var id)
               || !await scope.Db.EnrollmentKeys.AnyAsync(k => k.OrganizationId == org && k.Id == id && k.RevokedAt == null, ct);
    }

    /// <summary>Organizations (of the scope: one) with no active enrollment key; RB-05 lists them for the technician.</summary>
    public static async Task<bool> HasActiveKeyAsync(DbScope scope, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        return await scope.Db.EnrollmentKeys.AnyAsync(k => k.OrganizationId == org && k.RevokedAt == null, ct);
    }
}
