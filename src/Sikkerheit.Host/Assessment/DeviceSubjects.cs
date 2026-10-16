using Microsoft.EntityFrameworkCore;
using Sikkerheit.Host.Data;

namespace Sikkerheit.Host.Assessment;

/// <summary>
/// The subjects of a device — the device itself and its volumes — and their lifecycle (05 «Субъекты и идентичность
/// устройства»): they appear with the registration, leave at a revocation and after 90 days without a check-in, and come
/// back with the next check-in. The subject table belongs to this module; the agent module calls these methods.
/// </summary>
public static class DeviceSubjects
{
    /// <summary>Creates the device subject at registration, or brings a retired one back.</summary>
    public static async Task EnsureAsync(DbScope scope, Guid deviceId, string displayName, DateTimeOffset now, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        var key = deviceId.ToString();
        var subject = await scope.Db.Subjects.SingleOrDefaultAsync(
            s => s.OrganizationId == org && s.Type == "device" && s.Key == key, ct);
        if (subject is null)
        {
            scope.Db.Subjects.Add(new Subject
            {
                OrganizationId = org, Id = Guid.CreateVersion7(), Type = "device", Key = key, DisplayName = displayName,
                DeviceId = deviceId, FirstSeenAt = now, LastSeenAt = now,
            });
            return;
        }
        subject.DisplayName = displayName;
        subject.LastSeenAt = now;
        subject.RetiredAt = null;
    }

    /// <summary>A volume is named by its PC and its mount point, so that «C:» of two PCs are told apart in lists and reports.</summary>
    public static string VolumeName(string deviceName, string mount) => $"{deviceName} ({mount})";

    /// <summary>The name of the PC in the device subject and in the names of its volumes.</summary>
    public static async Task RenameAsync(DbScope scope, Guid deviceId, string displayName, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        var subjects = await scope.Db.Subjects.Where(s => s.OrganizationId == org && s.DeviceId == deviceId).ToListAsync(ct);
        foreach (var subject in subjects)
        {
            var open = subject.DisplayName?.LastIndexOf(" (", StringComparison.Ordinal) ?? -1;
            subject.DisplayName = subject.Type == "volume" && open >= 0
                ? VolumeName(displayName, subject.DisplayName![(open + 2)..^1])
                : displayName;
        }
    }

    /// <summary>A check-in or a batch: the device subject is seen now, and a retired one returns.</summary>
    public static async Task SeenAsync(DbScope scope, Guid deviceId, DateTimeOffset now, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        var key = deviceId.ToString();
        await scope.Db.Subjects.Where(s => s.OrganizationId == org && s.Type == "device" && s.Key == key)
            .ExecuteUpdateAsync(u => u.SetProperty(s => s.LastSeenAt, now).SetProperty(s => s.RetiredAt, (DateTimeOffset?)null), ct);
    }

    /// <summary>
    /// The devices leave the queue: their subjects and volumes are retired and the open findings get subject_retired — with
    /// cause manual_action and the actor at a revocation, source_change after 90 days without a check-in.
    /// </summary>
    public static async Task RetireAsync(DbScope scope, IReadOnlyCollection<Guid> deviceIds, string cause, Guid? actorId,
        DateTimeOffset now, CancellationToken ct)
    {
        if (deviceIds.Count == 0)
        {
            return;
        }
        var org = scope.OrganizationId!.Value;
        var subjects = await scope.Db.Subjects.Where(s => s.OrganizationId == org && s.DeviceId != null
                                                         && deviceIds.Contains(s.DeviceId.Value) && s.RetiredAt == null)
            .ToListAsync(ct);
        var subjectIds = subjects.Select(s => s.Id).ToList();
        var findings = await scope.Db.Findings.Where(f => f.OrganizationId == org && subjectIds.Contains(f.SubjectId)).ToListAsync(ct);
        var machine = new FindingMachine(scope.Db, org, now);
        foreach (var subject in subjects)
        {
            subject.RetiredAt = now;
            foreach (var finding in findings.Where(f => f.SubjectId == subject.Id))
            {
                machine.Retire(finding, cause, actorId);
            }
        }
    }
}
