using Microsoft.EntityFrameworkCore;
using Sikkerheit.Host.Data;

namespace Sikkerheit.Host.Organizations;

/// <summary>An organization as the lifecycle sees it: id, status and deletion date.</summary>
public sealed record OrganizationState(Guid Id, string Status, DateTimeOffset? DeletionDueAt);

/// <summary>
/// Lifecycle transitions of 05 «Жизненный цикл организации», shared by changeOrganizationLifecycle and the restore replay
/// (06 «Резервное копирование и восстановление»). The organization and policy tables belong to this module; other modules
/// change them only here.
/// </summary>
public static class OrganizationLifecycle
{
    /// <summary>After a restore no organization is deleted earlier than this (06, step 4).</summary>
    public static readonly TimeSpan RestoreDeletionGrace = TimeSpan.FromDays(7);

    /// <summary>Policy versions continue from the next epoch after a restore (external review F10).</summary>
    public const int PolicyEpoch = 10_000;

    /// <summary>The smallest multiple of the epoch greater than the highest stored version.</summary>
    public static int NextEpoch(int maxVersion) => (maxVersion / PolicyEpoch + 1) * PolicyEpoch;

    /// <summary>Every organization; only for components with the read-all scope (02 «Разделение клиентов»).</summary>
    public static async Task<IReadOnlyList<OrganizationState>> ListAsync(DbScope all, CancellationToken ct) =>
        await all.Db.Organizations.AsNoTracking().OrderBy(o => o.Id)
            .Select(o => new OrganizationState(o.Id, o.Status, o.DeletionDueAt)).ToListAsync(ct);

    /// <summary>The organization of the scope locked for a transition, or null when it does not exist.</summary>
    public static async Task<Organization?> LockAsync(DbScope scope, CancellationToken ct)
    {
        var id = scope.OrganizationId!.Value;
        return await scope.Db.Organizations.FromSqlInterpolated($"select * from organization where id = {id} for update")
            .SingleOrDefaultAsync(ct);
    }

    public static void Disable(Organization organization, DateTimeOffset at)
    {
        organization.Status = "disabled";
        organization.DisabledAt = at;
    }

    public static void Enable(Organization organization) => organization.Status = "active";

    public static void ScheduleDeletion(Organization organization, DateTimeOffset dueAt)
    {
        organization.Status = "deletion_scheduled";
        organization.DeletionDueAt = dueAt;
    }

    public static void CancelDeletion(Organization organization)
    {
        organization.Status = "disabled";
        organization.DeletionDueAt = null;
    }

    /// <summary>Replay of organization.disable: an active organization becomes disabled. False when it is not active.</summary>
    public static bool ReplayDisable(Organization organization, DateTimeOffset occurredAt)
    {
        if (organization.Status != "active")
        {
            return false;
        }
        Disable(organization, occurredAt);
        return true;
    }

    /// <summary>
    /// Replay of organization.schedule_deletion: deletion_scheduled with the date of the record, but not earlier than
    /// now + 7 days. False when the organization is already scheduled (the postponement step covers its date).
    /// </summary>
    public static bool ReplayScheduleDeletion(Organization organization, DateTimeOffset? recordedDueAt, DateTimeOffset now)
    {
        if (organization.Status == "deletion_scheduled")
        {
            return false;
        }
        var earliest = now + RestoreDeletionGrace;
        organization.DisabledAt ??= now;
        ScheduleDeletion(organization, recordedDueAt is { } due && due > earliest ? due : earliest);
        return true;
    }

    /// <summary>Replay of organization.cancel_deletion: a scheduled deletion is cancelled; the organization stays disabled.</summary>
    public static bool ReplayCancelDeletion(Organization organization)
    {
        if (organization.Status != "deletion_scheduled")
        {
            return false;
        }
        CancelDeletion(organization);
        return true;
    }

    /// <summary>Moves a scheduled deletion to now + 7 days at the earliest; returns the previous date when it moved.</summary>
    public static DateTimeOffset? PostponeDeletion(Organization organization, DateTimeOffset now)
    {
        var earliest = now + RestoreDeletionGrace;
        if (organization.Status != "deletion_scheduled" || organization.DeletionDueAt >= earliest)
        {
            return null;
        }
        var previous = organization.DeletionDueAt;
        organization.DeletionDueAt = earliest;
        return previous;
    }

    /// <summary>
    /// Moves the next policy version to the next epoch, so that a revision lost after the restore point never comes back
    /// with other content (06, step 5; F10). Lost revisions were numbered from the restored next version upwards, so the
    /// epoch is counted from the larger of it and the highest stored version: after an earlier restore the restored
    /// next version is itself an epoch, and revisions numbered from it may be the lost ones. The caller runs it once
    /// per restore point.
    /// </summary>
    public static int AdvancePolicyEpoch(Organization organization, int maxVersion)
    {
        organization.NextPolicyVersion = NextEpoch(Math.Max(maxVersion, organization.NextPolicyVersion));
        return organization.NextPolicyVersion;
    }

    /// <summary>The highest stored policy version of the scope's organization; 0 without revisions.</summary>
    public static async Task<int> MaxPolicyVersionAsync(DbScope scope, CancellationToken ct)
    {
        var id = scope.OrganizationId!.Value;
        return await scope.Db.PolicyRevisions.Where(p => p.OrganizationId == id).MaxAsync(p => (int?)p.Version, ct) ?? 0;
    }
}
