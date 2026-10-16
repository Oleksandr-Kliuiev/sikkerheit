using Microsoft.EntityFrameworkCore;
using Sikkerheit.Host.Data;

namespace Sikkerheit.Host.Assessment;

/// <summary>Subjects that leave their source together with the findings on them (05 «Таблица переходов finding»).</summary>
public static class SubjectRetirement
{
    /// <summary>
    /// The connection moved to another tenant: the tenant and the users of the previous one are retired in the scope, and
    /// their open M365 findings leave the queue (subject_retired, manual_action by the actor).
    /// </summary>
    public static async Task RetireTenantAsync(DbScope scope, Guid actorId, DateTimeOffset now, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        var subjects = await scope.Db.Subjects
            .Where(s => s.OrganizationId == org && (s.Type == "tenant" || s.Type == "user") && s.RetiredAt == null)
            .ToListAsync(ct);
        var findings = await scope.Db.Findings.Where(f => f.OrganizationId == org && f.CheckId.StartsWith("M365-")).ToListAsync(ct);
        var machine = new FindingMachine(scope.Db, org, now);
        foreach (var subject in subjects)
        {
            subject.RetiredAt = now;
            foreach (var finding in findings.Where(f => f.SubjectId == subject.Id))
            {
                machine.Retire(finding, "manual_action", actorId);
            }
        }
    }
}
