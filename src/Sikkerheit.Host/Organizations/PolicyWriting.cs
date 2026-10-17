using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;
using Sikkerheit.Host.Operations;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Organizations;

public static class PolicyWriting
{
    /// <summary>Caller locks the active organization row. Every writer uses its version counter, audit and queue.</summary>
    public static async Task<PolicyRevision> CreateAsync(DbScope scope, Organization organization, string ifMatch,
        JsonElement configuration, Actor actor, string correlationId, DateTimeOffset now, CancellationToken ct)
    {
        PolicyRules.Validate(configuration);
        var current = await scope.Db.PolicyRevisions.Where(p => p.OrganizationId == organization.Id).MaxAsync(p => p.Version, ct);
        PolicyTemplateStore.RequireVersion(ifMatch, current);
        var revision = new PolicyRevision
        {
            OrganizationId = organization.Id, Version = organization.NextPolicyVersion, EffectiveFrom = now,
            CreatedAt = now, CreatedBy = actor.EntraUserId, Configuration = configuration.GetRawText(),
        };
        organization.NextPolicyVersion++;
        scope.Db.PolicyRevisions.Add(revision);
        await JobQueue.EnqueueAsync(scope, "recalculate_policy", organization.Id,
            "policy:" + revision.Version.ToString(CultureInfo.InvariantCulture), null, now, ct);
        AuditLog.Staff(scope, actor, "policy.revision_create", "policy_revision",
            revision.Version.ToString(CultureInfo.InvariantCulture), correlationId);
        return revision;
    }
}
