using Microsoft.EntityFrameworkCore;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;

namespace Sikkerheit.Host.Assessment;

/// <summary>
/// recalculate_policy (05 «Выбор текущего состояния», step 4): after a new policy revision the current projections of
/// the organization are evaluated again, 200 subjects per transaction. Every transaction holds the lease and the
/// tenant_connection row — the serialization point with the final transaction of a collection run.
/// </summary>
public sealed class RecalculatePolicyJob(DbScopes scopes, TimeProvider clock) : IJobHandler
{
    public const int BatchSize = 200;

    public string Type => "recalculate_policy";

    public async Task ExecuteAsync(JobLease lease, CancellationToken ct)
    {
        var org = lease.OrganizationId ?? throw new InvalidOperationException("recalculate_policy needs an organization");
        var after = Guid.Empty;
        while (true)
        {
            await using var scope = await scopes.OrganizationAsync(org, ct);
            if (!await lease.HoldAsync(scope, ct))
            {
                throw new JobLeaseLostException();
            }
            var organization = await scope.Db.Organizations.AsNoTracking().SingleOrDefaultAsync(o => o.Id == org, ct);
            await scope.Db.TenantConnections
                .FromSqlInterpolated($"select * from tenant_connection where organization_id = {org} for update").ToListAsync(ct);
            var subjects = organization is not { Status: "active" } ? [] : await scope.Db.Subjects
                .FromSqlInterpolated($"""
                    select * from subject
                    where organization_id = {org} and type = any({M365Evaluator.SubjectTypes}) and retired_at is null
                      and id > {after}
                    order by id limit {BatchSize}
                    """).ToListAsync(ct);
            if (subjects.Count == 0)
            {
                await lease.CompleteAsync(scope, ct);
                await scope.CommitAsync(ct);
                return;
            }
            // Always the newest revision: a later revision supersedes the one that queued this job.
            var policy = await scope.Db.PolicyRevisions.Where(p => p.OrganizationId == org)
                .OrderByDescending(p => p.Version).FirstAsync(ct);
            await M365Evaluator.RecalculateAsync(scope, subjects, policy, clock.GetUtcNow(), ct);
            await scope.CommitAsync(ct);
            after = subjects[^1].Id;
        }
    }
}
