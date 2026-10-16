using Microsoft.EntityFrameworkCore;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;
using Sikkerheit.Host.M365;
using Sikkerheit.Host.Organizations;

namespace Sikkerheit.Host.Assessment;

/// <summary>
/// recalculate_policy (05 «Выбор текущего состояния», step 4): after a new policy revision the current projections of
/// the organization are evaluated again, 200 subjects per transaction. Every transaction holds the lease and the
/// tenant_connection row — the serialization point with the final transaction of a collection run.
/// </summary>
public sealed class RecalculatePolicyJob(DbScopes scopes, TimeProvider clock, IConfiguration configuration) : IJobHandler
{
    /// <summary>Subjects per transaction (05: 200); a test lowers it to see the lease checked between batches.</summary>
    private readonly int _batchSize = Math.Clamp(configuration.GetValue("Jobs:RecalculateBatchSize", 200), 1, 200);

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
            var organization = await OrganizationLifecycle.FindAsync(scope, forUpdate: false, ct);
            await TenantConnections.LockAsync(scope, ct);
            var subjects = organization is not { Status: "active" } ? [] : await scope.Db.Subjects
                .FromSqlInterpolated($"""
                    select * from subject
                    where organization_id = {org} and type = any({M365Evaluator.SubjectTypes}) and retired_at is null
                      and id > {after}
                    order by id limit {_batchSize}
                    """).ToListAsync(ct);
            if (subjects.Count == 0)
            {
                await lease.CompleteAsync(scope, ct);
                await scope.CommitAsync(ct);
                return;
            }
            // Always the newest revision: a later revision supersedes the one that queued this job.
            var policy = await Policies.CurrentAsync(scope, ct)
                ?? throw new InvalidOperationException("Organization has no policy revision");
            await M365Evaluator.RecalculateAsync(scope, subjects, policy, clock.GetUtcNow(), ct);
            await scope.CommitAsync(ct);
            after = subjects[^1].Id;
        }
    }
}
