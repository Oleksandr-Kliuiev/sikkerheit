using Microsoft.EntityFrameworkCore;
using Sikkerheit.Host.Agents;
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
                await scope.CommitAsync(ct);
                break;
            }
            // Always the newest revision: a later revision supersedes the one that queued this job.
            var policy = await Policies.CurrentAsync(scope, ct)
                ?? throw new InvalidOperationException("Organization has no policy revision");
            await M365Evaluator.RecalculateAsync(scope, subjects, policy, clock.GetUtcNow(), ct);
            await scope.CommitAsync(ct);
            after = subjects[^1].Id;
        }
        await RecalculateDevicesAsync(org, lease, ct);
        await using var done = await scopes.OrganizationAsync(org, ct);
        if (!await lease.HoldAsync(done, ct))
        {
            throw new JobLeaseLostException();
        }
        await lease.CompleteAsync(done, ct);
        await done.CommitAsync(ct);
    }

    /// <summary>
    /// The devices of the organization, one transaction each: it holds the lease and the row of the device, the same
    /// serialization point as the intake of a batch, so the job and a batch of one device never write findings together.
    /// </summary>
    private async Task RecalculateDevicesAsync(Guid org, JobLease lease, CancellationToken ct)
    {
        List<Guid> ids;
        await using (var list = await scopes.OrganizationAsync(org, ct))
        {
            ids = (await Devices.ActiveAsync(list, org, ct)).Where(d => d.ProjectionSequence is not null).Select(d => d.Id).ToList();
        }
        foreach (var id in ids)
        {
            await using var scope = await scopes.OrganizationAsync(org, ct);
            if (!await lease.HoldAsync(scope, ct))
            {
                throw new JobLeaseLostException();
            }
            var organization = await OrganizationLifecycle.FindAsync(scope, forUpdate: false, ct);
            if (organization is not { Status: "active" } || await Devices.LockAsync(scope, id, ct) is not { Status: "active" } device)
            {
                continue;
            }
            var policy = await Policies.CurrentAsync(scope, ct) ?? throw new InvalidOperationException("Organization has no policy revision");
            var catalog = await ReleaseCatalogStore.ViewAsync(scope, ct);
            await WindowsEvaluator.RecalculateAsync(scope, device, policy, catalog, clock.GetUtcNow(), ct);
            await scope.CommitAsync(ct);
        }
    }
}
