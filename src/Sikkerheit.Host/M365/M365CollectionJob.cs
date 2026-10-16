using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Sikkerheit.Host.Assessment;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;
using Sikkerheit.Host.Operations;

namespace Sikkerheit.Host.M365;

/// <summary>
/// Job m365_collect: collects outside the database, then writes everything in one final transaction that locks the
/// organization and the connection and checks that both are still active and the run is still running (05).
/// </summary>
public sealed class M365CollectionJob(DbScopes scopes, M365Collector collector, TimeProvider clock,
    ILogger<M365CollectionJob> logger) : IJobHandler
{
    /// <summary>Far beyond the 30-minute run timeout and the job retries: such a run has lost its job.</summary>
    public static readonly TimeSpan AbandonedAfter = TimeSpan.FromHours(6);

    public string Type => "m365_collect";

    public async Task ExecuteAsync(JobLease lease, CancellationToken ct)
    {
        var org = lease.OrganizationId!.Value;
        var runId = lease.InputId is null ? await ScheduleRunAsync(lease, org, ct) : Guid.Parse(lease.InputId);
        if (runId == Guid.Empty)
        {
            return;
        }
        Guid tenant;
        PolicyRevision policy;
        HashSet<Guid> previouslyPrivileged;
        await using (var start = await scopes.OrganizationAsync(org, ct))
        {
            if (!await lease.HoldAsync(start, ct))
            {
                throw new JobLeaseLostException();
            }
            var run = await start.Db.CollectionRuns.SingleOrDefaultAsync(r => r.OrganizationId == org && r.Id == runId, ct);
            var organization = await start.Db.Organizations.SingleOrDefaultAsync(o => o.Id == org, ct);
            var connection = await start.Db.TenantConnections.SingleOrDefaultAsync(c => c.OrganizationId == org, ct);
            if (run is null || run.State is not ("queued" or "running"))
            {
                await lease.CompleteAsync(start, ct);
                await start.CommitAsync(ct);
                return;
            }
            if (organization?.Status != "active" || connection?.Status != "active" || connection.EntraTenantId is null)
            {
                Cancel(run, clock.GetUtcNow());
                await lease.CompleteAsync(start, ct);
                await start.CommitAsync(ct);
                return;
            }
            tenant = connection.EntraTenantId.Value;
            policy = await start.Db.PolicyRevisions.Where(p => p.OrganizationId == org)
                .OrderByDescending(p => p.Version).FirstAsync(ct);
            run.State = "running";
            run.StartedAt = clock.GetUtcNow();
            run.PolicyVersion = policy.Version;
            previouslyPrivileged = await M365Evaluator.PreviouslyPrivilegedAsync(start, ct);
            await start.CommitAsync(ct);
        }

        var configuration = JsonDocument.Parse(policy.Configuration).RootElement;
        var outcome = await collector.CollectAsync(tenant, CollectorPolicy.From(configuration), previouslyPrivileged, ct);

        await using var final = await scopes.OrganizationAsync(org, ct);
        if (!await lease.HoldAsync(final, ct))
        {
            throw new JobLeaseLostException();
        }
        var now = clock.GetUtcNow();
        var lockedOrganization = await final.Db.Organizations
            .FromSqlInterpolated($"select * from organization where id = {org} for update").SingleAsync(ct);
        var lockedConnection = await final.Db.TenantConnections
            .FromSqlInterpolated($"select * from tenant_connection where organization_id = {org} for update").SingleAsync(ct);
        var current = await final.Db.CollectionRuns.SingleAsync(r => r.OrganizationId == org && r.Id == runId, ct);
        if (current.State != "running" || lockedOrganization.Status != "active" || lockedConnection.Status != "active"
            || lockedConnection.EntraTenantId != tenant)
        {
            if (current.State == "running")
            {
                Cancel(current, now);
            }
        }
        else if (outcome.State == "failed")
        {
            current.State = "failed";
            current.FailureCode = outcome.FailureCode;
            current.CompletedAt = now;
            current.Capabilities = M365Evaluator.Capabilities(outcome.Modules);
            lockedConnection.LastCollectionState = "failed";
            // Nothing is evaluated, so open findings stay open; the audit and the error log raise the RB-01 alert (06).
            AuditLog.System(final, outcome.FailureCode == "tenant_mismatch" ? "m365.tenant_mismatch" : "m365.collection_failed",
                "collection_run", runId.ToString(), "job:" + lease.JobId);
            if (outcome.FailureCode is "consent_missing" or "tenant_mismatch" or "credential_error")
            {
                logger.LogError("Microsoft 365 collection of organization {OrganizationId} failed: {FailureCode} (RB-01)",
                    org, outcome.FailureCode);
            }
            else
            {
                logger.LogWarning("Microsoft 365 collection of organization {OrganizationId} failed: {FailureCode}", org,
                    outcome.FailureCode);
            }
        }
        else
        {
            // The projection is evaluated by the revision in effect now; the run keeps the revision it started with.
            var effective = await final.Db.PolicyRevisions.Where(p => p.OrganizationId == org)
                .OrderByDescending(p => p.Version).FirstAsync(ct);
            await M365Evaluator.WriteAsync(final, current, tenant, outcome, effective, policy.Version, now, ct);
            current.State = outcome.State;
            current.CompletedAt = now;
            current.UsersComplete = outcome.UsersComplete;
            current.EntraP1 = outcome.EntraP1;
            current.Capabilities = M365Evaluator.Capabilities(outcome.Modules);
            lockedConnection.LastCollectedAt = now;
            lockedConnection.LastCollectionState = outcome.State;
            lockedConnection.EntraP1 = outcome.EntraP1 ?? lockedConnection.EntraP1;
            lockedConnection.Capabilities = current.Capabilities;
            lockedConnection.TenantDisplayName = outcome.TenantDisplayName ?? lockedConnection.TenantDisplayName;
            lockedConnection.PrimaryDomain = outcome.PrimaryDomain ?? lockedConnection.PrimaryDomain;
        }
        await lease.CompleteAsync(final, ct);
        await final.CommitAsync(ct);
    }

    /// <summary>A periodic job (periodKey = local date) creates the scheduled run unless one is open.</summary>
    private async Task<Guid> ScheduleRunAsync(JobLease lease, Guid org, CancellationToken ct)
    {
        await using var scope = await scopes.OrganizationAsync(org, ct);
        if (!await lease.HoldAsync(scope, ct))
        {
            throw new JobLeaseLostException();
        }
        var organization = await scope.Db.Organizations.SingleOrDefaultAsync(o => o.Id == org, ct);
        var connection = await scope.Db.TenantConnections.SingleOrDefaultAsync(c => c.OrganizationId == org, ct);
        if (organization?.Status != "active" || connection?.Status != "active")
        {
            await lease.CompleteAsync(scope, ct);
            await scope.CommitAsync(ct);
            return Guid.Empty;
        }
        var now = clock.GetUtcNow();
        // An open run already has its own job: the scheduled request joins it and does not collect twice (05).
        // A run left open far beyond the run timeout lost its job; it fails with run_timeout and frees the slot.
        var open = await scope.Db.CollectionRuns
            .SingleOrDefaultAsync(r => r.OrganizationId == org && (r.State == "queued" || r.State == "running"), ct);
        // The run of this very job (its id is the job id): a repeated capture of the job continues it.
        if (open is not null && open.Id == lease.JobId)
        {
            await scope.CommitAsync(ct);
            return open.Id;
        }
        if (open is not null && (open.StartedAt ?? open.QueuedAt) > now - AbandonedAfter)
        {
            await lease.CompleteAsync(scope, ct);
            await scope.CommitAsync(ct);
            return Guid.Empty;
        }
        if (open is not null)
        {
            open.State = "failed";
            open.FailureCode = "run_timeout";
            open.CompletedAt = now;
            await scope.Db.SaveChangesAsync(ct);
        }
        var run = new CollectionRun
        {
            OrganizationId = org, Id = lease.JobId, Trigger = "scheduled", State = "queued", QueuedAt = now,
            Capabilities = "[]",
        };
        scope.Db.CollectionRuns.Add(run);
        await scope.CommitAsync(ct);
        return run.Id;
    }

    private static void Cancel(CollectionRun run, DateTimeOffset now)
    {
        run.State = "failed";
        run.FailureCode = "cancelled";
        run.CompletedAt = now;
    }
}
