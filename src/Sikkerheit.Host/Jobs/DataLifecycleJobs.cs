using Microsoft.EntityFrameworkCore;
using Npgsql;
using Sikkerheit.Host.Agents;
using Sikkerheit.Host.Assessment;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Exports;
using Sikkerheit.Host.M365;
using Sikkerheit.Host.Operations;
using Sikkerheit.Host.Organizations;
using Sikkerheit.Host.Reports;

namespace Sikkerheit.Host.Jobs;

/// <summary>
/// organization_delete (05 «Жизненный цикл организации»): when deletionDueAt has passed, the security log record comes
/// first, then the files under the organization prefix, the rows of every client table and a tombstone.
/// </summary>
public sealed class OrganizationDeleteJob(DbScopes scopes, IFileStore files, ISecurityLog securityLog, TimeProvider clock,
    ILogger<OrganizationDeleteJob> logger) : IJobHandler
{
    public string Type => "organization_delete";

    public async Task ExecuteAsync(JobLease lease, CancellationToken ct)
    {
        var org = lease.OrganizationId ?? throw new InvalidOperationException("organization_delete needs an organization");
        await using var scope = await scopes.OrganizationAsync(org, ct);
        if (!await lease.HoldAsync(scope, ct))
        {
            throw new JobLeaseLostException();
        }
        var organization = await OrganizationLifecycle.FindAsync(scope, forUpdate: true, ct);
        var now = clock.GetUtcNow();
        if (organization is { Status: "deletion_scheduled" } && organization.DeletionDueAt <= now)
        {
            // Without the record the deletion does not happen; after a restore the record deletes the organization again.
            await securityLog.AppendAsync(new SecurityLogRecord(Guid.CreateVersion7(), "organization.delete", org,
                "organization", org.ToString(), now, "job:" + lease.JobId, null), ct);
            await OrganizationDeletion.DeleteAsync(scope, files, now, lease.JobId, deleteFiles: true, ct);
            logger.LogWarning("Organization {OrganizationId} deleted after its deletion date", org);
        }
        await lease.CompleteAsync(scope, ct);
        await scope.CommitAsync(ct);
    }
}

/// <summary>
/// Removal of all data of one organization in its scope: files under its prefix, the rows of every client table and a
/// tombstone. Used by organization_delete and by the restore replay of organization.delete (06). Every module removes its
/// own rows; the calls follow the foreign keys.
/// </summary>
public static class OrganizationDeletion
{
    /// <param name="keepJobId">The running deletion job, which completes in the same transaction.</param>
    /// <param name="deleteFiles">False in a restore drill, where the production files may only be read.</param>
    public static async Task DeleteAsync(DbScope scope, IFileStore files, DateTimeOffset now, Guid? keepJobId,
        bool deleteFiles, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        if (deleteFiles)
        {
            foreach (var container in FileContainers.All)
            {
                await files.DeletePrefixAsync(container, FileContainers.OrganizationPrefix(org), ct);
            }
        }
        await AuditLog.DeleteOrganizationDataAsync(scope, ct);
        await ReportService.DeleteOrganizationDataAsync(scope, ct);
        await OrganizationExports.DeleteOrganizationDataAsync(scope, ct);
        await AssessmentData.DeleteOrganizationDataAsync(scope, ct);
        await AgentData.DeleteOrganizationDataAsync(scope, ct);
        await TenantConnections.DeleteOrganizationDataAsync(scope, ct);
        await Idempotency.DeleteOrganizationDataAsync(scope, ct);
        await OrganizationLifecycle.DeleteOrganizationDataAsync(scope, ct);
        await using var command = new NpgsqlCommand("""
            delete from job where organization_id = @org and id is distinct from @job and state <> 'running';
            insert into organization_tombstone (id, deleted_at) values (@org, @now) on conflict do nothing;
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("org", org);
        command.Parameters.AddWithValue("job", NpgsqlTypes.NpgsqlDbType.Uuid, (object?)keepJobId ?? DBNull.Value);
        command.Parameters.AddWithValue("now", now);
        await command.ExecuteNonQueryAsync(ct);
    }

    /// <summary>True when the organization was deleted (a tombstone exists).</summary>
    public static async Task<bool> TombstoneExistsAsync(DbScope platform, Guid organizationId, CancellationToken ct) =>
        await platform.Db.OrganizationTombstones.AnyAsync(t => t.Id == organizationId, ct);
}

/// <summary>
/// retention_purge (04 «Сроки хранения»): daily in the scope of each organization. Evidence older than 90 days is
/// replaced by the basis snapshot, then rows past their terms are deleted in the order of 04 and the counts are written
/// to the audit summary retention.purge_summary.
/// </summary>
public sealed class RetentionPurgeJob(DbScopes scopes, IFileStore files, TimeProvider clock) : IJobHandler
{
    public static readonly TimeSpan Evidence = TimeSpan.FromDays(90);
    public static readonly TimeSpan History = TimeSpan.FromDays(365);

    public string Type => "retention_purge";

    public async Task ExecuteAsync(JobLease lease, CancellationToken ct)
    {
        var org = lease.OrganizationId ?? throw new InvalidOperationException("retention_purge needs an organization");
        var now = clock.GetUtcNow();
        await using var scope = await scopes.OrganizationAsync(org, ct);
        if (!await lease.HoldAsync(scope, ct))
        {
            throw new JobLeaseLostException();
        }
        if (await OrganizationLifecycle.FindAsync(scope, forUpdate: false, ct) is null)
        {
            await lease.CompleteAsync(scope, ct);
            await scope.CommitAsync(ct);
            return;
        }
        var cuts = new RetentionCuts(now, now - Evidence, now - History);

        // Evidence past its term gives way to the basis snapshot before the observations go.
        var snapshotted = await AssessmentData.ExpireEvidenceAsync(scope, cuts, ct);
        // Every owner deletes its rows past their terms, table by table in the order of the registry, which respects the
        // foreign keys; runs that observations still refer to stay.
        var deleted = new Dictionary<string, int>
        {
            ["risk_decision"] = await AssessmentData.PurgeRiskDecisionsAsync(scope, cuts, ct),
            ["finding_event"] = await AssessmentData.PurgeFindingEventsAsync(scope, cuts, ct),
            ["assessment"] = await AssessmentData.PurgeAssessmentsAsync(scope, cuts, ct),
            ["finding"] = await AssessmentData.PurgeFindingsAsync(scope, cuts, ct),
            ["observation"] = await AssessmentData.PurgeObservationsAsync(scope, cuts, ct),
            ["collection_run"] = await CollectionRuns.PurgeAsync(scope, cuts, await AssessmentData.ObservedRunsAsync(scope, ct), ct),
            ["scan_batch"] = await AgentData.PurgeBatchesAsync(scope, cuts, await AssessmentData.ObservedBatchesAsync(scope, ct), ct),
            ["scan_request"] = await AgentData.PurgeRequestsAsync(scope, cuts, ct),
            ["subject"] = await AssessmentData.PurgeSubjectsAsync(scope, cuts, ct),
            ["device_presence"] = await AgentData.PurgePresenceAsync(scope, cuts, ct),
            ["device"] = await AgentData.PurgeDevicesAsync(scope, cuts, ct),
            ["revoked_installation"] = await AgentData.PurgeInstallationsAsync(scope, cuts, ct),
        };
        // Enrollments, sessions and old keys are not in the registry order: nothing refers to them but the devices above.
        await AgentData.PurgeCredentialsAsync(scope, cuts, ct);
        await Idempotency.PurgeAsync(scope, cuts, ct);
        await AuditLog.PurgeAsync(scope, cuts, ct);

        // Report files and rows after 12 months; export files after their 7 days.
        await ReportService.PurgeAsync(scope, files, cuts, ct);
        await OrganizationExports.ExpireAsync(scope, files, now, ct);

        AuditLog.System(scope, "retention.purge_summary", "organization", org.ToString(), "job:" + lease.JobId, new
        {
            deleted,
            snapshotted,
        });
        await scope.Db.SaveChangesAsync(ct);
        await lease.CompleteAsync(scope, ct);
        await scope.CommitAsync(ct);
    }
}

/// <summary>Cut-offs of one retention run (04 «Сроки хранения»): evidence after 90 days, history after 12 months.</summary>
public sealed record RetentionCuts(DateTimeOffset Now, DateTimeOffset Evidence, DateTimeOffset History);
