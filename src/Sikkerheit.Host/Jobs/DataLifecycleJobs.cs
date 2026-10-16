using Microsoft.EntityFrameworkCore;
using Npgsql;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Operations;

namespace Sikkerheit.Host.Jobs;

/// <summary>
/// organization_delete (05 «Жизненный цикл организации»): when deletionDueAt has passed, the security log record comes
/// first, then the files under the organization prefix, the rows of every client table and a tombstone.
/// </summary>
public sealed class OrganizationDeleteJob(DbScopes scopes, IFileStore files, ISecurityLog securityLog, TimeProvider clock,
    ILogger<OrganizationDeleteJob> logger) : IJobHandler
{
    /// <summary>Client tables in an order that respects the foreign keys.</summary>
    private static readonly string[] Tables =
    [
        "audit_event", "report", "organization_export", "risk_decision", "finding_event", "finding", "assessment",
        "observation", "subject", "collection_run", "idempotency_record", "tenant_connection", "policy_revision",
    ];

    public string Type => "organization_delete";

    public async Task ExecuteAsync(JobLease lease, CancellationToken ct)
    {
        var org = lease.OrganizationId ?? throw new InvalidOperationException("organization_delete needs an organization");
        await using var scope = await scopes.OrganizationAsync(org, ct);
        if (!await lease.HoldAsync(scope, ct))
        {
            throw new JobLeaseLostException();
        }
        var organization = await scope.Db.Organizations
            .FromSqlInterpolated($"select * from organization where id = {org} for update").SingleOrDefaultAsync(ct);
        var now = clock.GetUtcNow();
        if (organization is { Status: "deletion_scheduled" } && organization.DeletionDueAt <= now)
        {
            // Without the record the deletion does not happen; after a restore the record deletes the organization again.
            await securityLog.AppendAsync(new SecurityLogRecord(Guid.CreateVersion7(), "organization.delete", org,
                "organization", org.ToString(), now, "job:" + lease.JobId, null), ct);
            foreach (var container in FileContainers.All)
            {
                await files.DeletePrefixAsync(container, FileContainers.OrganizationPrefix(org), ct);
            }
            foreach (var table in Tables)
            {
                await using var delete = new NpgsqlCommand($"delete from {table} where organization_id = @org",
                    scope.Connection, scope.Transaction);
                delete.Parameters.AddWithValue("org", org);
                await delete.ExecuteNonQueryAsync(ct);
            }
            await using (var command = new NpgsqlCommand("""
                delete from organization where id = @org;
                delete from job where organization_id = @org and id <> @job and state <> 'running';
                insert into organization_tombstone (id, deleted_at) values (@org, @now) on conflict do nothing;
                """, scope.Connection, scope.Transaction))
            {
                command.Parameters.AddWithValue("org", org);
                command.Parameters.AddWithValue("job", lease.JobId);
                command.Parameters.AddWithValue("now", now);
                await command.ExecuteNonQueryAsync(ct);
            }
            logger.LogWarning("Organization {OrganizationId} deleted after its deletion date", org);
        }
        await lease.CompleteAsync(scope, ct);
        await scope.CommitAsync(ct);
    }
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
        if (!await scope.Db.Organizations.AnyAsync(o => o.Id == org, ct))
        {
            await lease.CompleteAsync(scope, ct);
            await scope.CommitAsync(ct);
            return;
        }
        async Task<int> RunAsync(string sql)
        {
            await using var command = new NpgsqlCommand(sql, scope.Connection, scope.Transaction);
            command.Parameters.AddWithValue("org", org);
            command.Parameters.AddWithValue("now", now);
            command.Parameters.AddWithValue("evidence_cut", now - Evidence);
            command.Parameters.AddWithValue("history_cut", now - History);
            return await command.ExecuteNonQueryAsync(ct);
        }

        // Decisions of closed findings older than 12 months; active decisions stay with their events.
        await RunAsync("""
            delete from risk_decision d using finding f
            where d.organization_id = @org and f.organization_id = d.organization_id and f.id = d.finding_id
              and d.decided_at < @history_cut and f.technical_state = 'resolved'
            """);
        var findingEvents = await RunAsync("""
            delete from finding_event e
            where e.organization_id = @org and e.occurred_at < @history_cut
              and not exists (select 1 from risk_decision d where d.organization_id = e.organization_id and d.finding_event_id = e.id)
              and e.id not in (
                  select distinct on (x.finding_id) x.id from finding_event x
                  join finding f on f.organization_id = x.organization_id and f.id = x.finding_id and f.technical_state = 'open'
                  where x.organization_id = @org and x.event_type in ('opened', 'reopened')
                  order by x.finding_id, x.occurred_at desc, x.id desc)
            """);
        var snapshotted = await RunAsync("""
            update assessment a set observation_id = null, evidence_availability = 'expired'
            from observation o
            where a.organization_id = @org and o.organization_id = a.organization_id and o.id = a.observation_id
              and o.observed_at < @evidence_cut
            """);
        var assessments = await RunAsync("""
            delete from assessment a
            where a.organization_id = @org and a.evaluated_at < @history_cut
              and not exists (select 1 from finding_event e where e.organization_id = a.organization_id and e.assessment_id = a.id)
              and not exists (select 1 from finding f where f.organization_id = a.organization_id and f.latest_assessment_id = a.id)
            """);
        var findings = await RunAsync("""
            delete from finding f
            where f.organization_id = @org and f.technical_state = 'resolved'
              and not exists (select 1 from finding_event e where e.organization_id = f.organization_id and e.finding_id = f.id)
              and not exists (select 1 from risk_decision d where d.organization_id = f.organization_id and d.finding_id = f.id)
            """);
        var observations = await RunAsync("""
            delete from observation o
            where o.organization_id = @org and o.observed_at < @evidence_cut
              and not exists (select 1 from assessment a where a.organization_id = o.organization_id and a.observation_id = o.id)
            """);
        var runs = await RunAsync("""
            delete from collection_run r
            where r.organization_id = @org and r.queued_at < @evidence_cut and r.state not in ('queued', 'running')
              and not exists (select 1 from observation o where o.organization_id = r.organization_id and o.collection_run_id = r.id)
            """);
        var subjects = await RunAsync("""
            delete from subject s
            where s.organization_id = @org and s.retired_at < @history_cut
              and not exists (select 1 from finding f where f.organization_id = s.organization_id and f.subject_id = s.id)
              and not exists (select 1 from assessment a where a.organization_id = s.organization_id and a.subject_id = s.id)
              and not exists (select 1 from observation o where o.organization_id = s.organization_id and o.subject_id = s.id)
            """);
        await RunAsync("delete from idempotency_record where organization_id = @org and created_at < @now - interval '7 days'");
        await RunAsync("delete from audit_event where organization_id = @org and occurred_at < @history_cut");

        // Report files and rows after 12 months; export files after their 7 days.
        var oldReports = await scope.Db.Reports.Where(r => r.OrganizationId == org && r.CreatedAt < now - History).ToListAsync(ct);
        foreach (var report in oldReports.Where(r => r.BlobKey is not null))
        {
            await files.DeleteAsync(FileContainers.Reports, report.BlobKey!, ct);
        }
        scope.Db.Reports.RemoveRange(oldReports);
        var expired = await scope.Db.OrganizationExports
            .Where(e => e.OrganizationId == org && e.State == "ready" && e.ExpiresAt <= now).ToListAsync(ct);
        foreach (var export in expired)
        {
            await files.DeleteAsync(FileContainers.Exports, export.BlobKey!, ct);
            export.State = "expired";
            export.BlobKey = null;
        }

        AuditLog.System(scope, "retention.purge_summary", "organization", org.ToString(), "job:" + lease.JobId, new
        {
            deleted = new Dictionary<string, int>
            {
                ["finding_event"] = findingEvents, ["assessment"] = assessments, ["finding"] = findings,
                ["observation"] = observations, ["collection_run"] = runs, ["scan_batch"] = 0, ["scan_request"] = 0,
                ["subject"] = subjects, ["device_presence"] = 0, ["device"] = 0, ["revoked_installation"] = 0,
            },
            snapshotted,
        });
        await scope.Db.SaveChangesAsync(ct);
        await lease.CompleteAsync(scope, ct);
        await scope.CommitAsync(ct);
    }
}
