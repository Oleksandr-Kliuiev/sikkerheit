using Microsoft.EntityFrameworkCore;
using Npgsql;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;

namespace Sikkerheit.Host.Agents;

/// <summary>
/// Operations on all data of an organization in the tables of the agent module — enrollment_key, enrollment, device,
/// device_presence, revoked_installation, scan_batch, scan_request, and the platform rows of its sessions: deletion, the
/// terms of 04 «Сроки хранения» and the organization export.
/// </summary>
public static class AgentData
{
    private static readonly (string Table, string Order)[] ExportTables =
    [
        ("enrollment_key", "created_at, id"), ("device", "enrolled_at, id"), ("device_presence", "device_id, day"),
        ("revoked_installation", "revoked_at, installation_id"), ("enrollment", "created_at, id"),
        ("scan_batch", "completed_at, id"), ("scan_request", "created_at, id"),
    ];

    /// <summary>Removes the rows of the scope's organization, in the order of the foreign keys; sessions go with them.</summary>
    public static async Task DeleteOrganizationDataAsync(DbScope scope, CancellationToken ct)
    {
        await using (var sessions = new NpgsqlCommand("delete from agent_session where organization_id = @org", scope.Connection, scope.Transaction))
        {
            sessions.Parameters.AddWithValue("org", scope.OrganizationId!.Value);
            await sessions.ExecuteNonQueryAsync(ct);
        }
        await OrganizationRows.DeleteAsync(scope,
            ["device_presence", "scan_request", "scan_batch", "enrollment", "revoked_installation", "device", "enrollment_key"], ct);
    }

    public static Task ExportAsync(DbScope scope, TableRowsWriter write, CancellationToken ct) =>
        OrganizationRows.ExportAsync(scope, ExportTables, write, ct);

    // The terms of 04 «Сроки хранения», one method per table so that the job can run them in the order of the registry.

    /// <summary>Batches older than 90 days that no observation refers to any more.</summary>
    public static Task<int> PurgeBatchesAsync(DbScope scope, RetentionCuts cuts, IReadOnlyList<Guid> observedBatches, CancellationToken ct) =>
        RunAsync(scope, cuts, """
            delete from scan_batch b
            where b.organization_id = @org and b.received_at < @evidence_cut and not (b.id = any(@observed))
            """, ct, observedBatches);

    public static Task<int> PurgeRequestsAsync(DbScope scope, RetentionCuts cuts, CancellationToken ct) => RunAsync(scope, cuts,
        "delete from scan_request where organization_id = @org and created_at < @evidence_cut", ct);

    /// <summary>Days of presence older than 12 months.</summary>
    public static Task<int> PurgePresenceAsync(DbScope scope, RetentionCuts cuts, CancellationToken ct) => RunAsync(scope, cuts, """
        delete from device_presence where organization_id = @org and day < (@history_cut at time zone 'UTC')::date
        """, ct);

    /// <summary>Devices revoked more than 12 months ago that no batch, request, enrollment or presence refers to.</summary>
    public static Task<int> PurgeDevicesAsync(DbScope scope, RetentionCuts cuts, CancellationToken ct) => RunAsync(scope, cuts, """
        delete from device d
        where d.organization_id = @org and d.status = 'revoked' and d.revoked_at < @history_cut
          and not exists (select 1 from scan_batch b where b.organization_id = d.organization_id and b.device_id = d.id)
          and not exists (select 1 from scan_request r where r.organization_id = d.organization_id and r.device_id = d.id)
          and not exists (select 1 from enrollment e where e.organization_id = d.organization_id and e.device_id = d.id)
          and not exists (select 1 from device_presence p where p.organization_id = d.organization_id and p.device_id = d.id)
        """, ct);

    /// <summary>
    /// Revocations 24 months old, but not while the organization has an active enrollment key: the offline agent of a revoked
    /// device could register again with the key it keeps (04 «Отзыв и повторная регистрация»).
    /// </summary>
    public static Task<int> PurgeInstallationsAsync(DbScope scope, RetentionCuts cuts, CancellationToken ct) => RunAsync(scope, cuts, """
        delete from revoked_installation
        where organization_id = @org and revoked_at < @now - interval '24 months'
          and not exists (select 1 from enrollment_key k where k.organization_id = @org and k.revoked_at is null)
        """, ct);

    /// <summary>Enrollments 30 days after their window, sessions 30 days after expiry, keys 12 months after the revocation.</summary>
    public static async Task<int> PurgeCredentialsAsync(DbScope scope, RetentionCuts cuts, CancellationToken ct) =>
        await RunAsync(scope, cuts, "delete from enrollment where organization_id = @org and created_at < @now - interval '31 days'", ct)
        + await RunAsync(scope, cuts, "delete from agent_session where organization_id = @org and expires_at < @now - interval '30 days'", ct)
        + await RunAsync(scope, cuts, """
            delete from enrollment_key k
            where k.organization_id = @org and k.revoked_at < @history_cut
              and not exists (select 1 from enrollment e where e.organization_id = k.organization_id and e.enrollment_key_id = k.id)
            """, ct);

    /// <summary>Spent nonces a day after their expiry and sessions 30 days after theirs (platform rows).</summary>
    public static async Task PurgePlatformAsync(DbScope platform, DateTimeOffset now, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            delete from agent_challenge where expires_at < @now - interval '1 day';
            delete from agent_session where expires_at < @now - interval '30 days';
            """, platform.Connection, platform.Transaction);
        command.Parameters.AddWithValue("now", now);
        await command.ExecuteNonQueryAsync(ct);
    }

    private static async Task<int> RunAsync(DbScope scope, RetentionCuts cuts, string sql, CancellationToken ct,
        IReadOnlyList<Guid>? observed = null)
    {
        await using var command = new NpgsqlCommand(sql, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("org", scope.OrganizationId!.Value);
        command.Parameters.AddWithValue("now", cuts.Now);
        command.Parameters.AddWithValue("evidence_cut", cuts.Evidence);
        command.Parameters.AddWithValue("history_cut", cuts.History);
        if (observed is not null)
        {
            command.Parameters.AddWithValue("observed", observed.ToArray());
        }
        return await command.ExecuteNonQueryAsync(ct);
    }
}

/// <summary>scan_request_expiry (hourly): requests for a rescan past their day become expired.</summary>
public sealed class ScanRequestExpiryJob(DbScopes scopes, TimeProvider clock) : IJobHandler
{
    public string Type => "scan_request_expiry";

    public async Task ExecuteAsync(JobLease lease, CancellationToken ct)
    {
        var org = lease.OrganizationId ?? throw new InvalidOperationException("scan_request_expiry needs an organization");
        var now = clock.GetUtcNow();
        await using var scope = await scopes.OrganizationAsync(org, ct);
        if (!await lease.HoldAsync(scope, ct))
        {
            throw new JobLeaseLostException();
        }
        await scope.Db.ScanRequests.Where(r => r.OrganizationId == org && (r.State == "requested" || r.State == "delivered") && r.ExpiresAt <= now)
            .ExecuteUpdateAsync(u => u.SetProperty(r => r.State, "expired"), ct);
        await Devices.RecoverIdentitiesAsync(scope, now, ct);
        await lease.CompleteAsync(scope, ct);
        await scope.CommitAsync(ct);
    }
}

/// <summary>The routes of the agent module: the agent API on its hostname and the portal operations of an organization.</summary>
public static class AgentEndpoints
{
    public static void Map(WebApplication app)
    {
        var agent = app.MapGroup("/api/v1/agent");
        AgentEnrollment.Map(agent);
        AgentRequests.Map(agent);
        var org = app.MapGroup("/api/v1/organizations/{organizationId:guid}");
        EnrollmentKeys.Map(org);
        DeviceEndpoints.Map(org);
    }
}
