using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;
using Sikkerheit.Host.Operations;
using Sikkerheit.Host.Organizations;

namespace Sikkerheit.Host.Agents;

/// <summary>
/// agent_health_check (daily, per organization): the signals of the device table of 06 «Наблюдаемость и оповещения» that
/// are conditions on the fleet rather than on one request. A condition that holds is logged as an error — the alert of
/// Azure Monitor on errors of the service picks it up — with the runbook that answers it. No computer name goes into the log.
/// </summary>
public sealed class AgentHealthJob(DbScopes scopes, AgentOptions options, TimeProvider clock, ILogger<AgentHealthJob> logger) : IJobHandler
{
    public static readonly TimeSpan SilentAfter = TimeSpan.FromHours(72);
    public static readonly TimeSpan NewKeyGrace = TimeSpan.FromDays(14);

    public string Type => "agent_health_check";

    public async Task ExecuteAsync(JobLease lease, CancellationToken ct)
    {
        var org = lease.OrganizationId ?? throw new InvalidOperationException("agent_health_check needs an organization");
        var now = clock.GetUtcNow();
        await using var scope = await scopes.OrganizationAsync(org, ct);
        if (!await lease.HoldAsync(scope, ct))
        {
            throw new JobLeaseLostException();
        }
        if (await OrganizationLifecycle.FindAsync(scope, forUpdate: false, ct) is { Status: "active" })
        {
            await CheckAsync(scope, org, now, ct);
        }
        await lease.CompleteAsync(scope, ct);
        await scope.CommitAsync(ct);
    }

    private async Task CheckAsync(DbScope scope, Guid org, DateTimeOffset now, CancellationToken ct)
    {
        var devices = await scope.Db.Devices.AsNoTracking().Where(d => d.OrganizationId == org && d.Status == "active").ToListAsync(ct);
        var live = devices.Where(d => !Devices.IsDormant(d, now)).ToList();

        // RB-12: devices silent for 72 hours — at least 3 and more than 10% of the devices that are not dormant.
        var silent = live.Count(d => (d.LastSeenAt ?? d.EnrolledAt) < now - SilentAfter);
        if (silent >= 3 && silent * 10 > live.Count)
        {
            logger.LogError("Alert RB-12: {Silent} of {Live} devices of organization {OrganizationId} have not checked in for 72 hours",
                silent, live.Count, org);
        }
        var dropped = devices.Count(d => Counter(d.Telemetry, "droppedBatchCount") > 0);
        if (dropped > 0)
        {
            logger.LogError("Alert RB-12: {Count} devices of organization {OrganizationId} dropped batches from the buffer", dropped, org);
        }
        // RB-11: any identity conflict, and a device that resyncs its sequence on 2 of the last 3 days (a possible exact clone).
        var conflicts = devices.Count(d => d.IdentityState == "identity_conflict");
        if (conflicts > 0)
        {
            logger.LogError("Alert RB-11: {Count} devices of organization {OrganizationId} are in identity conflict", conflicts, org);
        }
        var resyncs = await AuditLog.TargetsWithEventsOnDaysAsync(scope, "device.sequence_resync", now.AddDays(-3), 2, ct);
        if (resyncs.Count > 0)
        {
            logger.LogError("Alert RB-11: {Count} devices of organization {OrganizationId} resync the sequence on 2 of the last 3 days",
                resyncs.Count, org);
        }
        // RB-08: agents below the minimum version or with a rejected configuration, restarts of the service.
        var below = devices.Count(d => d.AgentVersion is { } v && AgentVersions.Compare(v, options.MinimumAgentVersion) < 0);
        var rejected = devices.Count(d => Flag(d.Telemetry, "configRejected"));
        var restarting = devices.Count(d => Counter(d.Telemetry, "serviceStarts") > 3);
        if (below + rejected + restarting > 0)
        {
            logger.LogError("Alert RB-08: in organization {OrganizationId} {Below} agents are below the minimum version, {Rejected} reject "
                            + "the configuration, {Restarting} restart often", org, below, rejected, restarting);
        }
        // RB-10: more than half of the active devices are new in a day (at least 10), except for a key younger than 14 days.
        var keys = await scope.Db.EnrollmentKeys.AsNoTracking().Where(k => k.OrganizationId == org && k.CreatedAt <= now - NewKeyGrace)
            .Select(k => k.Id).ToListAsync(ct);
        var fresh = devices.Count(d => d.EnrolledAt > now.AddDays(-1) && d.EnrollmentKeyId is { } key && keys.Contains(key));
        if (fresh >= 10 && fresh * 2 > devices.Count)
        {
            logger.LogError("Alert RB-10: {Fresh} new devices of {Total} in organization {OrganizationId} registered in a day",
                fresh, devices.Count, org);
        }
    }

    private static long Counter(string telemetry, string name)
    {
        using var document = JsonDocument.Parse(telemetry);
        return document.RootElement.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number ? value.GetInt64() : 0;
    }

    private static bool Flag(string telemetry, string name)
    {
        using var document = JsonDocument.Parse(telemetry);
        return document.RootElement.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.True;
    }
}
