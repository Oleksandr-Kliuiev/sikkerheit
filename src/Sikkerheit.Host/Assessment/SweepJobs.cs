using Microsoft.EntityFrameworkCore;
using Sikkerheit.Host.Agents;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;
using Sikkerheit.Host.Organizations;

namespace Sikkerheit.Host.Assessment;

/// <summary>freshness_sweep: an open fresh fail that aged past the freshness window becomes stale (quality_changed).</summary>
public sealed class FreshnessSweepJob(DbScopes scopes, TimeProvider clock) : IJobHandler
{
    public string Type => "freshness_sweep";

    public async Task ExecuteAsync(JobLease lease, CancellationToken ct)
    {
        var org = lease.OrganizationId!.Value;
        var now = clock.GetUtcNow();
        await using var scope = await scopes.OrganizationAsync(org, ct);
        if (!await lease.HoldAsync(scope, ct))
        {
            throw new JobLeaseLostException();
        }
        var policy = await Policies.CurrentAsync(scope, ct);
        // The rows of the devices come first, as in the intake of a batch, so that the two never wait for each other in turns;
        // what the sweep decides about a device is decided on its locked state.
        var devices = await LockDevicesAsync(scope, org, ct);
        if (policy is not null)
        {
            using var configuration = System.Text.Json.JsonDocument.Parse(policy.Configuration);
            var checks = configuration.RootElement.GetProperty("checks");
            var machine = new FindingMachine(scope.Db, org, now);
            var open = await scope.Db.Findings.Where(f => f.OrganizationId == org && f.TechnicalState == "open"
                                                        && f.Quality == "fresh_fail").ToListAsync(ct);
            foreach (var finding in open)
            {
                var window = TimeSpan.FromHours(checks.GetProperty(finding.CheckId).GetProperty("freshnessWindowHours").GetInt32());
                if ((finding.LatestObservedAt ?? finding.OpenedAt) + window <= now)
                {
                    machine.Quality(finding, "stale");
                }
            }
        }
        await SweepDevicesAsync(scope, policy, devices, now, ct);
        await lease.CompleteAsync(scope, ct);
        await scope.CommitAsync(ct);
    }

    private static async Task<IReadOnlyList<DeviceState>> LockDevicesAsync(DbScope scope, Guid org, CancellationToken ct)
    {
        var locked = new List<DeviceState>();
        foreach (var device in (await Devices.ActiveAsync(scope, org, ct)).OrderBy(d => d.Id))
        {
            if (await Devices.LockAsync(scope, device.Id, ct) is { Status: "active" } state)
            {
                locked.Add(state);
            }
        }
        return locked;
    }

    /// <summary>
    /// Devices (05 «Субъекты и идентичность устройства»): without a check-in for 90 days (by the state read under the lock) a
    /// device leaves the tracking with its volumes (subject_retired/source_change), and SYS-001 is written when its value
    /// changes.
    /// </summary>
    private static async Task SweepDevicesAsync(DbScope scope, PolicyRevision? policy, IReadOnlyList<DeviceState> devices,
        DateTimeOffset now, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        var unseen = devices.Where(d => (d.LastSeenAt ?? d.EnrolledAt) < now - Devices.RetireAfter).Select(d => d.Id).ToList();
        await DeviceSubjects.RetireAsync(scope, unseen, "source_change", null, now, ct);
        if (policy is null)
        {
            return;
        }
        foreach (var device in devices.Where(d => d.ProjectionSequence is not null && !unseen.Contains(d.Id)))
        {
            var subject = await scope.Db.Subjects.SingleOrDefaultAsync(s => s.OrganizationId == org && s.Type == "device"
                && s.Key == device.Id.ToString() && s.RetiredAt == null, ct);
            if (subject is not null)
            {
                await ServerChecks.EvaluateAsync(scope, device, subject, policy, new ReleaseCatalogView([], null), now, "source_change",
                    onlyIfChanged: true, ct, freshnessOnly: true);
            }
        }
    }
}

/// <summary>review_expiry: a risk decision whose reviewAt passed returns the finding to new (review_expired).</summary>
public sealed class ReviewExpiryJob(DbScopes scopes, TimeProvider clock) : IJobHandler
{
    public string Type => "review_expiry";

    public async Task ExecuteAsync(JobLease lease, CancellationToken ct)
    {
        var org = lease.OrganizationId!.Value;
        var now = clock.GetUtcNow();
        await using var scope = await scopes.OrganizationAsync(org, ct);
        if (!await lease.HoldAsync(scope, ct))
        {
            throw new JobLeaseLostException();
        }
        var expired = await scope.Db.Findings.Where(f => f.OrganizationId == org
            && (f.WorkflowState == "risk_accepted" || f.WorkflowState == "suppressed") && f.ReviewAt <= now).ToListAsync(ct);
        foreach (var finding in expired)
        {
            scope.Db.FindingEvents.Add(new FindingEvent
            {
                OrganizationId = org, FindingId = finding.Id, Id = Guid.CreateVersion7(), EventType = "workflow_changed",
                Cause = "review_expired", FromWorkflowState = finding.WorkflowState, ToWorkflowState = "new", OccurredAt = now,
            });
            finding.WorkflowState = "new";
            finding.ReviewAt = null;
            finding.Revision++;
        }
        await lease.CompleteAsync(scope, ct);
        await scope.CommitAsync(ct);
    }
}
