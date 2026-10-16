using Microsoft.EntityFrameworkCore;
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
        await lease.CompleteAsync(scope, ct);
        await scope.CommitAsync(ct);
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
