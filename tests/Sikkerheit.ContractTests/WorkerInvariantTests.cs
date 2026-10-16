using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Sikkerheit.Contracts;
using Sikkerheit.ContractTests.Invariants;
using Sikkerheit.ContractTests.Support;
using Sikkerheit.Host.Jobs;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.ContractTests;

/// <summary>Records enforced by the background jobs: the job table, leases, the scheduler and the handlers.</summary>
[Enforcement("worker")]
public sealed class WorkerInvariantTests(PostgresFixture postgres) : IAsyncLifetime
{
    private ContractHost _host = null!;

    public async ValueTask InitializeAsync()
    {
        _host = await ContractHost.StartAsync(postgres);
        await _host.MoveToAsync(2026, 10, 7, 10);
    }

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    private static CancellationToken Ct => ContractHost.Ct;

    private async Task EnqueueAsync(string type, Guid? org, string period)
    {
        await using var platform = await _host.Scopes.PlatformAsync(Ct);
        await JobQueue.EnqueueAsync(platform, type, org, null, period, _host.Clock.GetUtcNow(), Ct);
        await platform.CommitAsync(Ct);
    }

    private async Task<List<Host.Data.Job>> JobsAsync(string type)
    {
        await using var platform = await _host.Scopes.PlatformAsync(Ct);
        return await platform.Db.Jobs.AsNoTracking().Where(j => j.Type == type).ToListAsync(Ct);
    }

    private Scheduler SecondInstance() =>
        new(_host.Scopes, _host.Clock, NullLogger<Scheduler>.Instance);

    [Fact]
    [Invariant("INV-065")]
    public async Task Inv065_expired_review_returns_the_finding_to_new_once()
    {
        var org = await _host.OrganizationAsync();
        var finding = await _host.InsertFindingAsync(org);
        await _host.Admin.PostAsync($"/api/v1/organizations/{org}/findings/{finding}/risk-decisions",
            new { decision = "risk_accepted", reason = "Kunden godtar til neste uke", reviewAt = _host.Clock.GetUtcNow().AddDays(1) }, "Finding",
            ifMatch: await _host.ETagAsync(org, finding));
        await _host.MoveToAsync(2026, 10, 9, 10);
        await EnqueueAsync("review_expiry", org, "2026-10-09T08");
        await _host.RunJobsAsync();
        await EnqueueAsync("review_expiry", org, "2026-10-09T09");
        await _host.RunJobsAsync();
        Assert.Equal("new", (await _host.FindingsAsync(org)).Single().WorkflowState);
        var events = (await _host.Admin.GetAsync($"/api/v1/organizations/{org}/findings/{finding}/events", "FindingEventPage"))
            .Body.GetProperty("items").EnumerateArray()
            .Select(e => (e.GetProperty("eventType").GetString(), e.GetProperty("cause").GetString())).ToList();
        Assert.Equal([("workflow_changed", "manual_action"), ("workflow_changed", "review_expired")], events);
    }

    [Fact]
    [Invariant("INV-071")]
    public async Task Inv071_retention_purge_deletes_in_the_registry_order_and_writes_a_summary()
    {
        var tenant = _host.Tenant();
        tenant.SecurityDefaults = true;
        tenant.GrantPolicies.Clear();
        var alice = tenant.AddUser("alice");
        var org = await _host.OrganizationAsync();
        await _host.ConnectAsync(org, tenant);
        await _host.RunJobsAsync();
        tenant.Users[tenant.Users.IndexOf(alice)] = alice with { Methods = ["microsoftAuthenticator"] };
        await _host.CollectAsync(org);
        Assert.Equal("resolved", (await _host.FindingsAsync(org, "M365-001")).Single().TechnicalState);

        // Thirteen months later the resolved finding and its events are past the term of 12 months.
        await _host.MoveToAsync(2027, 11, 20, 3);
        await EnqueueAsync("retention_purge", org, "2027-11-20");
        await _host.RunJobsAsync();
        Assert.Equal("succeeded", (await JobsAsync("retention_purge")).Single().State);
        Assert.Empty(await _host.FindingsAsync(org, "M365-001"));
        var summary = Assert.Single(await _host.AuditAsync(org, "retention.purge_summary"));
        var deleted = JsonDocument.Parse(summary.Details!).RootElement.GetProperty("deleted");
        Assert.Equal(Catalog.RetentionPurgeOrder.Order(), deleted.EnumerateObject().Select(p => p.Name).Order());
        // The events, assessments and findings went in one run: the foreign keys allow that only in the registry order.
        // The statements of the job follow the same order (jsonb does not keep the order of the summary keys).
        var source = File.ReadAllText(Path.Combine(InvariantRegistry.Root, "src", "Sikkerheit.Host", "Jobs", "DataLifecycleJobs.cs"));
        var purge = source[source.IndexOf("class RetentionPurgeJob", StringComparison.Ordinal)..];
        var statements = System.Text.RegularExpressions.Regex.Matches(purge, @"delete from ([a-z_]+)").Select(m => m.Groups[1].Value)
            .Where(Catalog.RetentionPurgeOrder.Contains).Distinct().ToList();
        Assert.Equal(Catalog.RetentionPurgeOrder.Where(statements.Contains), statements);
        Assert.True(deleted.GetProperty("finding_event").GetInt32() >= 2);
        Assert.True(deleted.GetProperty("finding").GetInt32() >= 1);
        Assert.True(deleted.GetProperty("observation").GetInt32() >= 1);
    }

    [Fact]
    [Invariant("INV-075")]
    public async Task Inv075_report_without_a_translation_fails_without_another_language()
    {
        var org = await _host.OrganizationAsync("Nynorsk AS", "nn");
        // A finding of a rule version whose nn text does not exist yet.
        await _host.InsertFindingAsync(org, checkId: "M365-999", openedAt: new DateTimeOffset(2026, 9, 29, 8, 0, 0, TimeSpan.Zero),
            openedEvent: true);
        var created = await _host.Admin.PostAsync($"/api/v1/organizations/{org}/reports",
            new { periodStart = "2026-09-28T00:00:00+02:00", periodEnd = "2026-10-05T00:00:00+02:00", format = "html" }, "Report");
        Assert.Equal(HttpStatusCode.Accepted, created.Status);
        await _host.RunJobsAsync();
        var report = (await _host.Admin.GetAsync($"/api/v1/organizations/{org}/reports", "ReportPage")).Body.GetProperty("items")[0];
        Assert.Equal(("failed", "translation_missing"), (report.GetProperty("state").GetString(), report.GetProperty("failureCode").GetString()));
        Assert.Single(await _host.AuditAsync(org, "report.failed"));
        Assert.Contains(_host.Factory.Logs.Entries, e => e.Level == LogLevel.Error && e.Message.Contains("translation_missing", StringComparison.Ordinal));
        Assert.False(Directory.Exists(Path.Combine(_host.Factory.FilesDirectory, "reports", org.ToString())));
    }

    [Fact]
    [Invariant("INV-077")]
    public async Task Inv077_periodic_job_of_one_period_is_created_once_by_two_instances()
    {
        var org = await _host.OrganizationAsync();
        await _host.MoveToAsync(2026, 10, 19, 6, 30);
        var first = _host.Factory.Services.GetRequiredService<Scheduler>();
        await Task.WhenAll(first.RunOnceAsync(Ct), SecondInstance().RunOnceAsync(Ct));
        await Task.WhenAll(first.RunOnceAsync(Ct), SecondInstance().RunOnceAsync(Ct));
        var weekly = (await JobsAsync("weekly_report")).Where(j => j.OrganizationId == org).Select(j => j.PeriodKey).ToList();
        Assert.Contains("2026-W42", weekly);
        Assert.Equal(weekly.Distinct().Count(), weekly.Count);
    }

    [Fact]
    [Invariant("INV-078")]
    public async Task Inv078_expired_lease_is_captured_again_and_the_old_owner_has_no_effect()
    {
        var org = await _host.OrganizationAsync();
        await EnqueueAsync("freshness_sweep", org, "2026-10-07T08");
        Guid id;
        await using (var platform = await _host.Scopes.PlatformAsync(Ct))
        {
            // The old owner paused longer than its lease.
            await using var paused = new NpgsqlCommand("""
                update job set state = 'running', lease_owner = 'paused:1', lease_token = 1, lease_until = @expired, attempts = 1
                where type = 'freshness_sweep' returning id
                """, platform.Connection, platform.Transaction);
            paused.Parameters.AddWithValue("expired", _host.Clock.GetUtcNow().AddMinutes(-1));
            id = (Guid)(await paused.ExecuteScalarAsync(Ct))!;
            await platform.CommitAsync(Ct);
        }
        Assert.True(await _host.Factory.Services.GetRequiredService<JobRunner>().RunOnceAsync(Ct));
        var job = (await JobsAsync("freshness_sweep")).Single();
        Assert.Equal(("succeeded", 2L), (job.State, job.LeaseToken));
        var completed = job.CompletedAt;

        var stale = new JobLease(id, 1, "freshness_sweep", org, null, "2026-10-07T08");
        await using (var scope = await _host.Scopes.OrganizationAsync(org, Ct))
        {
            Assert.False(await stale.HoldAsync(scope, Ct));
            await Assert.ThrowsAsync<JobLeaseLostException>(() => stale.CompleteAsync(scope, Ct));
        }
        Assert.Equal(completed, (await JobsAsync("freshness_sweep")).Single().CompletedAt);
    }

    [Fact]
    [Invariant("INV-079")]
    public async Task Inv079_unplanned_collection_joins_the_open_run()
    {
        var org = await _host.OrganizationAsync();
        var tenant = _host.Tenant();
        tenant.SecurityDefaults = true;
        await _host.ConnectAsync(org, tenant);
        // The verification queued a run that has not started; two more requests join it.
        var first = await _host.Admin.PostAsync($"/api/v1/organizations/{org}/collection-runs", new { idempotencyKey = Guid.NewGuid() }, "CollectionRun");
        var second = await _host.Admin.PostAsync($"/api/v1/organizations/{org}/collection-runs", new { idempotencyKey = Guid.NewGuid() }, "CollectionRun");
        Assert.Equal(first.Body.GetProperty("id").GetString(), second.Body.GetProperty("id").GetString());
        // The daily scheduled job comes while the run is still open: it does not start a second one.
        await _host.MoveToAsync(2026, 10, 7, 9, 58);
        await EnqueueAsync("m365_collect", org, "2026-10-07");
        Assert.True(await _host.Factory.Services.GetRequiredService<JobRunner>().RunOnceAsync(Ct));
        Assert.Equal("succeeded", (await JobsAsync("m365_collect")).Single(j => j.PeriodKey == "2026-10-07").State);
        await _host.MoveToAsync(2026, 10, 7, 10, 5);
        await _host.RunJobsAsync();
        await using var scope = await _host.Scopes.OrganizationAsync(org, Ct);
        var runs = await scope.Db.CollectionRuns.AsNoTracking().ToListAsync(Ct);
        Assert.Equal([first.Body.GetProperty("id").GetString()], runs.Select(r => r.Id.ToString()));
        Assert.Equal("completed", runs.Single().State);
    }

    [Fact]
    [Invariant("INV-084")]
    public async Task Inv084_job_without_an_organization_is_unique_by_type_and_period()
    {
        await _host.MoveToAsync(2026, 10, 8, 7, 45);
        var first = _host.Factory.Services.GetRequiredService<Scheduler>();
        await Task.WhenAll(first.RunOnceAsync(Ct), SecondInstance().RunOnceAsync(Ct));
        await EnqueueAsync("teams_digest", null, "2026-10-08");
        Assert.Equal(["2026-10-08"], (await JobsAsync("teams_digest")).Select(j => j.PeriodKey));
        await _host.RunJobsAsync();
        Assert.Single(_host.Factory.Teams.Requests);
    }
}
