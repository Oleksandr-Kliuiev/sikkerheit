using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sikkerheit.ContractTests.Invariants;
using Sikkerheit.Host.Agents;
using Sikkerheit.Host.Jobs;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.ContractTests;

/// <summary>Records enforced by the jobs of the agent module and the release catalog (02 «Фоновые задания», 05).</summary>
[Enforcement("worker")]
public sealed class AgentWorkerInvariantTests(PostgresFixture postgres) : IAsyncLifetime
{
    private AgentHost _host = null!;

    public async ValueTask InitializeAsync() => _host = await AgentHost.StartAsync(postgres);

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    private static CancellationToken Ct => AgentHost.Ct;

    private DateTimeOffset Now => _host.Clock.GetUtcNow();

    [Fact]
    [Invariant("INV-137")]
    public async Task Inv137_a_job_that_changes_the_problems_of_a_device_waits_for_the_row_of_the_device()
    {
        var agent = await _host.EnrolledAsync();
        Assert.Equal(HttpStatusCode.OK, (await agent.SubmitAsync(agent.Batch())).Status);
        // Revision 2 queues recalculate_policy; a batch of the same device is being taken in at that moment.
        Assert.Equal(HttpStatusCode.Created, (await _host.NewPolicyAsync(p => p["checks"]!["WIN-009"]!["parameters"]!["secureBootRequired"] = false)).Status);
        var runner = _host.Factory.Services.GetRequiredService<JobRunner>();
        Task job;
        await using (var holder = await _host.Scopes.OrganizationAsync(_host.Org, Ct))
        {
            Assert.NotNull(await Devices.LockAsync(holder, agent.DeviceId!.Value, Ct));
            job = Task.Run(async () =>
            {
                while (await runner.RunOnceAsync(Ct))
                {
                }
            }, Ct);
            await Task.Delay(1500, Ct);
            Assert.False(job.IsCompleted, "the job has to wait for the lock of the device row");
            Assert.Empty(await _host.AssessmentsForPolicyAsync("WIN-009", 2));
        }
        await job.WaitAsync(TimeSpan.FromSeconds(30), Ct);
        // One effect: the projection is assessed once by revision 2 (secure boot is no longer required).
        var current = await _host.AssessmentsForPolicyAsync("WIN-009", 2);
        Assert.Equal(("not_applicable", "policy_not_applicable"), (current.Single().Result, current.Single().ReasonCode));
    }

    private async Task LateOctoberCatalogAsync()
    {
        foreach (var (month, ubr, kb) in new[] { ("2026-08", 9400, "5060101"), ("2026-09", 9611, "5060102"), ("2026-10", 9711, "5060103") })
        {
            Assert.Equal(HttpStatusCode.Accepted, (await _host.ImportReleasesAsync(month,
                new AgentHost.ReleaseEntry(26200, ubr, kb, "security_monthly", month))).Status);
        }
        Assert.Equal(HttpStatusCode.OK, (await _host.VerifyMonthAsync("2026-08")).Status);
        Assert.Equal(HttpStatusCode.OK, (await _host.VerifyMonthAsync("2026-09")).Status);
    }

    [Fact]
    [Invariant("INV-171")]
    public async Task Inv171_putting_a_month_into_effect_sweeps_the_devices_without_a_new_rule_version()
    {
        await LateOctoberCatalogAsync();
        await _host.MoveToAsync(new DateTimeOffset(2026, 10, 27, 12, 0, 0, TimeSpan.Zero));
        var agent = await _host.EnrolledAsync();
        Assert.Equal(HttpStatusCode.OK, (await agent.SubmitAsync(agent.Batch(edit: b =>
            FakeAgent.ObservationOf(b, "WIN-011")["evidence"]!["ubr"] = 9611))).Status);
        var before = (await _host.AssessmentsAsync("SYS-003", "current")).Single();
        Assert.Equal("release_catalog_stale", before.ReasonCode);
        Assert.Empty(await _host.FindingsAsync("SYS-003"));

        // The grace period of October has long passed when the month is verified: the lagging device gets opened/source_change.
        Assert.Equal(HttpStatusCode.OK, (await _host.VerifyMonthAsync("2026-10")).Status);
        await _host.Factory.Services.GetRequiredService<Scheduler>().RunOnceAsync(Ct);
        await _host.RunJobsAsync();
        var finding = Assert.Single(await _host.FindingsAsync("SYS-003"));
        Assert.Equal(("open", "warning"), (finding.TechnicalState, finding.Severity));
        Assert.Equal(["opened/source_change"], await _host.EventsAsync("SYS-003"));
        var after = (await _host.AssessmentsAsync("SYS-003", "current")).First();
        Assert.Equal(before.RuleVersion, after.RuleVersion);
        Assert.Equal("fail", after.Result);
        // Verifying the month again changes nothing.
        Assert.Equal(HttpStatusCode.OK, (await _host.VerifyMonthAsync("2026-10")).Status);
        await _host.Factory.Services.GetRequiredService<Scheduler>().RunOnceAsync(Ct);
        await _host.RunJobsAsync();
        Assert.Equal(["opened/source_change"], await _host.EventsAsync("SYS-003"));
    }

    [Fact]
    [Invariant("INV-174")]
    public async Task Inv174_a_device_without_a_check_in_for_90_days_leaves_the_tracking_and_the_next_check_in_brings_it_back()
    {
        var agent = await _host.EnrolledAsync();
        Assert.Equal(HttpStatusCode.OK, (await agent.SubmitAsync(agent.Batch(edit: b =>
            FakeAgent.ObservationOf(b, "WIN-002")["evidence"]!["protectionStatus"] = "off"))).Status);
        Assert.Equal(["opened/source_change"], await _host.EventsAsync("WIN-002"));

        _host.Clock.Set(Now.AddDays(91));
        await _host.Factory.Services.GetRequiredService<Scheduler>().RunOnceAsync(Ct);
        await _host.RunJobsAsync();
        Assert.All(await _host.SubjectsAsync("device"), s => Assert.NotNull(s.RetiredAt));
        Assert.All(await _host.SubjectsAsync("volume"), s => Assert.NotNull(s.RetiredAt));
        // The finding first turns stale (72 hours), then its subject leaves the tracking.
        Assert.Equal(["opened/source_change", "quality_changed/data_quality", "subject_retired/source_change"], await _host.EventsAsync("WIN-002"));
        Assert.Equal("resolved", (await _host.FindingsAsync("WIN-002")).Single().TechnicalState);

        await agent.StartSessionAsync();
        Assert.Equal(HttpStatusCode.OK, (await agent.CheckInAsync()).Status);
        Assert.All(await _host.SubjectsAsync("device"), s => Assert.Null(s.RetiredAt));
        // The volume returns with the next batch; a failure there reopens the closed finding.
        Assert.Equal(HttpStatusCode.OK, (await agent.SubmitAsync(agent.Batch(edit: b =>
            FakeAgent.ObservationOf(b, "WIN-002")["evidence"]!["protectionStatus"] = "off"))).Status);
        Assert.Equal("reopened/source_change", (await _host.EventsAsync("WIN-002")).Last());
    }

    [Fact]
    [Invariant("INV-199")]
    public async Task Inv199_a_revoked_installation_stays_while_the_organization_has_an_active_enrollment_key()
    {
        var agent = await _host.EnrolledAsync();
        Assert.Equal(HttpStatusCode.NoContent,
            (await _host.Admin.PostAsync($"/api/v1/organizations/{_host.Org}/devices/{agent.DeviceId}/revoke", new { })).Status);
        // The revocation is 25 months old.
        await _host.ReadAsync(async scope =>
        {
            await scope.Db.RevokedInstallations.ExecuteUpdateAsync(u => u.SetProperty(r => r.RevokedAt, Now.AddMonths(-25)), Ct);
            await scope.CommitAsync(Ct);
            return 0;
        });
        await PurgeAsync("2026-10-14");
        Assert.Equal(1, await _host.ReadAsync(scope => scope.Db.RevokedInstallations.CountAsync(Ct)));

        // The last active key is revoked: now the record may go.
        await _host.Admin.PostAsync($"/api/v1/organizations/{_host.Org}/enrollment-keys/{_host.KeyId}/revoke", new { });
        await PurgeAsync("2026-10-15");
        Assert.Equal(0, await _host.ReadAsync(scope => scope.Db.RevokedInstallations.CountAsync(Ct)));
    }

    private async Task PurgeAsync(string period)
    {
        await using (var platform = await _host.Scopes.PlatformAsync(Ct))
        {
            await JobQueue.EnqueueAsync(platform, "retention_purge", _host.Org, null, period, Now, Ct);
            await platform.CommitAsync(Ct);
        }
        await _host.RunJobsAsync();
    }
}
