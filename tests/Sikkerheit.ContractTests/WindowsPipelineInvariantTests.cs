using System.Net;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Sikkerheit.ContractTests.Invariants;
using Sikkerheit.Host.Reports;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.ContractTests;

/// <summary>
/// Records of the evaluator that concern a batch on its way through the service (05 «Порядок приёма пакета»,
/// «Выбор текущего состояния», «Время и часы устройства»): the batch is sent over HTTP and the assessments, findings and
/// events are read from the database.
/// </summary>
[Enforcement("evaluator")]
public sealed class WindowsPipelineInvariantTests(PostgresFixture postgres) : IAsyncLifetime
{
    private AgentHost _host = null!;

    public async ValueTask InitializeAsync() => _host = await AgentHost.StartAsync(postgres);

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    private static CancellationToken Ct => AgentHost.Ct;

    private DateTimeOffset Now => _host.Clock.GetUtcNow();

    private static void Accepted(FakeAgent.Reply reply) => Assert.Equal(HttpStatusCode.OK, reply.Status);

    private static void BitlockerOff(JsonObject batch) => FakeAgent.ObservationOf(batch, "WIN-002")["evidence"]!["protectionStatus"] = "off";

    [Fact]
    [Invariant("INV-125")]
    public async Task Inv125_a_batch_older_than_the_projection_goes_to_history_only()
    {
        var agent = await _host.EnrolledAsync();
        Accepted(await agent.SubmitAsync(agent.Batch(Now.AddMinutes(-10))));
        var device = await _host.DeviceAsync(agent.DeviceId!.Value);
        // A PC restored from a checkpoint renumbers an old batch: its completedAt is older than the projection's.
        var old = agent.Batch(Now.AddHours(-3), BitlockerOff);
        Accepted(await agent.SubmitAsync(old));
        var after = await _host.DeviceAsync(agent.DeviceId!.Value);
        Assert.Equal((device.ProjectionSequence, device.ProjectionCompletedAt), (after.ProjectionSequence, after.ProjectionCompletedAt));
        Assert.Equal(2, after.LastAcceptedSequence);
        Assert.Empty(await _host.FindingsAsync());
        Assert.Empty(await _host.EventsAsync());
        var scopes = (await _host.AssessmentsAsync("WIN-002")).Select(a => (a.AssessmentScope, a.Result)).ToList();
        Assert.Contains(("historical", "fail"), scopes);
        Assert.Single((await _host.AssessmentsAsync("WIN-002", "current")));
        Assert.Equal("pass", (await _host.AssessmentsAsync("WIN-002", "current")).Single().Result);
    }

    private static void SetVolume(JsonObject batch, string volume)
    {
        foreach (var id in new[] { "WIN-001", "WIN-002" })
        {
            FakeAgent.ObservationOf(batch, id)["subject"]!["volumeId"] = volume;
        }
    }

    [Fact]
    [Invariant("INV-136")]
    public async Task Inv136_a_volume_leaves_only_by_a_positive_proof_and_a_collector_failure_is_unknown()
    {
        var agent = await _host.EnrolledAsync();
        Accepted(await agent.SubmitAsync(agent.Batch(Now.AddMinutes(-30), b => FakeAgent.ObservationOf(b, "WIN-001")["evidence"] =
            new JsonObject { ["totalBytes"] = 100_000_000_000, ["freeBytes"] = 1_000_000_000 })));
        var volume = Assert.Single(await _host.SubjectsAsync("volume"));
        Assert.Contains(await _host.FindingsAsync("WIN-001"), f => f.SubjectId == volume.Id && f.TechnicalState == "open");

        // The disk did not answer in 30 seconds: the volume stays and the result is unknown with the reason of the collector.
        _host.Clock.Set(Now.AddHours(1));
        await agent.StartSessionAsync();
        var timeout = agent.Batch(Now.AddMinutes(-1), b =>
        {
            FakeAgent.MakeUnavailable(b, "WIN-001", "collector_timeout");
            FakeAgent.MakeUnavailable(b, "WIN-002", "collector_timeout");
        });
        Accepted(await agent.SubmitAsync(timeout));
        Assert.Null((await _host.SubjectsAsync("volume")).Single().RetiredAt);
        var latest = (await _host.AssessmentsAsync("WIN-001", "current")).First();
        Assert.Equal(("unknown", "collector_timeout"), (latest.Result, latest.ReasonCode));
        Assert.DoesNotContain("subject_retired/source_change", await _host.EventsAsync("WIN-001"));

        // A full batch with the OS volume of another volumeId is the proof: the old volume and its finding go.
        _host.Clock.Set(Now.AddHours(1));
        await agent.StartSessionAsync();
        Accepted(await agent.SubmitAsync(agent.Batch(Now.AddMinutes(-1), b => SetVolume(b, @"\\?\Volume{aaaaaaaa-8a8f-4b3e-9a51-3c1d2e4f6a7b}\"))));
        var volumes = await _host.SubjectsAsync("volume");
        Assert.Equal(2, volumes.Count);
        Assert.NotNull(volumes.Single(v => v.Id == volume.Id).RetiredAt);
        Assert.Null(volumes.Single(v => v.Id != volume.Id).RetiredAt);
        Assert.Contains("subject_retired/source_change", await _host.EventsAsync("WIN-001"));
    }

    [Fact]
    [Invariant("INV-138")]
    public async Task Inv138_an_active_check_without_an_observation_in_the_batch_is_unknown()
    {
        var agent = await _host.EnrolledAsync();
        Accepted(await agent.SubmitAsync(agent.Batch(edit: b => FakeAgent.Remove(b, "WIN-005"))));
        var assessment = (await _host.AssessmentsAsync("WIN-005", "current")).Single();
        Assert.Equal(("assessed", "unknown", "missing_observation"), (assessment.AssessmentMode, assessment.Result, assessment.ReasonCode));
        Assert.Null(assessment.ObservationId);
    }

    [Fact]
    [Invariant("INV-139")]
    public async Task Inv139_a_difference_over_five_minutes_between_the_clock_of_the_pc_and_the_server_flags_the_batch()
    {
        var agent = await _host.EnrolledAsync();
        // The PC is three days behind: the batch is labelled with its time and sent with it.
        var slow = agent.Batch(Now.AddDays(-3).AddSeconds(-30));
        var receipt = await agent.SubmitAsync(slow, sentAt: Now.AddDays(-3));
        Accepted(receipt);
        Assert.True(receipt.Body.GetProperty("clockInconsistent").GetBoolean());
        Assert.Equal("inconsistent", (await _host.DeviceAsync(agent.DeviceId!.Value)).ClockStatus);
        var assessment = (await _host.AssessmentsAsync("WIN-009")).Single();
        Assert.Equal(("historical", "unknown", "clock_inconsistent"), (assessment.AssessmentScope, assessment.Result, assessment.ReasonCode));
        // SYS-002 and SYS-003 are not computed from such a batch.
        Assert.Empty(await _host.AssessmentsAsync("SYS-002"));
        // The first batch without the flag brings the status back.
        Accepted(await agent.SubmitAsync(agent.Batch()));
        Assert.Equal("ok", (await _host.DeviceAsync(agent.DeviceId!.Value)).ClockStatus);
        Assert.Equal("pass", (await _host.AssessmentsAsync("SYS-002", "current")).Single().Result);
        // A check-in off by an hour sets the status too.
        await agent.CheckInAsync(b => { b["observedAt"] = FakeAgent.Time(Now.AddHours(1)); return b; });
        Assert.Equal("inconsistent", (await _host.DeviceAsync(agent.DeviceId!.Value)).ClockStatus);
    }

    [Fact]
    [Invariant("INV-140")]
    public async Task Inv140_labels_from_the_future_are_accepted_but_do_not_move_the_projection()
    {
        var agent = await _host.EnrolledAsync();
        Accepted(await agent.SubmitAsync(agent.Batch(Now.AddMinutes(-10))));
        var projection = (await _host.DeviceAsync(agent.DeviceId!.Value)).ProjectionSequence;
        // The clock of the PC is a day ahead and the batch is labelled with it; the header carries the real time of sending.
        var ahead = agent.Batch(Now.AddDays(1), BitlockerOff);
        var receipt = await agent.SubmitAsync(ahead, sentAt: Now);
        Accepted(receipt);
        Assert.True(receipt.Body.GetProperty("clockInconsistent").GetBoolean());
        Assert.Equal(projection, (await _host.DeviceAsync(agent.DeviceId!.Value)).ProjectionSequence);
        var historical = (await _host.AssessmentsAsync("WIN-002", "historical")).Single();
        Assert.Equal(("unknown", "clock_inconsistent"), (historical.Result, historical.ReasonCode));
        Assert.Empty(await _host.FindingsAsync());
        Assert.Empty(await _host.EventsAsync());
    }

    [Fact]
    [Invariant("INV-165")]
    public async Task Inv165_without_a_fresh_inventory_the_server_checks_are_unknown()
    {
        var agent = await _host.EnrolledAsync();
        Accepted(await agent.SubmitAsync(agent.Batch()));
        Assert.Equal("pass", (await _host.AssessmentsAsync("SYS-002", "current")).First().Result);
        // WIN-011 is older than its window of 72 hours.
        _host.Clock.Set(Now.AddDays(4));
        await _host.SweepAsync("2026-10-18");
        foreach (var check in new[] { "SYS-002", "SYS-003" })
        {
            var latest = (await _host.AssessmentsAsync(check, "current")).First();
            Assert.Equal(("unknown", "os_inventory_missing"), (latest.Result, latest.ReasonCode));
        }
    }

    [Fact]
    [Invariant("INV-170")]
    public async Task Inv170_entries_that_are_only_imported_do_not_count_before_the_month_is_verified()
    {
        Assert.Equal(HttpStatusCode.Accepted, (await _host.ImportReleasesAsync("2026-08",
            new AgentHost.ReleaseEntry(26200, 9400, "5060101", "security_monthly", "2026-08"))).Status);
        Assert.Equal(HttpStatusCode.Accepted, (await _host.ImportReleasesAsync("2026-09",
            new AgentHost.ReleaseEntry(26200, 9611, "5060102", "security_monthly", "2026-09"))).Status);
        Assert.Equal(HttpStatusCode.Accepted, (await _host.ImportReleasesAsync("2026-10",
            new AgentHost.ReleaseEntry(26200, 9711, "5060103", "security_monthly", "2026-10"))).Status);
        Assert.Equal(HttpStatusCode.OK, (await _host.VerifyMonthAsync("2026-08")).Status);
        Assert.Equal(HttpStatusCode.OK, (await _host.VerifyMonthAsync("2026-09")).Status);

        // 2026-10-27: 14 days after Patch Tuesday of October; October is still a draft.
        await _host.MoveToAsync(new DateTimeOffset(2026, 10, 27, 12, 0, 0, TimeSpan.Zero));
        var agent = await _host.EnrolledAsync();
        Accepted(await agent.SubmitAsync(agent.Batch(edit: b => FakeAgent.ObservationOf(b, "WIN-011")["evidence"]!["ubr"] = 9611)));
        var stale = (await _host.AssessmentsAsync("SYS-003", "current")).Single();
        Assert.Equal(("unknown", "release_catalog_stale"), (stale.Result, stale.ReasonCode));
        Assert.Empty(await _host.FindingsAsync("SYS-003"));
    }

    [Fact]
    [Invariant("INV-175")]
    public async Task Inv175_the_inventory_of_a_renumbered_old_batch_is_not_the_input_of_the_server_checks()
    {
        var agent = await _host.EnrolledAsync();
        Accepted(await agent.SubmitAsync(agent.Batch(Now.AddMinutes(-10))));
        var support = (await _host.AssessmentsAsync("SYS-002", "current")).Count;
        // The old batch reports Windows 10 22H2, which fails SYS-002; it is older than the projection by completedAt.
        var old = agent.Batch(Now.AddHours(-3), b => FakeAgent.ObservationOf(b, "WIN-011")["evidence"] = new JsonObject
        {
            ["editionId"] = "Professional", ["displayVersion"] = "22H2", ["build"] = 19045, ["ubr"] = 1, ["architecture"] = "x64",
        });
        Accepted(await agent.SubmitAsync(old));
        Assert.Equal(support, (await _host.AssessmentsAsync("SYS-002", "current")).Count);
        await _host.SweepAsync("2026-10-14");
        var latest = (await _host.AssessmentsAsync("SYS-002", "current")).First();
        Assert.Equal("pass", latest.Result);
        Assert.Empty(await _host.FindingsAsync("SYS-002"));
    }

    [Fact]
    [Invariant("INV-173")]
    public async Task Inv173_a_dormant_device_and_a_device_without_presence_are_outside_the_denominators_and_shown_apart()
    {
        var anne = await _host.EnrolledAsync("PC-ANNE");
        var ola = await _host.EnrolledAsync("PC-OLA");
        Accepted(await anne.SubmitAsync(anne.Batch()));
        Accepted(await ola.SubmitAsync(ola.Batch()));
        var both = await _host.ReadAsync(scope => Coverage.AtAsync(scope, _host.Org, Now, Ct));
        Assert.Equal(0, both.DormantDevices);
        Assert.True(both.Pairs > 0 && both.Pairs % 2 == 0);

        // Ola's laptop is away for three weeks; Anne keeps checking in.
        _host.Clock.Set(Now.AddDays(21));
        await anne.StartSessionAsync();
        Assert.Equal(HttpStatusCode.OK, (await anne.CheckInAsync()).Status);
        var apart = await _host.ReadAsync(scope => Coverage.AtAsync(scope, _host.Org, Now, Ct));
        Assert.Equal(1, apart.DormantDevices);
        Assert.Equal(both.Pairs / 2, apart.Pairs);
        // In the last week Ola was never present: outside the denominator of the period, and counted apart.
        var period = await _host.ReadAsync(scope => Coverage.PeriodAsync(scope, _host.Org, Now.AddDays(-7), Now, Ct));
        Assert.Equal(1, period.NoPresenceDevices);
        var wholePeriod = await _host.ReadAsync(scope => Coverage.PeriodAsync(scope, _host.Org, Now.AddDays(-30), Now, Ct));
        Assert.Equal(0, wholePeriod.NoPresenceDevices);
        Assert.True(period.PeriodPairs < wholePeriod.PeriodPairs);
    }

    [Fact]
    [Invariant("INV-200")]
    public async Task Inv200_completeness_counts_the_agent_checks_only_and_a_missing_pair_is_unknown()
    {
        var agent = await _host.EnrolledAsync();
        // The policy has all M365 checks active, yet a batch with every WIN check is a full scan.
        Accepted(await agent.SubmitAsync(agent.Batch()));
        var device = await _host.DeviceAsync(agent.DeviceId!.Value);
        Assert.NotNull(device.LastFullScanAt);
        Assert.True(await _host.ReadAsync(scope => scope.Db.ScanBatches.AnyAsync(b => b.IsFull, Ct)));

        _host.Clock.Set(Now.AddHours(2));
        await agent.StartSessionAsync();
        var partial = agent.Batch(edit: b => FakeAgent.Remove(b, "WIN-009"));
        Accepted(await agent.SubmitAsync(partial));
        Assert.Equal(1, await _host.ReadAsync(scope => scope.Db.ScanBatches.CountAsync(b => b.IsFull, Ct)));
        var missing = (await _host.AssessmentsAsync("WIN-009", "current")).First();
        Assert.Equal(("unknown", "missing_observation"), (missing.Result, missing.ReasonCode));
        Assert.Equal(device.LastFullScanAt, (await _host.DeviceAsync(agent.DeviceId!.Value)).LastFullScanAt);
    }
}
