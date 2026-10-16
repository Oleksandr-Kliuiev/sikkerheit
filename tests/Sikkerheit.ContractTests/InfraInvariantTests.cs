using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Npgsql;
using Sikkerheit.ContractTests.Invariants;
using Sikkerheit.ContractTests.Support;
using Sikkerheit.Host.Jobs;
using Sikkerheit.Host.Operations;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.ContractTests;

/// <summary>
/// Records enforced by operations: the restore command after a point-in-time restore (a copy of the database at T stands
/// in for PITR), the security log and the job settings of the slots. The Bicep side of INV-081, INV-083 and INV-085 is
/// checked by tools/iac/check_arm.py.
/// </summary>
[Enforcement("infra")]
public sealed class InfraInvariantTests(PostgresFixture postgres)
{
    private const string Oslo = ContractHost.Oslo;
    private readonly string _log = Path.Combine(Path.GetTempPath(), "sikkerheit-tests", Guid.NewGuid().ToString("N"), "log");
    private readonly string _files = Path.Combine(Path.GetTempPath(), "sikkerheit-tests", Guid.NewGuid().ToString("N"), "files");

    private static CancellationToken Ct => ContractHost.Ct;

    private static async Task RunJobsAsync(ApiFactory factory)
    {
        var runner = factory.Services.GetRequiredService<JobRunner>();
        while (await runner.RunOnceAsync(Ct))
        {
        }
    }

    private static async Task<StaffClient.Answer> LifecycleAsync(StaffClient admin, Guid org, string action) =>
        await admin.PostAsync($"/api/v1/organizations/{org}/lifecycle", action == "schedule_deletion"
            ? new { action, reason = "Avslutning", idempotencyKey = Guid.NewGuid(), exportWaived = true }
            : new { action, reason = "Avslutning", idempotencyKey = Guid.NewGuid() }, "Organization");

    private static async Task<Guid> OrganizationAsync(StaffClient admin, string name) =>
        Guid.Parse((await admin.PostAsync("/api/v1/organizations", new { name, timezone = Oslo, reportLanguage = "nb" }, "Organization"))
            .Body.GetProperty("id").GetString()!);

    /// <summary>
    /// Builds the history on one database and returns a copy taken at T. «before» runs before the copy, «after» on the
    /// original after it; both get an Admin client. Returns the connection string of the copy and T.
    /// </summary>
    private async Task<(string Restored, DateTimeOffset T)> HistoryAsync(Func<ApiFactory, StaffClient, Task> before,
        Func<ApiFactory, StaffClient, Task> after, (int Month, int Day, int Hour) at)
    {
        var live = await postgres.CreateDatabaseAsync();
        DateTimeOffset t;
        await using (var factory = new ApiFactory(live, _log, _files))
        {
            factory.Clock.SetLocal(Oslo, 2026, 10, 1, 10);
            await before(factory, await StaffClient.SignInAsync(factory, "Admin"));
            factory.Clock.SetLocal(Oslo, 2026, at.Month, at.Day, at.Hour);
            t = factory.Clock.GetUtcNow();
        }
        var restored = await postgres.CloneDatabaseAsync(live);
        await using (var factory = new ApiFactory(live, _log, _files))
        {
            factory.Clock.Set(t.AddHours(2));
            await after(factory, await StaffClient.SignInAsync(factory, "Admin"));
        }
        return (restored, t);
    }

    private async Task<(ApiFactory Factory, RestoreReport Report)> RestoreAsync(string restored, DateTimeOffset since, int month, int day,
        bool drill = false)
    {
        var factory = new ApiFactory(restored, _log, _files);
        factory.Clock.SetLocal(Oslo, 2026, month, day, 10);
        var report = await factory.Services.GetRequiredService<RestoreReplay>().RunAsync(new RestoreOptions(since, drill), Ct);
        Assert.True(report.Verification.Passed, string.Join("; ", report.Verification.Problems));
        return (factory, report);
    }

    private static async Task<string> StatusAsync(StaffClient admin, Guid org) =>
        (await admin.GetAsync($"/api/v1/organizations/{org}", "Organization")).Body.GetProperty("status").GetString()!;

    [Fact]
    [Invariant("INV-080")]
    public async Task Inv080_replay_applies_the_log_from_five_minutes_before_T_in_time_order_once()
    {
        Guid disabledAfter = default, scheduledAndCancelled = default, justBefore = default;
        var (restored, t) = await HistoryAsync(async (factory, admin) =>
        {
            disabledAfter = await OrganizationAsync(admin, "Etter AS");
            scheduledAndCancelled = await OrganizationAsync(admin, "Rekkefølge AS");
            justBefore = await OrganizationAsync(admin, "Like før AS");
            factory.Clock.SetLocal(Oslo, 2026, 10, 10, 9, 57);
            admin = await StaffClient.SignInAsync(factory, "Admin");
            await LifecycleAsync(admin, justBefore, "disable");
        }, async (_, admin) =>
        {
            await LifecycleAsync(admin, disabledAfter, "disable");
            await LifecycleAsync(admin, scheduledAndCancelled, "disable");
            await LifecycleAsync(admin, scheduledAndCancelled, "schedule_deletion");
            await LifecycleAsync(admin, scheduledAndCancelled, "cancel_deletion");
        }, (10, 10, 10));

        var (factory, report) = await RestoreAsync(restored, t, 10, 20);
        await using (factory)
        {
            Assert.Equal(t.AddMinutes(-5), report.ReplayFrom);
            Assert.Equal(["organization.disable/already_satisfied", "organization.disable/applied", "organization.disable/applied",
                "organization.schedule_deletion/applied", "organization.cancel_deletion/applied"],
                report.Records.Select(r => r.Action + "/" + r.Outcome));
            var admin = await StaffClient.SignInAsync(factory, "Admin");
            Assert.Equal("disabled", await StatusAsync(admin, disabledAfter));
            // Out of order the cancellation would come first and the deletion would stay scheduled.
            Assert.Equal("disabled", await StatusAsync(admin, scheduledAndCancelled));
            var audit = await admin.GetAsync($"/api/v1/organizations/{disabledAfter}/audit-events", "AuditEventPage");
            Assert.Single(audit.Body.GetProperty("items").EnumerateArray(), e => e.GetProperty("action").GetString() == "restore.replay_applied");

            var again = await factory.Services.GetRequiredService<RestoreReplay>().RunAsync(new RestoreOptions(t, Drill: false), Ct);
            Assert.All(again.Records.Skip(1), r => Assert.Equal("already_applied", r.Outcome));
            audit = await admin.GetAsync($"/api/v1/organizations/{disabledAfter}/audit-events", "AuditEventPage");
            Assert.Single(audit.Body.GetProperty("items").EnumerateArray(), e => e.GetProperty("action").GetString() == "restore.replay_applied");
        }
    }

    [Fact]
    [Invariant("INV-081")]
    public async Task Inv081_files_without_rows_go_to_quarantine_and_a_drill_only_lists_them()
    {
        Guid org = default;
        string? report = null;
        var (restored, t) = await HistoryAsync(async (_, admin) => org = await OrganizationAsync(admin, "Rapport AS"),
            async (factory, admin) =>
            {
                var created = await admin.PostAsync($"/api/v1/organizations/{org}/reports",
                    new { periodStart = "2026-10-05T00:00:00+02:00", periodEnd = "2026-10-12T00:00:00+02:00", format = "html" }, "Report");
                report = created.Body.GetProperty("id").GetString();
                await RunJobsAsync(factory);
            }, (10, 13, 10));
        var key = $"{org}/2026-W41/{report}.html";
        var original = Path.Combine(_files, "reports", key);
        Assert.True(File.Exists(original));

        var (drill, listed) = await RestoreAsync(restored, t, 10, 20, drill: true);
        await drill.DisposeAsync();
        Assert.Equal([(key, false)], listed.OrphanFiles.Select(f => (f.Key, f.Moved)));
        Assert.True(File.Exists(original));

        var (factory, moved) = await RestoreAsync(restored, t, 10, 20);
        await using (factory)
        {
            Assert.Equal([(key, "restore-orphans/" + key, true)], moved.OrphanFiles.Select(f => (f.Key, f.QuarantineKey, f.Moved)));
            Assert.False(File.Exists(original));
            Assert.True(File.Exists(Path.Combine(_files, "reports", "restore-orphans", key)));
        }
    }

    [Fact]
    [Invariant("INV-082", Decision = "F11 (0.3.1): a deletion that happened is repeated at once")]
    public async Task Inv082_cancelled_deletion_stays_cancelled_and_no_deletion_comes_within_seven_days()
    {
        Guid cancelled = default, scheduled = default, deleted = default;
        var (restored, t) = await HistoryAsync(async (_, admin) =>
        {
            cancelled = await OrganizationAsync(admin, "Avbrutt AS");
            scheduled = await OrganizationAsync(admin, "Planlagt AS");
            deleted = await OrganizationAsync(admin, "Slettet AS");
            foreach (var org in new[] { cancelled, scheduled, deleted })
            {
                await LifecycleAsync(admin, org, "disable");
                await LifecycleAsync(admin, org, "schedule_deletion");
            }
        }, async (factory, admin) =>
        {
            await LifecycleAsync(admin, cancelled, "cancel_deletion");
            // 31 October: the deletion date of the scheduled organizations has passed; the job deletes one of them.
            factory.Clock.SetLocal(Oslo, 2026, 11, 1, 10);
            await using var platform = await factory.Services.GetRequiredService<Host.Data.DbScopes>().PlatformAsync(Ct);
            await JobQueue.EnqueueAsync(platform, "organization_delete", deleted, null, "2026-11-01T09", factory.Clock.GetUtcNow(), Ct);
            await platform.CommitAsync(Ct);
            await RunJobsAsync(factory);
        }, (10, 20, 10));

        // Restored on 5 November: the copy has all three scheduled with a passed date.
        var (factory, report) = await RestoreAsync(restored, t, 11, 5);
        await using (factory)
        {
            var admin = await StaffClient.SignInAsync(factory, "Admin");
            Assert.Equal("disabled", await StatusAsync(admin, cancelled));
            Assert.Equal(System.Net.HttpStatusCode.NotFound, (await admin.GetAsync($"/api/v1/organizations/{deleted}")).Status);
            var due = (await admin.GetAsync($"/api/v1/organizations/{scheduled}", "Organization")).Body.GetProperty("deletionDueAt").GetDateTimeOffset();
            Assert.True(due >= factory.Clock.GetUtcNow().AddDays(7).AddMinutes(-1), due.ToString("O"));
            Assert.Contains(report.DeletionsPostponed, d => d.OrganizationId == scheduled);

            // The hourly deletion right after the restore deletes nothing.
            await factory.Services.GetRequiredService<Scheduler>().RunOnceAsync(Ct);
            await RunJobsAsync(factory);
            Assert.Equal("deletion_scheduled", await StatusAsync(admin, scheduled));
            Assert.Equal("disabled", await StatusAsync(admin, cancelled));
        }
    }

    [Fact]
    [Invariant("INV-083")]
    public async Task Inv083_security_log_records_are_never_overwritten_and_the_log_has_no_delete()
    {
        var log = new FileSecurityLog(_log);
        var record = new SecurityLogRecord(Guid.CreateVersion7(), "organization.disable", Guid.NewGuid(), "organization", "x",
            DateTimeOffset.UtcNow, "test", null);
        await log.AppendAsync(record, Ct);
        var file = Assert.Single(Directory.GetFiles(_log));
        var content = await File.ReadAllTextAsync(file, Ct);
        await Assert.ThrowsAsync<SecurityLogUnavailableException>(() => log.AppendAsync(record with { Action = "organization.enable" }, Ct));
        Assert.Equal(content, await File.ReadAllTextAsync(file, Ct));
        // The service can only append and read; changing or deleting records is not part of its interface.
        Assert.Equal(["AppendAsync", "ReadSinceAsync"], typeof(ISecurityLog).GetMethods().Select(m => m.Name).Order());
        Assert.Contains(InvariantRegistry.IacInvariants(), id => id == "INV-083");
    }

    [Fact]
    [Invariant("INV-085")]
    public async Task Inv085_jobs_run_only_where_the_slot_setting_enables_them()
    {
        // The staging slot: Jobs:Enabled=false — neither the runner nor the scheduler is hosted.
        await using (var staging = await ApiFactory.CreateAsync(postgres))
        {
            staging.Settings["Jobs:Enabled"] = "false";
            var hosted = staging.Services.GetServices<IHostedService>().Select(s => s.GetType()).ToList();
            Assert.DoesNotContain(typeof(JobRunner), hosted);
            Assert.DoesNotContain(typeof(Scheduler), hosted);
        }
        await using (var production = await ApiFactory.CreateAsync(postgres))
        {
            production.Settings["Jobs:Enabled"] = "true";
            production.Settings["Jobs:SchedulerEnabled"] = "true";
            var hosted = production.Services.GetServices<IHostedService>().Select(s => s.GetType()).ToList();
            Assert.Contains(typeof(JobRunner), hosted);
            Assert.Contains(typeof(Scheduler), hosted);
        }
        Assert.Contains(InvariantRegistry.IacInvariants(), id => id == "INV-085");
    }

    /// <summary>A new policy revision with the configuration of the latest one; returns its version.</summary>
    private static async Task<int> RevisionAsync(StaffClient admin, Guid org)
    {
        var policies = $"/api/v1/organizations/{org}/policy-revisions";
        var latest = (await admin.GetAsync(policies, "PolicyRevisionPage")).Body.GetProperty("items")[0];
        var created = await admin.PostAsync(policies, new { configuration = latest.GetProperty("configuration") }, "PolicyRevision",
            ifMatch: $"\"{latest.GetProperty("version").GetInt32()}\"");
        return created.Body.GetProperty("version").GetInt32();
    }

    [Fact]
    [Invariant("INV-195", Decision = "the epoch follows max(stored version, version counter): at the 9999 boundary the next "
        + "epoch is 20000, so the lost revision 10000 is not issued again")]
    public async Task Inv195_after_a_restore_policy_versions_continue_from_the_next_epoch()
    {
        Guid org = default, boundary = default;
        var lost = new List<int>();
        var (restored, t) = await HistoryAsync(async (factory, admin) =>
        {
            org = await OrganizationAsync(admin, "Policy AS");
            Assert.Equal(2, await RevisionAsync(admin, org));
            // An organization whose counter reached the end of an epoch before T.
            boundary = await OrganizationAsync(admin, "Grense AS");
            await using (var scope = await factory.Services.GetRequiredService<Host.Data.DbScopes>().OrganizationAsync(boundary, Ct))
            {
                await using var counter = new NpgsqlCommand("update organization set next_policy_version = 9999 where id = @org",
                    scope.Connection, scope.Transaction);
                counter.Parameters.AddWithValue("org", boundary);
                await counter.ExecuteNonQueryAsync(Ct);
                await scope.CommitAsync(Ct);
            }
            Assert.Equal(9999, await RevisionAsync(admin, boundary));
        }, async (_, admin) =>
        {
            // Revisions after T are lost with the restore.
            lost.Add(await RevisionAsync(admin, org));
            lost.Add(await RevisionAsync(admin, org));
            lost.Add(await RevisionAsync(admin, boundary));
        }, (10, 10, 10));
        Assert.Equal([3, 4, 10_000], lost);

        var (factory, report) = await RestoreAsync(restored, t, 10, 20);
        await using (factory)
        {
            Assert.Contains(new RestorePolicyEpoch(org, 2, 10_000, AlreadyAdvanced: false), report.PolicyEpochs);
            Assert.Contains(new RestorePolicyEpoch(boundary, 9999, 20_000, AlreadyAdvanced: false), report.PolicyEpochs);
            var admin = await StaffClient.SignInAsync(factory, "Admin");
            Assert.Equal(10_000, await RevisionAsync(admin, org));
            Assert.Equal(20_000, await RevisionAsync(admin, boundary));

            // A repeated run for the same restore point does not move the epoch again.
            var again = await factory.Services.GetRequiredService<RestoreReplay>().RunAsync(new RestoreOptions(t, Drill: false), Ct);
            Assert.Contains(new RestorePolicyEpoch(org, 10_000, 10_001, AlreadyAdvanced: true), again.PolicyEpochs);
            Assert.Equal(10_001, await RevisionAsync(admin, org));
        }
    }
}
