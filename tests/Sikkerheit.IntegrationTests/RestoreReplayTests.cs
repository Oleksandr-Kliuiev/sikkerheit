using System.Diagnostics;
using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;
using Sikkerheit.Host.Operations;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.IntegrationTests;

/// <summary>
/// AT-11, part P1 (06 «Резервное копирование и восстановление», RB-05): a copy of the database taken at T stands in for
/// the point-in-time restore; the service keeps working on the original after T, then the restore command replays the
/// security log on the copy with the same log and files.
/// </summary>
public sealed class RestoreReplayTests(PostgresFixture postgres)
{
    private const string Oslo = "Europe/Oslo";
    private static readonly DateTimeOffset T = new(2026, 10, 21, 8, 0, 0, TimeSpan.Zero); // 10:00 Oslo (CEST)
    private readonly string _log = Path.Combine(Path.GetTempPath(), "sikkerheit-tests", Guid.NewGuid().ToString("N"), "log");
    private readonly string _files = Path.Combine(Path.GetTempPath(), "sikkerheit-tests", Guid.NewGuid().ToString("N"), "files");

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private sealed record Scenario(string ConnectionString, Dictionary<string, Guid> Organizations, Guid LostReportId);

    private static async Task RunJobsAsync(ApiFactory factory)
    {
        var runner = factory.Services.GetRequiredService<JobRunner>();
        while (await runner.RunOnceAsync(Ct))
        {
        }
    }

    private static async Task<Guid> CreateOrganizationAsync(StaffClient admin, string name)
    {
        var created = await admin.PostAsync("/api/v1/organizations", new { name, timezone = Oslo, reportLanguage = "nb" }, "Organization");
        return Guid.Parse(created.Body.GetProperty("id").GetString()!);
    }

    private static async Task<StaffClient.Answer> LifecycleAsync(StaffClient admin, Guid org, string action) =>
        await admin.PostAsync($"/api/v1/organizations/{org}/lifecycle", action == "schedule_deletion"
            ? new { action, reason = "Kunden har sagt opp", idempotencyKey = Guid.NewGuid(), exportWaived = true }
            : new { action, reason = "Kunden har sagt opp", idempotencyKey = Guid.NewGuid() }, "Organization");

    /// <summary>
    /// Before T: A active, B deletion scheduled 1 October (due 31 October), C connected to Microsoft 365, E deletion
    /// scheduled (due 31 October), F active, G deletion scheduled 15 October (due 14 November), a job running at T.
    /// After T: A disabled, B deletion cancelled, C disconnected, F gets policy v2 and a report, E is deleted on 1 November.
    /// </summary>
    private async Task<Scenario> BuildAsync()
    {
        var orgs = new Dictionary<string, Guid>();
        var live = await postgres.CreateDatabaseAsync();
        await using (var before = new ApiFactory(live, _log, _files))
        {
            before.Clock.SetLocal(Oslo, 2026, 10, 1, 10);
            var admin = await StaffClient.SignInAsync(before, "Admin");
            foreach (var name in new[] { "A", "B", "C", "E", "F", "G" })
            {
                orgs[name] = await CreateOrganizationAsync(admin, "Restore " + name + " AS");
            }
            foreach (var name in new[] { "B", "E" })
            {
                await LifecycleAsync(admin, orgs[name], "disable");
                Assert.Equal("deletion_scheduled", (await LifecycleAsync(admin, orgs[name], "schedule_deletion")).Body.GetProperty("status").GetString());
            }
            var tenant = before.Graph.AddTenant();
            tenant.SecurityDefaults = true;
            await admin.PostAsync($"/api/v1/organizations/{orgs["C"]}/m365-connection/consent", new { tenantHint = tenant.TenantId.ToString() }, "ConsentStart");
            await admin.PostAsync($"/api/v1/organizations/{orgs["C"]}/m365-connection/verify", new { }, "TenantConnection");
            await RunJobsAsync(before);

            before.Clock.SetLocal(Oslo, 2026, 10, 15, 10);
            admin = await StaffClient.SignInAsync(before, "Admin");
            await LifecycleAsync(admin, orgs["G"], "disable");
            await LifecycleAsync(admin, orgs["G"], "schedule_deletion");

            // A job that was running when the database was copied: its lease must not survive the restore.
            var scopes = before.Services.GetRequiredService<DbScopes>();
            await using var platform = await scopes.PlatformAsync(Ct);
            await using var running = new NpgsqlCommand("""
                insert into job (id, type, organization_id, period_key, state, lease_owner, lease_token, lease_until, attempts, next_attempt_at, created_at)
                values (gen_random_uuid(), 'retention_purge', @org, '2026-10-21', 'running', 'crashed:1', 3, @until, 1, @at, @at)
                """, platform.Connection, platform.Transaction);
            running.Parameters.AddWithValue("org", orgs["A"]);
            running.Parameters.AddWithValue("until", T.AddMinutes(4));
            running.Parameters.AddWithValue("at", T.AddMinutes(-1));
            await running.ExecuteNonQueryAsync(Ct);
            await platform.CommitAsync(Ct);
        }

        var restored = await postgres.CloneDatabaseAsync(live);

        Guid lostReport;
        await using (var after = new ApiFactory(live, _log, _files))
        {
            after.Clock.SetLocal(Oslo, 2026, 10, 25, 12);
            var admin = await StaffClient.SignInAsync(after, "Admin");
            Assert.Equal("disabled", (await LifecycleAsync(admin, orgs["A"], "disable")).Body.GetProperty("status").GetString());
            Assert.Equal("disabled", (await LifecycleAsync(admin, orgs["B"], "cancel_deletion")).Body.GetProperty("status").GetString());
            await admin.PostAsync($"/api/v1/organizations/{orgs["C"]}/m365-connection/disconnect", new { }, "TenantConnection");
            var policies = $"/api/v1/organizations/{orgs["F"]}/policy-revisions";
            var configuration = (await admin.GetAsync(policies, "PolicyRevisionPage")).Body.GetProperty("items")[0].GetProperty("configuration");
            Assert.Equal(2, (await admin.PostAsync(policies, new { configuration }, "PolicyRevision", ifMatch: "\"1\"")).Body.GetProperty("version").GetInt32());
            var report = await admin.PostAsync($"/api/v1/organizations/{orgs["F"]}/reports",
                new { periodStart = "2026-10-12T00:00:00+02:00", periodEnd = "2026-10-19T00:00:00+02:00", format = "html" }, "Report");
            lostReport = Guid.Parse(report.Body.GetProperty("id").GetString()!);
            await RunJobsAsync(after);
            Assert.True(File.Exists(Path.Combine(_files, "reports", orgs["F"].ToString(), "2026-W42", lostReport + ".html")));

            // E is past its deletion date: the hourly deletion job runs (the scheduler would also queue weekly reports).
            after.Clock.SetLocal(Oslo, 2026, 11, 1, 11);
            await using (var platform = await after.Services.GetRequiredService<DbScopes>().PlatformAsync(Ct))
            {
                await JobQueue.EnqueueAsync(platform, "organization_delete", orgs["E"], null, "2026-11-01T10", after.Clock.GetUtcNow(), Ct);
                await platform.CommitAsync(Ct);
            }
            await RunJobsAsync(after);
            admin = await StaffClient.SignInAsync(after, "Admin");
            Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync($"/api/v1/organizations/{orgs["E"]}")).Status);
        }
        return new Scenario(restored, orgs, lostReport);
    }

    private static async Task<List<JsonElement>> AuditAsync(StaffClient admin, Guid org, string action)
    {
        var page = await admin.GetAsync($"/api/v1/organizations/{org}/audit-events?limit=100", "AuditEventPage");
        return page.Body.GetProperty("items").EnumerateArray().Where(e => e.GetProperty("action").GetString() == action).ToList();
    }

    [Fact]
    public async Task Replay_restores_every_restriction_after_the_restore_point_and_is_idempotent()
    {
        var scenario = await BuildAsync();
        var orgs = scenario.Organizations;
        await using var restored = new ApiFactory(scenario.ConnectionString, _log, _files);
        restored.Clock.SetLocal(Oslo, 2026, 11, 10, 10);
        var replay = restored.Services.GetRequiredService<RestoreReplay>();
        var scopes = restored.Services.GetRequiredService<DbScopes>();
        await using (var copy = await scopes.OrganizationAsync(orgs["B"], Ct))
        {
            // Why the replay exists: the copy at T still holds B as scheduled for deletion, and its date has passed.
            var b0 = await copy.Db.Organizations.AsNoTracking().SingleAsync(Ct);
            Assert.True(b0 is { Status: "deletion_scheduled" } && b0.DeletionDueAt < restored.Clock.GetUtcNow());
        }

        var report = await replay.RunAsync(new RestoreOptions(T, Drill: false), Ct);

        Assert.True(report.Verification.Passed, string.Join("; ", report.Verification.Problems));
        Assert.Equal(T.AddMinutes(-5), report.ReplayFrom);
        Assert.Equal(4, report.RecordsRead);
        Assert.Equal(["organization.disable/applied", "organization.cancel_deletion/applied", "m365.disconnect/applied",
            "organization.delete/applied"], report.Records.Select(r => r.Action + "/" + r.Outcome));
        Assert.Equal(1, report.LeasesReset);

        var admin = await StaffClient.SignInAsync(restored, "Admin");
        async Task<JsonElement> OrganizationAsync(string name) =>
            (await admin.GetAsync($"/api/v1/organizations/{orgs[name]}", "Organization")).Body;
        Assert.Equal("disabled", (await OrganizationAsync("A")).GetProperty("status").GetString());
        var b = await OrganizationAsync("B");
        Assert.Equal(("disabled", JsonValueKind.Null), (b.GetProperty("status").GetString(), b.GetProperty("deletionDueAt").ValueKind));
        Assert.Equal("disconnected", (await admin.GetAsync($"/api/v1/organizations/{orgs["C"]}/m365-connection", "TenantConnection"))
            .Body.GetProperty("status").GetString());
        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync($"/api/v1/organizations/{orgs["E"]}")).Status);
        // G was due on 14 November: after the restore not earlier than 17 November 10:00 Oslo.
        var g = await OrganizationAsync("G");
        Assert.InRange(g.GetProperty("deletionDueAt").GetDateTimeOffset(), new DateTimeOffset(2026, 11, 17, 9, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 11, 17, 9, 1, 0, TimeSpan.Zero));
        Assert.Contains(report.DeletionsPostponed, d => d.OrganizationId == orgs["G"] && d.To == g.GetProperty("deletionDueAt").GetDateTimeOffset());

        var applied = Assert.Single(await AuditAsync(admin, orgs["A"], RestoreReplay.AppliedAction));
        Assert.Equal(("system", "organization"), (applied.GetProperty("actorType").GetString(), applied.GetProperty("targetType").GetString()));
        Assert.StartsWith("restore:20261021T080000Z:organization.disable:", applied.GetProperty("correlationId").GetString());

        // The lost revision 2 of F is not issued again with other content: the next one is 10000.
        Assert.All(report.PolicyEpochs, e => Assert.Equal(10_000, e.NextVersion));
        var policies = $"/api/v1/organizations/{orgs["F"]}/policy-revisions";
        var configuration = (await admin.GetAsync(policies, "PolicyRevisionPage")).Body.GetProperty("items")[0].GetProperty("configuration");
        Assert.Equal(10_000, (await admin.PostAsync(policies, new { configuration }, "PolicyRevision", ifMatch: "\"1\"")).Body.GetProperty("version").GetInt32());

        // The report made after T has no row: its file waits in quarantine and its week is not generated again.
        var key = $"{orgs["F"]}/2026-W42/{scenario.LostReportId}.html";
        var orphan = Assert.Single(report.OrphanFiles);
        Assert.Equal(("reports", key, "restore-orphans/" + key, true), (orphan.Container, orphan.Key, orphan.QuarantineKey, orphan.Moved));
        Assert.False(File.Exists(Path.Combine(_files, "reports", key)));
        Assert.True(File.Exists(Path.Combine(_files, "reports", "restore-orphans", key)));
        Assert.Equal([(orgs["F"], "2026-W42")], report.WeeklyReportsMarked.Select(m => (m.OrganizationId, m.Period)));
        Assert.Equal(20, report.DigestPeriodsMarked.Count);
        Assert.Equal(["2026-10-22", "2026-11-10"], new[] { report.DigestPeriodsMarked[0], report.DigestPeriodsMarked[^1] });

        // A second run changes nothing.
        var again = await replay.RunAsync(new RestoreOptions(T, Drill: false), Ct);
        Assert.True(again.Verification.Passed);
        Assert.Equal(["already_applied", "already_applied", "already_applied", "already_satisfied"], again.Records.Select(r => r.Outcome));
        Assert.All(again.PolicyEpochs, e => Assert.True(e.AlreadyAdvanced));
        Assert.Equal(10_001, again.PolicyEpochs.Single(e => e.OrganizationId == orgs["F"]).NextVersion);
        Assert.Empty(again.OrphanFiles);
        Assert.Single(await AuditAsync(admin, orgs["A"], RestoreReplay.AppliedAction));

        // The service opens again: nothing is deleted early, the lost weeks are generated, the done ones are not.
        await restored.Services.GetRequiredService<Scheduler>().RunOnceAsync(Ct);
        await RunJobsAsync(restored);
        Assert.Equal("disabled", (await OrganizationAsync("B")).GetProperty("status").GetString());
        Assert.Equal("deletion_scheduled", (await OrganizationAsync("G")).GetProperty("status").GetString());
        var weeks = (await admin.GetAsync($"/api/v1/organizations/{orgs["F"]}/reports?limit=100", "ReportPage"))
            .Body.GetProperty("items").EnumerateArray().Select(r => r.GetProperty("periodStart").GetDateTimeOffset()).Order().ToList();
        Assert.Equal([new DateTimeOffset(2026, 10, 18, 22, 0, 0, TimeSpan.Zero), new DateTimeOffset(2026, 10, 25, 23, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 11, 1, 23, 0, 0, TimeSpan.Zero)], weeks);
        Assert.Empty(restored.Teams.Requests);
    }

    [Fact]
    public async Task Drill_lists_files_without_moving_or_deleting_them()
    {
        var scenario = await BuildAsync();
        await using var restored = new ApiFactory(scenario.ConnectionString, _log, _files);
        restored.Clock.SetLocal(Oslo, 2026, 11, 10, 10);
        var e = scenario.Organizations["E"];
        Assert.False(Directory.Exists(Path.Combine(_files, "reports", e.ToString())));
        // E had files before T in this variant: a drill must leave production files alone even for a deleted organization.
        var kept = Path.Combine(_files, "exports", e.ToString(), Guid.NewGuid() + ".zip");
        Directory.CreateDirectory(Path.GetDirectoryName(kept)!);
        await File.WriteAllTextAsync(kept, "zip", Ct);

        var report = await restored.Services.GetRequiredService<RestoreReplay>().RunAsync(new RestoreOptions(T, Drill: true), Ct);

        Assert.True(report.Verification.Passed, string.Join("; ", report.Verification.Problems));
        Assert.True(report.Drill);
        Assert.True(File.Exists(kept));
        var key = $"{scenario.Organizations["F"]}/2026-W42/{scenario.LostReportId}.html";
        Assert.True(File.Exists(Path.Combine(_files, "reports", key)));
        Assert.Contains(report.OrphanFiles, f => f.Container == "reports" && f.Key == key && !f.Moved);
        Assert.Contains(report.OrphanFiles, f => f.Container == "exports" && !f.Moved);
        Assert.DoesNotContain(report.OrphanFiles, f => f.Moved);
    }

    [Fact]
    public async Task Command_line_runs_the_replay_in_maintenance_mode_only()
    {
        await using var factory = await ApiFactory.CreateAsync(postgres, _log);
        var admin = await StaffClient.SignInAsync(factory, "Admin");
        var org = await CreateOrganizationAsync(admin, "Kommando AS");
        await LifecycleAsync(admin, org, "disable");
        var since = DateTimeOffset.UtcNow.AddMinutes(-1).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);
        var reportFile = Path.Combine(Path.GetTempPath(), "sikkerheit-tests", Guid.NewGuid().ToString("N") + ".json");

        var (exit, output, errors) = await HostAsync(factory, jobs: false, "restore-replay", "--since", since, "--report", reportFile);
        Assert.True(exit == 0, errors);
        var report = JsonDocument.Parse(output).RootElement;
        Assert.True(report.GetProperty("verification").GetProperty("passed").GetBoolean());
        var record = Assert.Single(report.GetProperty("records").EnumerateArray());
        Assert.Equal(("organization.disable", "already_satisfied"),
            (record.GetProperty("action").GetString(), record.GetProperty("outcome").GetString()));
        Assert.Equal(output.Trim(), (await File.ReadAllTextAsync(reportFile, Ct)).Trim());

        Assert.Equal(2, (await HostAsync(factory, jobs: true, "restore-replay", "--since", since)).Exit);
        var wrong = await HostAsync(factory, jobs: false, "restore-replay", "--since", "2026-10-21 10:00");
        Assert.Equal(2, wrong.Exit);
        Assert.Contains("--since must be an ISO 8601 time with an offset", wrong.Errors, StringComparison.Ordinal);
    }

    /// <summary>Runs the built service image with arguments and the configuration of the factory, as RB-05 does over SSH.</summary>
    private static async Task<(int Exit, string Output, string Errors)> HostAsync(ApiFactory factory, bool jobs, params string[] args)
    {
        var host = Path.Combine(AppContext.BaseDirectory, "Sikkerheit.Host.dll");
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet")
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false,
            WorkingDirectory = AppContext.BaseDirectory,
        };
        start.ArgumentList.Add(host);
        foreach (var arg in args)
        {
            start.ArgumentList.Add(arg);
        }
        start.Environment["ASPNETCORE_ENVIRONMENT"] = "Testing";
        start.Environment["ConnectionStrings__Sikkerheit"] = factory.ConnectionString;
        start.Environment["SecurityLog__Directory"] = factory.SecurityLogDirectory;
        start.Environment["Storage__LocalDirectory"] = factory.FilesDirectory;
        start.Environment["Jobs__Enabled"] = jobs ? "true" : "false";
        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync(Ct);
        var errors = process.StandardError.ReadToEndAsync(Ct);
        await process.WaitForExitAsync(Ct);
        return (process.ExitCode, await output, await errors);
    }
}
