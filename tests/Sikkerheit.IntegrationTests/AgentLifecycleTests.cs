using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Agents;
using Sikkerheit.Host.Jobs;
using Sikkerheit.Host.Reports;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.IntegrationTests;

/// <summary>
/// The rest of the server side of P2 beyond the registry (WP-10): rescan requests, the jobs of the catalog, the data
/// lifecycle of devices, the Teams digest, the health signals and the rate limits.
/// </summary>
public sealed class AgentLifecycleTests(PostgresFixture postgres) : IAsyncLifetime
{
    private AgentHost _host = null!;

    public async ValueTask InitializeAsync() => _host = await AgentHost.StartAsync(postgres);

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    private static CancellationToken Ct => AgentHost.Ct;

    private DateTimeOffset Now => _host.Clock.GetUtcNow();

    private string DevicePath(Guid device, string tail = "") => $"/api/v1/organizations/{_host.Org}/devices/{device}{tail}";

    [Fact]
    public async Task A_rescan_request_is_delivered_with_the_check_in_and_completed_by_its_batch()
    {
        var agent = await _host.EnrolledAsync();
        var key = Guid.NewGuid();
        var requested = await _host.Admin.PostAsync(DevicePath(agent.DeviceId!.Value, "/scan-requests"),
            new { idempotencyKey = key, reason = "verify_remediation" }, "ScanRequest");
        Assert.Equal(HttpStatusCode.Accepted, requested.Status);
        var id = requested.Body.GetProperty("id").GetString();
        Assert.Equal("requested", requested.Body.GetProperty("state").GetString());
        // The same key and a second request both return the open one.
        var repeat = await _host.Admin.PostAsync(DevicePath(agent.DeviceId.Value, "/scan-requests"),
            new { idempotencyKey = key, reason = "verify_remediation" }, "ScanRequest");
        var other = await _host.Admin.PostAsync(DevicePath(agent.DeviceId.Value, "/scan-requests"),
            new { idempotencyKey = Guid.NewGuid(), reason = "verify_remediation" }, "ScanRequest");
        Assert.Equal((id, id), (repeat.Body.GetProperty("id").GetString(), other.Body.GetProperty("id").GetString()));

        var config = await agent.CheckInAsync();
        Assert.Equal(id, config.Body.GetProperty("pendingScanRequestId").GetString());
        Assert.Equal("delivered", await _host.ReadAsync(async scope => (await scope.Db.ScanRequests.SingleAsync(Ct)).State));

        var batch = agent.Batch(edit: b => b["scanRequestId"] = id);
        Assert.Equal(HttpStatusCode.OK, (await agent.SubmitAsync(batch)).Status);
        Assert.Equal("completed", await _host.ReadAsync(async scope => (await scope.Db.ScanRequests.SingleAsync(Ct)).State));
        Assert.Null((await agent.CheckInAsync()).Body.GetProperty("pendingScanRequestId").GetString());
    }

    [Fact]
    public async Task A_foreign_or_expired_scan_request_id_is_ignored_and_open_requests_expire_after_a_day()
    {
        var agent = await _host.EnrolledAsync();
        var foreign = agent.Batch(edit: b => b["scanRequestId"] = Guid.NewGuid().ToString());
        Assert.Equal(HttpStatusCode.OK, (await agent.SubmitAsync(foreign)).Status);
        Assert.Contains(_host.Factory.Logs.Entries, e => e.Message.Contains("is not an open request", StringComparison.Ordinal));

        await _host.Admin.PostAsync(DevicePath(agent.DeviceId!.Value, "/scan-requests"),
            new { idempotencyKey = Guid.NewGuid(), reason = "verify_remediation" }, "ScanRequest");
        _host.Clock.Set(Now.AddHours(25));
        await _host.Factory.Services.GetRequiredService<Scheduler>().RunOnceAsync(Ct);
        await _host.RunJobsAsync();
        Assert.Equal("expired", await _host.ReadAsync(async scope => (await scope.Db.ScanRequests.SingleAsync(Ct)).State));
    }

    [Fact]
    public async Task Deleting_the_organization_removes_the_rows_of_devices_and_sessions_and_the_export_carries_them()
    {
        var agent = await _host.EnrolledAsync();
        await agent.SubmitAsync(agent.Batch());
        var export = await _host.Admin.PostAsync($"/api/v1/organizations/{_host.Org}/exports", new { idempotencyKey = Guid.NewGuid() }, "OrganizationExport");
        Assert.Equal(HttpStatusCode.Accepted, export.Status);
        await _host.RunJobsAsync();
        var id = export.Body.GetProperty("id").GetString();
        var download = await _host.Admin.DownloadAsync($"/api/v1/organizations/{_host.Org}/exports/{id}/download");
        using (var zip = new System.IO.Compression.ZipArchive(new MemoryStream(download.Body)))
        {
            var names = zip.Entries.Select(e => e.FullName).ToList();
            Assert.Contains(names, n => n.Contains("device", StringComparison.Ordinal));
            Assert.Contains(names, n => n.Contains("scan_batch", StringComparison.Ordinal));
            Assert.Contains(names, n => n.Contains("enrollment_key", StringComparison.Ordinal));
        }

        await _host.LifecycleAsync("disable");
        var scheduled = await _host.Admin.PostAsync($"/api/v1/organizations/{_host.Org}/lifecycle",
            new { action = "schedule_deletion", reason = "Avslutning", idempotencyKey = Guid.NewGuid(), exportWaived = true }, "Organization");
        Assert.Equal(HttpStatusCode.OK, scheduled.Status);
        _host.Clock.Set(Now.AddDays(31));
        await _host.Factory.Services.GetRequiredService<Scheduler>().RunOnceAsync(Ct);
        await _host.RunJobsAsync();
        await using var platform = await _host.Scopes.PlatformAsync(Ct);
        Assert.Equal(0, await platform.Db.AgentSessions.CountAsync(Ct));
        // The agent is told the device is unknown, and its key is not accepted any more.
        var session = await agent.SessionAsync();
        Assert.Equal((HttpStatusCode.Unauthorized, ProblemCodes.DeviceUnknown), (session.Status, session.Code));
        using var fresh = _host.NewAgent("PC-NY");
        Assert.Equal(ProblemCodes.EnrollmentKeyInvalid, (await fresh.EnrollAsync()).Code);
    }

    [Fact]
    public async Task Retention_removes_old_batches_requests_and_presence()
    {
        var agent = await _host.EnrolledAsync();
        await agent.SubmitAsync(agent.Batch());
        _host.Clock.Set(Now.AddDays(95));
        await using (var platform = await _host.Scopes.PlatformAsync(Ct))
        {
            await JobQueue.EnqueueAsync(platform, "retention_purge", _host.Org, null, "2027-01-17", Now, Ct);
            await platform.CommitAsync(Ct);
        }
        await _host.RunJobsAsync();
        // Batches and the observations of 90 days ago are gone; the device and its findings stay; presence is kept 12 months.
        Assert.Equal(0, await _host.ReadAsync(scope => scope.Db.ScanBatches.CountAsync(Ct)));
        Assert.Equal(1, await _host.ReadAsync(scope => scope.Db.Devices.CountAsync(Ct)));
        Assert.True(await _host.ReadAsync(scope => scope.Db.DevicePresences.CountAsync(Ct)) > 0);
        var summary = Assert.Single(await _host.AuditAsync("retention.purge_summary"));
        Assert.Equal(1, JsonDocument.Parse(summary.Details!).RootElement.GetProperty("deleted").GetProperty("scan_batch").GetInt32());
    }

    private static string Cvrf(string month, params (string Build, string Kb)[] fixes)
    {
        var products = new JsonArray(
            new JsonObject { ["ProductID"] = "12001", ["Value"] = "Windows 11 Version 25H2 for x64-based Systems" },
            new JsonObject { ["ProductID"] = "12002", ["Value"] = "Windows Server 2025" });
        var remediations = new JsonArray();
        foreach (var (build, kb) in fixes)
        {
            remediations.Add(new JsonObject
            {
                ["Type"] = 2, ["FixedBuild"] = build, ["Description"] = new JsonObject { ["Value"] = kb },
                ["ProductID"] = new JsonArray("12001"),
            });
        }
        remediations.Add(new JsonObject
        {
            ["Type"] = 2, ["FixedBuild"] = "10.0.26100.7777", ["Description"] = new JsonObject { ["Value"] = "5069999" },
            ["ProductID"] = new JsonArray("12002"),
        });
        return new JsonObject
        {
            ["DocumentTracking"] = new JsonObject { ["InitialReleaseDate"] = month + "-13T08:00:00Z" },
            ["ProductTree"] = new JsonObject { ["FullProductName"] = products },
            ["Vulnerability"] = new JsonArray(new JsonObject { ["Remediations"] = remediations }),
        }.ToJsonString();
    }

    [Fact]
    public async Task The_release_import_job_reads_the_msrc_document_of_the_month_into_drafts_of_client_products_only()
    {
        _host.Factory.Msrc.Documents["2026-Oct"] = Cvrf("2026-10", ("10.0.26200.9711", "KB5062002"), ("10.0.26200.9711", "KB5062002"));
        var import = await _host.Admin.PostAsync("/api/v1/windows-releases/imports", new { source = "msrc_cvrf", securityMonth = "2026-10" },
            "WindowsReleaseMonth");
        Assert.Equal(HttpStatusCode.Accepted, import.Status);
        Assert.Equal(("draft", 0), (import.Body.GetProperty("state").GetString(), import.Body.GetProperty("releases").GetInt32()));
        await _host.RunJobsAsync();
        Assert.Equal(new Uri("https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Oct"), Assert.Single(_host.Factory.Msrc.Requests));
        var page = await _host.Admin.GetAsync("/api/v1/windows-releases?state=draft&securityMonth=2026-10", "WindowsReleasePage");
        var release = Assert.Single(page.Body.GetProperty("items").EnumerateArray());
        Assert.Equal((26200, 9711, "5062002", "draft"), (release.GetProperty("branchBuild").GetInt32(), release.GetProperty("ubr").GetInt32(),
            release.GetProperty("kb").GetString(), release.GetProperty("state").GetString()));

        // Verified, the month cannot be changed by a later import that contradicts it.
        Assert.Equal(HttpStatusCode.OK, (await _host.VerifyMonthAsync("2026-10")).Status);
        var contradiction = await _host.ImportReleasesAsync("2026-10", new AgentHost.ReleaseEntry(26200, 9711, "5069999", "security_monthly", "2026-10"));
        Assert.Equal((HttpStatusCode.UnprocessableEntity, ProblemCodes.ValidationFailed), (contradiction.Status, contradiction.Code));
        // The same entry is skipped.
        var same = await _host.ImportReleasesAsync("2026-10", new AgentHost.ReleaseEntry(26200, 9711, "5062002", "security_monthly", "2026-10",
            "2026-10-13T08:00:00Z"));
        Assert.Equal(HttpStatusCode.Accepted, same.Status);
    }

    [Fact]
    public async Task A_month_without_entries_is_verified_only_with_the_no_new_releases_flag()
    {
        var refused = await _host.VerifyMonthAsync("2026-11");
        Assert.Equal((HttpStatusCode.UnprocessableEntity, ProblemCodes.ValidationFailed), (refused.Status, refused.Code));
        var verified = await _host.VerifyMonthAsync("2026-11", noNewReleases: true);
        Assert.Equal((HttpStatusCode.OK, true), (verified.Status, verified.Body.GetProperty("noNewReleases").GetBoolean()));
        Assert.Equal("verified", verified.Body.GetProperty("state").GetString());
    }

    [Fact]
    public async Task An_unverified_month_seven_days_after_patch_tuesday_raises_the_alert_of_the_catalog()
    {
        await _host.ImportReleasesAsync("2026-09", new AgentHost.ReleaseEntry(26200, 9611, "5062001", "security_monthly", "2026-09"));
        await _host.VerifyMonthAsync("2026-09");
        await _host.ImportReleasesAsync("2026-10", new AgentHost.ReleaseEntry(26200, 9711, "5062002", "security_monthly", "2026-10"));
        // Patch Tuesday of October 2026 is the 13th: the seventh day after it is the 20th.
        await _host.MoveToAsync(new DateTimeOffset(2026, 10, 19, 12, 0, 0, TimeSpan.Zero));
        await RunCheckAsync("2026-10-19");
        Assert.DoesNotContain(_host.Factory.Logs.Entries, e => e.Level == LogLevel.Error && e.Message.Contains("is not verified", StringComparison.Ordinal));
        await _host.MoveToAsync(new DateTimeOffset(2026, 10, 21, 12, 0, 0, TimeSpan.Zero));
        await RunCheckAsync("2026-10-21");
        Assert.Contains(_host.Factory.Logs.Entries, e => e.Level == LogLevel.Error && e.Message.Contains("2026-10 is not verified", StringComparison.Ordinal));
        var before = _host.Factory.Logs.Entries.Count(e => e.Level == LogLevel.Error);
        await _host.VerifyMonthAsync("2026-10");
        await RunCheckAsync("2026-10-22");
        Assert.Equal(before, _host.Factory.Logs.Entries.Count(e => e.Level == LogLevel.Error));
    }

    private async Task RunCheckAsync(string period)
    {
        await using (var platform = await _host.Scopes.PlatformAsync(Ct))
        {
            await JobQueue.EnqueueAsync(platform, "release_catalog_check", null, null, period, Now, Ct);
            await platform.CommitAsync(Ct);
        }
        await _host.RunJobsAsync();
    }

    [Fact]
    public async Task The_teams_digest_counts_new_devices_and_key_replacements_and_reports_an_unverified_month()
    {
        await _host.ImportReleasesAsync("2026-09", new AgentHost.ReleaseEntry(26200, 9611, "5062001", "security_monthly", "2026-09"));
        var agent = await _host.EnrolledAsync("PC-MED-NAVN");
        // Audit events carry the wall clock of the server, so the window of the digest is around the real time.
        var digest = _host.Factory.Services.GetServices<IJobHandler>().OfType<TeamsDigestJob>().Single();
        var items = await digest.CollectAsync(DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddHours(1), Ct);
        Assert.Contains(items, i => i is { Kind: "device", Text: "1 nye enheter registrert" });
        Assert.DoesNotContain(items, i => i.Text.Contains("PC-MED-NAVN", StringComparison.Ordinal));
        Assert.Contains(items, i => i is { Kind: "catalog", OrganizationName: "Windows-utgivelser" } && i.Text.Contains("RB-13", StringComparison.Ordinal));
        Assert.True(agent.DeviceId.HasValue);
    }

    [Fact]
    public async Task The_health_check_logs_the_alerts_of_the_fleet_without_computer_names()
    {
        var agents = new List<FakeAgent>();
        for (var i = 0; i < 4; i++)
        {
            agents.Add(await _host.EnrolledAsync("PC-" + i));
        }
        // A clone of the first one raises an identity conflict.
        using var clone = new FakeAgent(_host.Factory, _host.KeySecret, agents[0].InstallationId, "PC-KLON", machineGuid: "0A1B2C3D-0000-4000-8000-00000000AAAA");
        await clone.EnrollAsync();
        // Three days without any check-in: all devices are silent, none is dormant yet.
        _host.Clock.Set(Now.AddDays(4));
        await _host.Factory.Services.GetRequiredService<Scheduler>().RunOnceAsync(Ct);
        await _host.RunJobsAsync();
        var errors = _host.Factory.Logs.Entries.Where(e => e.Level == LogLevel.Error).Select(e => e.Message).ToList();
        Assert.Contains(errors, m => m.Contains("RB-12", StringComparison.Ordinal) && m.Contains("4 of 4", StringComparison.Ordinal));
        Assert.Contains(errors, m => m.Contains("RB-11", StringComparison.Ordinal) && m.Contains("identity conflict", StringComparison.Ordinal));
        Assert.DoesNotContain(errors, m => m.Contains("PC-", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Anonymous_agent_requests_are_limited_per_address()
    {
        using var agent = _host.NewAgent();
        FakeAgent.Reply? last = null;
        for (var i = 0; i < 61; i++)
        {
            last = await agent.ChallengeAsync();
        }
        Assert.Equal((HttpStatusCode.TooManyRequests, ProblemCodes.RateLimited), (last!.Status, last.Code));
        Assert.True(int.Parse(last.Headers["Retry-After"]) > 0);
        _host.Clock.Set(Now.AddMinutes(2));
        Assert.Equal(HttpStatusCode.Created, (await agent.ChallengeAsync()).Status);
    }

    [Fact]
    public async Task Registrations_are_limited_per_enrollment_key()
    {
        FakeAgent.Reply? last = null;
        for (var i = 0; i < 21; i++)
        {
            using var agent = _host.NewAgent("PC-" + i);
            last = await agent.EnrollAsync();
            // Spread the registrations over the minutes so that only the limit of the key is reached.
            _host.Clock.Set(Now.AddMinutes(1.5));
        }
        Assert.Equal((HttpStatusCode.TooManyRequests, ProblemCodes.RateLimited), (last!.Status, last.Code));
    }

    [Fact]
    public async Task The_identity_conflict_is_kept_for_the_technician_and_keep_clears_it()
    {
        var agent = await _host.EnrolledAsync();
        agent.Fingerprint = FakeAgent.ComputeFingerprint(agent.InstallationId, "4C4C4544-0042-3510-8058-B4C04F4E3732", "AAAAAAAA-0000-4000-8000-000000000000");
        agent.DisplayName = "PC-ANNE-NY";
        Assert.Equal(HttpStatusCode.Conflict, (await agent.CheckInAsync()).Status);
        var listed = await _host.Admin.GetAsync($"/api/v1/organizations/{_host.Org}/devices", "DevicePage");
        var conflict = listed.Body.GetProperty("items")[0].GetProperty("identityConflict");
        Assert.Equal(("fingerprint", "PC-ANNE-NY"), (conflict.GetProperty("kind").GetString(), conflict.GetProperty("reportedDisplayName").GetString()));
        var kept = await _host.Admin.PostAsync(DevicePath(agent.DeviceId!.Value, "/identity-resolutions"), new { decision = "keep" }, "Device");
        Assert.Equal("ok", kept.Body.GetProperty("identityState").GetString());
        // A decision for a conflict of another kind leaves the device as it is.
        var other = await _host.Admin.PostAsync(DevicePath(agent.DeviceId.Value, "/identity-resolutions"), new { decision = "accept_new_key" }, "Device");
        Assert.Equal("ok", other.Body.GetProperty("identityState").GetString());
    }

    [Fact]
    public async Task Roles_limit_the_operations_of_devices_and_keys()
    {
        var agent = await _host.EnrolledAsync();
        var technician = await StaffClient.SignInAsync(_host.Factory, "Technician");
        var reader = await StaffClient.SignInAsync(_host.Factory, "Reader");
        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync($"/api/v1/organizations/{_host.Org}/devices", "DevicePage")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await reader.GetAsync($"/api/v1/organizations/{_host.Org}/enrollment-keys")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await technician.PostAsync($"/api/v1/organizations/{_host.Org}/enrollment-keys", new { label = "x" })).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await technician.PostAsync(DevicePath(agent.DeviceId!.Value, "/revoke"), new { })).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await technician.PatchAsync(DevicePath(agent.DeviceId.Value), new { displayName = "x" })).Status);
        Assert.Equal(HttpStatusCode.Accepted, (await technician.PostAsync(DevicePath(agent.DeviceId.Value, "/scan-requests"),
            new { idempotencyKey = Guid.NewGuid(), reason = "verify_remediation" }, "ScanRequest")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await reader.PostAsync(DevicePath(agent.DeviceId.Value, "/scan-requests"),
            new { idempotencyKey = Guid.NewGuid(), reason = "verify_remediation" })).Status);
    }
}
