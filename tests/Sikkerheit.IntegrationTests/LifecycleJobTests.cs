using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.IntegrationTests;

/// <summary>AT-09 and AT-10: export with a manifest, deletion after the due date, retention terms and the Teams digest.</summary>
public sealed class LifecycleJobTests(PostgresFixture postgres) : IAsyncLifetime
{
    private const string Oslo = "Europe/Oslo";
    private const string GlobalAdministrator = "62e90394-69f5-4237-9190-012177145e10";
    private static readonly ContractSchemas Schemas = new();
    private ApiFactory _factory = null!;
    private StaffClient _admin = null!;

    public async ValueTask InitializeAsync()
    {
        _factory = await ApiFactory.CreateAsync(postgres);
        _factory.Clock.SetLocal(Oslo, 2026, 10, 7, 10);
        _admin = await StaffClient.SignInAsync(_factory, "Admin");
    }

    public async ValueTask DisposeAsync() => await _factory.DisposeAsync();

    private CancellationToken Ct => TestContext.Current.CancellationToken;

    private async Task RunJobsAsync()
    {
        var runner = _factory.Services.GetRequiredService<JobRunner>();
        while (await runner.RunOnceAsync(Ct))
        {
        }
    }

    private async Task MoveToAsync(int year, int month, int day, int hour, int minute = 0)
    {
        _factory.Clock.SetLocal(Oslo, year, month, day, hour, minute);
        _admin = await StaffClient.SignInAsync(_factory, "Admin");
    }

    /// <summary>No Security Defaults and no policy: M365-003 is critical; the admin without MFA gives M365-002.</summary>
    private async Task<string> CollectedOrganizationAsync(string name = "Fjord Drift AS")
    {
        var tenant = _factory.Graph.AddTenant();
        tenant.AddUser("alice");
        tenant.Assignments.Add((tenant.AddUser("ola.admin").Id, GlobalAdministrator, false));
        tenant.Assignments.Add((tenant.AddUser("kari.admin", methods: "fido2").Id, GlobalAdministrator, false));
        var created = await _admin.PostAsync("/api/v1/organizations", new { name, timezone = Oslo, reportLanguage = "nb" }, "Organization");
        var org = created.Body.GetProperty("id").GetString()!;
        await _admin.PostAsync($"/api/v1/organizations/{org}/m365-connection/consent", new { tenantHint = tenant.TenantId.ToString() }, "ConsentStart");
        await _admin.PostAsync($"/api/v1/organizations/{org}/m365-connection/verify", new { }, "TenantConnection");
        await RunJobsAsync();
        return org;
    }

    private async Task<StaffClient.Answer> LifecycleAsync(string org, string action, bool? exportWaived = null) =>
        await _admin.PostAsync($"/api/v1/organizations/{org}/lifecycle", exportWaived is null
            ? new { action, reason = "Kunden har sagt opp avtalen", idempotencyKey = Guid.NewGuid() }
            : new { action, reason = "Kunden har sagt opp avtalen", idempotencyKey = Guid.NewGuid(), exportWaived });

    private async Task<string> ExportAsync(string org)
    {
        var created = await _admin.PostAsync($"/api/v1/organizations/{org}/exports", new { idempotencyKey = Guid.NewGuid() },
            "OrganizationExport");
        Assert.Equal(HttpStatusCode.Accepted, created.Status);
        await RunJobsAsync();
        return created.Body.GetProperty("id").GetString()!;
    }

    [Fact]
    public async Task Export_has_every_table_the_reports_and_a_manifest_with_hashes()
    {
        var org = await CollectedOrganizationAsync();
        await MoveToAsync(2026, 10, 12, 9);
        var report = await _admin.PostAsync($"/api/v1/organizations/{org}/reports",
            new { periodStart = "2026-10-05T00:00:00+02:00", periodEnd = "2026-10-12T00:00:00+02:00", format = "html" }, "Report");
        await RunJobsAsync();

        var key = Guid.NewGuid();
        var created = await _admin.PostAsync($"/api/v1/organizations/{org}/exports", new { idempotencyKey = key }, "OrganizationExport");
        var repeat = await _admin.PostAsync($"/api/v1/organizations/{org}/exports", new { idempotencyKey = key }, "OrganizationExport");
        Assert.Equal(created.Body.GetProperty("id").GetString(), repeat.Body.GetProperty("id").GetString());
        var exportId = created.Body.GetProperty("id").GetString()!;
        Assert.Equal("queued", created.Body.GetProperty("state").GetString());
        var early = await _admin.DownloadAsync($"/api/v1/organizations/{org}/exports/{exportId}/download");
        Assert.Equal(ProblemCodes.ResourceNotReady, early.Code);
        await RunJobsAsync();

        var state = await _admin.GetAsync($"/api/v1/organizations/{org}/exports/{exportId}", "OrganizationExport");
        Assert.Equal("ready", state.Body.GetProperty("state").GetString());
        var technician = await StaffClient.SignInAsync(_factory, "Technician");
        Assert.Equal(ProblemCodes.Forbidden,
            (await technician.DownloadAsync($"/api/v1/organizations/{org}/exports/{exportId}/download")).Code);

        var file = await _admin.DownloadAsync($"/api/v1/organizations/{org}/exports/{exportId}/download");
        Assert.Equal(HttpStatusCode.OK, file.Status);
        Assert.Empty(Schemas.ValidateResponseHeaders("downloadOrganizationExport", 200, file.Headers));
        using var zip = new ZipArchive(new MemoryStream(file.Body), ZipArchiveMode.Read);
        var manifest = JsonDocument.Parse(Read(zip, "manifest.json")).RootElement;
        Assert.Equal(org, manifest.GetProperty("organizationId").GetString());
        var listed = manifest.GetProperty("files").EnumerateArray().ToList();
        foreach (var entry in listed)
        {
            var content = Read(zip, entry.GetProperty("path").GetString()!);
            Assert.Equal(entry.GetProperty("sha256").GetString(), Convert.ToHexStringLower(SHA256.HashData(content)));
        }
        var paths = listed.Select(e => e.GetProperty("path").GetString()).ToList();
        Assert.Contains("data/finding_event.jsonl", paths);
        Assert.Contains($"reports/report-{report.Body.GetProperty("id").GetString()}.html", paths);
        var organization = JsonDocument.Parse(Encoding.UTF8.GetString(Read(zip, "data/organization.jsonl"))).RootElement;
        Assert.Equal("Fjord Drift AS", organization.GetProperty("name").GetString());
        Assert.NotEmpty(Encoding.UTF8.GetString(Read(zip, "data/observation.jsonl")).Split('\n', StringSplitOptions.RemoveEmptyEntries));

        var audit = await _admin.GetAsync($"/api/v1/organizations/{org}/audit-events", "AuditEventPage");
        Assert.Contains(audit.Body.GetProperty("items").EnumerateArray(),
            e => e.GetProperty("action").GetString() == "organization_export.download");
    }

    [Fact]
    public async Task Organization_is_deleted_after_the_due_date_with_files_and_a_tombstone()
    {
        var org = await CollectedOrganizationAsync();
        await MoveToAsync(2026, 10, 12, 9);
        await _admin.PostAsync($"/api/v1/organizations/{org}/reports",
            new { periodStart = "2026-10-05T00:00:00+02:00", periodEnd = "2026-10-12T00:00:00+02:00", format = "html" }, "Report");
        await RunJobsAsync();
        Assert.Equal("disabled", (await LifecycleAsync(org, "disable")).Body.GetProperty("status").GetString());
        Assert.Equal(ProblemCodes.LifecycleTransitionForbidden, (await LifecycleAsync(org, "schedule_deletion")).Code);
        await ExportAsync(org);
        var scheduled = await LifecycleAsync(org, "schedule_deletion");
        Assert.Equal("deletion_scheduled", scheduled.Body.GetProperty("status").GetString());
        Assert.True(Directory.Exists(Path.Combine(_factory.FilesDirectory, "reports", org)));

        // Before the due date nothing happens; after it the scheduler queues organization_delete.
        var scheduler = _factory.Services.GetRequiredService<Scheduler>();
        await MoveToAsync(2026, 11, 10, 12);
        await scheduler.RunOnceAsync(Ct);
        await RunJobsAsync();
        Assert.Equal(HttpStatusCode.OK, (await _admin.GetAsync($"/api/v1/organizations/{org}", "Organization")).Status);
        await MoveToAsync(2026, 11, 12, 12);
        await scheduler.RunOnceAsync(Ct);
        await RunJobsAsync();

        var gone = await _admin.GetAsync($"/api/v1/organizations/{org}");
        Assert.Equal((HttpStatusCode.NotFound, ProblemCodes.NotFound), (gone.Status, gone.Code));
        Assert.False(Directory.Exists(Path.Combine(_factory.FilesDirectory, "reports", org)));
        Assert.False(Directory.Exists(Path.Combine(_factory.FilesDirectory, "exports", org)));
        Assert.Contains(Directory.GetFiles(_factory.SecurityLogDirectory),
            f => File.ReadAllText(f).Contains("organization.delete", StringComparison.Ordinal)
                 && File.ReadAllText(f).Contains(org, StringComparison.Ordinal));
        var scopes = _factory.Services.GetRequiredService<DbScopes>();
        await using var platform = await scopes.PlatformAsync(Ct);
        await using var command = new NpgsqlCommand("select count(*) from organization_tombstone where id = @id",
            platform.Connection, platform.Transaction);
        command.Parameters.AddWithValue("id", Guid.Parse(org));
        Assert.Equal(1L, await command.ExecuteScalarAsync(Ct));
        await using var scope = await scopes.OrganizationAsync(Guid.Parse(org), Ct);
        Assert.Equal(0, await scope.Db.Findings.CountAsync(Ct));
        Assert.Equal(0, await scope.Db.AuditEvents.CountAsync(Ct));
    }

    [Fact]
    public async Task Retention_replaces_old_evidence_by_the_snapshot_and_writes_a_summary()
    {
        var org = await CollectedOrganizationAsync();
        var scopes = _factory.Services.GetRequiredService<DbScopes>();
        await using (var before = await scopes.OrganizationAsync(Guid.Parse(org), Ct))
        {
            Assert.NotEqual(0, await before.Db.Observations.CountAsync(Ct));
        }
        // 100 days later at 03:00 the daily purge removes observations older than 90 days.
        await MoveToAsync(2027, 1, 15, 3);
        await _factory.Services.GetRequiredService<Scheduler>().RunOnceAsync(Ct);
        await RunJobsAsync();

        await using (var after = await scopes.OrganizationAsync(Guid.Parse(org), Ct))
        {
            Assert.Equal(0, await after.Db.Observations.CountAsync(Ct));
            Assert.All(await after.Db.Assessments.AsNoTracking().ToListAsync(Ct),
                a => Assert.Equal("expired", a.EvidenceAvailability));
            Assert.NotEqual(0, await after.Db.Findings.CountAsync(f => f.TechnicalState == "open", Ct));
        }
        var audit = await _admin.GetAsync($"/api/v1/organizations/{org}/audit-events", "AuditEventPage");
        var summary = Assert.Single(audit.Body.GetProperty("items").EnumerateArray(),
            e => e.GetProperty("action").GetString() == "retention.purge_summary");
        Assert.Equal("system", summary.GetProperty("actorType").GetString());
        Assert.True(summary.GetProperty("details").GetProperty("snapshotted").GetInt32() > 0);
        Assert.True(summary.GetProperty("details").GetProperty("deleted").GetProperty("observation").GetInt32() > 0);
        var assessments = await _admin.GetAsync($"/api/v1/organizations/{org}/assessments", "AssessmentPage");
        Assert.All(assessments.Body.GetProperty("items").EnumerateArray(), a =>
            Assert.Equal(JsonValueKind.Null, a.GetProperty("evidence").ValueKind));
    }

    [Fact]
    public async Task Teams_digest_lists_new_critical_issues_once_per_day_without_user_names()
    {
        var org = await CollectedOrganizationAsync("Fjord [klikk](https://evil.example) AS");
        var scheduler = _factory.Services.GetRequiredService<Scheduler>();
        await MoveToAsync(2026, 10, 8, 7, 15);
        await scheduler.RunOnceAsync(Ct);
        await RunJobsAsync();
        Assert.Empty(_factory.Teams.Requests);

        await MoveToAsync(2026, 10, 8, 7, 45);
        await scheduler.RunOnceAsync(Ct);
        await RunJobsAsync();
        var (uri, body) = Assert.Single(_factory.Teams.Requests);
        Assert.Equal(ApiFactory.TeamsWebhook, uri.ToString());
        var card = JsonDocument.Parse(body).RootElement.GetProperty("attachments")[0].GetProperty("content");
        var runs = card.GetProperty("body").EnumerateArray()
            .Select(b => b.GetProperty("inlines")[0].GetProperty("text").GetString()!).ToList();
        Assert.Contains("Fjord [klikk](https://evil.example) AS", runs);
        Assert.Contains(runs, t => t.Contains("nye kritiske", StringComparison.Ordinal) && t.Contains("M365-003", StringComparison.Ordinal));
        Assert.DoesNotContain("@fjord.example", body, StringComparison.Ordinal);
        Assert.All(card.GetProperty("body").EnumerateArray(), b => Assert.Equal("RichTextBlock", b.GetProperty("type").GetString()));

        // The same day is sent once, even when the job runs again.
        await scheduler.RunOnceAsync(Ct);
        var scopes = _factory.Services.GetRequiredService<DbScopes>();
        await using (var platform = await scopes.PlatformAsync(Ct))
        {
            await using var requeue = new NpgsqlCommand(
                "update job set state = 'queued', attempts = 0, next_attempt_at = @now where type = 'teams_digest'",
                platform.Connection, platform.Transaction);
            requeue.Parameters.AddWithValue("now", _factory.Clock.GetUtcNow().AddMinutes(-1));
            await requeue.ExecuteNonQueryAsync(Ct);
            await platform.CommitAsync(Ct);
        }
        await RunJobsAsync();
        Assert.Single(_factory.Teams.Requests);
        _ = org;
    }

    private static byte[] Read(ZipArchive zip, string path)
    {
        using var stream = zip.GetEntry(path)!.Open();
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        return buffer.ToArray();
    }
}
