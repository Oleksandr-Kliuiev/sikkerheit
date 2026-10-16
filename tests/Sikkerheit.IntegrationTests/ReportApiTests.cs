using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.IntegrationTests;

/// <summary>FR-07 and AT-08: the weekly HTML report, its immutable snapshot, coverage and the delivery headers.</summary>
public sealed class ReportApiTests(PostgresFixture postgres) : IAsyncLifetime
{
    private const string Oslo = "Europe/Oslo";
    private const string GlobalAdministrator = "62e90394-69f5-4237-9190-012177145e10";
    private static readonly ContractSchemas Schemas = new();
    private ApiFactory _factory = null!;
    private StaffClient _admin = null!;

    public async ValueTask InitializeAsync()
    {
        _factory = await ApiFactory.CreateAsync(postgres);
        // Wednesday of ISO week 41, 2026 (5–11 October); Oslo is UTC+2 until 25 October.
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

    private async Task CollectAsync(string org)
    {
        var request = await _admin.PostAsync($"/api/v1/organizations/{org}/collection-runs",
            new { idempotencyKey = Guid.NewGuid() }, "CollectionRun");
        Assert.Equal(HttpStatusCode.Accepted, request.Status);
        await RunJobsAsync();
    }

    /// <summary>A tenant with Security Defaults, two FIDO2 admins, Bob with Authenticator, Alice and Carol without MFA.</summary>
    private async Task<(string Org, FakeTenant Tenant, FakeUser Alice)> ConnectedOrganizationAsync()
    {
        var tenant = _factory.Graph.AddTenant();
        tenant.SecurityDefaults = true;
        tenant.GrantPolicies.Clear();
        var alice = tenant.AddUser("alice");
        tenant.AddUser("carol");
        tenant.AddUser("bob", methods: "microsoftAuthenticator");
        for (var i = 0; i < 2; i++)
        {
            tenant.Assignments.Add((tenant.AddUser("admin" + i, methods: "fido2").Id, GlobalAdministrator, false));
        }
        var created = await _admin.PostAsync("/api/v1/organizations",
            new { name = "Fjord & Sønn \"Rapport\" AS", timezone = Oslo, reportLanguage = "nb" }, "Organization");
        var org = created.Body.GetProperty("id").GetString()!;
        await _admin.PostAsync($"/api/v1/organizations/{org}/m365-connection/consent",
            new { tenantHint = tenant.TenantId.ToString() }, "ConsentStart");
        var verified = await _admin.PostAsync($"/api/v1/organizations/{org}/m365-connection/verify", new { }, "TenantConnection");
        Assert.Equal("active", verified.Body.GetProperty("status").GetString());
        await RunJobsAsync();
        return (org, tenant, alice);
    }

    private async Task<StaffClient.Answer> CreateReportAsync(string org, string start, string end) =>
        await _admin.PostAsync($"/api/v1/organizations/{org}/reports",
            new { periodStart = start, periodEnd = end, format = "html" });

    [Fact]
    public async Task Weekly_report_is_generated_on_monday_and_delivered_with_the_contract_headers()
    {
        var (org, tenant, alice) = await ConnectedOrganizationAsync();

        // Thursday: Alice registers Authenticator (fixed); Carol stays without MFA (open).
        _factory.Clock.SetLocal(Oslo, 2026, 10, 8, 12);
        tenant.Users[tenant.Users.IndexOf(alice)] = alice with { Methods = ["microsoftAuthenticator"] };
        _admin = await StaffClient.SignInAsync(_factory, "Admin");
        await CollectAsync(org);
        // Sunday evening: a fresh collection before the end of the week.
        _factory.Clock.SetLocal(Oslo, 2026, 10, 11, 20);
        _admin = await StaffClient.SignInAsync(_factory, "Admin");
        await CollectAsync(org);

        // Monday 05:30 the report is not due yet; at 07:00 the scheduler creates weekly_report for week 41 only.
        var scheduler = _factory.Services.GetRequiredService<Scheduler>();
        _factory.Clock.SetLocal(Oslo, 2026, 10, 12, 5, 30);
        await scheduler.RunOnceAsync(Ct);
        _factory.Clock.SetLocal(Oslo, 2026, 10, 12, 7);
        _admin = await StaffClient.SignInAsync(_factory, "Admin");
        await scheduler.RunOnceAsync(Ct);
        Assert.Equal(["2026-W41"], await WeeklyJobsAsync(org));

        // A staff request before generation returns the queued report; its download is not ready yet.
        var queued = await CreateReportAsync(org, "2026-10-05T00:00:00+02:00", "2026-10-12T00:00:00+02:00");
        Assert.Equal(HttpStatusCode.Accepted, queued.Status);
        Assert.Empty(Schemas.ValidateComponent("Report", queued.Body));
        Assert.Equal("queued", queued.Body.GetProperty("state").GetString());
        var reportId = queued.Body.GetProperty("id").GetString()!;
        var early = await _admin.DownloadAsync($"/api/v1/organizations/{org}/reports/{reportId}/download");
        Assert.Equal((HttpStatusCode.Conflict, ProblemCodes.ResourceNotReady), (early.Status, early.Code));

        await RunJobsAsync();
        var list = await _admin.GetAsync($"/api/v1/organizations/{org}/reports", "ReportPage");
        var report = Assert.Single(list.Body.GetProperty("items").EnumerateArray());
        Assert.Equal(reportId, report.GetProperty("id").GetString());
        Assert.Equal("ready", report.GetProperty("state").GetString());
        Assert.Equal("2026-10-04T22:00:00Z", report.GetProperty("periodStart").GetString());
        Assert.Equal("2026-10-11T22:00:00Z", report.GetProperty("periodEnd").GetString());
        Assert.Equal((Oslo, "nb"), (report.GetProperty("timezone").GetString(), report.GetProperty("language").GetString()));

        var reader = await StaffClient.SignInAsync(_factory, "Reader");
        var file = await reader.DownloadAsync($"/api/v1/organizations/{org}/reports/{reportId}/download");
        Assert.Equal(HttpStatusCode.OK, file.Status);
        Assert.Empty(Schemas.ValidateResponseHeaders("downloadReport", 200, file.Headers));
        Assert.Equal("text/html; charset=utf-8", file.Headers["Content-Type"]);
        var html = file.Text;
        Assert.StartsWith("<!doctype html>\n<html lang=\"nb\">", html, StringComparison.Ordinal);
        Assert.Contains("Fjord &amp; Sønn &quot;Rapport&quot; AS", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("http://", html, StringComparison.Ordinal);
        Assert.DoesNotContain("https://", html, StringComparison.Ordinal);
        Assert.Contains("carol@fjord.example", html, StringComparison.Ordinal);
        Assert.Contains("alice@fjord.example", html, StringComparison.Ordinal);
        Assert.Contains("Sikkerhetsrapport", html, StringComparison.Ordinal);

        // A repeat request returns the same ready report; a reader may not create reports.
        var repeat = await CreateReportAsync(org, "2026-10-04T22:00:00Z", "2026-10-11T22:00:00Z");
        Assert.Equal((HttpStatusCode.Accepted, reportId, "ready"),
            (repeat.Status, repeat.Body.GetProperty("id").GetString(), repeat.Body.GetProperty("state").GetString()));
        var forbidden = await reader.PostAsync($"/api/v1/organizations/{org}/reports",
            new { periodStart = "2026-10-04T22:00:00Z", periodEnd = "2026-10-11T22:00:00Z", format = "html" });
        Assert.Equal(ProblemCodes.Forbidden, forbidden.Code);

        var snapshot = await SnapshotAsync(org, reportId);
        var coverage = snapshot.GetProperty("coverage");
        // Ten required pairs: M365-001 of five users, M365-002 of two admins, M365-003/005/006 of the tenant.
        Assert.Equal(10, coverage.GetProperty("pairs").GetInt32());
        Assert.Equal(1.0, coverage.GetProperty("coverageAt").GetDouble());
        Assert.Equal(1.0, coverage.GetProperty("coveragePeriod").GetDouble());
        Assert.Equal(0.9, coverage.GetProperty("compliance").GetDouble(), 6);
        var events = snapshot.GetProperty("events").EnumerateArray()
            .Select(e => e.GetProperty("eventType").GetString() + "/" + e.GetProperty("subject").GetProperty("name").GetString())
            .ToList();
        Assert.Contains("opened/alice@fjord.example", events);
        Assert.Contains("resolved/alice@fjord.example", events);
        var open = Assert.Single(snapshot.GetProperty("openAtEnd").EnumerateArray());
        Assert.Equal("carol@fjord.example", open.GetProperty("subject").GetProperty("name").GetString());

        // Every download is audited.
        var audit = await _admin.GetAsync($"/api/v1/organizations/{org}/audit-events", "AuditEventPage");
        Assert.Contains(audit.Body.GetProperty("items").EnumerateArray(),
            e => e.GetProperty("action").GetString() == "report.download" && e.GetProperty("targetId").GetString() == reportId);
    }

    [Fact]
    public async Task Only_completed_iso_weeks_of_the_organization_timezone_are_accepted()
    {
        var (org, _, _) = await ConnectedOrganizationAsync();
        var current = await CreateReportAsync(org, "2026-10-05T00:00:00+02:00", "2026-10-12T00:00:00+02:00");
        Assert.Equal((HttpStatusCode.UnprocessableEntity, ProblemCodes.ValidationFailed), (current.Status, current.Code));
        var utcMidnight = await CreateReportAsync(org, "2026-09-28T00:00:00Z", "2026-10-05T00:00:00Z");
        Assert.Equal(ProblemCodes.ValidationFailed, utcMidnight.Code);
        var twoWeeks = await CreateReportAsync(org, "2026-09-21T00:00:00+02:00", "2026-10-05T00:00:00+02:00");
        Assert.Equal(ProblemCodes.ValidationFailed, twoWeeks.Code);
        var wrongFormat = await _admin.PostAsync($"/api/v1/organizations/{org}/reports",
            new { periodStart = "2026-09-28T00:00:00+02:00", periodEnd = "2026-10-05T00:00:00+02:00", format = "pdf" });
        Assert.Equal(ProblemCodes.SchemaViolation, wrongFormat.Code);
        var missing = await _admin.DownloadAsync($"/api/v1/organizations/{org}/reports/{Guid.NewGuid()}/download");
        Assert.Equal((HttpStatusCode.NotFound, ProblemCodes.NotFound), (missing.Status, missing.Code));
    }

    [Fact]
    public async Task Ready_report_rows_and_history_are_immutable_for_the_application_role()
    {
        var (org, _, _) = await ConnectedOrganizationAsync();
        _factory.Clock.SetLocal(Oslo, 2026, 10, 12, 9);
        _admin = await StaffClient.SignInAsync(_factory, "Admin");
        var created = await CreateReportAsync(org, "2026-10-05T00:00:00+02:00", "2026-10-12T00:00:00+02:00");
        var reportId = Guid.Parse(created.Body.GetProperty("id").GetString()!);
        await RunJobsAsync();

        var scopes = _factory.Services.GetRequiredService<DbScopes>();
        await using var scope = await scopes.OrganizationAsync(Guid.Parse(org), Ct);
        var report = await scope.Db.Reports.AsNoTracking().SingleAsync(r => r.Id == reportId, Ct);
        Assert.Equal("ready", report.State);
        await using (var update = new NpgsqlCommand("update report set state = 'failed' where id = @id", scope.Connection, scope.Transaction))
        {
            update.Parameters.AddWithValue("id", reportId);
            var error = await Assert.ThrowsAsync<PostgresException>(() => update.ExecuteNonQueryAsync(Ct));
            Assert.Equal("P0001", error.SqlState);
        }
        await using var other = await scopes.OrganizationAsync(Guid.Parse(org), Ct);
        await using var rewrite = new NpgsqlCommand("update finding_event set cause = 'rule_change'", other.Connection, other.Transaction);
        var denied = await Assert.ThrowsAsync<PostgresException>(() => rewrite.ExecuteNonQueryAsync(Ct));
        Assert.Equal("42501", denied.SqlState);
    }

    private async Task<List<string>> WeeklyJobsAsync(string org)
    {
        var scopes = _factory.Services.GetRequiredService<DbScopes>();
        await using var scope = await scopes.PlatformAsync(Ct);
        await using var command = new NpgsqlCommand(
            "select period_key from job where type = 'weekly_report' and organization_id = @org order by period_key",
            scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("org", Guid.Parse(org));
        var keys = new List<string>();
        await using var reader = await command.ExecuteReaderAsync(Ct);
        while (await reader.ReadAsync(Ct))
        {
            keys.Add(reader.GetString(0));
        }
        return keys;
    }

    private async Task<JsonElement> SnapshotAsync(string org, string reportId)
    {
        var scopes = _factory.Services.GetRequiredService<DbScopes>();
        await using var scope = await scopes.OrganizationAsync(Guid.Parse(org), Ct);
        var report = await scope.Db.Reports.AsNoTracking().SingleAsync(r => r.Id == Guid.Parse(reportId), Ct);
        return JsonDocument.Parse(report.Snapshot!).RootElement.Clone();
    }
}
