using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Jobs;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.IntegrationTests;

/// <summary>FR-06, FR-07, FR-09: queue, workflow, risk decisions, events and assessments (AT-06, AT-08).</summary>
public sealed class FindingApiTests(PostgresFixture postgres) : IAsyncLifetime
{
    private ApiFactory _factory = null!;
    private StaffClient _admin = null!;
    private string _org = "";

    public async ValueTask InitializeAsync()
    {
        _factory = await ApiFactory.CreateAsync(postgres);
        _admin = await StaffClient.SignInAsync(_factory, "Admin");
        var tenant = _factory.Graph.AddTenant();
        tenant.SecurityDefaults = true;
        tenant.GrantPolicies.Clear();
        tenant.AddUser("alice");
        tenant.AddUser("kari");
        for (var i = 0; i < 2; i++)
        {
            tenant.Assignments.Add((tenant.AddUser("admin" + i, methods: "fido2").Id, "62e90394-69f5-4237-9190-012177145e10", false));
        }
        var created = await _admin.PostAsync("/api/v1/organizations",
            new { name = "Queue Test AS", timezone = "Europe/Oslo", reportLanguage = "nn" }, "Organization");
        _org = created.Body.GetProperty("id").GetString()!;
        await _admin.PostAsync($"/api/v1/organizations/{_org}/m365-connection/consent", new { tenantHint = tenant.TenantId.ToString() });
        await _admin.PostAsync($"/api/v1/organizations/{_org}/m365-connection/verify", new { });
        var runner = _factory.Services.GetRequiredService<JobRunner>();
        while (await runner.RunOnceAsync(TestContext.Current.CancellationToken))
        {
        }
    }

    public async ValueTask DisposeAsync() => await _factory.DisposeAsync();

    /// <summary>Now plus days at the microsecond precision of the contract (at most 6 fractional digits): Linux has a 100 ns clock.</summary>
    private static DateTimeOffset InDays(int days)
    {
        var moment = DateTimeOffset.UtcNow.AddDays(days);
        return moment.AddTicks(-(moment.Ticks % 10));
    }

    [Fact]
    public async Task Queue_lists_open_findings_with_filters_and_localized_texts()
    {
        var page = await _admin.GetAsync($"/api/v1/organizations/{_org}/findings?technicalState=open&checkId=M365-001", "FindingPage");
        var items = page.Body.GetProperty("items").EnumerateArray().ToList();
        Assert.Equal(2, items.Count);
        Assert.All(items, i => Assert.Equal("fresh", i.GetProperty("freshness").GetString()));
        Assert.Equal("Bruker uten registrert MFA-metode", items[0].GetProperty("title").GetString());

        var across = await _admin.GetAsync("/api/v1/findings?severity=warning&limit=100", "FindingPage");
        Assert.Contains(across.Body.GetProperty("items").EnumerateArray(), i => i.GetProperty("organizationId").GetString() == _org);

        var wrong = await _admin.GetAsync($"/api/v1/organizations/{_org}/findings?severity=fatal");
        Assert.Equal(ProblemCodes.SchemaViolation, wrong.Code);
    }

    [Fact]
    public async Task Workflow_and_risk_decisions_follow_the_state_machine()
    {
        var page = await _admin.GetAsync($"/api/v1/organizations/{_org}/findings?checkId=M365-001", "FindingPage");
        var id = page.Body.GetProperty("items")[0].GetProperty("id").GetString();
        var path = $"/api/v1/organizations/{_org}/findings/{id}";
        var finding = await _admin.GetAsync(path, "Finding");
        var etag = finding.ETag!;

        Assert.Equal(ProblemCodes.IfMatchRequired, (await _admin.PatchAsync(path, new { workflowState = "in_progress" })).Code);
        var stale = await _admin.SendAsync(HttpMethod.Patch, path, """{"workflowState":"in_progress"}""", null, ifMatch: "\"99\"");
        Assert.Equal(ProblemCodes.RevisionMismatch, stale.Code);
        var invalid = await _admin.SendAsync(HttpMethod.Patch, path, """{"workflowState":"risk_accepted"}""", null, ifMatch: etag);
        Assert.Equal(ProblemCodes.SchemaViolation, invalid.Code);
        var notStaff = await _admin.SendAsync(HttpMethod.Patch, path, $$"""{"assigneeId":"{{Guid.NewGuid()}}"}""", null, ifMatch: etag);
        Assert.Equal(ProblemCodes.ValidationFailed, notStaff.Code);

        var progressed = await _admin.SendAsync(HttpMethod.Patch, path,
            $$"""{"workflowState":"in_progress","assigneeId":"{{_admin.EntraUserId}}"}""", "Finding", ifMatch: etag);
        Assert.Equal("in_progress", progressed.Body.GetProperty("workflowState").GetString());

        var technician = await StaffClient.SignInAsync(_factory, "Technician");
        var forbidden = await technician.PostAsync($"{path}/risk-decisions",
            new { decision = "risk_accepted", reason = "Kunden godtek", reviewAt = InDays(30) }, ifMatch: progressed.ETag);
        Assert.Equal(ProblemCodes.Forbidden, forbidden.Code);

        var tooLate = await _admin.PostAsync($"{path}/risk-decisions",
            new { decision = "risk_accepted", reason = "Kunden godtek", reviewAt = InDays(400) }, ifMatch: progressed.ETag);
        Assert.Equal(ProblemCodes.ValidationFailed, tooLate.Code);

        var accepted = await _admin.PostAsync($"{path}/risk-decisions",
            new { decision = "risk_accepted", reason = "Kunden godtek risikoen", reviewAt = InDays(30) },
            "Finding", ifMatch: progressed.ETag);
        Assert.Equal("risk_accepted", accepted.Body.GetProperty("workflowState").GetString());
        Assert.Equal("Kunden godtek risikoen", accepted.Body.GetProperty("workflowReason").GetString());

        var noWorkflowInDecision = await _admin.SendAsync(HttpMethod.Patch, path, """{"workflowState":"new"}""", null, ifMatch: accepted.ETag);
        Assert.Equal(ProblemCodes.WorkflowTransitionForbidden, noWorkflowInDecision.Code);

        var withdrawn = await _admin.PostAsync($"{path}/risk-decisions", new { decision = "withdrawn" }, "Finding", ifMatch: accepted.ETag);
        Assert.Equal("new", withdrawn.Body.GetProperty("workflowState").GetString());

        var events = await _admin.GetAsync($"{path}/events", "FindingEventPage");
        var pairs = events.Body.GetProperty("items").EnumerateArray()
            .Select(e => e.GetProperty("eventType").GetString() + "/" + e.GetProperty("cause").GetString()).ToList();
        Assert.Equal(["opened/source_change", "workflow_changed/manual_action", "workflow_changed/manual_action",
            "workflow_changed/manual_action"], pairs);
    }

    [Fact]
    public async Task Assessments_show_current_results_with_explanations()
    {
        var page = await _admin.SendAsync(HttpMethod.Get, $"/api/v1/organizations/{_org}/assessments?checkId=M365-003", null,
            "AssessmentPage", csrf: false);
        var assessment = Assert.Single(page.Body.GetProperty("items").EnumerateArray());
        Assert.Equal("pass", assessment.GetProperty("result").GetString());
        Assert.Contains("Security Defaults", assessment.GetProperty("explanation").GetString());
        Assert.Equal("enabled", assessment.GetProperty("evidence").GetProperty("securityDefaults").GetString());
    }
}
