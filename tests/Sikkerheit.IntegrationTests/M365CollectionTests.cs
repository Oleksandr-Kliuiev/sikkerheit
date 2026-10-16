using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.IntegrationTests;

/// <summary>FR-04, FR-05: consent bound to the expected tenant, verification, collection and findings (AT-03…AT-05).</summary>
public sealed class M365CollectionTests(PostgresFixture postgres) : IAsyncLifetime
{
    private const string GlobalAdministrator = "62e90394-69f5-4237-9190-012177145e10";
    private ApiFactory _factory = null!;
    private StaffClient _admin = null!;

    public async ValueTask InitializeAsync()
    {
        _factory = await ApiFactory.CreateAsync(postgres);
        _admin = await StaffClient.SignInAsync(_factory, "Admin");
    }

    public async ValueTask DisposeAsync() => await _factory.DisposeAsync();

    private async Task<string> OrganizationAsync()
    {
        var created = await _admin.PostAsync("/api/v1/organizations",
            new { name = "Fjord Test AS", timezone = "Europe/Oslo", reportLanguage = "nb" }, "Organization");
        return created.Body.GetProperty("id").GetString()!;
    }

    private async Task RunJobsAsync()
    {
        var runner = _factory.Services.GetRequiredService<JobRunner>();
        while (await runner.RunOnceAsync(TestContext.Current.CancellationToken))
        {
        }
    }

    private async Task<List<Finding>> FindingsAsync(string org)
    {
        var scopes = _factory.Services.GetRequiredService<DbScopes>();
        await using var scope = await scopes.OrganizationAsync(Guid.Parse(org), TestContext.Current.CancellationToken);
        return await scope.Db.Findings.AsNoTracking().ToListAsync(TestContext.Current.CancellationToken);
    }

    private async Task<StaffClient.Answer> ConnectAsync(string org, Guid tenant)
    {
        var consent = await _admin.PostAsync($"/api/v1/organizations/{org}/m365-connection/consent",
            new { tenantHint = tenant.ToString() }, "ConsentStart");
        Assert.Equal(HttpStatusCode.Created, consent.Status);
        Assert.StartsWith($"https://login.microsoftonline.com/{tenant}/v2.0/adminconsent?", consent.Body.GetProperty("consentUrl").GetString());
        return await _admin.PostAsync($"/api/v1/organizations/{org}/m365-connection/verify", new { }, "TenantConnection");
    }

    [Fact]
    public async Task Connection_and_collection_open_the_expected_findings()
    {
        var tenant = _factory.Graph.AddTenant();
        var alice = tenant.AddUser("alice");
        tenant.AddUser("bob", methods: "microsoftAuthenticator");
        var admin = tenant.AddUser("ola.admin");
        tenant.AddUser("gjest", type: "Guest");
        tenant.AddUser("old", enabled: false);
        tenant.Assignments.Add((admin.Id, GlobalAdministrator, false));
        // Reference case: only a report-only policy requires MFA, Security Defaults off, per-user MFA off.
        tenant.ConditionalAccessPolicies.Add(ConditionalAccess.MfaPolicy("enabledForReportingButNotEnforced"));
        var org = await OrganizationAsync();

        var verified = await ConnectAsync(org, tenant.TenantId);
        Assert.Equal(HttpStatusCode.OK, verified.Status);
        Assert.Equal("active", verified.Body.GetProperty("status").GetString());
        Assert.Equal(tenant.TenantId.ToString(), verified.Body.GetProperty("entraTenantId").GetString());

        await RunJobsAsync();
        var runs = await _admin.GetAsync($"/api/v1/organizations/{org}/collection-runs", "CollectionRunPage");
        var run = Assert.Single(runs.Body.GetProperty("items").EnumerateArray());
        Assert.Equal("completed", run.GetProperty("state").GetString());

        var findings = await FindingsAsync(org);
        var byCheck = findings.GroupBy(f => f.CheckId).ToDictionary(g => g.Key, g => g.ToList());
        Assert.Equal(2, byCheck["M365-001"].Count); // alice and the admin have no MFA method
        Assert.All(byCheck["M365-001"], f => Assert.Equal("warning", f.Severity));
        Assert.Equal("critical", Assert.Single(byCheck["M365-002"]).Severity);
        Assert.Equal("critical", Assert.Single(byCheck["M365-003"]).Severity); // report-only is not enforcement
        Assert.Equal("warning", Assert.Single(byCheck["M365-005"]).Severity); // one global admin, minimum 2
        Assert.Equal("warning", Assert.Single(byCheck["M365-006"]).Severity); // legacy consent policy
        Assert.False(byCheck.ContainsKey("M365-004")); // informational by default
        Assert.All(findings, f => Assert.Equal("new", f.WorkflowState));

        var connection = await _admin.GetAsync($"/api/v1/organizations/{org}/m365-connection", "TenantConnection");
        Assert.Equal("completed", connection.Body.GetProperty("lastCollectionState").GetString());
        Assert.True(connection.Body.GetProperty("entraP1").GetBoolean());
        _ = alice;
    }

    [Fact]
    public async Task Fixing_mfa_resolves_and_a_repeated_collection_writes_no_second_event()
    {
        var tenant = _factory.Graph.AddTenant();
        tenant.SecurityDefaults = true;
        tenant.GrantPolicies.Clear();
        var alice = tenant.AddUser("alice");
        for (var i = 0; i < 2; i++)
        {
            tenant.Assignments.Add((tenant.AddUser("admin" + i, methods: "fido2").Id, GlobalAdministrator, false));
        }
        var org = await OrganizationAsync();
        await ConnectAsync(org, tenant.TenantId);
        await RunJobsAsync();
        var opened = Assert.Single(await FindingsAsync(org));
        Assert.Equal("M365-001", opened.CheckId);

        // The user registers Authenticator; the next run resolves the finding with source_change.
        tenant.Users[tenant.Users.IndexOf(alice)] = alice with { Methods = ["microsoftAuthenticator"] };
        for (var i = 0; i < 2; i++)
        {
            var request = await _admin.PostAsync($"/api/v1/organizations/{org}/collection-runs",
                new { idempotencyKey = Guid.NewGuid() }, "CollectionRun");
            Assert.Equal(HttpStatusCode.Accepted, request.Status);
            await RunJobsAsync();
        }
        var resolved = Assert.Single(await FindingsAsync(org));
        Assert.Equal("resolved", resolved.TechnicalState);

        var scopes = _factory.Services.GetRequiredService<DbScopes>();
        await using var scope = await scopes.OrganizationAsync(Guid.Parse(org), TestContext.Current.CancellationToken);
        var events = await scope.Db.FindingEvents.AsNoTracking().OrderBy(e => e.OccurredAt)
            .Select(e => e.EventType + "/" + e.Cause).ToListAsync(TestContext.Current.CancellationToken);
        Assert.Equal(["opened/source_change", "resolved/source_change"], events);
    }

    [Fact]
    public async Task Tenant_of_another_organization_and_missing_consent_are_refused()
    {
        var tenant = _factory.Graph.AddTenant();
        tenant.SecurityDefaults = true;
        var first = await OrganizationAsync();
        await ConnectAsync(first, tenant.TenantId);
        var second = await OrganizationAsync();
        var conflict = await _admin.PostAsync($"/api/v1/organizations/{second}/m365-connection/consent",
            new { tenantHint = tenant.TenantId.ToString() });
        Assert.Equal(ProblemCodes.TenantConflict, conflict.Code);

        var unconsented = _factory.Graph.AddTenant();
        unconsented.Consented = false;
        var third = await OrganizationAsync();
        await _admin.PostAsync($"/api/v1/organizations/{third}/m365-connection/consent",
            new { tenantHint = unconsented.TenantId.ToString() }, "ConsentStart");
        var verify = await _admin.PostAsync($"/api/v1/organizations/{third}/m365-connection/verify", new { });
        Assert.Equal(ProblemCodes.ConsentNotGranted, verify.Code);
        var state = await _admin.GetAsync($"/api/v1/organizations/{third}/m365-connection", "TenantConnection");
        Assert.Equal("consent_pending", state.Body.GetProperty("status").GetString());
    }

    [Fact]
    public async Task Disconnect_writes_the_security_log_and_stops_collection_requests()
    {
        var tenant = _factory.Graph.AddTenant();
        tenant.SecurityDefaults = true;
        var org = await OrganizationAsync();
        await ConnectAsync(org, tenant.TenantId);
        var disconnected = await _admin.PostAsync($"/api/v1/organizations/{org}/m365-connection/disconnect", new { }, "TenantConnection");
        Assert.Equal("disconnected", disconnected.Body.GetProperty("status").GetString());
        await RunJobsAsync();
        var runs = await _admin.GetAsync($"/api/v1/organizations/{org}/collection-runs", "CollectionRunPage");
        var run = Assert.Single(runs.Body.GetProperty("items").EnumerateArray());
        Assert.Equal("cancelled", run.GetProperty("failureCode").GetString());
        var request = await _admin.PostAsync($"/api/v1/organizations/{org}/collection-runs", new { idempotencyKey = Guid.NewGuid() });
        Assert.Equal(ProblemCodes.ConnectionStateConflict, request.Code);
        Assert.Contains(Directory.GetFiles(_factory.SecurityLogDirectory),
            f => File.ReadAllText(f).Contains("m365.disconnect", StringComparison.Ordinal));
    }

    [Fact]
    public async Task New_policy_revision_recalculates_projections_with_policy_change_once()
    {
        var tenant = _factory.Graph.AddTenant();
        tenant.SecurityDefaults = true;
        var alice = tenant.AddUser("alice");
        for (var i = 0; i < 2; i++)
        {
            tenant.Assignments.Add((tenant.AddUser("admin" + i, methods: "fido2").Id, GlobalAdministrator, false));
        }
        var org = await OrganizationAsync();
        await ConnectAsync(org, tenant.TenantId);
        await RunJobsAsync();
        var before = await FindingsAsync(org);
        Assert.Equal(["M365-001", "M365-006"], before.Where(f => f.TechnicalState == "open").Select(f => f.CheckId).Order());

        // Revision 2 excludes Alice, drops M365-006 and makes M365-004 assessed.
        var path = $"/api/v1/organizations/{org}/policy-revisions";
        var current = (await _admin.GetAsync(path, "PolicyRevisionPage")).Body.GetProperty("items")[0].GetProperty("configuration");
        var configuration = System.Text.Json.Nodes.JsonNode.Parse(current.GetRawText())!.AsObject();
        configuration["m365"]!["excludedUserIds"] = new System.Text.Json.Nodes.JsonArray(alice.Id.ToString());
        configuration["activeCheckIds"] = new System.Text.Json.Nodes.JsonArray(configuration["activeCheckIds"]!.AsArray()
            .Select(x => x!.GetValue<string>()).Where(c => c != "M365-006").Select(c => (System.Text.Json.Nodes.JsonNode?)c).ToArray());
        configuration["checks"]!["M365-004"]!["assessmentMode"] = "assessed";
        var created = await _admin.PostAsync(path, new { configuration }, "PolicyRevision", ifMatch: "\"1\"");
        Assert.Equal(HttpStatusCode.Created, created.Status);
        await RunJobsAsync();

        var after = await FindingsAsync(org);
        Assert.All(after, f => Assert.Equal("resolved", f.TechnicalState));
        var scopes = _factory.Services.GetRequiredService<DbScopes>();
        async Task<List<string>> EventsAsync()
        {
            await using var scope = await scopes.OrganizationAsync(Guid.Parse(org), TestContext.Current.CancellationToken);
            return await scope.Db.FindingEvents.AsNoTracking().Where(e => e.Cause == "policy_change")
                .Select(e => e.EventType).ToListAsync(TestContext.Current.CancellationToken);
        }
        Assert.Equal(["policy_changed", "policy_changed"], await EventsAsync());
        await using (var scope = await scopes.OrganizationAsync(Guid.Parse(org), TestContext.Current.CancellationToken))
        {
            var legacy = await scope.Db.Assessments.AsNoTracking().Where(a => a.CheckId == "M365-004")
                .OrderByDescending(a => a.EvaluatedAt).FirstAsync(TestContext.Current.CancellationToken);
            Assert.Equal(("assessed", "pass", 2, 1), (legacy.AssessmentMode, legacy.Result, legacy.EvaluatedPolicyVersion,
                legacy.SourcePolicyVersion));
        }

        // The same revision recalculated again writes nothing new.
        await using (var platform = await scopes.PlatformAsync(TestContext.Current.CancellationToken))
        {
            await using var requeue = new Npgsql.NpgsqlCommand(
                "update job set state = 'queued', attempts = 0, next_attempt_at = @now where type = 'recalculate_policy'",
                platform.Connection, platform.Transaction);
            requeue.Parameters.AddWithValue("now", _factory.Clock.GetUtcNow().AddMinutes(-1));
            Assert.Equal(1, await requeue.ExecuteNonQueryAsync(TestContext.Current.CancellationToken));
            await platform.CommitAsync(TestContext.Current.CancellationToken);
        }
        await RunJobsAsync();
        Assert.Equal(["policy_changed", "policy_changed"], await EventsAsync());
    }

    [Fact]
    public async Task Forbidden_module_gives_unknown_instead_of_a_false_result()
    {
        var tenant = _factory.Graph.AddTenant();
        tenant.Forbidden.Add("/policies/identitySecurityDefaultsEnforcementPolicy");
        tenant.Assignments.Add((tenant.AddUser("a", methods: "fido2").Id, GlobalAdministrator, false));
        tenant.Assignments.Add((tenant.AddUser("b", methods: "fido2").Id, GlobalAdministrator, false));
        var org = await OrganizationAsync();
        await ConnectAsync(org, tenant.TenantId);
        await RunJobsAsync();
        var runs = await _admin.GetAsync($"/api/v1/organizations/{org}/collection-runs", "CollectionRunPage");
        Assert.Equal("partial", runs.Body.GetProperty("items")[0].GetProperty("state").GetString());
        Assert.DoesNotContain(await FindingsAsync(org), f => f.CheckId == "M365-003");
        var scopes = _factory.Services.GetRequiredService<DbScopes>();
        await using var scope = await scopes.OrganizationAsync(Guid.Parse(org), TestContext.Current.CancellationToken);
        var assessment = await scope.Db.Assessments.AsNoTracking().SingleAsync(a => a.CheckId == "M365-003", TestContext.Current.CancellationToken);
        Assert.Equal("unknown", assessment.Result);
        Assert.Equal("permission_denied", assessment.ReasonCode);
    }
}
