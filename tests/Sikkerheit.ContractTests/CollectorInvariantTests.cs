using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Sikkerheit.Contracts;
using Sikkerheit.ContractTests.Invariants;
using Sikkerheit.ContractTests.Support;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.ContractTests;

/// <summary>Records enforced by the Microsoft 365 collector: the fake Graph answers with the negative example.</summary>
[Enforcement("collector")]
public sealed class CollectorInvariantTests(PostgresFixture postgres) : IAsyncLifetime
{
    private ContractHost _host = null!;

    public async ValueTask InitializeAsync() => _host = await ContractHost.StartAsync(postgres);

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    private static string? Module(Host.Data.CollectionRun run, string module) => ContractHost.Module(run, module);

    private async Task<(Guid Org, FakeTenant Tenant)> ConnectedAsync(Action<FakeTenant>? setup = null)
    {
        var tenant = _host.Tenant();
        tenant.SecurityDefaults = true;
        setup?.Invoke(tenant);
        var org = await _host.OrganizationAsync();
        await _host.ConnectAsync(org, tenant);
        await _host.RunJobsAsync();
        return (org, tenant);
    }

    [Fact]
    [Invariant("INV-016")]
    public async Task Inv016_tenant_mismatch_stops_the_run_without_observations()
    {
        var (org, tenant) = await ConnectedAsync();
        tenant.OrganizationIdOverride = Guid.NewGuid();
        var run = await _host.CollectAsync(org);
        Assert.Equal(("failed", "tenant_mismatch"), (run.State, run.FailureCode));
        Assert.Empty(await _host.ObservationsAsync(org, run.Id));
        Assert.Contains(await _host.AuditAsync(org, "m365.tenant_mismatch"), a => a.TargetId == run.Id.ToString() && a.ActorType == "system");
    }

    [Fact]
    [Invariant("INV-017")]
    public async Task Inv017_revoked_consent_fails_the_run_raises_an_alert_and_keeps_findings_open()
    {
        var (org, tenant) = await ConnectedAsync(t => t.AddUser("alice"));
        var open = (await _host.FindingsAsync(org)).Where(f => f.TechnicalState == "open").Select(f => f.Id).Order().ToList();
        Assert.NotEmpty(open);
        // The application was removed from the client's tenant: no token for it any more.
        tenant.Consented = false;
        var run = await _host.CollectAsync(org);
        Assert.Equal(("failed", "consent_missing"), (run.State, run.FailureCode));
        Assert.Equal(open, (await _host.FindingsAsync(org)).Where(f => f.TechnicalState == "open").Select(f => f.Id).Order().ToList());
        Assert.Single(await _host.AuditAsync(org, "m365.collection_failed"));
        Assert.Contains(_host.Factory.Logs.Entries, e => e.Level == LogLevel.Error && e.Message.Contains("consent_missing", StringComparison.Ordinal));
        var connection = await _host.Admin.GetAsync($"/api/v1/organizations/{org}/m365-connection", "TenantConnection");
        Assert.Equal(("active", "failed"), (connection.Body.GetProperty("status").GetString(),
            connection.Body.GetProperty("lastCollectionState").GetString()));
    }

    [Fact]
    [Invariant("INV-018")]
    public async Task Inv018_disconnect_during_the_run_cancels_it_without_writing()
    {
        var (org, tenant) = await ConnectedAsync(t => t.AddUser("alice"));
        var before = (await _host.FindingsAsync(org)).Count;
        var disconnected = false;
        _host.Graph.OnRequest = async path =>
        {
            if (!disconnected && path == "/users")
            {
                disconnected = true;
                await _host.Admin.PostAsync($"/api/v1/organizations/{org}/m365-connection/disconnect", new { }, "TenantConnection");
            }
        };
        tenant.AddUser("bob");
        var requested = await _host.Admin.PostAsync($"/api/v1/organizations/{org}/collection-runs", new { idempotencyKey = Guid.NewGuid() },
            "CollectionRun");
        await _host.RunJobsAsync();
        var run = await _host.RunAsync(org, Guid.Parse(requested.Body.GetProperty("id").GetString()!));
        Assert.True(disconnected);
        Assert.Equal(("failed", "cancelled"), (run.State, run.FailureCode));
        Assert.Empty(await _host.ObservationsAsync(org, run.Id));
        Assert.Equal(before, (await _host.FindingsAsync(org)).Count);
    }

    [Fact]
    [Invariant("INV-019")]
    public async Task Inv019_next_page_on_another_host_is_not_followed_and_the_module_is_partial()
    {
        var (org, tenant) = await ConnectedAsync();
        tenant.UsersPageSize = 1;
        tenant.UsersNextLink = "https://example.invalid/v1.0/users";
        var run = await _host.CollectAsync(org);
        Assert.Equal(("partial", "partial", false), (run.State, Module(run, "users"), run.UsersComplete));
        Assert.DoesNotContain(_host.Graph.Requests, r => r.Contains("example.invalid", StringComparison.Ordinal));
        // A link to the same host with another path is not followed either.
        tenant.UsersNextLink = "https://graph.microsoft.com/v1.0/groups";
        var other = await _host.CollectAsync(org);
        Assert.Equal(("partial", false), (Module(other, "users"), other.UsersComplete));
        Assert.DoesNotContain(_host.Graph.Requests, r => r.StartsWith("GET /v1.0/groups", StringComparison.Ordinal));
    }

    [Fact]
    [Invariant("INV-020")]
    public async Task Inv020_answer_without_a_required_property_is_not_complete()
    {
        var (org, tenant) = await ConnectedAsync();
        tenant.AddUser("alice", methods: ["microsoftAuthenticator", "untyped"]);
        var run = await _host.CollectAsync(org);
        Assert.Equal(("partial", "partial"), (run.State, Module(run, "auth_methods")));
        var observation = Assert.Single(await _host.ObservationsAsync(org, run.Id),
            o => o.CheckId == "M365-001" && o.CollectionStatus == "unavailable");
        Assert.Equal("partial_data", observation.ReasonCode);
        var assessment = Assert.Single(await _host.AssessmentsAsync(org, "M365-001"), a => a.ObservationId == observation.Id);
        Assert.Equal(("unknown", "partial_data"), (assessment.Result, assessment.ReasonCode));
        // Authenticator alone would have been a pass: the incomplete answer is not read as the methods of the user.
        Assert.DoesNotContain(await _host.FindingsAsync(org, "M365-001"), f => f.TechnicalState == "resolved");
    }

    [Fact]
    [Invariant("INV-021")]
    public async Task Inv021_forbidden_module_is_permission_missing_not_license_missing()
    {
        var (org, tenant) = await ConnectedAsync();
        tenant.SecurityDefaults = false;
        tenant.Forbidden.Add("/identity/conditionalAccess/policies");
        var run = await _host.CollectAsync(org);
        Assert.True(tenant.EntraP1);
        Assert.Equal("permission_missing", Module(run, "conditional_access"));
    }

    [Fact]
    [Invariant("INV-022")]
    public async Task Inv022_module_needing_entra_p1_is_license_missing_without_a_request()
    {
        var (org, tenant) = await ConnectedAsync(t =>
        {
            t.EntraP1 = false;
            t.SecurityDefaults = false;
        });
        var run = await _host.LastRunAsync(org);
        Assert.Equal("license_missing", Module(run, "conditional_access"));
        Assert.DoesNotContain(_host.Graph.Requests, r => r.Contains("/identity/conditionalAccess", StringComparison.Ordinal));
        _ = tenant;
    }

    [Fact]
    [Invariant("INV-023")]
    public async Task Inv023_throttling_honours_retry_after_and_ends_as_temporary_error()
    {
        var (org, tenant) = await ConnectedAsync();
        // Two 429 answers with Retry-After: 1 second, then the answer.
        tenant.Throttled["/policies/authorizationPolicy"] = (2, 1);
        _host.Graph.Requests.Clear();
        _host.Graph.RequestTimes.Clear();
        var recovered = await _host.CollectAsync(org);
        Assert.Equal("available", Module(recovered, "authorization_policy"));
        var times = _host.Graph.Requests.Select((r, i) => (r, _host.Graph.RequestTimes[i]))
            .Where(x => x.r.Contains("/policies/authorizationPolicy", StringComparison.Ordinal)).Select(x => x.Item2).ToList();
        Assert.Equal(3, times.Count);
        Assert.All(times.Zip(times.Skip(1)), pair => Assert.True(pair.Second - pair.First >= TimeSpan.FromMilliseconds(950)));

        // Five 429 answers in a row: after the attempts are spent the module is temporary_error.
        tenant.Throttled["/policies/authorizationPolicy"] = (5, 0);
        var failed = await _host.CollectAsync(org);
        Assert.Equal(("temporary_error", "partial"), (Module(failed, "authorization_policy"), failed.State));
    }

    [Fact]
    [Invariant("INV-025")]
    public async Task Inv025_observation_outside_the_allowlist_schema_is_kept_as_partial_data()
    {
        var (org, tenant) = await ConnectedAsync();
        tenant.AddUser("robot", type: "Robot");
        var bob = tenant.AddUser("bob", methods: "fido2");
        var run = await _host.CollectAsync(org);
        Assert.Equal("partial", Module(run, "auth_methods"));
        var observations = await _host.ObservationsAsync(org, run.Id);
        var unavailable = Assert.Single(observations, o => o.CheckId == "M365-001" && o.CollectionStatus == "unavailable");
        Assert.Equal("partial_data", unavailable.ReasonCode);
        var assessment = Assert.Single(await _host.AssessmentsAsync(org, "M365-001"), a => a.ObservationId == unavailable.Id);
        Assert.Equal(("assessed", "unknown", "partial_data"), (assessment.AssessmentMode, assessment.Result, assessment.ReasonCode));
        Assert.Contains(observations, o => o.CheckId == "M365-001" && o.CollectionStatus == "collected"
                                           && o.Evidence!.Contains("fido2", StringComparison.Ordinal));
        _ = bob;
    }

    [Fact]
    [Invariant("INV-035")]
    public async Task Inv035_pim_activation_does_not_change_the_global_administrator_count()
    {
        var tenant = _host.Tenant();
        tenant.SecurityDefaults = true;
        tenant.EntraP2 = true;
        var activated = tenant.AddUser("vakt", methods: "fido2");
        tenant.Assignments.Add((activated.Id, ContractHost.GlobalAdministrator, false));
        tenant.Activations.Add((activated.Id, ContractHost.GlobalAdministrator));
        var org = await _host.OrganizationAsync();
        await _host.ConnectAsync(org, tenant);
        await _host.RunJobsAsync();

        var run = await _host.LastRunAsync(org);
        Assert.Equal("completed", run.State);
        Assert.Contains(_host.Graph.Requests, r => r.Contains("roleAssignmentScheduleInstances", StringComparison.Ordinal));
        var observations = await _host.ObservationsAsync(org, run.Id);
        var admins = JsonDocument.Parse(observations.Single(o => o.CheckId == "M365-005").Evidence!).RootElement;
        Assert.Equal(2, admins.GetProperty("globalAdminUserIds").GetArrayLength());
        Assert.DoesNotContain(admins.GetProperty("globalAdminUserIds").EnumerateArray(), id => id.GetString() == activated.Id.ToString());
        Assert.Equal("pass", (await _host.AssessmentsAsync(org, "M365-005"))[0].Result);
        // M365-002 assesses the activation as its own kind of assignment — INV-178.
    }

    [Fact]
    [Invariant("INV-181")]
    public async Task Inv181_unrecognized_security_defaults_or_conditions_give_partial_and_unknown()
    {
        // Security Defaults with separate protections instead of a boolean isEnabled (preview shape, H-SD1).
        var (sd, _) = await ConnectedAsync(t =>
        {
            t.SecurityDefaults = false;
            t.SecurityDefaultsBody = new JsonObject { ["protections"] = new JsonObject { ["requireMfa"] = "enabled" } };
        });
        Assert.Equal("partial", Module(await _host.LastRunAsync(sd), "security_defaults"));
        var bySd = (await _host.AssessmentsAsync(sd, "M365-003"))[0];
        Assert.Equal(("unknown", "partial_data"), (bySd.Result, bySd.ReasonCode));

        // An MFA policy with a condition outside CA_CONDITIONS.
        var (times, _) = await ConnectedAsync(t =>
        {
            t.SecurityDefaults = false;
            var policy = ConditionalAccess.MfaPolicy("enabled");
            policy["conditions"]!["times"] = new JsonObject { ["includedRanges"] = new JsonArray("08:00-16:00") };
            t.ConditionalAccessPolicies.Add(policy);
        });
        Assert.Equal("partial", Module(await _host.LastRunAsync(times), "conditional_access"));
        var byTimes = (await _host.AssessmentsAsync(times, "M365-003"))[0];
        Assert.Equal(("unknown", "partial_data"), (byTimes.Result, byTimes.ReasonCode));

        // insiderRiskLevels is a flags string in Graph: the policy is conditional, never the unconditional pass.
        var (insider, _) = await ConnectedAsync(t =>
        {
            t.SecurityDefaults = false;
            var policy = ConditionalAccess.MfaPolicy("enabled");
            policy["conditions"]!["insiderRiskLevels"] = "elevated";
            t.ConditionalAccessPolicies.Add(policy);
        });
        var run = await _host.LastRunAsync(insider);
        var evidence = JsonDocument.Parse((await _host.ObservationsAsync(insider, run.Id)).Single(o => o.CheckId == "M365-003").Evidence!).RootElement;
        Assert.Contains("insider_risk", evidence.GetProperty("mfaPolicies")[0].GetProperty("conditions").EnumerateArray().Select(c => c.GetString()));
        Assert.NotEqual("pass", (await _host.AssessmentsAsync(insider, "M365-003"))[0].Result);
    }

    [Fact]
    [Invariant("INV-182")]
    public async Task Inv182_sign_in_activity_is_always_skipped_in_p1()
    {
        var (org, _) = await ConnectedAsync();
        var run = await _host.LastRunAsync(org);
        Assert.Equal("skipped", Module(run, "sign_in_activity"));
        Assert.DoesNotContain(_host.Graph.Requests, r => r.Contains("signInActivity", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain("AuditLog.Read.All", Catalog.GraphPermissions);
        Assert.DoesNotContain(await _host.ObservationsAsync(org, run.Id), o => o.CheckId == "M365-007");
    }
}
