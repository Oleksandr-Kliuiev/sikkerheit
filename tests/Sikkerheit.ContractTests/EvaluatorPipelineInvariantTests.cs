using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sikkerheit.ContractTests.Invariants;
using Sikkerheit.ContractTests.Support;
using Sikkerheit.Host.Assessment;
using Sikkerheit.Host.Jobs;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.ContractTests;

/// <summary>
/// Records enforced by the evaluator that depend on what a collection run brings: the run goes through the fake Graph and
/// the final transaction, the test reads assessments, findings and events.
/// </summary>
[Enforcement("evaluator")]
public sealed class EvaluatorPipelineInvariantTests(PostgresFixture postgres) : IAsyncLifetime
{
    private ContractHost _host = null!;

    public async ValueTask InitializeAsync() => _host = await ContractHost.StartAsync(postgres);

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    private static CancellationToken Ct => ContractHost.Ct;

    private async Task<Guid> ConnectedAsync(FakeTenant tenant)
    {
        var org = await _host.OrganizationAsync();
        await _host.ConnectAsync(org, tenant);
        await _host.RunJobsAsync();
        return org;
    }

    [Fact]
    [Invariant("INV-024")]
    public async Task Inv024_temporary_error_of_a_required_module_gives_unknown_not_fail()
    {
        var tenant = _host.Tenant();
        tenant.Throttled["/identity/conditionalAccess/policies"] = (10, 0);
        var org = await ConnectedAsync(tenant);
        var assessment = (await _host.AssessmentsAsync(org, "M365-003"))[0];
        Assert.Equal(("assessed", "unknown", "temporary_error"), (assessment.AssessmentMode, assessment.Result, assessment.ReasonCode));
        Assert.Empty(await _host.FindingsAsync(org, "M365-003"));
    }

    [Fact]
    [Invariant("INV-026")]
    public async Task Inv026_forbidden_methods_of_a_user_give_unknown_permission_denied()
    {
        var tenant = _host.Tenant();
        tenant.SecurityDefaults = true;
        var alice = tenant.AddUser("alice");
        tenant.Forbidden.Add($"/users/{alice.Id}/authentication");
        var org = await ConnectedAsync(tenant);
        var subject = await _host.SubjectIdAsync(org, alice.Id.ToString());
        var assessment = (await _host.AssessmentsAsync(org, "M365-001")).Single(a => a.SubjectId == subject);
        Assert.Equal(("unknown", "permission_denied"), (assessment.Result, assessment.ReasonCode));
        Assert.DoesNotContain(await _host.FindingsAsync(org, "M365-001"), f => f.SubjectId == subject);
    }

    [Fact]
    [Invariant("INV-027")]
    public async Task Inv027_forbidden_role_group_members_leave_direct_admins_assessed_and_the_count_unknown()
    {
        var tenant = _host.Tenant(twoAdmins: false);
        tenant.SecurityDefaults = true;
        var direct = tenant.AddUser("direkte.admin");
        tenant.Assignments.Add((direct.Id, ContractHost.GlobalAdministrator, false));
        var group = Guid.NewGuid();
        tenant.Assignments.Add((group, ContractHost.GlobalAdministrator, true));
        tenant.GroupMembers[group] = [tenant.AddUser("gruppe.admin", methods: "fido2").Id];
        tenant.Forbidden.Add($"/groups/{group}");
        var org = await ConnectedAsync(tenant);

        Assert.Equal("partial", ContractHost.Module(await _host.LastRunAsync(org), "roles"));
        var directSubject = await _host.SubjectIdAsync(org, direct.Id.ToString());
        var admin = (await _host.AssessmentsAsync(org, "M365-002")).Single(a => a.SubjectId == directSubject);
        Assert.Equal(("fail", "critical"), (admin.Result, admin.Severity));
        var count = (await _host.AssessmentsAsync(org, "M365-005"))[0];
        Assert.Equal(("unknown", "partial_data"), (count.Result, count.ReasonCode));
    }

    [Fact]
    [Invariant("INV-034")]
    public async Task Inv034_removed_last_privileged_role_resolves_with_applicability_change()
    {
        var tenant = _host.Tenant();
        tenant.SecurityDefaults = true;
        var admin = tenant.AddUser("tidligere.admin", methods: "email");
        tenant.Assignments.Add((admin.Id, "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", false)); // SharePoint Administrator
        var org = await ConnectedAsync(tenant);
        Assert.Equal("open", Assert.Single(await _host.FindingsAsync(org, "M365-002")).TechnicalState);

        tenant.Assignments.RemoveAll(a => a.Principal == admin.Id);
        await _host.CollectAsync(org);
        Assert.Equal("resolved", Assert.Single(await _host.FindingsAsync(org, "M365-002")).TechnicalState);
        Assert.Equal(["opened/source_change", "resolved/applicability_change"], await _host.EventsAsync(org, "M365-002"));
        var subject = await _host.SubjectIdAsync(org, admin.Id.ToString());
        var assessment = (await _host.AssessmentsAsync(org, "M365-002")).First(a => a.SubjectId == subject);
        Assert.Equal(("not_applicable", "policy_not_applicable"), (assessment.Result, assessment.ReasonCode));
    }

    [Fact]
    [Invariant("INV-054")]
    public async Task Inv054_new_rule_version_recalculates_current_projections_with_rule_change()
    {
        var tenant = _host.Tenant();
        tenant.SecurityDefaults = true;
        var alice = tenant.AddUser("alice", methods: "microsoftAuthenticator");
        var org = await ConnectedAsync(tenant);
        var subject = await _host.SubjectIdAsync(org, alice.Id.ToString());
        Assert.DoesNotContain(await _host.FindingsAsync(org, "M365-001"), f => f.SubjectId == subject);

        // The stored evaluation came from the previous rule version, which also counted email as MFA.
        await using (var scope = await _host.Scopes.OrganizationAsync(org, Ct))
        {
            await scope.Db.Database.ExecuteSqlInterpolatedAsync($$"""
                update observation set evidence = jsonb_set(evidence, '{methodKinds}', '["password","email"]')
                where subject_id = {{subject}} and check_id = 'M365-001';
                update assessment set rule_version = '0.9.0' where subject_id = {{subject}} and check_id = 'M365-001';
                """, Ct);
            await scope.CommitAsync(Ct);
        }
        // The scheduler queues one recalculation per organization and rule version.
        await _host.Factory.Services.GetRequiredService<Scheduler>().RunOnceAsync(Ct);
        await _host.RunJobsAsync();
        var finding = Assert.Single(await _host.FindingsAsync(org, "M365-001"), f => f.SubjectId == subject);
        Assert.Equal("open", finding.TechnicalState);
        await using (var scope = await _host.Scopes.OrganizationAsync(org, Ct))
        {
            var events = await scope.Db.FindingEvents.AsNoTracking().Where(e => e.FindingId == finding.Id)
                .Select(e => e.EventType + "/" + e.Cause).ToListAsync(Ct);
            Assert.Equal(["opened/rule_change"], events);
            var current = await scope.Db.Assessments.AsNoTracking().Where(a => a.SubjectId == subject && a.CheckId == "M365-001")
                .OrderByDescending(a => a.EvaluatedAt).FirstAsync(Ct);
            Assert.Equal((RuleEngine.RuleVersion, "fail"), (current.RuleVersion, current.Result));
        }
        // A repeat of the scheduler and the job writes nothing new.
        await _host.Factory.Services.GetRequiredService<Scheduler>().RunOnceAsync(Ct);
        await _host.RunJobsAsync();
        Assert.Equal(["opened/rule_change"], (await _host.EventsAsync(org, "M365-001")).Where(e => e.EndsWith("rule_change", StringComparison.Ordinal)));
    }

    [Fact]
    [Invariant("INV-056")]
    public async Task Inv056_user_missing_from_a_complete_list_is_retired_and_an_incomplete_list_retires_nobody()
    {
        var tenant = _host.Tenant();
        tenant.SecurityDefaults = true;
        var bob = tenant.AddUser("bob");
        var alice = tenant.AddUser("alice");
        var org = await ConnectedAsync(tenant);
        Assert.Equal(2, (await _host.FindingsAsync(org, "M365-001")).Count(f => f.TechnicalState == "open"));

        // Bob is deleted in the tenant: the complete list retires him.
        tenant.Users.Remove(bob);
        await _host.CollectAsync(org);
        var bobSubject = await _host.SubjectIdAsync(org, bob.Id.ToString());
        var bobFinding = Assert.Single(await _host.FindingsAsync(org, "M365-001"), f => f.SubjectId == bobSubject);
        Assert.Equal("resolved", bobFinding.TechnicalState);
        await using (var scope = await _host.Scopes.OrganizationAsync(org, Ct))
        {
            Assert.Equal(["opened/source_change", "subject_retired/source_change"], await scope.Db.FindingEvents.AsNoTracking()
                .Where(e => e.FindingId == bobFinding.Id).OrderBy(e => e.OccurredAt).Select(e => e.EventType + "/" + e.Cause).ToListAsync(Ct));
            Assert.NotNull((await scope.Db.Subjects.AsNoTracking().SingleAsync(s => s.Id == bobSubject, Ct)).RetiredAt);
        }

        // Alice is missing from a list that ended early: nobody is retired.
        tenant.Users.Remove(alice);
        tenant.UsersPageSize = 1;
        tenant.UsersNextLink = "https://example.invalid/v1.0/users";
        var partial = await _host.CollectAsync(org);
        Assert.False(partial.UsersComplete);
        var aliceSubject = await _host.SubjectIdAsync(org, alice.Id.ToString());
        Assert.Equal("open", Assert.Single(await _host.FindingsAsync(org, "M365-001"), f => f.SubjectId == aliceSubject).TechnicalState);
    }

    [Fact]
    [Invariant("INV-178")]
    public async Task Inv178_an_activated_role_without_mfa_is_a_critical_m365_002_finding()
    {
        var tenant = _host.Tenant();
        tenant.SecurityDefaults = true;
        tenant.EntraP2 = true;
        var activated = tenant.AddUser("vakt");
        tenant.Assignments.Add((activated.Id, ContractHost.GlobalAdministrator, false));
        tenant.Activations.Add((activated.Id, ContractHost.GlobalAdministrator));
        var org = await ConnectedAsync(tenant);

        var subject = await _host.SubjectIdAsync(org, activated.Id.ToString());
        var finding = Assert.Single(await _host.FindingsAsync(org, "M365-002"), f => f.SubjectId == subject);
        Assert.Equal(("open", "critical"), (finding.TechnicalState, finding.Severity));
        var run = await _host.LastRunAsync(org);
        var observation = (await _host.ObservationsAsync(org, run.Id)).Single(o => o.CheckId == "M365-002" && o.SubjectId == subject);
        var evidence = JsonDocument.Parse(observation.Evidence!).RootElement;
        Assert.Equal([ContractHost.GlobalAdministrator], evidence.GetProperty("temporaryRoleTemplateIds").EnumerateArray().Select(r => r.GetString()));
        Assert.Equal("m365-002.fail.temporary",
            JsonDocument.Parse((await _host.AssessmentsAsync(org, "M365-002")).First(a => a.SubjectId == subject).BasisSnapshot)
                .RootElement.GetProperty("explanation").GetString());
        // The activation never counts as a global administrator (INV-035): the two standing ones pass M365-005.
        Assert.Equal("pass", (await _host.AssessmentsAsync(org, "M365-005"))[0].Result);
    }

    [Fact]
    [Invariant("INV-184")]
    public async Task Inv184_recalculation_gives_unknown_without_an_observation_only_to_assessed_pairs()
    {
        var tenant = _host.Tenant();
        tenant.SecurityDefaults = true;
        var anna = tenant.AddUser("anna", methods: "fido2");
        var org = await _host.OrganizationAsync();
        // Revision 2 before the first collection leaves M365-006 out: nothing of it is ever observed.
        var policy = await _host.PolicyAsync(org);
        policy["activeCheckIds"] = new JsonArray(policy["activeCheckIds"]!.AsArray().Select(c => c!.GetValue<string>())
            .Where(c => c != "M365-006").Select(c => (JsonNode)c).ToArray());
        Assert.Equal(System.Net.HttpStatusCode.Created, (await _host.PolicyRevisionAsync(org, policy, 1)).Status);
        await _host.ConnectAsync(org, tenant);
        await _host.RunJobsAsync();
        Assert.Empty(await _host.AssessmentsAsync(org, "M365-006"));

        // Revision 3 brings M365-006 back in assessed mode: the tenant has no observation of it.
        policy["activeCheckIds"]!.AsArray().Add("M365-006");
        Assert.Equal(System.Net.HttpStatusCode.Created, (await _host.PolicyRevisionAsync(org, policy, 2)).Status);
        await _host.RunJobsAsync();
        var consent = Assert.Single(await _host.AssessmentsAsync(org, "M365-006"));
        Assert.Equal(("unknown", "missing_observation", 3), (consent.Result, consent.ReasonCode, consent.EvaluatedPolicyVersion));
        // Informational M365-007 is never collected and M365-002 has no projection for a user without a role: no assessment.
        Assert.Empty(await _host.AssessmentsAsync(org, "M365-007"));
        var annaSubject = await _host.SubjectIdAsync(org, anna.Id.ToString());
        Assert.DoesNotContain(await _host.AssessmentsAsync(org, "M365-002"), a => a.SubjectId == annaSubject);
    }

    [Fact]
    [Invariant("INV-193")]
    public async Task Inv193_a_connected_tenant_before_its_first_collection_has_zero_coverage()
    {
        var tenant = _host.Tenant();
        tenant.SecurityDefaults = true;
        var org = await _host.OrganizationAsync();
        async Task<JsonElement> CoverageAsync()
        {
            var page = await _host.Admin.GetAsync("/api/v1/organizations?limit=100", "OrganizationOverviewPage");
            return page.Body.GetProperty("items").EnumerateArray()
                .Single(i => i.GetProperty("organization").GetProperty("id").GetString() == org.ToString()).GetProperty("coverageAt");
        }
        // Not connected: there are no pairs, so «no data».
        Assert.Equal(JsonValueKind.Null, (await CoverageAsync()).ValueKind);
        // Connected, the first collection has not run yet: the required tenant pairs count without data.
        await _host.ConnectAsync(org, tenant);
        Assert.Equal(0.0, (await CoverageAsync()).GetDouble());
    }
}
