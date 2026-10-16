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
}
