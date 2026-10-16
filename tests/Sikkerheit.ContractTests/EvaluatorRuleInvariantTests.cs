using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Sikkerheit.Contracts;
using Sikkerheit.ContractTests.Invariants;
using Sikkerheit.Host.Assessment;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Organizations;

namespace Sikkerheit.ContractTests;

/// <summary>
/// Records enforced by the evaluator, tested on the evaluator itself: the rules of 03 and the finding state machine of 05
/// on fixed evidence, without a database.
/// </summary>
[Enforcement("evaluator")]
public sealed class EvaluatorRuleInvariantTests
{
    private const string User = "00000000-0000-4000-8000-000000000001";
    private static readonly string Defaults = new PolicyRules(new ContractSchemas()).DefaultConfiguration;
    private static readonly DateTimeOffset Observed = new(2026, 10, 12, 3, 4, 0, TimeSpan.Zero);

    private static JsonElement Policy(Action<JsonObject>? change = null)
    {
        var node = JsonNode.Parse(Defaults)!.AsObject();
        change?.Invoke(node);
        return JsonDocument.Parse(node.ToJsonString()).RootElement.Clone();
    }

    private static JsonElement Assessed(string checkId, Action<JsonObject>? change = null) => Policy(p =>
    {
        p["checks"]![checkId]!["assessmentMode"] = "assessed";
        change?.Invoke(p);
    });

    private static RuleOutcome Run(string checkId, string evidence, JsonElement? policy = null) =>
        RuleEngine.Evaluate(new RuleInput(checkId, User, "collected", JsonDocument.Parse(evidence).RootElement, null, Observed),
            checkId, policy ?? Policy());

    private static RuleOutcome Unavailable(string checkId, string reason, JsonElement? policy = null) =>
        RuleEngine.Evaluate(new RuleInput(checkId, User, "unavailable", null, reason, Observed), checkId, policy ?? Policy());

    private static void Outcome(RuleOutcome outcome, string? result, string? reason = null, string? severity = null)
    {
        Assert.Equal((result, reason), (outcome.Result, outcome.ReasonCode));
        if (severity is not null)
        {
            Assert.Equal(severity, outcome.Severity);
        }
    }

    private static string Member(string methods, bool enabled = true, string type = "\"Member\"", bool sync = false) =>
        $$"""{"accountEnabled":{{(enabled ? "true" : "false")}},"userType":{{type}},"directorySyncAccount":{{(sync ? "true" : "false")}},"methodKinds":{{methods}}}""";

    private static string Admin(string methods, string type = "\"Member\"") =>
        $$"""{"accountEnabled":true,"userType":{{type}},"roleTemplateIds":["62e90394-69f5-4237-9190-012177145e10"],"assignment":"direct","methodKinds":{{methods}}}""";

    private static string Signins(string? last, string? created, bool enabled = true, string type = "\"Member\"", bool sync = false) =>
        $$"""{"accountEnabled":{{(enabled ? "true" : "false")}},"userType":{{type}},"directorySyncAccount":{{(sync ? "true" : "false")}},"lastSuccessfulSignInAt":{{(last is null ? "null" : $"\"{last}\"")}},"createdAt":{{(created is null ? "null" : $"\"{created}\"")}}}""";

    private static string CaPolicy(string state = "enabled", string conditions = "[]", string grant = """["mfa"]""", string op = "OR",
        int outside = 0, string strength = "null", bool allUsers = true) =>
        $$"""{"policyId":"44444444-0000-4000-8000-000000000001","state":"{{state}}","allUsers":{{(allUsers ? "true" : "false")}},"allApplications":true,"excludedApplications":0,"conditions":{{conditions}},"excludedUsersOutsidePolicy":{{outside}},"unresolvedExclusions":0,"allClientAppTypes":true,"grantOperator":"{{op}}","grantControls":{{grant}},"authStrengthRequiresMfa":{{strength}}}""";

    private static string Enforcement(string policies, string perUser = """{"required":0,"notRequired":3,"unknown":0}""",
        string ca = "available") =>
        $$"""{"securityDefaults":"disabled","conditionalAccess":"{{ca}}","mfaPolicies":[{{policies}}],"perUserMfa":{{perUser}}}""";

    [Fact]
    [Invariant("INV-028", Decision = "F04: M365-007 is introduced by a later rule version; its rule already follows 03")]
    public void Inv028_missing_license_is_carried_into_an_informational_result()
    {
        Outcome(Unavailable("M365-007", "license_missing"), null, "license_missing");
        Outcome(Unavailable("M365-004", "license_missing"), null, "license_missing");
        Outcome(Unavailable("M365-007", "license_missing", Assessed("M365-007")), "unknown", "license_missing");
    }

    [Fact]
    [Invariant("INV-029")]
    public void Inv029_password_email_and_temporary_access_pass_are_no_mfa()
    {
        Outcome(Run("M365-001", Member("""["password","email"]""")), "fail", severity: "warning");
        Outcome(Run("M365-001", Member("""["password","temporary_access_pass"]""")), "fail", severity: "warning");
        Outcome(Run("M365-001", Member("""["password","microsoft_authenticator"]""")), "pass");
    }

    [Fact]
    [Invariant("INV-030")]
    public void Inv030_phone_only_fails_when_phone_methods_are_not_accepted()
    {
        var strict = Policy(p => p["checks"]!["M365-001"]!["parameters"]!["phoneMethodsAccepted"] = false);
        Outcome(Run("M365-001", Member("""["password","phone"]"""), strict), "fail");
        Outcome(Run("M365-001", Member("""["password","phone"]""")), "pass");
    }

    [Fact]
    [Invariant("INV-031", Decision = "F04: M365-007 is deferred; its rule is checked here for the version that introduces it")]
    public void Inv031_excluded_guest_disabled_and_sync_accounts_are_not_applicable()
    {
        var excluded = Policy(p => p["m365"]!["excludedUserIds"] = new JsonArray(User));
        var inactive = Assessed("M365-007", p => p["m365"]!["excludedUserIds"] = new JsonArray(User));
        foreach (var outcome in new[]
                 {
                     Run("M365-001", Member("""["password"]"""), excluded), Run("M365-001", Member("null", type: "\"Guest\"")),
                     Run("M365-001", Member("null", enabled: false)), Run("M365-001", Member("null", sync: true)),
                     Run("M365-007", Signins(null, null), inactive), Run("M365-007", Signins(null, null, type: "\"Guest\""), Assessed("M365-007")),
                     Run("M365-007", Signins(null, null, enabled: false), Assessed("M365-007")),
                     Run("M365-007", Signins(null, null, sync: true), Assessed("M365-007")),
                 })
        {
            Outcome(outcome, "not_applicable", "policy_not_applicable");
        }
    }

    [Fact]
    [Invariant("INV-032")]
    public void Inv032_excluded_administrator_with_only_a_password_is_a_critical_failure()
    {
        var excluded = Policy(p => p["m365"]!["excludedUserIds"] = new JsonArray(User));
        Outcome(Run("M365-002", Admin("""["password"]"""), excluded), "fail", severity: "critical");
    }

    [Fact]
    [Invariant("INV-033")]
    public void Inv033_guest_with_a_privileged_role_fails_whatever_its_methods()
    {
        Outcome(Run("M365-002", Admin("""["fido2","microsoft_authenticator"]""", type: "\"Guest\"")), "fail", severity: "warning");
    }

    [Fact]
    [Invariant("INV-036")]
    public void Inv036_report_only_policy_of_the_reference_example_is_a_failure()
    {
        using var example = JsonDocument.Parse(File.ReadAllText(Path.Combine(InvariantRegistry.Root, "development-package", "examples",
            "m365-collection.json")));
        var observation = example.RootElement.GetProperty("observations").EnumerateArray()
            .Single(o => o.GetProperty("checkId").GetString() == "M365-003");
        Assert.Equal("enabledForReportingButNotEnforced",
            observation.GetProperty("evidence").GetProperty("mfaPolicies")[0].GetProperty("state").GetString());
        Outcome(Run("M365-003", observation.GetProperty("evidence").GetRawText()), "fail", severity: "critical");
    }

    [Fact]
    [Invariant("INV-037")]
    public void Inv037_enabled_mfa_policies_that_do_not_cover_everyone_are_unconfirmed()
    {
        Outcome(Run("M365-003", Enforcement(CaPolicy(allUsers: false))), "unknown", "enforcement_unconfirmed");
    }

    [Fact]
    [Invariant("INV-038")]
    public void Inv038_conditional_policy_for_everyone_is_unconfirmed_unless_the_policy_allows_it()
    {
        Outcome(Run("M365-003", Enforcement(CaPolicy(conditions: """["sign_in_risk"]"""))), "unknown", "enforcement_unconfirmed");
        Outcome(Run("M365-003", Enforcement(CaPolicy(grant: """["mfa","compliant_device"]"""))), "unknown", "enforcement_unconfirmed");
        Outcome(Run("M365-003", Enforcement(CaPolicy(conditions: """["locations_trusted_excluded"]"""))), "unknown", "enforcement_unconfirmed");
        var lenient = Policy(p => p["checks"]!["M365-003"]!["parameters"]!["deviceAlternativeAccepted"] = true);
        Outcome(Run("M365-003", Enforcement(CaPolicy(grant: """["mfa","compliant_device"]""")), lenient), "pass");
    }

    [Fact]
    [Invariant("INV-039")]
    public void Inv039_strength_without_mfa_or_exclusions_outside_the_policy_never_pass()
    {
        Outcome(Run("M365-003", Enforcement(CaPolicy(grant: """["authentication_strength"]""", strength: "false"))), "unknown",
            "enforcement_unconfirmed");
        Outcome(Run("M365-003", Enforcement(CaPolicy(outside: 30))), "unknown", "enforcement_unconfirmed");
    }

    [Fact]
    [Invariant("INV-040", Decision = "F01: only per-user MFA enforced counts; enabled stays unknown until SP-01")]
    public void Inv040_per_user_mfa_enforced_for_everyone_passes_also_with_entra_p1()
    {
        Outcome(Run("M365-003", Enforcement("", """{"required":12,"notRequired":0,"unknown":0}""")), "pass");
        Outcome(Run("M365-003", Enforcement("", """{"required":10,"notRequired":0,"unknown":2}""")), "unknown", "enforcement_unconfirmed");
    }

    [Fact]
    [Invariant("INV-041")]
    public void Inv041_without_conditional_access_and_security_defaults_per_user_mfa_decides()
    {
        Outcome(Run("M365-003", Enforcement("", """{"required":4,"notRequired":3,"unknown":0}""", ca: "license_missing")), "fail",
            severity: "critical");
        Outcome(Run("M365-003", Enforcement("", "null", ca: "license_missing")), "unknown", "enforcement_unconfirmed");
    }

    [Fact]
    [Invariant("INV-042")]
    public void Inv042_disabled_global_administrators_do_not_count()
    {
        var policy = Policy(p => p["checks"]!["M365-005"]!["parameters"]!["minGlobalAdmins"] = 2);
        Outcome(Run("M365-005", """{"globalAdminUserIds":["00000000-0000-4000-8000-000000000001"],"disabledGlobalAdminUserIds":["00000000-0000-4000-8000-000000000002"],"unresolvedGroupAssignments":0}""",
            policy), "fail", severity: "warning");
    }

    private static RuleOutcome Consent(string policies, JsonElement? policy = null) =>
        Run("M365-006", $$"""{"permissionGrantPolicies":{{policies}}}""", policy);

    [Fact]
    [Invariant("INV-043")]
    public void Inv043_legacy_consent_fails_and_no_or_allowed_consent_passes()
    {
        Outcome(Consent("""["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]"""), "fail", severity: "warning");
        Outcome(Consent("[]"), "pass");
        Outcome(Consent("""["ManagePermissionGrantsForSelf.microsoft-user-default-low"]"""), "pass");
    }

    [Fact]
    [Invariant("INV-044")]
    public void Inv044_known_microsoft_policy_outside_the_allowed_ones_fails()
    {
        Outcome(Consent("""["ManagePermissionGrantsForSelf.microsoft-user-default-recommended"]"""), "fail", severity: "warning");
        var allowing = Policy(p => p["checks"]!["M365-006"]!["parameters"]!["allowedPermissionGrantPolicies"] =
            new JsonArray("ManagePermissionGrantsForSelf.microsoft-user-default-recommended"));
        Outcome(Consent("""["ManagePermissionGrantsForSelf.microsoft-user-default-recommended"]""", allowing), "pass");
    }

    [Fact]
    [Invariant("INV-045")]
    public void Inv045_custom_consent_policy_is_unmapped()
    {
        Outcome(Consent("""["ManagePermissionGrantsForSelf.fjord-custom-apps"]"""), "unknown", "unmapped_state");
    }

    [Fact]
    [Invariant("INV-046", Decision = "F04: applies once M365-007 is introduced")]
    public void Inv046_account_without_sign_in_and_without_a_creation_date_fails()
    {
        var policy = Assessed("M365-007");
        Outcome(Run("M365-007", Signins(null, null), policy), "fail", severity: "warning");
        Outcome(Run("M365-007", Signins(null, "2024-01-15T00:00:00Z"), policy), "fail");
        Outcome(Run("M365-007", Signins("2026-10-01T08:00:00Z", "2016-03-01T00:00:00Z"), policy), "pass");
        Outcome(Run("M365-007", Signins("2026-06-01T08:00:00Z", "2016-03-01T00:00:00Z"), policy), "fail");
        Outcome(Run("M365-007", Signins(null, "2026-09-30T00:00:00Z"), policy), "pass");
    }

    [Fact]
    [Invariant("INV-047")]
    public void Inv047_active_check_without_an_observation_is_unknown_missing_observation()
    {
        Outcome(RuleEngine.Evaluate(null, "M365-001", Policy()), "unknown", "missing_observation");
        Outcome(RuleEngine.Evaluate(null, "M365-003", Policy()), "unknown", "missing_observation");
    }

    [Fact]
    [Invariant("INV-048")]
    public void Inv048_informational_result_keeps_no_reason_of_the_rule()
    {
        var outcome = Run("M365-004", """{"securityDefaults":"disabled","conditionalAccess":"license_missing","legacyBlockPolicies":[]}""");
        Outcome(outcome, null);
        Assert.Equal("m365-004.unknown.no_conditional_access", outcome.Explanation);
    }

    // The finding state machine of 05 «Таблица переходов finding» on an in-memory context: it only adds rows.

    private static readonly Guid Org = Guid.NewGuid();
    private static readonly DateTimeOffset Now = new(2026, 10, 12, 4, 0, 0, TimeSpan.Zero);

    private static SikkerheitDb Memory() =>
        new(new DbContextOptionsBuilder<SikkerheitDb>().UseNpgsql("Host=unused.invalid").Options);

    private static Host.Data.Assessment Result(string result, string? severity = "warning", string checkId = "M365-001") => new()
    {
        OrganizationId = Org, Id = Guid.CreateVersion7(), SubjectId = Subject, CheckId = checkId, RuleId = checkId,
        RuleVersion = RuleEngine.RuleVersion, AssessmentMode = "assessed", Result = result,
        Severity = result == "fail" ? severity : null, ObservedAt = Now, ReceivedAt = Now, EvaluatedAt = Now, BasisSnapshot = "{}",
    };

    private static readonly Guid Subject = Guid.NewGuid();

    private static Finding Open(string workflow = "new", DateTimeOffset? reviewAt = null) => new()
    {
        OrganizationId = Org, Id = Guid.CreateVersion7(), SubjectId = Subject, CheckId = "M365-001", TechnicalState = "open",
        WorkflowState = workflow, AssessmentResult = "fail", Severity = "warning", Quality = "fresh_fail", OpenedAt = Now.AddDays(-3),
        ReviewAt = reviewAt,
    };

    private static List<string> Events(SikkerheitDb db) =>
        db.ChangeTracker.Entries<FindingEvent>().Select(e => e.Entity.EventType + "/" + e.Entity.Cause).ToList();

    [Fact]
    [Invariant("INV-049")]
    public void Inv049_fresh_fail_without_a_finding_opens_it_as_new()
    {
        using var db = Memory();
        new FindingMachine(db, Org, Now).Apply(null, Result("fail"), "source_change", notApplicableBySource: false);
        var finding = Assert.Single(db.ChangeTracker.Entries<Finding>()).Entity;
        Assert.Equal(("open", "new"), (finding.TechnicalState, finding.WorkflowState));
        Assert.Equal(["opened/source_change"], Events(db));
    }

    [Fact]
    [Invariant("INV-050")]
    public void Inv050_fresh_pass_resolves_with_source_change_and_keeps_the_workflow()
    {
        using var db = Memory();
        var finding = Open("in_progress");
        new FindingMachine(db, Org, Now).Apply(finding, Result("pass"), "source_change", notApplicableBySource: false);
        Assert.Equal(("resolved", "in_progress"), (finding.TechnicalState, finding.WorkflowState));
        Assert.Equal(["resolved/source_change"], Events(db));
    }

    [Fact]
    [Invariant("INV-051")]
    public void Inv051_fail_after_resolved_reopens_as_new_unless_a_risk_decision_is_in_force()
    {
        using var db = Memory();
        var machine = new FindingMachine(db, Org, Now);
        var finding = Open("in_progress");
        finding.TechnicalState = "resolved";
        machine.Apply(finding, Result("fail"), "source_change", notApplicableBySource: false);
        Assert.Equal(("open", "new"), (finding.TechnicalState, finding.WorkflowState));
        var accepted = Open("risk_accepted", reviewAt: Now.AddDays(30));
        accepted.TechnicalState = "resolved";
        machine.Apply(accepted, Result("fail"), "source_change", notApplicableBySource: false);
        Assert.Equal(("open", "risk_accepted"), (accepted.TechnicalState, accepted.WorkflowState));
        Assert.Equal(["reopened/source_change", "reopened/source_change"], Events(db));
    }

    [Fact]
    [Invariant("INV-052")]
    public void Inv052_new_revision_that_excludes_or_drops_the_check_writes_policy_changed()
    {
        using var db = Memory();
        var machine = new FindingMachine(db, Org, Now);
        var excluded = Open();
        var outcome = RuleEngine.Evaluate(new RuleInput("M365-001", User, "collected", JsonDocument.Parse(Member("""["password"]""")).RootElement,
            null, Now), "M365-001", Policy(p => p["m365"]!["excludedUserIds"] = new JsonArray(User)));
        var assessment = Result("not_applicable");
        assessment.Result = outcome.Result;
        machine.Apply(excluded, assessment, "policy_change", notApplicableBySource: false);
        var dropped = Open();
        machine.PolicyRemoved(dropped);
        Assert.Equal(("resolved", "resolved"), (excluded.TechnicalState, dropped.TechnicalState));
        Assert.Equal(["policy_changed/policy_change", "policy_changed/policy_change"], Events(db));
    }

    [Fact]
    [Invariant("INV-053")]
    public void Inv053_not_applicable_by_source_facts_resolves_with_applicability_change()
    {
        using var db = Memory();
        var finding = Open();
        Assert.Equal("not_applicable", Run("M365-001", Member("""["password"]""", enabled: false)).Result);
        new FindingMachine(db, Org, Now).Apply(finding, Result("not_applicable"), "source_change", notApplicableBySource: true);
        Assert.Equal("resolved", finding.TechnicalState);
        Assert.Equal(["resolved/applicability_change"], Events(db));
    }

    [Fact]
    [Invariant("INV-055")]
    public void Inv055_quality_change_is_written_once()
    {
        using var db = Memory();
        var machine = new FindingMachine(db, Org, Now);
        var finding = Open();
        // freshness_sweep twice after 49 hours without a collection, then unknown twice, then a fresh fail.
        machine.Quality(finding, "stale");
        machine.Quality(finding, "stale");
        Assert.Equal(["quality_changed/data_quality"], Events(db));
        machine.Apply(finding, Result("unknown"), "source_change", notApplicableBySource: false);
        machine.Apply(finding, Result("unknown"), "source_change", notApplicableBySource: false);
        machine.Apply(finding, Result("fail"), "source_change", notApplicableBySource: false);
        Assert.Equal(["quality_changed/data_quality", "quality_changed/data_quality", "quality_changed/data_quality"], Events(db));
        Assert.Equal("fresh_fail", finding.Quality);
    }
}
