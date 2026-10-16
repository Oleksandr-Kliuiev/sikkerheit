using System.Text.Json;
using System.Text.Json.Nodes;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Assessment;
using Sikkerheit.Host.Organizations;

namespace Sikkerheit.UnitTests.Assessment;

/// <summary>AT-05: rules M365-001…M365-006 on synthetic evidence, including every negative case of M365-003.</summary>
public sealed class M365RulesTests
{
    private static readonly string Defaults = new PolicyRules(new ContractSchemas()).DefaultConfiguration;

    private static JsonElement Policy(Action<JsonObject>? change = null)
    {
        var node = JsonNode.Parse(Defaults)!.AsObject();
        change?.Invoke(node);
        return JsonDocument.Parse(node.ToJsonString()).RootElement.Clone();
    }

    private static RuleOutcome Run(string checkId, string evidence, JsonElement? policy = null, string subject = "00000000-0000-4000-8000-000000000001") =>
        RuleEngine.Evaluate(new RuleInput(checkId, subject, "collected", JsonDocument.Parse(evidence).RootElement, null), checkId,
            policy ?? Policy());

    private static string User(string methods, bool enabled = true, string type = "\"Member\"", bool sync = false) =>
        $$"""{"accountEnabled":{{enabled.ToString().ToLowerInvariant()}},"userType":{{type}},"directorySyncAccount":{{sync.ToString().ToLowerInvariant()}},"methodKinds":{{methods}}}""";

    [Theory]
    [InlineData("""["password","email"]""", "fail")]
    [InlineData("""["password","microsoft_authenticator"]""", "pass")]
    [InlineData("""["password","temporary_access_pass","qr_code_pin"]""", "fail")]
    [InlineData("""["fido2"]""", "pass")]
    public void M365_001_counts_only_mfa_methods(string methods, string expected) =>
        Assert.Equal(expected, Run("M365-001", User(methods)).Result);

    [Fact]
    public void M365_001_phone_counts_only_when_accepted()
    {
        Assert.Equal("pass", Run("M365-001", User("""["phone"]""")).Result);
        var strict = Policy(p => p["checks"]!["M365-001"]!["parameters"]!["phoneMethodsAccepted"] = false);
        Assert.Equal("fail", Run("M365-001", User("""["phone"]"""), strict).Result);
    }

    [Fact]
    public void M365_001_is_not_applicable_to_disabled_guest_excluded_and_sync_accounts()
    {
        Assert.Equal("not_applicable", Run("M365-001", User("null", enabled: false)).Result);
        Assert.Equal("not_applicable", Run("M365-001", User("null", type: "\"Guest\"")).Result);
        Assert.Equal("not_applicable", Run("M365-001", User("null", sync: true)).Result);
        var excluded = Policy(p => p["m365"]!["excludedUserIds"] = new JsonArray("00000000-0000-4000-8000-000000000001"));
        var outcome = Run("M365-001", User("""["password"]"""), excluded);
        Assert.Equal("not_applicable", outcome.Result);
        Assert.Equal("policy_not_applicable", outcome.ReasonCode);
    }

    private static string Admin(string roles, string methods, string type = "\"Member\"", bool enabled = true) =>
        $$"""{"accountEnabled":{{enabled.ToString().ToLowerInvariant()}},"userType":{{type}},"roleTemplateIds":{{roles}},"assignment":"direct","methodKinds":{{methods}}}""";

    [Fact]
    public void M365_002_rules_in_order()
    {
        const string role = """["62e90394-69f5-4237-9190-012177145e10"]""";
        Assert.Equal("not_applicable", Run("M365-002", Admin("[]", """["password"]""")).Result);
        Assert.Equal("not_applicable", Run("M365-002", Admin(role, """["password"]""", enabled: false)).Result);
        var guest = Run("M365-002", Admin(role, """["fido2"]""", type: "\"Guest\""));
        Assert.Equal(("fail", "warning"), (guest.Result, guest.Severity));
        Assert.Equal("pass", Run("M365-002", Admin(role, """["fido2"]""")).Result);
        var none = Run("M365-002", Admin(role, """["password"]"""));
        Assert.Equal(("fail", "critical"), (none.Result, none.Severity));
    }

    private static string CaPolicy(string state = "enabled", string conditions = "[]", string grant = """["mfa"]""",
        string op = "OR", int excludedApps = 0, int outside = 0, int unresolved = 0, string strength = "null",
        bool allUsers = true, bool allClients = true) =>
        $$"""{"policyId":"44444444-0000-4000-8000-000000000001","state":"{{state}}","allUsers":{{allUsers.ToString().ToLowerInvariant()}},"allApplications":true,"excludedApplications":{{excludedApps}},"conditions":{{conditions}},"excludedUsersOutsidePolicy":{{outside}},"unresolvedExclusions":{{unresolved}},"allClientAppTypes":{{allClients.ToString().ToLowerInvariant()}},"grantOperator":"{{op}}","grantControls":{{grant}},"authStrengthRequiresMfa":{{strength}}}""";

    private static string Enforcement(string policies, string perUser = "null", string sd = "disabled", string ca = "available") =>
        $$"""{"securityDefaults":"{{sd}}","conditionalAccess":"{{ca}}","mfaPolicies":[{{policies}}],"perUserMfa":{{perUser}}}""";

    private const string PerUserOff = """{"required":0,"notRequired":3,"unknown":0}""";

    [Fact]
    public void M365_003_report_only_policy_is_a_failure_not_a_pass() =>
        Assert.Equal("fail", Run("M365-003", Enforcement(CaPolicy("enabledForReportingButNotEnforced"), PerUserOff)).Result);

    [Fact]
    public void M365_003_passes_with_security_defaults_or_an_unconditional_policy()
    {
        Assert.Equal("pass", Run("M365-003", Enforcement("", sd: "enabled")).Result);
        Assert.Equal("pass", Run("M365-003", Enforcement(CaPolicy())).Result);
        Assert.Equal("pass", Run("M365-003", Enforcement(CaPolicy(grant: """["authentication_strength"]""", strength: "true"))).Result);
    }

    [Theory]
    [InlineData("""["sign_in_risk"]""", """["mfa"]""", "OR", 0, 0, 0, "null")]
    [InlineData("""["locations_trusted_excluded"]""", """["mfa"]""", "OR", 0, 0, 0, "null")]
    [InlineData("[]", """["mfa","compliant_device"]""", "OR", 0, 0, 0, "null")]
    [InlineData("[]", """["mfa"]""", "OR", 1, 0, 0, "null")]
    [InlineData("[]", """["mfa"]""", "OR", 0, 1, 0, "null")]
    [InlineData("[]", """["mfa"]""", "OR", 0, 0, 1, "null")]
    [InlineData("[]", """["authentication_strength"]""", "OR", 0, 0, 0, "false")]
    public void M365_003_conditional_policies_never_pass(string conditions, string grant, string op, int apps, int outside,
        int unresolved, string strength)
    {
        var outcome = Run("M365-003", Enforcement(CaPolicy(conditions: conditions, grant: grant, op: op, excludedApps: apps,
            outside: outside, unresolved: unresolved, strength: strength), PerUserOff));
        Assert.NotEqual("pass", outcome.Result);
    }

    [Fact]
    public void M365_003_accepts_device_and_trusted_location_alternatives_only_when_the_policy_allows()
    {
        var lenient = Policy(p =>
        {
            p["checks"]!["M365-003"]!["parameters"]!["deviceAlternativeAccepted"] = true;
            p["checks"]!["M365-003"]!["parameters"]!["trustedLocationsExclusionAccepted"] = true;
        });
        Assert.Equal("pass", Run("M365-003", Enforcement(CaPolicy(grant: """["mfa","compliant_device"]""")), lenient).Result);
        Assert.Equal("pass", Run("M365-003", Enforcement(CaPolicy(conditions: """["locations_trusted_excluded"]""")), lenient).Result);
    }

    [Fact]
    public void M365_003_per_user_mfa_needs_enforced_for_everyone()
    {
        Assert.Equal("pass", Run("M365-003", Enforcement("", """{"required":4,"notRequired":0,"unknown":0}""", ca: "license_missing")).Result);
        var enabled = Run("M365-003", Enforcement("", """{"required":2,"notRequired":0,"unknown":2}""", ca: "license_missing"));
        Assert.Equal(("unknown", "enforcement_unconfirmed"), (enabled.Result, enabled.ReasonCode));
        Assert.Equal("fail", Run("M365-003", Enforcement("", PerUserOff, ca: "license_missing")).Result);
        var off = Run("M365-003", Enforcement("", "null", ca: "license_missing"));
        Assert.Equal(("unknown", "enforcement_unconfirmed"), (off.Result, off.ReasonCode));
    }

    [Theory]
    [InlineData(1, "fail")]
    [InlineData(2, "pass")]
    [InlineData(4, "pass")]
    [InlineData(5, "fail")]
    public void M365_005_counts_enabled_global_admins(int count, string expected)
    {
        var ids = string.Join(',', Enumerable.Range(1, count).Select(i => $"\"00000000-0000-4000-8000-00000000000{i}\""));
        Assert.Equal(expected, Run("M365-005", $$"""{"globalAdminUserIds":[{{ids}}],"disabledGlobalAdminUserIds":[],"unresolvedGroupAssignments":0}""").Result);
    }

    [Fact]
    public void M365_005_unresolved_group_is_unknown() =>
        Assert.Equal("partial_data", Run("M365-005", """{"globalAdminUserIds":[],"disabledGlobalAdminUserIds":[],"unresolvedGroupAssignments":1}""").ReasonCode);

    [Theory]
    [InlineData("""["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]""", "fail")]
    [InlineData("""["ManagePermissionGrantsForSelf.microsoft-user-default-low"]""", "pass")]
    [InlineData("""["ManagePermissionGrantsForSelf.microsoft-user-default-recommended"]""", "fail")]
    [InlineData("""["ManagePermissionGrantsForSelf.microsoft-user-default-allow-consent-apps"]""", "pass")]
    [InlineData("""["ManagePermissionGrantsForSelf.contoso-custom"]""", "unknown")]
    [InlineData("[]", "pass")]
    public void M365_006_consent_policies(string policies, string expected) =>
        Assert.Equal(expected, Run("M365-006", $$"""{"permissionGrantPolicies":{{policies}}}""").Result);

    [Fact]
    public void Informational_mode_has_no_result_and_keeps_only_transferable_reasons()
    {
        var outcome = Run("M365-004", """{"securityDefaults":"disabled","conditionalAccess":"license_missing","legacyBlockPolicies":[]}""");
        Assert.Null(outcome.Result);
        Assert.Null(outcome.ReasonCode);
        var unavailable = RuleEngine.Evaluate(new RuleInput("M365-004", "t", "unavailable", null, "permission_denied"), "M365-004", Policy());
        Assert.Null(unavailable.Result);
        Assert.Equal("permission_denied", unavailable.ReasonCode);
    }

    [Fact]
    public void Every_explanation_key_has_three_languages()
    {
        foreach (var key in Texts.ExplanationKeys)
        {
            Assert.True(Texts.HasAllLanguages(key));
        }
        Assert.Equal("nn", Texts.Language("nn-NO,nb;q=0.8"));
        Assert.Equal("nb", Texts.Language("sv-SE"));
        Assert.Equal("nb", Texts.Language("no"));
    }
}
