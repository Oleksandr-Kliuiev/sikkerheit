using System.Text.Json;
using Sikkerheit.Contracts;

namespace Sikkerheit.Host.Assessment;

/// <summary>Result of a rule: result, severity, reason and the explanation key with its arguments.</summary>
public sealed record RuleOutcome(string? Result, string? Severity, string? ReasonCode, string Explanation,
    IReadOnlyDictionary<string, string>? Arguments = null)
{
    public static RuleOutcome Pass(string explanation, IReadOnlyDictionary<string, string>? args = null) =>
        new("pass", null, null, explanation, args);

    public static RuleOutcome Fail(string severity, string explanation, IReadOnlyDictionary<string, string>? args = null) =>
        new("fail", severity, null, explanation, args);

    public static RuleOutcome Unknown(string reason, string explanation, IReadOnlyDictionary<string, string>? args = null) =>
        new("unknown", null, reason, explanation, args);

    public static RuleOutcome NotApplicable(string explanation) =>
        new("not_applicable", null, "policy_not_applicable", explanation);
}

/// <summary>Observation as stored: status, evidence or reason, subject key and the time it was observed.</summary>
public sealed record RuleInput(string CheckId, string SubjectKey, string CollectionStatus, JsonElement? Evidence, string? ReasonCode,
    DateTimeOffset? ObservedAt = null);

/// <summary>
/// Order of evaluation of 03 «Семантика результата»: missing observation → unavailable → rule; informational mode
/// keeps only transferable reasons and never gives a result.
/// </summary>
public static class RuleEngine
{
    public const string RuleVersion = "1.0.0";

    public static RuleOutcome Evaluate(RuleInput? observation, string checkId, JsonElement configuration)
    {
        var check = configuration.GetProperty("checks").GetProperty(checkId);
        var mode = check.GetProperty("assessmentMode").GetString()!;
        RuleOutcome outcome;
        if (observation is null)
        {
            outcome = RuleOutcome.Unknown("missing_observation", "common.missing_observation");
        }
        else if (observation.CollectionStatus == "unavailable")
        {
            outcome = RuleOutcome.Unknown(observation.ReasonCode!, "common.unavailable." + observation.ReasonCode);
        }
        else
        {
            outcome = checkId switch
            {
                "M365-001" => M365Rules.MfaRegistration(observation, configuration),
                "M365-002" => M365Rules.AdminMfaRegistration(observation, configuration),
                "M365-003" => M365Rules.MfaEnforcement(observation, check.GetProperty("parameters")),
                "M365-004" => M365Rules.LegacyAuthentication(observation),
                "M365-005" => M365Rules.GlobalAdmins(observation, check.GetProperty("parameters")),
                "M365-006" => M365Rules.UserConsent(observation, check.GetProperty("parameters")),
                "M365-007" => M365Rules.InactiveAccount(observation, configuration),
                _ => RuleOutcome.Unknown("missing_observation", "common.not_implemented"),
            };
        }
        if (mode == "informational")
        {
            var transferable = outcome.ReasonCode is not null && Catalog.InformationalReasons.Contains(outcome.ReasonCode);
            return new RuleOutcome(null, null, transferable ? outcome.ReasonCode : null, outcome.Explanation, outcome.Arguments);
        }
        return outcome;
    }
}

/// <summary>
/// Rules M365-001…M365-007 of 03. M365-007 is not collected yet (AuditLog.Read.All is deferred), its rule is ready for the
/// version of the rules that introduces it.
/// </summary>
public static class M365Rules
{
    private static readonly HashSet<string> StrongMethods =
        ["microsoft_authenticator", "fido2", "windows_hello_for_business", "platform_credential", "software_oath",
         "hardware_oath", "external"];

    public static bool HasMfaMethod(JsonElement methods, bool phoneAccepted) =>
        methods.ValueKind == JsonValueKind.Array && methods.EnumerateArray().Select(m => m.GetString()!)
            .Any(m => StrongMethods.Contains(m) || (phoneAccepted && m == "phone"));

    private static Dictionary<string, string> Methods(JsonElement methods) => new()
    {
        ["methods"] = methods.ValueKind == JsonValueKind.Array
            ? string.Join(", ", methods.EnumerateArray().Select(m => m.GetString())) : "",
    };

    public static RuleOutcome MfaRegistration(RuleInput input, JsonElement configuration)
    {
        var e = input.Evidence!.Value;
        var excluded = configuration.GetProperty("m365").GetProperty("excludedUserIds").EnumerateArray()
            .Any(id => string.Equals(id.GetString(), input.SubjectKey, StringComparison.OrdinalIgnoreCase));
        if (!e.GetProperty("accountEnabled").GetBoolean())
        {
            return RuleOutcome.NotApplicable("m365-001.not_applicable.disabled");
        }
        if (e.GetProperty("userType").ValueKind == JsonValueKind.String && e.GetProperty("userType").GetString() == "Guest")
        {
            return RuleOutcome.NotApplicable("m365-001.not_applicable.guest");
        }
        if (excluded)
        {
            return RuleOutcome.NotApplicable("m365-001.not_applicable.excluded");
        }
        if (e.GetProperty("directorySyncAccount").GetBoolean())
        {
            return RuleOutcome.NotApplicable("m365-001.not_applicable.sync_account");
        }
        var methods = e.GetProperty("methodKinds");
        if (methods.ValueKind != JsonValueKind.Array)
        {
            return RuleOutcome.Unknown("missing_observation", "common.missing_observation");
        }
        var phone = configuration.GetProperty("checks").GetProperty("M365-001").GetProperty("parameters")
            .GetProperty("phoneMethodsAccepted").GetBoolean();
        return HasMfaMethod(methods, phone)
            ? RuleOutcome.Pass("m365-001.pass", Methods(methods))
            : RuleOutcome.Fail("warning", "m365-001.fail", Methods(methods));
    }

    public static RuleOutcome AdminMfaRegistration(RuleInput input, JsonElement configuration)
    {
        var e = input.Evidence!.Value;
        if (e.GetProperty("roleTemplateIds").GetArrayLength() == 0)
        {
            return RuleOutcome.NotApplicable("m365-002.not_applicable.no_role");
        }
        if (!e.GetProperty("accountEnabled").GetBoolean())
        {
            return RuleOutcome.NotApplicable("m365-002.not_applicable.disabled");
        }
        if (e.GetProperty("userType").ValueKind == JsonValueKind.String && e.GetProperty("userType").GetString() == "Guest")
        {
            return RuleOutcome.Fail("warning", "m365-002.fail.guest");
        }
        var methods = e.GetProperty("methodKinds");
        var phone = configuration.GetProperty("checks").GetProperty("M365-001").GetProperty("parameters")
            .GetProperty("phoneMethodsAccepted").GetBoolean();
        // A role held only through a PIM activation is assessed like a standing one; the explanation names it (03).
        var temporary = e.TryGetProperty("temporaryRoleTemplateIds", out var t) && t.ValueKind == JsonValueKind.Array
                        && t.GetArrayLength() > 0;
        var suffix = temporary ? ".temporary" : "";
        return HasMfaMethod(methods, phone)
            ? RuleOutcome.Pass("m365-002.pass" + suffix, Methods(methods))
            : RuleOutcome.Fail("critical", "m365-002.fail" + suffix, Methods(methods));
    }

    /// <summary>Unconditional policy of 03 «Правило M365-003».</summary>
    public static bool IsUnconditional(JsonElement policy, bool deviceAlternativeAccepted, bool trustedLocationsAccepted)
    {
        if (policy.GetProperty("state").GetString() != "enabled" || !policy.GetProperty("allUsers").GetBoolean()
            || !policy.GetProperty("allApplications").GetBoolean() || policy.GetProperty("excludedApplications").GetInt32() != 0
            || !policy.GetProperty("allClientAppTypes").GetBoolean()
            || policy.GetProperty("excludedUsersOutsidePolicy").GetInt32() != 0
            || policy.GetProperty("unresolvedExclusions").GetInt32() != 0)
        {
            return false;
        }
        var conditions = policy.GetProperty("conditions").EnumerateArray().Select(c => c.GetString()!).ToList();
        if (conditions.Any(c => !(c == "locations_trusted_excluded" && trustedLocationsAccepted)))
        {
            return false;
        }
        var controls = policy.GetProperty("grantControls").EnumerateArray().Select(c => c.GetString()!).ToHashSet();
        var strengthMfa = policy.GetProperty("authStrengthRequiresMfa").ValueKind == JsonValueKind.True;
        var mfa = controls.Contains("mfa") || (controls.Contains("authentication_strength") && strengthMfa);
        if (!mfa)
        {
            return false;
        }
        if (policy.GetProperty("grantOperator").GetString() == "AND")
        {
            return true;
        }
        // With OR every other control is an alternative to MFA; only a device alternative may be accepted.
        var alternatives = controls.Where(c => c is not "mfa" && !(c == "authentication_strength" && strengthMfa)).ToList();
        return alternatives.Count == 0
               || (deviceAlternativeAccepted && alternatives.All(c => c is "compliant_device" or "domain_joined_device"));
    }

    public static RuleOutcome MfaEnforcement(RuleInput input, JsonElement parameters)
    {
        var e = input.Evidence!.Value;
        if (e.GetProperty("securityDefaults").GetString() == "enabled")
        {
            return RuleOutcome.Pass("m365-003.pass.security_defaults");
        }
        var device = parameters.GetProperty("deviceAlternativeAccepted").GetBoolean();
        var trusted = parameters.GetProperty("trustedLocationsExclusionAccepted").GetBoolean();
        var caAvailable = e.GetProperty("conditionalAccess").GetString() == "available";
        var policies = e.GetProperty("mfaPolicies").EnumerateArray().ToList();
        if (caAvailable && policies.FirstOrDefault(p => IsUnconditional(p, device, trusted)) is { ValueKind: JsonValueKind.Object } policy)
        {
            return RuleOutcome.Pass("m365-003.pass.conditional_access",
                new Dictionary<string, string> { ["policyId"] = policy.GetProperty("policyId").GetString()! });
        }
        var perUser = e.GetProperty("perUserMfa");
        if (perUser.ValueKind == JsonValueKind.Object && perUser.GetProperty("notRequired").GetInt32() == 0)
        {
            // Per-user «enabled» is not counted as enforcement until SP-01 confirms it; without the field it is in unknown.
            var enabled = perUser.TryGetProperty("enabled", out var en) && en.ValueKind == JsonValueKind.Number ? en.GetInt32() : 0;
            return perUser.GetProperty("unknown").GetInt32() + enabled == 0
                ? RuleOutcome.Pass("m365-003.pass.per_user_mfa")
                : RuleOutcome.Unknown("enforcement_unconfirmed", "m365-003.unknown.per_user_enabled");
        }
        if (caAvailable && policies.Any(p => p.GetProperty("state").GetString() == "enabled"))
        {
            return RuleOutcome.Unknown("enforcement_unconfirmed", "m365-003.unknown.conditional_policies");
        }
        if (perUser.ValueKind == JsonValueKind.Null)
        {
            return RuleOutcome.Unknown("enforcement_unconfirmed", "m365-003.unknown.per_user_off");
        }
        return RuleOutcome.Fail("critical", "m365-003.fail");
    }

    public static RuleOutcome LegacyAuthentication(RuleInput input)
    {
        var e = input.Evidence!.Value;
        if (e.GetProperty("securityDefaults").GetString() == "enabled")
        {
            return RuleOutcome.Pass("m365-004.pass.security_defaults");
        }
        var blocking = e.GetProperty("legacyBlockPolicies").EnumerateArray().Any(p =>
            p.GetProperty("state").GetString() == "enabled" && p.GetProperty("allUsers").GetBoolean()
            && p.GetProperty("allApplications").GetBoolean() && p.GetProperty("excludedApplications").GetInt32() == 0
            && p.GetProperty("conditions").GetArrayLength() == 0 && p.GetProperty("coversExchangeActiveSync").GetBoolean()
            && p.GetProperty("coversOtherClients").GetBoolean() && p.GetProperty("excludedUsersOutsidePolicy").GetInt32() == 0
            && p.GetProperty("unresolvedExclusions").GetInt32() == 0);
        if (blocking)
        {
            return RuleOutcome.Pass("m365-004.pass.conditional_access");
        }
        return e.GetProperty("conditionalAccess").GetString() == "available"
            ? RuleOutcome.Fail("warning", "m365-004.fail")
            : RuleOutcome.Unknown("enforcement_unconfirmed", "m365-004.unknown.no_conditional_access");
    }

    public static RuleOutcome GlobalAdmins(RuleInput input, JsonElement parameters)
    {
        var e = input.Evidence!.Value;
        if (e.GetProperty("unresolvedGroupAssignments").GetInt32() > 0)
        {
            return RuleOutcome.Unknown("partial_data", "m365-005.unknown.groups");
        }
        var count = e.GetProperty("globalAdminUserIds").GetArrayLength();
        var args = new Dictionary<string, string>
        {
            ["count"] = count.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["disabled"] = e.GetProperty("disabledGlobalAdminUserIds").GetArrayLength().ToString(System.Globalization.CultureInfo.InvariantCulture),
        };
        var min = parameters.GetProperty("minGlobalAdmins").GetInt32();
        var max = parameters.GetProperty("maxGlobalAdmins").GetInt32();
        // Roles outside privilegedRoleTemplateIds never change the result; the explanation lists them (03).
        var uncovered = e.TryGetProperty("uncoveredRoleTemplateIds", out var u) && u.ValueKind == JsonValueKind.Array
            ? u.EnumerateArray().Select(r => r.GetString()!).ToList() : [];
        var suffix = uncovered.Count > 0 ? ".uncovered" : "";
        if (uncovered.Count > 0)
        {
            args["roles"] = string.Join(", ", uncovered.Select(RoleNames.Name));
        }
        return count < min || count > max
            ? RuleOutcome.Fail("warning", (count < min ? "m365-005.fail.too_few" : "m365-005.fail.too_many") + suffix, args)
            : RuleOutcome.Pass("m365-005.pass" + suffix, args);
    }

    /// <summary>signInActivity is filled since 1 December 2023; createdDateTime is null for some accounts before June 2018.</summary>
    public static RuleOutcome InactiveAccount(RuleInput input, JsonElement configuration)
    {
        var e = input.Evidence!.Value;
        var excluded = configuration.GetProperty("m365").GetProperty("excludedUserIds").EnumerateArray()
            .Any(id => string.Equals(id.GetString(), input.SubjectKey, StringComparison.OrdinalIgnoreCase));
        if (!e.GetProperty("accountEnabled").GetBoolean())
        {
            return RuleOutcome.NotApplicable("m365-007.not_applicable.disabled");
        }
        if (e.GetProperty("userType").ValueKind == JsonValueKind.String && e.GetProperty("userType").GetString() == "Guest")
        {
            return RuleOutcome.NotApplicable("m365-007.not_applicable.guest");
        }
        if (excluded)
        {
            return RuleOutcome.NotApplicable("m365-007.not_applicable.excluded");
        }
        if (e.GetProperty("directorySyncAccount").GetBoolean())
        {
            return RuleOutcome.NotApplicable("m365-007.not_applicable.sync_account");
        }
        var limit = configuration.GetProperty("checks").GetProperty("M365-007").GetProperty("parameters")
            .GetProperty("inactiveDays").GetInt32();
        var now = input.ObservedAt ?? throw new InvalidOperationException("M365-007 needs the time of the observation");
        var culture = System.Globalization.CultureInfo.InvariantCulture;
        int DaysSince(JsonElement value) => (int)Math.Floor((now - DateTimeOffset.Parse(value.GetString()!, culture)).TotalDays);
        var args = new Dictionary<string, string> { ["limit"] = limit.ToString(culture) };
        var signIn = e.GetProperty("lastSuccessfulSignInAt");
        var created = e.GetProperty("createdAt");
        if (signIn.ValueKind == JsonValueKind.String)
        {
            var days = DaysSince(signIn);
            args["days"] = days.ToString(culture);
            return days > limit ? RuleOutcome.Fail("warning", "m365-007.fail.inactive", args) : RuleOutcome.Pass("m365-007.pass", args);
        }
        if (created.ValueKind != JsonValueKind.String)
        {
            return RuleOutcome.Fail("warning", "m365-007.fail.legacy", args);
        }
        var age = DaysSince(created);
        args["days"] = age.ToString(culture);
        return age > limit ? RuleOutcome.Fail("warning", "m365-007.fail.never", args) : RuleOutcome.Pass("m365-007.pass.new", args);
    }

    private const string Legacy = "ManagePermissionGrantsForSelf.microsoft-user-default-legacy";
    private static readonly string[] KnownMicrosoft =
    [
        Legacy, "ManagePermissionGrantsForSelf.microsoft-user-default-recommended",
        "ManagePermissionGrantsForSelf.microsoft-user-default-low",
    ];
    private static readonly string[] MailClients =
    [
        "ManagePermissionGrantsForSelf.microsoft-user-default-allow-consent-apps",
        "ManagePermissionGrantsForSelf.microsoft-user-default-allow-consent-mail-apps",
    ];

    public static RuleOutcome UserConsent(RuleInput input, JsonElement parameters)
    {
        var assigned = input.Evidence!.Value.GetProperty("permissionGrantPolicies").EnumerateArray()
            .Select(p => p.GetString()!).ToList();
        var allowed = parameters.GetProperty("allowedPermissionGrantPolicies").EnumerateArray()
            .Select(p => p.GetString()!).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var args = new Dictionary<string, string> { ["policies"] = string.Join(", ", assigned) };
        if (assigned.Contains(Legacy, StringComparer.OrdinalIgnoreCase))
        {
            return RuleOutcome.Fail("warning", "m365-006.fail.legacy", args);
        }
        if (assigned.Count == 0)
        {
            return RuleOutcome.Pass("m365-006.pass.disabled");
        }
        if (assigned.All(p => allowed.Contains(p) || MailClients.Contains(p, StringComparer.OrdinalIgnoreCase)))
        {
            return RuleOutcome.Pass("m365-006.pass.allowed", args);
        }
        return assigned.Any(p => KnownMicrosoft.Contains(p, StringComparer.OrdinalIgnoreCase) && !allowed.Contains(p))
            ? RuleOutcome.Fail("warning", "m365-006.fail.not_allowed", args)
            : RuleOutcome.Unknown("unmapped_state", "m365-006.unknown.custom", args);
    }
}
