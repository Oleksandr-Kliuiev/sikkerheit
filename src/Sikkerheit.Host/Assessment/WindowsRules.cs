using System.Globalization;
using System.Text.Json;
using Sikkerheit.Contracts;

namespace Sikkerheit.Host.Assessment;

/// <summary>
/// What a Windows rule knows besides its own observation: the observations of the same batch it depends on (WIN-011 for
/// the edition, WIN-003 for Defender), the clock flag of the batch and the reboot episode of WIN-007.
/// </summary>
public sealed record WindowsContext(
    bool ClockInconsistent, IReadOnlyDictionary<string, RuleInput> BatchInputs, DateTimeOffset? EpisodeSince)
{
    public RuleInput? Input(string checkId) => BatchInputs.GetValueOrDefault(checkId);
}

/// <summary>
/// Rules WIN-001…WIN-011 of 03 «Проверки Windows». The order of 03 «Семантика результата»: clock flag of the batch →
/// applicability from another observation of the batch → own observation → the rule. Informational mode keeps only the
/// reasons of missing data and never gives a result.
/// </summary>
public static class WindowsRules
{
    public static RuleOutcome Evaluate(RuleInput? observation, string checkId, JsonElement configuration, WindowsContext context)
    {
        var check = configuration.GetProperty("checks").GetProperty(checkId);
        var mode = check.GetProperty("assessmentMode").GetString()!;
        var parameters = check.GetProperty("parameters");
        var outcome = Raw(observation, checkId, configuration, check, parameters, context);
        if (mode == "informational")
        {
            var transferable = outcome.ReasonCode is not null && Catalog.InformationalReasons.Contains(outcome.ReasonCode);
            return new RuleOutcome(null, null, transferable ? outcome.ReasonCode : null, outcome.Explanation, outcome.Arguments);
        }
        return outcome;
    }

    private static RuleOutcome Raw(RuleInput? observation, string checkId, JsonElement configuration, JsonElement check,
        JsonElement parameters, WindowsContext context)
    {
        if (context.ClockInconsistent)
        {
            return RuleOutcome.Unknown("clock_inconsistent", "win.clock_inconsistent");
        }
        if (Applicability(checkId, configuration, check, parameters, context) is { } applicability)
        {
            return applicability;
        }
        if (observation is null)
        {
            return RuleOutcome.Unknown("missing_observation", "common.missing_observation");
        }
        if (observation.CollectionStatus == "unavailable")
        {
            return RuleOutcome.Unknown(observation.ReasonCode!, "win.unavailable." + observation.ReasonCode);
        }
        var e = observation.Evidence!.Value;
        return checkId switch
        {
            "WIN-001" => DiskSpace(e, parameters),
            "WIN-002" => Bitlocker(e),
            "WIN-003" => Antivirus(e, parameters),
            "WIN-004" => SignatureAge(e, parameters, observation.ObservedAt!.Value),
            "WIN-005" => Firewall(e, parameters),
            "WIN-006" => UpdateService(e, parameters, observation.ObservedAt!.Value),
            "WIN-007" => RebootPending(e, parameters, observation.ObservedAt!.Value, context.EpisodeSince),
            "WIN-008" => LocalAdministrators(e, parameters),
            "WIN-009" => SecureBoot(e),
            "WIN-010" => EntraJoin(e, parameters),
            "WIN-011" => RuleOutcome.Pass("win-011.inventory"),
            _ => RuleOutcome.Unknown("missing_observation", "common.not_implemented"),
        };
    }

    /// <summary>Applicability that depends on the policy or on another observation of the batch; null when the check applies.</summary>
    private static RuleOutcome? Applicability(string checkId, JsonElement configuration, JsonElement check, JsonElement parameters,
        WindowsContext context)
    {
        var editions = check.TryGetProperty("notApplicableEditionIds", out var list) && list.ValueKind == JsonValueKind.Array
            ? list.EnumerateArray().Select(i => i.GetString()!).ToList() : [];
        switch (checkId)
        {
            case "WIN-002" when !parameters.GetProperty("encryptionRequired").GetBoolean():
                return RuleOutcome.NotApplicable("win.not_applicable.policy");
            case "WIN-009" when !parameters.GetProperty("secureBootRequired").GetBoolean():
                return RuleOutcome.NotApplicable("win.not_applicable.policy");
            case "WIN-004":
                // Defender must be the approved antivirus of the policy and run normally (03, WIN-004).
                if (!configuration.GetProperty("checks").GetProperty("WIN-003").GetProperty("parameters")
                        .GetProperty("defenderApproved").GetBoolean())
                {
                    return RuleOutcome.NotApplicable("win-004.not_applicable.policy");
                }
                if (context.Input("WIN-003") is not { CollectionStatus: "collected" } antivirus)
                {
                    return RuleOutcome.Unknown("applicability_input_missing", "win.applicability_input_missing");
                }
                var defender = antivirus.Evidence!.Value.GetProperty("defender");
                return defender.ValueKind != JsonValueKind.Object || defender.GetProperty("amRunningMode").GetString() != "normal"
                    ? RuleOutcome.NotApplicable("win-004.not_applicable.defender")
                    : null;
        }
        if (editions.Count > 0 && checkId != "WIN-011")
        {
            if (context.Input("WIN-011") is not { CollectionStatus: "collected" } inventory)
            {
                return RuleOutcome.Unknown("applicability_input_missing", "win.applicability_input_missing");
            }
            var edition = inventory.Evidence!.Value.GetProperty("editionId").GetString()!;
            if (editions.Contains(edition, StringComparer.OrdinalIgnoreCase))
            {
                return RuleOutcome.NotApplicable("win.not_applicable.edition");
            }
        }
        return null;
    }

    private static Dictionary<string, string> Args(params (string Name, object? Value)[] items) =>
        items.ToDictionary(i => i.Name, i => Convert.ToString(i.Value, CultureInfo.InvariantCulture) ?? "");

    private static RuleOutcome DiskSpace(JsonElement e, JsonElement p)
    {
        var total = e.GetProperty("totalBytes").GetInt64();
        var free = e.GetProperty("freeBytes").GetInt64();
        var percent = total == 0 ? 0 : free * 100.0 / total;
        var args = Args(("percent", percent.ToString("0.0", CultureInfo.InvariantCulture)),
            ("freeGiB", (free / 1073741824.0).ToString("0.0", CultureInfo.InvariantCulture)));
        if (percent < p.GetProperty("criticalFreePercent").GetInt32() || free < p.GetProperty("criticalFreeBytes").GetInt64())
        {
            return RuleOutcome.Fail("critical", "win-001.fail.critical", args);
        }
        if (percent < p.GetProperty("warnFreePercent").GetInt32() || free < p.GetProperty("warnFreeBytes").GetInt64())
        {
            return RuleOutcome.Fail("warning", "win-001.fail.warning", args);
        }
        return RuleOutcome.Pass("win-001.pass", args);
    }

    private static RuleOutcome Bitlocker(JsonElement e)
    {
        var status = e.GetProperty("volumeStatus").GetString();
        var protection = e.GetProperty("protectionStatus").GetString();
        var args = Args(("status", status), ("protection", protection), ("percent", e.GetProperty("encryptionPercentage").GetInt32()));
        return (status, protection) switch
        {
            ("fully_encrypted", "on") => RuleOutcome.Pass("win-002.pass", args),
            ("fully_encrypted", "off") => RuleOutcome.Fail("critical", "win-002.fail.suspended", args),
            ("fully_encrypted", _) => RuleOutcome.Unknown("unmapped_state", "win-002.unknown.protection", args),
            ("encrypting", _) => RuleOutcome.Unknown("unmapped_state", "win-002.unknown.encrypting", args),
            _ => RuleOutcome.Fail("critical", "win-002.fail.not_encrypted", args),
        };
    }

    private static bool Approved(string provider, JsonElement approved) =>
        approved.EnumerateArray().Any(a => provider.StartsWith(a.GetString()!, StringComparison.OrdinalIgnoreCase));

    private static RuleOutcome Antivirus(JsonElement e, JsonElement p)
    {
        var approvedProviders = p.GetProperty("approvedProviders");
        var defenderApproved = p.GetProperty("defenderApproved").GetBoolean();
        var defender = e.GetProperty("defender");
        // Defender is active only in normal mode with real-time protection; the other modes are not an active antivirus.
        var defenderActive = defenderApproved && defender.ValueKind == JsonValueKind.Object
            && defender.GetProperty("amRunningMode").GetString() == "normal"
            && defender.GetProperty("realTimeProtectionEnabled").GetBoolean();
        var third = e.GetProperty("products").EnumerateArray()
            .Where(x => x.GetProperty("statusSource").GetString() != "defender" && Approved(x.GetProperty("provider").GetString()!, approvedProviders))
            .ToList();
        var anyApproved = third.Count > 0 || (defenderApproved && defender.ValueKind == JsonValueKind.Object);
        if (defenderActive || third.Any(x => x.GetProperty("productState").GetString() == "on"))
        {
            return RuleOutcome.Pass("win-003.pass");
        }
        if (third.Any(x => x.GetProperty("productState").GetString() == "unknown"))
        {
            return RuleOutcome.Unknown("unmapped_state", "win-003.unknown.state");
        }
        return RuleOutcome.Fail("critical", anyApproved ? "win-003.fail.inactive" : "win-003.fail.none");
    }

    private static DateTimeOffset? Time(JsonElement e, string property) =>
        e.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
        && DateTimeOffset.TryParse(value.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
            ? parsed : null;

    private static RuleOutcome SignatureAge(JsonElement e, JsonElement p, DateTimeOffset observedAt)
    {
        if (Time(e, "signatureLastUpdatedAt") is not { } updated || updated > observedAt)
        {
            return RuleOutcome.Unknown("evidence_time_invalid", "win.evidence_time_invalid");
        }
        var days = (observedAt - updated).TotalDays;
        var args = Args(("days", Math.Floor(days)));
        if (days > p.GetProperty("criticalDays").GetInt32())
        {
            return RuleOutcome.Fail("critical", "win-004.fail.critical", args);
        }
        return days > p.GetProperty("warnDays").GetInt32()
            ? RuleOutcome.Fail("warning", "win-004.fail.warning", args)
            : RuleOutcome.Pass("win-004.pass", args);
    }

    private static RuleOutcome Firewall(JsonElement e, JsonElement p)
    {
        var required = p.GetProperty("requiredProfiles").EnumerateArray().Select(i => i.GetString()).ToList();
        bool Enabled(string profile) => e.GetProperty(profile + "Enabled").GetBoolean();
        if (required.All(profile => Enabled(profile!)))
        {
            return RuleOutcome.Pass("win-005.pass");
        }
        var approved = e.GetProperty("firewallProducts").EnumerateArray()
            .Where(x => Approved(x.GetProperty("provider").GetString()!, p.GetProperty("approvedFirewallProviders"))).ToList();
        if (approved.Any(x => x.GetProperty("productState").GetString() == "on"))
        {
            return RuleOutcome.Pass("win-005.pass.third_party");
        }
        var args = Args(("profiles", string.Join(", ", required.Where(profile => !Enabled(profile!)))));
        return approved.Any(x => x.GetProperty("productState").GetString() == "unknown")
            ? RuleOutcome.Unknown("unmapped_state", "win-005.unknown.state", args)
            : RuleOutcome.Fail("critical", "win-005.fail", args);
    }

    private static RuleOutcome UpdateService(JsonElement e, JsonElement p, DateTimeOffset observedAt)
    {
        var raw = e.GetProperty("lastSearchSuccessAt");
        var search = Time(e, "lastSearchSuccessAt");
        if (raw.ValueKind == JsonValueKind.String && search is null || search > observedAt)
        {
            return RuleOutcome.Unknown("evidence_time_invalid", "win.evidence_time_invalid");
        }
        if (search is null || (observedAt - search.Value).TotalDays > p.GetProperty("maxSearchAgeDays").GetInt32())
        {
            return RuleOutcome.Fail("warning", "win-006.fail", Args(("days", search is null ? "?" : Math.Floor((observedAt - search.Value).TotalDays))));
        }
        return RuleOutcome.Pass("win-006.pass");
    }

    /// <summary>The episode is kept by the batch intake; the rule only measures it against warnDays.</summary>
    private static RuleOutcome RebootPending(JsonElement e, JsonElement p, DateTimeOffset observedAt, DateTimeOffset? since)
    {
        if (!e.GetProperty("rebootRequired").GetBoolean() || since is null)
        {
            return RuleOutcome.Pass("win-007.pass");
        }
        var days = (observedAt - since.Value).TotalDays;
        var args = Args(("since", since.Value.UtcDateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)),
            ("lastBootAt", Time(e, "lastBootAt")?.UtcDateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)),
            ("days", Math.Floor(days)));
        return days >= p.GetProperty("warnDays").GetInt32()
            ? RuleOutcome.Fail("warning", "win-007.fail", args)
            : RuleOutcome.Pass("win-007.pending", args);
    }

    private static RuleOutcome LocalAdministrators(JsonElement e, JsonElement p)
    {
        var allowBuiltin = p.GetProperty("allowBuiltinAdministrator").GetBoolean();
        var rids = p.GetProperty("allowedDomainRids").EnumerateArray().Select(i => i.GetInt32()).ToHashSet();
        var sids = p.GetProperty("allowedSids").EnumerateArray().Select(i => i.GetString()!).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var maxLocal = p.GetProperty("maxOtherLocalAccounts").GetInt32();
        var offenders = new List<string>();
        var locals = new List<string>();
        foreach (var member in e.GetProperty("members").EnumerateArray())
        {
            var sid = member.GetProperty("sid").GetString()!;
            var kind = member.GetProperty("kind").GetString();
            var rid = member.GetProperty("relativeId").ValueKind == JsonValueKind.Number ? member.GetProperty("relativeId").GetInt32() : (int?)null;
            if (sids.Contains(sid) || (kind == "builtin_administrator" && allowBuiltin) || (kind == "domain" && rid is { } r && rids.Contains(r)))
            {
                continue;
            }
            if (kind == "local_account")
            {
                locals.Add(sid);
            }
            else
            {
                offenders.Add(sid);
            }
        }
        offenders.AddRange(locals.Order(StringComparer.Ordinal).Skip(maxLocal));
        return offenders.Count == 0
            ? RuleOutcome.Pass("win-008.pass")
            : RuleOutcome.Fail("warning", "win-008.fail", Args(("members", string.Join(", ", offenders)), ("count", offenders.Count)));
    }

    private static RuleOutcome SecureBoot(JsonElement e) =>
        !e.GetProperty("enabled").GetBoolean() || e.GetProperty("platform").GetString() == "legacy_bios"
            ? RuleOutcome.Fail("critical", "win-009.fail", Args(("platform", e.GetProperty("platform").GetString()), ("enabled", e.GetProperty("enabled").GetBoolean() ? "true" : "false")))
            : RuleOutcome.Pass("win-009.pass");

    private static RuleOutcome EntraJoin(JsonElement e, JsonElement p)
    {
        var expected = p.GetProperty("expectedTenantId");
        var join = e.GetProperty("joinType").GetString();
        var args = Args(("joinType", join));
        if (expected.ValueKind != JsonValueKind.String)
        {
            return RuleOutcome.Unknown("applicability_input_missing", "win-010.unknown.no_expected", args);
        }
        if (join is "domain_joined" or "not_joined")
        {
            return RuleOutcome.Fail("warning", "win-010.fail.not_joined", args);
        }
        var tenant = e.GetProperty("tenantId");
        if (tenant.ValueKind != JsonValueKind.String)
        {
            return RuleOutcome.Unknown("unmapped_state", "win-010.unknown.tenant", args);
        }
        return string.Equals(tenant.GetString(), expected.GetString(), StringComparison.OrdinalIgnoreCase)
            ? RuleOutcome.Pass("win-010.pass", args)
            : RuleOutcome.Fail("warning", "win-010.fail.other_tenant", args);
    }
}
