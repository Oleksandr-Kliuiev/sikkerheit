using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sikkerheit.Contracts;
using Sikkerheit.ContractTests.Invariants;
using Sikkerheit.Host.Assessment;
using Sikkerheit.Host.Organizations;

namespace Sikkerheit.ContractTests;

/// <summary>
/// Records of the Windows and server rules (03 «Проверки Windows», «Поддержка ОС и уровень патчей»), tested on the rules
/// themselves with fixed evidence and fixed time, without a database.
/// </summary>
[Enforcement("evaluator")]
public sealed class WindowsRuleInvariantTests
{
    private static readonly string Defaults = new PolicyRules(new ContractSchemas()).DefaultConfiguration;
    private static readonly DateTimeOffset Observed = new(2026, 10, 14, 10, 0, 0, TimeSpan.Zero);

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

    private static JsonObject Parameters(JsonObject policy, string checkId) => policy["checks"]![checkId]!["parameters"]!.AsObject();

    private static RuleInput Input(string checkId, string evidence, DateTimeOffset? at = null) =>
        new(checkId, "device", "collected", JsonDocument.Parse(evidence).RootElement, null, at ?? Observed);

    private static RuleInput Gone(string checkId, string reason) => new(checkId, "device", "unavailable", null, reason, Observed);

    private static readonly RuleInput Professional = Input("WIN-011",
        """{"editionId":"Professional","displayVersion":"25H2","build":26200,"ubr":9711,"architecture":"x64"}""");

    private static WindowsContext Context(bool clock = false, DateTimeOffset? episode = null, params RuleInput[] inputs) =>
        new(clock, inputs.ToDictionary(i => i.CheckId), episode);

    private static RuleOutcome Run(RuleInput? input, string checkId, JsonElement policy, WindowsContext? context = null) =>
        WindowsRules.Evaluate(input, checkId, policy, context ?? Context(inputs: Professional));

    private static void Outcome(RuleOutcome outcome, string? result, string? reason = null, string? severity = null)
    {
        Assert.Equal((result, reason), (outcome.Result, outcome.ReasonCode));
        if (severity is not null)
        {
            Assert.Equal(severity, outcome.Severity);
        }
    }

    [Fact]
    [Invariant("INV-141")]
    public void Inv141_the_clock_flag_gives_an_informational_check_no_result()
    {
        Outcome(Run(Input("WIN-011", """{"editionId":"Professional","displayVersion":"25H2","build":26200,"ubr":1,"architecture":"x64"}"""),
            "WIN-011", Policy(), Context(clock: true)), null, "clock_inconsistent");
        // The same flag on an assessed check is unknown, not a result.
        Outcome(Run(Input("WIN-009", """{"enabled":true,"platform":"uefi"}"""), "WIN-009", Policy(), Context(clock: true)),
            "unknown", "clock_inconsistent");
    }

    [Fact]
    [Invariant("INV-142")]
    public void Inv142_suspended_protection_on_a_fully_encrypted_volume_fails_the_example_of_the_package()
    {
        var example = JsonDocument.Parse(File.ReadAllText(Path.Combine(InvariantRegistry.Root, "development-package", "examples", "scan-batch.json")));
        var evidence = example.RootElement.GetProperty("observations").EnumerateArray()
            .Single(o => o.GetProperty("checkId").GetString() == "WIN-002").GetProperty("evidence").GetRawText();
        Outcome(Run(Input("WIN-002", evidence), "WIN-002", Policy()), "fail", severity: "critical");
        Outcome(Run(Input("WIN-002", """{"volumeStatus":"fully_encrypted","protectionStatus":"on","encryptionPercentage":100}"""), "WIN-002",
            Policy()), "pass");
    }

    [Theory]
    [Invariant("INV-143")]
    [InlineData("encrypting", "unknown", "unmapped_state")]
    [InlineData("encryption_paused", "fail", null)]
    [InlineData("decrypting", "fail", null)]
    [InlineData("decryption_paused", "fail", null)]
    [InlineData("fully_decrypted", "fail", null)]
    public void Inv143_bitlocker_in_progress_is_unknown_and_a_pause_is_a_failure(string status, string result, string? reason)
    {
        Outcome(Run(Input("WIN-002", $$"""{"volumeStatus":"{{status}}","protectionStatus":"on","encryptionPercentage":40}"""), "WIN-002", Policy()),
            result, reason);
    }

    private static string Admins(params (string Sid, string Kind, int? Rid)[] members) => JsonSerializer.Serialize(new
    {
        members = members.Select(m => new { sid = m.Sid, kind = m.Kind, relativeId = m.Rid }), membershipScope = "direct_members",
    });

    [Fact]
    [Invariant("INV-144")]
    public void Inv144_the_builtin_administrator_and_domain_admins_are_allowed_and_an_extra_local_account_is_not()
    {
        var policy = Assessed("WIN-008");
        var allowed = Admins(("S-1-5-21-1-2-3-500", "builtin_administrator", 500), ("S-1-5-21-9-9-9-512", "domain", 512));
        Outcome(Run(Input("WIN-008", allowed), "WIN-008", policy), "pass");
        var extra = Admins(("S-1-5-21-1-2-3-500", "builtin_administrator", 500), ("S-1-5-21-1-2-3-1001", "local_account", 1001));
        var outcome = Run(Input("WIN-008", extra), "WIN-008", policy);
        Outcome(outcome, "fail", severity: "warning");
        Assert.Contains("S-1-5-21-1-2-3-1001", outcome.Arguments!["members"]);
        // One local account (a LAPS account) is within the limit of the policy.
        var laps = Assessed("WIN-008", p => Parameters(p, "WIN-008")["maxOtherLocalAccounts"] = 1);
        Outcome(Run(Input("WIN-008", extra), "WIN-008", laps), "pass");
        // A user of the PC added to the administrators: an Entra SID outside allowedSids is a failure.
        Outcome(Run(Input("WIN-008", Admins(("S-1-12-1-1-2-3-4", "entra", null))), "WIN-008", policy), "fail");
        Outcome(Run(Input("WIN-008", Admins(("S-1-12-1-1-2-3-4", "entra", null))), "WIN-008",
            Assessed("WIN-008", p => Parameters(p, "WIN-008")["allowedSids"] = new JsonArray("S-1-12-1-1-2-3-4"))), "pass");
    }

    [Theory]
    [Invariant("INV-145")]
    [InlineData("domain_joined", "null", "fail", null)]
    [InlineData("not_joined", "null", "fail", null)]
    [InlineData("entra_joined", "\"22222222-2222-4222-8222-222222222222\"", "pass", null)]
    [InlineData("hybrid_joined", "\"99999999-2222-4222-8222-222222222222\"", "fail", null)]
    [InlineData("entra_joined", "null", "unknown", "unmapped_state")]
    public void Inv145_a_join_to_another_tenant_or_to_a_domain_only_fails_when_the_tenant_is_expected(string join, string tenant,
        string result, string? reason)
    {
        var policy = Assessed("WIN-010", p => Parameters(p, "WIN-010")["expectedTenantId"] = "22222222-2222-4222-8222-222222222222");
        var evidence = $$"""{"joinType":"{{join}}","tenantId":{{tenant}},"entraDeviceId":null}""";
        Outcome(Run(Input("WIN-010", evidence), "WIN-010", policy), result, reason);
    }

    [Fact]
    [Invariant("INV-146")]
    public void Inv146_disabled_windows_profiles_with_an_active_approved_third_party_firewall_pass()
    {
        var policy = Assessed("WIN-005", p => Parameters(p, "WIN-005")["approvedFirewallProviders"] = new JsonArray("Contoso Security"));
        string Evidence(string state) => $$"""
            {"domainEnabled":false,"privateEnabled":false,"publicEnabled":false,"firewallProducts":[{"provider":"Contoso Security Suite 9","productState":"{{state}}"}]}
            """;
        Outcome(Run(Input("WIN-005", Evidence("on")), "WIN-005", policy), "pass");
        Outcome(Run(Input("WIN-005", Evidence("off")), "WIN-005", policy), "fail", severity: "critical");
        Outcome(Run(Input("WIN-005", Evidence("unknown")), "WIN-005", policy), "unknown", "unmapped_state");
    }

    [Fact]
    [Invariant("INV-147")]
    public void Inv147_an_edition_of_the_exception_list_in_the_same_batch_makes_bitlocker_not_applicable()
    {
        var home = Input("WIN-011", """{"editionId":"Core","displayVersion":"25H2","build":26200,"ubr":1,"architecture":"x64"}""");
        Outcome(Run(Input("WIN-002", """{"volumeStatus":"fully_decrypted","protectionStatus":"off","encryptionPercentage":0}"""), "WIN-002",
            Policy(), Context(inputs: home)), "not_applicable", "policy_not_applicable");
    }

    [Fact]
    [Invariant("INV-148")]
    public void Inv148_without_the_input_observation_of_the_same_batch_the_applicability_is_unknown()
    {
        var bitlocker = Input("WIN-002", """{"volumeStatus":"fully_encrypted","protectionStatus":"on","encryptionPercentage":100}""");
        Outcome(Run(bitlocker, "WIN-002", Policy(), Context(inputs: Gone("WIN-011", "temporary_error"))), "unknown", "applicability_input_missing");
        Outcome(Run(bitlocker, "WIN-002", Policy(), Context()), "unknown", "applicability_input_missing");
        var signatures = Input("WIN-004", $$"""{"signatureLastUpdatedAt":"{{Observed.AddHours(-1):yyyy-MM-dd'T'HH:mm:ss'Z'}}"}""");
        Outcome(Run(signatures, "WIN-004", Policy(), Context()), "unknown", "applicability_input_missing");
        Outcome(Run(signatures, "WIN-004", Policy(), Context(inputs: Gone("WIN-003", "permission_denied"))), "unknown", "applicability_input_missing");
    }

    [Fact]
    [Invariant("INV-149")]
    public void Inv149_a_third_party_antivirus_of_unknown_state_is_unknown_when_nothing_else_is_active()
    {
        var policy = Assessed("WIN-003", p =>
        {
            Parameters(p, "WIN-003")["approvedProviders"] = new JsonArray("VendorX");
            Parameters(p, "WIN-003")["defenderApproved"] = false;
        });
        const string Unknown = """
            {"products":[{"provider":"VendorX Endpoint 3.1","productState":"unknown","statusSource":"windows_security_center","rawState":266240}],"defender":null}
            """;
        Outcome(Run(Input("WIN-003", Unknown), "WIN-003", policy), "unknown", "unmapped_state");
        const string On = """
            {"products":[{"provider":"VendorX Endpoint 3.1","productState":"on","statusSource":"windows_security_center","rawState":null}],"defender":null}
            """;
        Outcome(Run(Input("WIN-003", On), "WIN-003", policy), "pass");
        Outcome(Run(Input("WIN-003", """{"products":[],"defender":null}"""), "WIN-003", policy), "fail", severity: "critical");
    }

    [Fact]
    [Invariant("INV-150")]
    public void Inv150_signatures_from_the_future_are_an_invalid_time_not_a_pass()
    {
        var defender = Input("WIN-003", """
            {"products":[],"defender":{"amRunningMode":"normal","realTimeProtectionEnabled":true}}
            """);
        var context = Context(inputs: [Professional, defender]);
        Outcome(Run(Input("WIN-004", $$"""{"signatureLastUpdatedAt":"{{Observed.AddHours(3):yyyy-MM-dd'T'HH:mm:ss'Z'}}"}"""), "WIN-004", Policy(), context),
            "unknown", "evidence_time_invalid");
        Outcome(Run(Input("WIN-004", $$"""{"signatureLastUpdatedAt":"{{Observed.AddDays(-4):yyyy-MM-dd'T'HH:mm:ss'Z'}}"}"""), "WIN-004", Policy(), context),
            "fail", severity: "warning");
        Outcome(Run(Input("WIN-004", $$"""{"signatureLastUpdatedAt":"{{Observed.AddDays(-8):yyyy-MM-dd'T'HH:mm:ss'Z'}}"}"""), "WIN-004", Policy(), context),
            "fail", severity: "critical");
    }

    [Fact]
    [Invariant("INV-151")]
    public void Inv151_an_unavailable_observation_of_an_informational_check_keeps_the_reason_of_the_collector()
    {
        Outcome(Run(Gone("WIN-008", "permission_denied"), "WIN-008", Policy()), null, "permission_denied");
        Outcome(Run(Gone("WIN-008", "collector_timeout"), "WIN-008", Policy()), null, "collector_timeout");
        Outcome(Run(Gone("WIN-008", "permission_denied"), "WIN-008", Assessed("WIN-008")), "unknown", "permission_denied");
    }

    [Fact]
    [Invariant("INV-155")]
    public void Inv155_an_old_or_missing_successful_update_search_fails_an_assessed_check()
    {
        var policy = Assessed("WIN-006");
        string Evidence(string? search) =>
            $$"""{"lastSearchSuccessAt":{{(search is null ? "null" : $"\"{search}\"")}},"lastInstallSuccessAt":null,"wsusConfigured":false}""";
        Outcome(Run(Input("WIN-006", Evidence(Observed.AddDays(-20).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture))),
            "WIN-006", policy), "fail", severity: "warning");
        Outcome(Run(Input("WIN-006", Evidence(null)), "WIN-006", policy), "fail");
        Outcome(Run(Input("WIN-006", Evidence(Observed.AddDays(-2).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture))),
            "WIN-006", policy), "pass");
    }

    private static string Reboot(bool required, DateTimeOffset boot) =>
        $$"""{"rebootRequired":{{(required ? "true" : "false")}},"lastBootAt":"{{boot:yyyy-MM-dd'T'HH:mm:ss'Z'}}"}""";

    /// <summary>The episode and the result of a series of collections: observed time, required, last boot.</summary>
    private static List<string> Episodes(params (DateTimeOffset At, bool Required, DateTimeOffset Boot)[] collections)
    {
        var results = new List<string>();
        var episode = new DeviceEpisode(null, null);
        foreach (var (at, required, boot) in collections)
        {
            var evidence = JsonDocument.Parse(Reboot(required, boot)).RootElement;
            episode = WindowsEvaluator.NextEpisode(episode, evidence, at);
            var outcome = Run(Input("WIN-007", evidence.GetRawText(), at), "WIN-007", Policy(), Context(episode: episode.Since, inputs: Professional));
            results.Add(outcome.Result!);
        }
        return results;
    }

    [Fact]
    [Invariant("INV-156")]
    public void Inv156_an_episode_is_broken_by_false_and_fails_only_after_warn_days()
    {
        var d0 = Observed.AddDays(-10);
        var boot = d0.AddDays(-1);
        // true on day 0, false on day 1, true on day 3: the second episode has just begun.
        Assert.Equal(["pass", "pass", "pass"], Episodes((d0, true, boot), (d0.AddDays(1), false, boot), (d0.AddDays(3), true, boot)));
        // The same requirement over 3 days is a failure; a restart in between breaks the episode.
        Assert.Equal(["pass", "pass", "fail"], Episodes((d0, true, boot), (d0.AddDays(1), true, boot), (d0.AddDays(3), true, boot)));
        Assert.Equal(["pass", "pass", "pass"],
            Episodes((d0, true, boot), (d0.AddDays(1), true, boot), (d0.AddDays(3), true, d0.AddDays(2))));
    }

    [Fact]
    [Invariant("INV-157")]
    public void Inv157_a_shift_of_the_boot_time_by_seconds_is_the_same_boot_session()
    {
        var d0 = Observed.AddDays(-10);
        var boot = d0.AddDays(-1);
        Assert.Equal(["pass", "fail"], Episodes((d0, true, boot), (d0.AddDays(4), true, boot.AddSeconds(40))));
        Assert.Equal(["pass", "pass"], Episodes((d0, true, boot), (d0.AddDays(4), true, boot.AddMinutes(3))));
    }

    [Fact]
    [Invariant("INV-158")]
    public void Inv158_secure_boot_off_or_a_legacy_bios_fails_when_it_is_required()
    {
        Outcome(Run(Input("WIN-009", """{"enabled":false,"platform":"uefi"}"""), "WIN-009", Policy()), "fail", severity: "critical");
        Outcome(Run(Input("WIN-009", """{"enabled":false,"platform":"legacy_bios"}"""), "WIN-009", Policy()), "fail", severity: "critical");
        Outcome(Run(Input("WIN-009", """{"enabled":true,"platform":"uefi"}"""), "WIN-009", Policy()), "pass");
        var optional = Policy(p => Parameters(p, "WIN-009")["secureBootRequired"] = false);
        Outcome(Run(Input("WIN-009", """{"enabled":false,"platform":"legacy_bios"}"""), "WIN-009", optional), "not_applicable", "policy_not_applicable");
    }

    private static JsonElement Inventory(string edition, int build, string? version = "25H2", string architecture = "x64", int ubr = 100) =>
        JsonDocument.Parse(JsonSerializer.Serialize(new { editionId = edition, displayVersion = version, build, ubr, architecture })).RootElement;

    private static DateTimeOffset At(string date) => DateTimeOffset.Parse(date + "T12:00:00Z", CultureInfo.InvariantCulture);

    private static void Support(ServerOutcome server, string result, string? reason = null) =>
        Assert.Equal((result, reason), (server.Outcome.Result, server.Outcome.ReasonCode));

    [Fact]
    [Invariant("INV-159")]
    public void Inv159_a_version_out_of_servicing_fails()
    {
        Support(ServerRules.OsSupport(Inventory("Professional", 19045, "22H2"), At("2026-10-14")), "fail");
        Assert.Equal("critical", ServerRules.OsSupport(Inventory("Professional", 19045, "22H2"), At("2026-10-14")).Outcome.Severity);
        Assert.Equal("sys-002.fail.esu", ServerRules.OsSupport(Inventory("Professional", 19045, "22H2"), At("2026-10-14")).Outcome.Explanation);
        // 24H2 Home and Pro: the last day of servicing is 2026-10-13, the end is exclusive at the start of the next day in Los Angeles.
        Support(ServerRules.OsSupport(Inventory("Professional", 26100, "24H2"), At("2026-10-13")), "pass");
        Support(ServerRules.OsSupport(Inventory("Professional", 26100, "24H2"), At("2026-10-15")), "fail");
        Support(ServerRules.OsSupport(Inventory("Enterprise", 26100, "24H2"), At("2026-10-15")), "pass");
    }

    [Fact]
    [Invariant("INV-160")]
    public void Inv160_an_architecture_or_edition_outside_the_matrix_is_unknown_not_a_failure()
    {
        Support(ServerRules.OsSupport(Inventory("Professional", 26200, architecture: "arm64"), At("2026-10-14")), "unknown", "os_version_unknown");
        Support(ServerRules.OsSupport(Inventory("ServerStandard", 26100, "24H2"), At("2026-10-14")), "unknown", "os_version_unknown");
    }

    [Fact]
    [Invariant("INV-161")]
    public void Inv161_an_old_build_without_a_row_of_the_table_fails()
    {
        Support(ServerRules.OsSupport(Inventory("Enterprise", 19044, "21H2"), At("2026-10-14")), "fail");
        Support(ServerRules.OsSupport(Inventory("Professional", 19043, "21H1"), At("2026-10-14")), "fail");
        Support(ServerRules.OsSupport(Inventory("EnterpriseS", 14393, null), At("2026-10-14")), "fail");
    }

    [Fact]
    [Invariant("INV-162")]
    public void Inv162_iot_enterprise_ltsc_has_its_own_servicing_dates()
    {
        Support(ServerRules.OsSupport(Inventory("IoTEnterpriseS", 19044, "21H2"), At("2027-02-15")), "pass");
        // The same build of the LTSC family ends in January 2027.
        Support(ServerRules.OsSupport(Inventory("EnterpriseS", 19044, "21H2"), At("2027-02-15")), "fail");
    }

    [Fact]
    [Invariant("INV-163")]
    public void Inv163_a_build_without_display_version_is_found_by_its_build()
    {
        Support(ServerRules.OsSupport(Inventory("EnterpriseS", 17763, null), At("2026-10-14")), "pass");
        Support(ServerRules.OsSupport(Inventory("EnterpriseS", 17763, null), At("2029-01-11")), "fail");
        Assert.Equal("2029-01-10T08:00:00Z",
            ServerRules.OsSupport(Inventory("EnterpriseS", 17763, null), At("2026-10-14")).Evidence!["servicingEndsAt"]!.GetValue<string>());
    }

    [Fact]
    [Invariant("INV-164")]
    public void Inv164_a_version_of_the_matrix_without_a_row_is_unknown()
    {
        Support(ServerRules.OsSupport(Inventory("Professional", 26400, "27H1"), At("2026-10-14")), "unknown", "os_version_unknown");
    }

    private static ReleaseCatalogView Catalog_(string? verifiedThrough, params (int Branch, int Ubr, string Kb, string Kind, string? Month)[] rows) =>
        new(rows.Select(r => new CatalogRelease(r.Branch, r.Ubr, r.Kb, r.Kind, r.Month, true)).ToList(), verifiedThrough);

    private static JsonElement Parameters_(int grace = 14, int critical = 2) =>
        JsonDocument.Parse($$"""{"graceDays":{{grace}},"criticalBehindMonths":{{critical}}}""").RootElement;

    private static ServerOutcome Patch(JsonElement inventory, ReleaseCatalogView catalog, string date, int grace = 14) =>
        ServerRules.PatchLevel(inventory, catalog, Parameters_(grace), At(date));

    [Fact]
    [Invariant("INV-166")]
    public void Inv166_a_branch_outside_the_catalog_is_unknown()
    {
        var catalog = Catalog_("2026-10", (26100, 8457, "5061234", "security_monthly", "2026-10"));
        Support(Patch(Inventory("Professional", 27842, "Insider", ubr: 1), catalog, "2026-10-27"), "unknown", "build_not_in_catalog");
    }

    [Fact]
    [Invariant("INV-167")]
    public void Inv167_a_month_whose_grace_has_passed_and_is_not_verified_gives_unknown_not_a_pass()
    {
        var catalog = Catalog_("2026-09", (26200, 9611, "5062001", "security_monthly", "2026-09"),
            (26200, 9711, "5062002", "security_monthly", "2026-10"));
        // 2026-10-13 is Patch Tuesday; its grace of 14 days ends on 2026-10-27.
        Support(Patch(Inventory("Professional", 26200, ubr: 9611), catalog, "2026-10-26"), "pass");
        var stale = Patch(Inventory("Professional", 26200, ubr: 9611), catalog, "2026-10-27");
        Support(stale, "unknown", "release_catalog_stale");
        Assert.Equal("2026-09", stale.Evidence!["verifiedThroughMonth"]!.GetValue<string>());
        Assert.Equal("2026-10", stale.Evidence!["expectedSecurityMonth"]!.GetValue<string>());
    }

    [Fact]
    [Invariant("INV-168")]
    public void Inv168_a_hotpatch_below_the_monthly_release_of_its_month_is_at_the_level_of_that_month()
    {
        var catalog = Catalog_("2026-05",
            (26100, 8457, "5060001", "security_monthly", "2026-05"), (26100, 8390, "5060002", "hotpatch", "2026-05"));
        var outcome = Patch(Inventory("Enterprise", 26100, "24H2", ubr: 8390), catalog, "2026-05-30");
        Support(outcome, "pass");
        Assert.Equal("2026-05", outcome.Evidence!["deviceSecurityMonth"]!.GetValue<string>());
        // Without an exact record the level is the highest month of a non-hotpatch release at or below the UBR.
        Support(Patch(Inventory("Enterprise", 26100, "24H2", ubr: 8500), catalog, "2026-05-30"), "pass");
    }

    [Fact]
    [Invariant("INV-169")]
    public void Inv169_the_lag_counts_months_of_security_releases_and_out_of_band_releases_do_not_add_to_it()
    {
        var catalog = Catalog_("2026-10",
            (26200, 9400, "5060101", "security_monthly", "2026-08"), (26200, 9611, "5060102", "security_monthly", "2026-09"),
            (26200, 9711, "5060103", "security_monthly", "2026-10"), (26200, 9650, "5060104", "security_oob", "2026-09"),
            (26200, 9660, "5060105", "preview", "2026-09"));
        var one = Patch(Inventory("Professional", 26200, ubr: 9611), catalog, "2026-10-27");
        Support(one, "fail");
        Assert.Equal(("warning", 1, "5060103"), (one.Outcome.Severity, one.Evidence!["monthsBehind"]!.GetValue<int>(), one.Evidence["missingKb"]!.GetValue<string>()));
        var two = Patch(Inventory("Professional", 26200, ubr: 9400), catalog, "2026-10-27");
        Assert.Equal(("fail", "critical", 2), (two.Outcome.Result, two.Outcome.Severity, two.Evidence!["monthsBehind"]!.GetValue<int>()));
        // Out-of-band and preview releases of September are one month with the monthly release, not extra months.
        var oob = Patch(Inventory("Professional", 26200, ubr: 9650), catalog, "2026-10-27");
        Assert.Equal(1, oob.Evidence!["monthsBehind"]!.GetValue<int>());
        // A UBR below the earliest record of the branch counts as critical.
        Assert.Equal("critical", Patch(Inventory("Professional", 26200, ubr: 5), catalog, "2026-10-27").Outcome.Severity);
        Support(Patch(Inventory("Professional", 26200, ubr: 9711), catalog, "2026-10-27"), "pass");
    }

    [Fact]
    [Invariant("INV-176")]
    public void Inv176_the_freshness_check_cannot_be_made_assessed()
    {
        var schemas = new ContractSchemas();
        var assessed = JsonNode.Parse(Defaults)!.AsObject();
        assessed["checks"]!["SYS-001"]!["assessmentMode"] = "assessed";
        Assert.NotEmpty(schemas.ValidateComponent("PolicyConfiguration", JsonDocument.Parse(assessed.ToJsonString()).RootElement));
        Assert.Empty(schemas.ValidateComponent("PolicyConfiguration", JsonDocument.Parse(Defaults).RootElement));
        Assert.Equal("informational", Catalog.Check("SYS-001").DefaultMode);
    }
}
