using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sikkerheit.Host.Assessment;

/// <summary>A row of the Windows lifecycle table (03 «Жизненный цикл ОС»): servicingEndsAt is the exclusive end.</summary>
public sealed record LifecycleRow(string Product, string Family, string DisplayVersion, int Build, DateTimeOffset ServicingEndsAt);

/// <summary>A verified release of the catalog as the SYS-003 rule reads it.</summary>
public sealed record CatalogRelease(int BranchBuild, int Ubr, string Kb, string Kind, string? SecurityMonth, bool AutoOffered);

/// <summary>The verified part of the release catalog and how far the months have been verified (03 «Правило SYS-003»).</summary>
public sealed record ReleaseCatalogView(IReadOnlyList<CatalogRelease> Releases, string? VerifiedThroughMonth);

/// <summary>Result of a server check: the outcome of the rule and the evidence of the server observation.</summary>
public sealed record ServerOutcome(RuleOutcome Outcome, JsonObject? Evidence);

/// <summary>
/// The server rules SYS-001…SYS-003 of 03 «Поддержка ОС и уровень патчей». They work on the last collected WIN-011
/// and on the time of the server, never on the clock of the PC.
/// </summary>
public static class ServerRules
{
    /// <summary>Family by editionId (03 «Жизненный цикл ОС»).</summary>
    private static readonly Dictionary<string, string> Families = BuildFamilies();

    private static Dictionary<string, string> BuildFamilies()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var edition in new[] { "Core", "CoreN", "CoreSingleLanguage", "CoreCountrySpecific", "Professional", "ProfessionalN",
                     "ProfessionalEducation", "ProfessionalEducationN", "ProfessionalWorkstation", "ProfessionalWorkstationN" })
        {
            map[edition] = "home_pro";
        }
        foreach (var edition in new[] { "Enterprise", "EnterpriseN", "Education", "EducationN", "IoTEnterprise", "ServerRdsh" })
        {
            map[edition] = "enterprise_education";
        }
        map["EnterpriseS"] = "ltsc";
        map["EnterpriseSN"] = "ltsc";
        map["IoTEnterpriseS"] = "iot_ltsc";
        return map;
    }

    private static LifecycleRow Row(string product, string family, string version, int build, string endsAt) =>
        new(product, family, version, build, DateTimeOffset.Parse(endsAt, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal));

    /// <summary>The lifecycle table, values checked on 2026-10-15. A change is a new version of the service (rule_change).</summary>
    public static readonly IReadOnlyList<LifecycleRow> Lifecycle =
    [
        Row("windows_10", "ltsc", "1809", 17763, "2029-01-10T08:00:00Z"),
        Row("windows_10", "iot_ltsc", "1809", 17763, "2029-01-10T08:00:00Z"),
        Row("windows_10", "ltsc", "21H2", 19044, "2027-01-13T08:00:00Z"),
        Row("windows_10", "iot_ltsc", "21H2", 19044, "2032-01-14T08:00:00Z"),
        Row("windows_10", "home_pro", "22H2", 19045, "2025-10-15T07:00:00Z"),
        Row("windows_10", "enterprise_education", "22H2", 19045, "2025-10-15T07:00:00Z"),
        Row("windows_11", "home_pro", "21H2", 22000, "2023-10-11T07:00:00Z"),
        Row("windows_11", "enterprise_education", "21H2", 22000, "2024-10-09T07:00:00Z"),
        Row("windows_11", "home_pro", "22H2", 22621, "2024-10-09T07:00:00Z"),
        Row("windows_11", "enterprise_education", "22H2", 22621, "2025-10-15T07:00:00Z"),
        Row("windows_11", "home_pro", "23H2", 22631, "2025-11-12T08:00:00Z"),
        Row("windows_11", "enterprise_education", "23H2", 22631, "2026-11-11T08:00:00Z"),
        Row("windows_11", "home_pro", "24H2", 26100, "2026-10-14T07:00:00Z"),
        Row("windows_11", "enterprise_education", "24H2", 26100, "2027-10-13T07:00:00Z"),
        Row("windows_11", "ltsc", "24H2", 26100, "2029-10-10T07:00:00Z"),
        Row("windows_11", "iot_ltsc", "24H2", 26100, "2034-10-11T07:00:00Z"),
        Row("windows_11", "home_pro", "25H2", 26200, "2027-10-13T07:00:00Z"),
        Row("windows_11", "enterprise_education", "25H2", 26200, "2028-10-11T07:00:00Z"),
        Row("windows_11", "home_pro", "26H1", 28000, "2028-03-15T07:00:00Z"),
        Row("windows_11", "enterprise_education", "26H1", 28000, "2029-03-14T07:00:00Z"),
        Row("windows_11", "home_pro", "26H2", 26300, "2028-10-11T07:00:00Z"),
        Row("windows_11", "enterprise_education", "26H2", 26300, "2029-10-10T07:00:00Z"),
    ];

    public static string? FamilyOf(string editionId) => Families.GetValueOrDefault(editionId);

    public static string ProductOf(int build) => build < 22000 ? "windows_10" : "windows_11";

    /// <summary>SYS-002 on the inventory (WIN-011 evidence) at the time of the server.</summary>
    public static ServerOutcome OsSupport(JsonElement inventory, DateTimeOffset now)
    {
        var edition = inventory.GetProperty("editionId").GetString()!;
        var build = inventory.GetProperty("build").GetInt32();
        var architecture = inventory.GetProperty("architecture").GetString()!;
        var version = inventory.GetProperty("displayVersion").ValueKind == JsonValueKind.String
            ? inventory.GetProperty("displayVersion").GetString() : null;
        var family = FamilyOf(edition);
        var product = ProductOf(build);
        JsonObject Evidence(string? fam, DateTimeOffset? ends) => new()
        {
            ["product"] = product, ["family"] = fam, ["displayVersion"] = version, ["build"] = build, ["architecture"] = architecture,
            ["servicingEndsAt"] = ends is null ? null : Platform.UtcTimeConverter.Format(ends.Value),
        };
        // Outside the agent matrix (a server edition, ARM64): Microsoft may support it, so the answer is unknown, not fail.
        if (family is null || architecture != "x64")
        {
            return new ServerOutcome(RuleOutcome.Unknown("os_version_unknown", "sys-002.unknown.matrix"), Evidence(family, null));
        }
        var row = Lifecycle.FirstOrDefault(r => r.Family == family && r.Build == build);
        if (row is not null)
        {
            var date = row.ServicingEndsAt.AddDays(-1).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            var args = new Dictionary<string, string> { ["version"] = row.DisplayVersion, ["date"] = date, ["product"] = row.Product };
            if (now >= row.ServicingEndsAt)
            {
                var esu = row.Product == "windows_10" && row.Build == 19045;
                return new ServerOutcome(RuleOutcome.Fail("critical", esu ? "sys-002.fail.esu" : "sys-002.fail", args), Evidence(family, row.ServicingEndsAt));
            }
            return new ServerOutcome(RuleOutcome.Pass("sys-002.pass", args), Evidence(family, row.ServicingEndsAt));
        }
        // No row: the servicing of every older version has ended; a newer one is a version the table does not know yet.
        var oldest = family is "ltsc" or "iot_ltsc" ? Lifecycle.Where(r => r.Family == family).Min(r => r.Build) : 19045;
        return build < oldest
            ? new ServerOutcome(RuleOutcome.Fail("critical", "sys-002.fail.old", new Dictionary<string, string> { ["build"] = build.ToString(CultureInfo.InvariantCulture) }), Evidence(family, null))
            : new ServerOutcome(RuleOutcome.Unknown("os_version_unknown", "sys-002.unknown.version"), Evidence(family, null));
    }

    /// <summary>The second Tuesday of a month (patch Tuesday), UTC date.</summary>
    public static DateTime SecondTuesday(int year, int month)
    {
        var first = new DateTime(year, month, 1, 0, 0, 0, DateTimeKind.Utc);
        var offset = ((int)DayOfWeek.Tuesday - (int)first.DayOfWeek + 7) % 7;
        return first.AddDays(offset + 7);
    }

    /// <summary>E(t): the last security month whose second Tuesday plus graceDays is not later than the date of t (UTC).</summary>
    public static string ExpectedMonth(DateTimeOffset now, int graceDays)
    {
        var date = now.UtcDateTime.Date;
        var month = new DateTime(date.Year, date.Month, 1, 0, 0, 0, DateTimeKind.Utc);
        for (var i = 0; i < 3; i++)
        {
            if (SecondTuesday(month.Year, month.Month).AddDays(graceDays) <= date)
            {
                return month.ToString("yyyy-MM", CultureInfo.InvariantCulture);
            }
            month = month.AddMonths(-1);
        }
        return month.ToString("yyyy-MM", CultureInfo.InvariantCulture);
    }

    public static IEnumerable<string> MonthsBetween(string from, string to)
    {
        var month = DateTime.ParseExact(from + "-01", "yyyy-MM-dd", CultureInfo.InvariantCulture);
        var end = DateTime.ParseExact(to + "-01", "yyyy-MM-dd", CultureInfo.InvariantCulture);
        for (; month <= end; month = month.AddMonths(1))
        {
            yield return month.ToString("yyyy-MM", CultureInfo.InvariantCulture);
        }
    }

    /// <summary>SYS-003 on the inventory at the time of the server (03 «Правило SYS-003 и каталог выпусков»).</summary>
    public static ServerOutcome PatchLevel(JsonElement inventory, ReleaseCatalogView catalog, JsonElement parameters, DateTimeOffset now)
    {
        var build = inventory.GetProperty("build").GetInt32();
        var ubr = inventory.GetProperty("ubr").GetInt32();
        var grace = parameters.GetProperty("graceDays").GetInt32();
        var criticalBehind = parameters.GetProperty("criticalBehindMonths").GetInt32();
        var branch = catalog.Releases.Where(r => r.BranchBuild == build).ToList();
        var expected = ExpectedMonth(now, grace);
        JsonObject Evidence(string? level, int? behind, string? kb) => new()
        {
            ["branchBuild"] = build, ["ubr"] = ubr, ["deviceSecurityMonth"] = level, ["expectedSecurityMonth"] = expected,
            ["monthsBehind"] = behind, ["missingKb"] = kb, ["verifiedThroughMonth"] = catalog.VerifiedThroughMonth,
        };
        if (branch.Count == 0)
        {
            return new ServerOutcome(RuleOutcome.Unknown("build_not_in_catalog", "sys-003.unknown.branch",
                new Dictionary<string, string> { ["build"] = build.ToString(CultureInfo.InvariantCulture) }), Evidence(null, null, null));
        }
        if (catalog.VerifiedThroughMonth is null || string.CompareOrdinal(catalog.VerifiedThroughMonth, expected) < 0)
        {
            return new ServerOutcome(RuleOutcome.Unknown("release_catalog_stale", "sys-003.unknown.stale",
                new Dictionary<string, string> { ["expected"] = expected, ["verified"] = catalog.VerifiedThroughMonth ?? "-" }),
                Evidence(null, null, null));
        }
        var exact = branch.FirstOrDefault(r => r.Ubr == ubr);
        string? level = exact is not null
            ? exact.SecurityMonth
            : branch.Where(r => r.Kind != "hotpatch" && r.Ubr <= ubr && r.SecurityMonth is not null)
                .Select(r => r.SecurityMonth).Max(StringComparer.Ordinal);
        var months = branch.Where(r => r.Kind == "security_monthly" && r.SecurityMonth is not null
                                       && string.CompareOrdinal(r.SecurityMonth, expected) <= 0).ToList();
        var behind = months.Select(r => r.SecurityMonth!).Distinct(StringComparer.Ordinal)
            .Count(m => level is null || string.CompareOrdinal(m, level) > 0);
        if (level is null)
        {
            behind = Math.Max(behind, criticalBehind);
        }
        var missing = months.Where(r => level is null || string.CompareOrdinal(r.SecurityMonth, level) > 0)
            .OrderByDescending(r => r.SecurityMonth, StringComparer.Ordinal).ThenByDescending(r => r.Ubr).FirstOrDefault();
        var args = new Dictionary<string, string>
        {
            ["build"] = build.ToString(CultureInfo.InvariantCulture), ["ubr"] = ubr.ToString(CultureInfo.InvariantCulture),
            ["level"] = level ?? "-", ["expected"] = expected, ["behind"] = behind.ToString(CultureInfo.InvariantCulture),
            ["kb"] = missing?.Kb ?? "",
        };
        if (behind == 0)
        {
            return new ServerOutcome(RuleOutcome.Pass("sys-003.pass", args), Evidence(level, 0, null));
        }
        var key = behind >= criticalBehind ? "critical" : "warning";
        return new ServerOutcome(RuleOutcome.Fail(key, "sys-003.fail." + key, args), Evidence(level, behind, missing?.Kb));
    }
}
