using System.Text.Json;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Agents;
using Sikkerheit.Host.Assessment;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.M365;
using Sikkerheit.Host.Organizations;

namespace Sikkerheit.Host.Reports;

/// <summary>A subject of the calculation; ActiveAtEnd is false for subjects active only earlier in the period.</summary>
public sealed record CoverageSubject(Guid Id, string Type, string Key, string? Name, bool ActiveAtEnd, bool Dormant = false,
    bool NoPresence = false);

/// <summary>The latest current assessment of a pair at the moment of the calculation.</summary>
public sealed record LatestAssessment(string Mode, string? Result, string? Severity, string? ReasonCode, DateTimeOffset ObservedAt);

/// <summary>A pair as the report snapshot keeps it: what was counted and why.</summary>
public sealed record CoveragePair(
    string SubjectType, string SubjectKey, string? SubjectName, string CheckId, string Category, string? Result,
    string? Severity, string? ReasonCode, DateTimeOffset? ObservedAt, bool Fresh, bool DeterminedInPeriod, bool ActiveAtEnd);

public sealed record CoverageResult(
    DateTimeOffset At, int PolicyVersion, int Pairs, int FreshPass, int FreshFail, int Stale, int Unknown, int NoData,
    int Informational, int NotApplicable, int NotConfigured, double? CoverageAt, double? Compliance, double? StaleShare,
    int? PeriodPairs, int? PeriodDetermined, double? CoveragePeriod, IReadOnlyList<CoveragePair> Rows, int DormantDevices = 0,
    int NoPresenceDevices = 0);

/// <summary>
/// Coverage and compliance of 05 «Отчёт и покрытие»: one function for the portal (coverageAt now) and the report
/// (coverageAt on periodEnd and coveragePeriod). Category of a pair: required (assessed, active), informational,
/// not_applicable, not_configured.
/// </summary>
public static class Coverage
{
    /// <summary>Checks whose subjects are only the users the collector reports (M365-002: privileged users).</summary>
    private static readonly HashSet<string> PresenceDefinesApplicability = ["M365-002"];

    private static readonly string[] SubjectTypes = Catalog.Checks.Select(c => c.SubjectType).Distinct().ToArray();

    public static CoverageResult Compute(JsonElement policy, int policyVersion, IReadOnlyList<CoverageSubject> subjects,
        IReadOnlyDictionary<(Guid, string), LatestAssessment> latest, ISet<(Guid, string)>? determinedInPeriod,
        DateTimeOffset at)
    {
        var active = policy.GetProperty("activeCheckIds").EnumerateArray().Select(e => e.GetString()!).ToHashSet();
        var settings = policy.GetProperty("checks");
        var rows = new List<CoveragePair>();
        int pairs = 0, freshPass = 0, freshFail = 0, stale = 0, unknown = 0, noData = 0, informational = 0,
            notApplicable = 0, notConfigured = 0, periodPairs = 0, periodDetermined = 0;
        foreach (var subject in subjects)
        {
            foreach (var check in Catalog.Checks.Where(c => c.SubjectType == subject.Type))
            {
                if (!settings.TryGetProperty(check.CheckId, out var setting))
                {
                    continue;
                }
                var collected = check.Source != "server";
                if (collected && !active.Contains(check.CheckId))
                {
                    continue;
                }
                latest.TryGetValue((subject.Id, check.CheckId), out var assessment);
                var mode = setting.GetProperty("assessmentMode").GetString();
                var determined = determinedInPeriod?.Contains((subject.Id, check.CheckId)) ?? false;
                CoveragePair Row(string category, bool fresh) => new(subject.Type, subject.Key, subject.Name, check.CheckId,
                    category, assessment?.Result, assessment?.Severity, assessment?.ReasonCode, assessment?.ObservedAt,
                    fresh, determined, subject.ActiveAtEnd);
                if (mode == "informational")
                {
                    if (assessment is not null && subject.ActiveAtEnd)
                    {
                        informational++;
                        if (NotConfiguredByPolicy(check.CheckId, setting))
                        {
                            notConfigured++;
                        }
                        rows.Add(Row("informational", false));
                    }
                    continue;
                }
                if (assessment is null && PresenceDefinesApplicability.Contains(check.CheckId))
                {
                    continue;
                }
                if (assessment?.Result == "not_applicable")
                {
                    if (subject.ActiveAtEnd)
                    {
                        notApplicable++;
                        rows.Add(Row("not_applicable", false));
                    }
                    continue;
                }
                // A device with no day of presence in the period is outside the denominator of the period (INV-173).
                if (!subject.NoPresence)
                {
                    periodPairs++;
                    if (determined)
                    {
                        periodDetermined++;
                    }
                }
                // A dormant device (no check-in for 14 days) is outside the denominator of the moment and is shown apart.
                if (!subject.ActiveAtEnd || subject.Dormant)
                {
                    rows.Add(Row("required", false));
                    continue;
                }
                pairs++;
                var window = TimeSpan.FromHours(setting.GetProperty("freshnessWindowHours").GetInt32());
                var fresh = assessment is not null && assessment.ObservedAt > at - window;
                switch (assessment?.Result)
                {
                    case "pass" when fresh:
                        freshPass++;
                        break;
                    case "fail" when fresh:
                        freshFail++;
                        break;
                    case "pass" or "fail":
                        stale++;
                        break;
                    case "unknown":
                        unknown++;
                        break;
                    default:
                        noData++;
                        break;
                }
                rows.Add(Row("required", fresh && assessment?.Result is "pass" or "fail"));
            }
        }
        double? Share(int part, int whole) => whole == 0 ? null : (double)part / whole;
        return new CoverageResult(at, policyVersion, pairs, freshPass, freshFail, stale, unknown, noData, informational,
            notApplicable, notConfigured, Share(freshPass + freshFail, pairs), Share(freshPass, freshPass + freshFail),
            Share(stale, pairs), determinedInPeriod is null ? null : periodPairs,
            determinedInPeriod is null ? null : periodDetermined,
            determinedInPeriod is null ? null : Share(periodDetermined, periodPairs), rows,
            subjects.Count(s => s is { Type: "device", ActiveAtEnd: true, Dormant: true }),
            subjects.Count(s => s is { Type: "device", NoPresence: true }));
    }

    /// <summary>Informational only because inputs are missing (WIN-010 without expectedTenantId, WIN-003 without products).</summary>
    private static bool NotConfiguredByPolicy(string checkId, JsonElement setting)
    {
        var parameters = setting.TryGetProperty("parameters", out var p) ? p : default;
        return checkId switch
        {
            "WIN-010" => parameters.ValueKind != JsonValueKind.Object
                         || !parameters.TryGetProperty("expectedTenantId", out var tenant) || tenant.ValueKind == JsonValueKind.Null,
            // WIN-003 has no input for assessed mode without an approved provider and without Defender (03 «Правило WIN-003»).
            "WIN-003" => parameters.ValueKind != JsonValueKind.Object
                         || (parameters.TryGetProperty("approvedProviders", out var providers) && providers.ValueKind == JsonValueKind.Array
                             && providers.GetArrayLength() == 0
                             && parameters.TryGetProperty("defenderApproved", out var defender) && defender.ValueKind == JsonValueKind.False),
            _ => false,
        };
    }

    /// <summary>coverageAt at a moment (portal) — the same calculation as the report without a period.</summary>
    public static Task<CoverageResult> AtAsync(DbScope scope, Guid organizationId, DateTimeOffset at, CancellationToken ct) =>
        LoadAsync(scope, organizationId, null, at, ct);

    /// <summary>coverageAt on periodEnd and coveragePeriod for [start, end) by the policy in effect at the end.</summary>
    public static Task<CoverageResult> PeriodAsync(DbScope scope, Guid organizationId, DateTimeOffset start,
        DateTimeOffset end, CancellationToken ct) => LoadAsync(scope, organizationId, start, end, ct);

    private static async Task<CoverageResult> LoadAsync(DbScope scope, Guid organizationId, DateTimeOffset? start,
        DateTimeOffset at, CancellationToken ct)
    {
        var (version, configuration) = await Policies.AtAsync(scope, organizationId, at, ct);
        using var policy = JsonDocument.Parse(configuration);
        var inPeriod = await Subjects.InPeriodAsync(scope, organizationId, SubjectTypes, start ?? at, at, ct);
        // Windows devices: dormant ones (14 days without a check-in) and those without a day of presence in the period.
        var devices = (await Devices.ActiveAsync(scope, organizationId, ct)).ToDictionary(d => d.Id);
        var presence = await Devices.PresenceDaysAsync(scope, organizationId, start ?? at.AddDays(-1), at, ct);
        bool Dormant(Guid? id) => id is { } d && devices.TryGetValue(d, out var device) && (device.LastSeenAt ?? device.EnrolledAt) < at - Devices.DormantAfter;
        bool NoPresence(Guid? id) => start is not null && id is { } d && !presence.ContainsKey(d);
        var subjects = inPeriod.Select(s => new CoverageSubject(s.Id, s.Type, s.Key, s.Name, s.ActiveAtEnd, Dormant(s.DeviceId),
            NoPresence(s.DeviceId))).ToList();
        // A connected tenant before its first collection: its checks count as pairs without data.
        if (!subjects.Any(s => s is { Type: "tenant", ActiveAtEnd: true })
            && await TenantConnections.ActiveTenantAtAsync(scope, organizationId, at, ct) is { } tenant)
        {
            subjects.Add(new CoverageSubject(Guid.Empty, "tenant", tenant.ToString(), null, true));
        }
        var latest = (await Assessments.LatestAsync(scope, organizationId, at, ct)).ToDictionary(a => (a.SubjectId, a.CheckId),
            a => new LatestAssessment(a.Mode, a.Result, a.Severity, a.ReasonCode, a.ObservedAt));
        var determined = start is null ? null
            : (await Assessments.DeterminedAsync(scope, organizationId, start.Value, at, ct)).ToHashSet();
        return Compute(policy.RootElement, version, subjects, latest, determined, at);
    }
}
