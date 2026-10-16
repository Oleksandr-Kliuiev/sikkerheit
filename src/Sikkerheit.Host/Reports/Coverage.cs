using System.Text.Json;
using Npgsql;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Data;

namespace Sikkerheit.Host.Reports;

/// <summary>A subject of the calculation; ActiveAtEnd is false for subjects active only earlier in the period.</summary>
public sealed record CoverageSubject(Guid Id, string Type, string Key, string? Name, bool ActiveAtEnd);

/// <summary>The latest current assessment of a pair at the moment of the calculation.</summary>
public sealed record LatestAssessment(string Mode, string? Result, string? Severity, string? ReasonCode, DateTimeOffset ObservedAt);

/// <summary>A pair as the report snapshot keeps it: what was counted and why.</summary>
public sealed record CoveragePair(
    string SubjectType, string SubjectKey, string? SubjectName, string CheckId, string Category, string? Result,
    string? Severity, string? ReasonCode, DateTimeOffset? ObservedAt, bool Fresh, bool DeterminedInPeriod, bool ActiveAtEnd);

public sealed record CoverageResult(
    DateTimeOffset At, int PolicyVersion, int Pairs, int FreshPass, int FreshFail, int Stale, int Unknown, int NoData,
    int Informational, int NotApplicable, int NotConfigured, double? CoverageAt, double? Compliance, double? StaleShare,
    int? PeriodPairs, int? PeriodDetermined, double? CoveragePeriod, IReadOnlyList<CoveragePair> Rows);

/// <summary>
/// Coverage and compliance of 05 «Отчёт и покрытие»: one function for the portal (coverageAt now) and the report
/// (coverageAt on periodEnd and coveragePeriod). Category of a pair: required (assessed, active), informational,
/// not_applicable, not_configured.
/// </summary>
public static class Coverage
{
    /// <summary>Checks whose subjects are only the users the collector reports (M365-002: privileged users).</summary>
    private static readonly HashSet<string> PresenceDefinesApplicability = ["M365-002"];

    private static readonly string[] SubjectTypes = ["tenant", "user"];

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
                periodPairs++;
                if (determined)
                {
                    periodDetermined++;
                }
                if (!subject.ActiveAtEnd)
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
            determinedInPeriod is null ? null : Share(periodDetermined, periodPairs), rows);
    }

    /// <summary>Informational only because inputs are missing (WIN-010 without expectedTenantId, WIN-003 without products).</summary>
    private static bool NotConfiguredByPolicy(string checkId, JsonElement setting)
    {
        var parameters = setting.TryGetProperty("parameters", out var p) ? p : default;
        return checkId switch
        {
            "WIN-010" => parameters.ValueKind != JsonValueKind.Object
                         || !parameters.TryGetProperty("expectedTenantId", out var tenant) || tenant.ValueKind == JsonValueKind.Null,
            "WIN-003" => parameters.ValueKind != JsonValueKind.Object
                         || !parameters.TryGetProperty("approvedProducts", out var products)
                         || products.ValueKind != JsonValueKind.Array || products.GetArrayLength() == 0,
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
        var (version, configuration) = await PolicyAtAsync(scope, organizationId, at, ct);
        using var policy = JsonDocument.Parse(configuration);
        var subjects = new List<CoverageSubject>();
        await using (var command = new NpgsqlCommand("""
            select id, type, key, display_name, (retired_at is null or retired_at > @at) and first_seen_at <= @at
            from subject
            where organization_id = @org and type = any(@types)
              and first_seen_at <= @at and (retired_at is null or retired_at > @from)
            """, scope.Connection, scope.Transaction))
        {
            command.Parameters.AddWithValue("org", organizationId);
            command.Parameters.AddWithValue("types", SubjectTypes);
            command.Parameters.AddWithValue("at", at);
            command.Parameters.AddWithValue("from", start ?? at);
            await using var reader = await command.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                subjects.Add(new CoverageSubject(reader.GetGuid(0), reader.GetString(1), reader.GetString(2),
                    reader.IsDBNull(3) ? null : reader.GetString(3), reader.GetBoolean(4)));
            }
        }
        // A connected tenant before its first collection: its checks count as pairs without data.
        if (!subjects.Any(s => s is { Type: "tenant", ActiveAtEnd: true }))
        {
            await using var command = new NpgsqlCommand("""
                select entra_tenant_id from tenant_connection
                where organization_id = @org and status = 'active' and connected_at <= @at and entra_tenant_id is not null
                """, scope.Connection, scope.Transaction);
            command.Parameters.AddWithValue("org", organizationId);
            command.Parameters.AddWithValue("at", at);
            if (await command.ExecuteScalarAsync(ct) is Guid tenant)
            {
                subjects.Add(new CoverageSubject(Guid.Empty, "tenant", tenant.ToString(), null, true));
            }
        }
        var latest = new Dictionary<(Guid, string), LatestAssessment>();
        await using (var command = new NpgsqlCommand("""
            select distinct on (a.subject_id, a.check_id) a.subject_id, a.check_id, a.assessment_mode, a.result,
                   a.severity, a.reason_code, a.observed_at
            from assessment a
            where a.organization_id = @org and a.assessment_scope = 'current' and a.evaluated_at <= @at
            order by a.subject_id, a.check_id, a.evaluated_at desc, a.id desc
            """, scope.Connection, scope.Transaction))
        {
            command.Parameters.AddWithValue("org", organizationId);
            command.Parameters.AddWithValue("at", at);
            await using var reader = await command.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                latest[(reader.GetGuid(0), reader.GetString(1))] = new LatestAssessment(reader.GetString(2),
                    reader.IsDBNull(3) ? null : reader.GetString(3), reader.IsDBNull(4) ? null : reader.GetString(4),
                    reader.IsDBNull(5) ? null : reader.GetString(5), reader.GetFieldValue<DateTimeOffset>(6));
            }
        }
        HashSet<(Guid, string)>? determined = null;
        if (start is not null)
        {
            determined = [];
            await using var command = new NpgsqlCommand("""
                select distinct subject_id, check_id from assessment
                where organization_id = @org and assessment_scope = 'current' and result in ('pass', 'fail')
                  and observed_at >= @start and observed_at < @end
                """, scope.Connection, scope.Transaction);
            command.Parameters.AddWithValue("org", organizationId);
            command.Parameters.AddWithValue("start", start.Value);
            command.Parameters.AddWithValue("end", at);
            await using var reader = await command.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                determined.Add((reader.GetGuid(0), reader.GetString(1)));
            }
        }
        return Compute(policy.RootElement, version, subjects, latest, determined, at);
    }

    /// <summary>The revision in effect at the moment; before the first revision — the first one.</summary>
    public static async Task<(int Version, string Configuration)> PolicyAtAsync(DbScope scope, Guid organizationId,
        DateTimeOffset at, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            select version, configuration::text from policy_revision
            where organization_id = @org
            order by (effective_from <= @at) desc, case when effective_from <= @at then version end desc, version
            limit 1
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("org", organizationId);
        command.Parameters.AddWithValue("at", at);
        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
        {
            throw new InvalidOperationException("Organization has no policy revision");
        }
        return (reader.GetInt32(0), reader.GetString(1));
    }
}
