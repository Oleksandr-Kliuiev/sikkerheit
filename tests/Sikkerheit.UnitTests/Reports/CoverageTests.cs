using System.Text.Json;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Organizations;
using Sikkerheit.Host.Reports;

namespace Sikkerheit.UnitTests.Reports;

/// <summary>The worked example of 05 «Отчёт и покрытие»: coverageAt 75 %, coveragePeriod 87,5 %, compliance 50 %.</summary>
public sealed class CoverageTests
{
    private static readonly JsonElement Policy =
        JsonDocument.Parse(new PolicyRules(new ContractSchemas()).DefaultConfiguration).RootElement.Clone();

    private static readonly DateTimeOffset End = new(2026, 10, 11, 22, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Worked_example_of_the_package()
    {
        var u = Enumerable.Range(1, 4).Select(i => new CoverageSubject(Guid.NewGuid(), "user", "u" + i, "U" + i, true)).ToArray();
        var guest = new CoverageSubject(Guid.NewGuid(), "user", "g", "G", true);
        var tenant = new CoverageSubject(Guid.NewGuid(), "tenant", "t", null, true);
        var fresh = End.AddHours(-6);
        LatestAssessment Assessed(string result, string? reason = null) =>
            new("assessed", result, result == "fail" ? "warning" : null, reason, fresh);
        var informational = new LatestAssessment("informational", null, null, null, fresh);
        var latest = new Dictionary<(Guid, string), LatestAssessment>
        {
            [(u[0].Id, "M365-001")] = Assessed("pass"),
            [(u[1].Id, "M365-001")] = Assessed("fail"),
            [(u[2].Id, "M365-001")] = Assessed("pass"),
            [(u[2].Id, "M365-002")] = Assessed("pass"),
            [(u[3].Id, "M365-001")] = Assessed("unknown", "temporary_error"),
            [(guest.Id, "M365-001")] = Assessed("not_applicable"),
            [(tenant.Id, "M365-003")] = Assessed("fail"),
            [(tenant.Id, "M365-005")] = Assessed("fail"),
            [(tenant.Id, "M365-006")] = Assessed("unknown", "temporary_error"),
            [(tenant.Id, "M365-004")] = informational,
        };
        foreach (var subject in u.Append(guest))
        {
            latest[(subject.Id, "M365-007")] = informational;
        }
        // Every determined result of the table lies in the week; M365-006 also passed on Tuesday.
        var determined = new HashSet<(Guid, string)>
        {
            (u[0].Id, "M365-001"), (u[1].Id, "M365-001"), (u[2].Id, "M365-001"), (u[2].Id, "M365-002"),
            (tenant.Id, "M365-003"), (tenant.Id, "M365-005"), (tenant.Id, "M365-006"),
        };

        var result = Coverage.Compute(Policy, 1, [.. u, guest, tenant], latest, determined, End);

        Assert.Equal(8, result.Pairs);
        Assert.Equal(0.75, result.CoverageAt);
        Assert.Equal(0.875, result.CoveragePeriod);
        Assert.Equal(0.5, result.Compliance);
        Assert.Equal((6, 1, 2, 0), (result.Informational, result.NotApplicable, result.Unknown, result.Stale));
        Assert.Equal(0, result.NotConfigured);
    }

    [Fact]
    public void Stale_results_leave_the_numerator_and_no_pairs_give_no_data()
    {
        var tenant = new CoverageSubject(Guid.NewGuid(), "tenant", "t", null, true);
        var old = new LatestAssessment("assessed", "pass", null, null, End.AddHours(-49));
        var latest = new Dictionary<(Guid, string), LatestAssessment> { [(tenant.Id, "M365-003")] = old };
        var result = Coverage.Compute(Policy, 1, [tenant], latest, null, End);
        // M365-003 stale; M365-005 and M365-006 have no assessment yet.
        Assert.Equal((3, 1, 2), (result.Pairs, result.Stale, result.NoData));
        Assert.Equal(0.0, result.CoverageAt);
        Assert.Null(result.Compliance);
        Assert.Null(result.CoveragePeriod);

        var empty = Coverage.Compute(Policy, 1, [], new Dictionary<(Guid, string), LatestAssessment>(), null, End);
        Assert.Null(empty.CoverageAt);
    }

    [Fact]
    public void Subjects_retired_in_the_period_count_only_for_the_period()
    {
        var gone = new CoverageSubject(Guid.NewGuid(), "user", "gone", "Gone", ActiveAtEnd: false);
        var latest = new Dictionary<(Guid, string), LatestAssessment>
        {
            [(gone.Id, "M365-001")] = new("assessed", "pass", null, null, End.AddDays(-3)),
        };
        var result = Coverage.Compute(Policy, 1, [gone], latest, new HashSet<(Guid, string)> { (gone.Id, "M365-001") }, End);
        Assert.Equal((0, 1, 1), (result.Pairs, result.PeriodPairs, result.PeriodDetermined));
        Assert.Null(result.CoverageAt);
        Assert.Equal(1.0, result.CoveragePeriod);
    }
}
