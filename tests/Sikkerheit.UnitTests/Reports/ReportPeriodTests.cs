using Sikkerheit.Host.Jobs;
using Sikkerheit.Host.Reports;

namespace Sikkerheit.UnitTests.Reports;

/// <summary>ISO weeks in the organization timezone and the Monday 06:00 schedule with catch-up of 4 weeks.</summary>
public sealed class ReportPeriodTests
{
    private static readonly TimeZoneInfo Oslo = TimeZoneInfo.FindSystemTimeZoneById("Europe/Oslo");

    private static DateTimeOffset Local(int year, int month, int day, int hour)
    {
        var local = new DateTime(year, month, day, hour, 0, 0, DateTimeKind.Unspecified);
        return new DateTimeOffset(local, Oslo.GetUtcOffset(local));
    }

    [Fact]
    public void Week_boundaries_are_local_mondays_including_the_daylight_saving_change()
    {
        var (start, end) = ReportPeriod.Week(Oslo, 2026, 41);
        Assert.Equal(DateTimeOffset.Parse("2026-10-04T22:00:00Z"), start);
        Assert.Equal(DateTimeOffset.Parse("2026-10-11T22:00:00Z"), end);
        // Week 43 ends after the change to winter time on 25 October: 7 days and 1 hour.
        var (dstStart, dstEnd) = ReportPeriod.Week(Oslo, 2026, 43);
        Assert.Equal(DateTimeOffset.Parse("2026-10-18T22:00:00Z"), dstStart);
        Assert.Equal(DateTimeOffset.Parse("2026-10-25T23:00:00Z"), dstEnd);
    }

    [Fact]
    public void Only_exact_week_boundaries_are_a_week()
    {
        Assert.True(ReportPeriod.IsWeek(Oslo, DateTimeOffset.Parse("2026-10-05T00:00:00+02:00"),
            DateTimeOffset.Parse("2026-10-12T00:00:00+02:00"), out var key));
        Assert.Equal("2026-W41", key);
        Assert.False(ReportPeriod.IsWeek(Oslo, DateTimeOffset.Parse("2026-10-05T00:00:00Z"),
            DateTimeOffset.Parse("2026-10-12T00:00:00Z"), out _));
        Assert.False(ReportPeriod.IsWeek(Oslo, DateTimeOffset.Parse("2026-10-05T00:00:00+02:00"),
            DateTimeOffset.Parse("2026-10-19T00:00:00+02:00"), out _));
    }

    [Theory]
    [InlineData("2026-W41", true)]
    [InlineData("2026-W53", true)]
    [InlineData("2025-W53", false)]
    [InlineData("2026-W00", false)]
    [InlineData("2026-41", false)]
    [InlineData(null, false)]
    public void Week_keys(string? key, bool valid) => Assert.Equal(valid, ReportPeriod.TryParseKey(key, out _, out _));

    [Fact]
    public void Reports_are_due_from_monday_six_and_catch_up_four_weeks()
    {
        var longAgo = DateTimeOffset.Parse("2020-01-01T00:00:00Z");
        Assert.Equal(["2026-W41", "2026-W40", "2026-W39", "2026-W38"],
            Scheduler.DueReportWeeks(Oslo, Local(2026, 10, 12, 7), longAgo));
        Assert.Equal(["2026-W40", "2026-W39", "2026-W38", "2026-W37"],
            Scheduler.DueReportWeeks(Oslo, Local(2026, 10, 12, 5), longAgo));
        Assert.Equal(["2026-W41"], Scheduler.DueReportWeeks(Oslo, Local(2026, 10, 12, 7), Local(2026, 10, 7, 10)));
        Assert.Empty(Scheduler.DueReportWeeks(Oslo, Local(2026, 10, 12, 7), Local(2026, 10, 12, 1)));
        // Across the year: ISO 2026 has 53 weeks.
        Assert.Equal("2026-W53", Scheduler.DueReportWeeks(Oslo, Local(2027, 1, 4, 7), longAgo).First());
    }
}
