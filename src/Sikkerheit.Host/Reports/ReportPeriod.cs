using System.Globalization;

namespace Sikkerheit.Host.Reports;

/// <summary>ISO weeks from Monday 00:00 to Monday 00:00 in the organization timezone; UTC boundaries are stored (05).</summary>
public static class ReportPeriod
{
    public static (DateTimeOffset Start, DateTimeOffset End) Week(TimeZoneInfo zone, int isoYear, int week)
    {
        var monday = ISOWeek.ToDateTime(isoYear, week, DayOfWeek.Monday);
        return (Instant(zone, monday), Instant(zone, monday.AddDays(7)));
    }

    /// <summary>The week that contains the local moment.</summary>
    public static (int Year, int Week) WeekOf(TimeZoneInfo zone, DateTimeOffset moment)
    {
        var local = TimeZoneInfo.ConvertTime(moment, zone).DateTime;
        return (ISOWeek.GetYear(local), ISOWeek.GetWeekOfYear(local));
    }

    /// <summary>The week before the given one.</summary>
    public static (int Year, int Week) Previous(int year, int week)
    {
        var monday = ISOWeek.ToDateTime(year, week, DayOfWeek.Monday).AddDays(-7);
        return (ISOWeek.GetYear(monday), ISOWeek.GetWeekOfYear(monday));
    }

    public static string Key(int year, int week) =>
        year.ToString(CultureInfo.InvariantCulture) + "-W" + week.ToString("00", CultureInfo.InvariantCulture);

    public static bool TryParseKey(string? key, out int year, out int week)
    {
        year = 0;
        week = 0;
        if (key is not { Length: 8 } || key[4] != '-' || key[5] != 'W'
            || !int.TryParse(key.AsSpan(0, 4), NumberStyles.None, CultureInfo.InvariantCulture, out year)
            || !int.TryParse(key.AsSpan(6, 2), NumberStyles.None, CultureInfo.InvariantCulture, out week))
        {
            return false;
        }
        return year is >= 2000 and <= 9998 && week >= 1 && week <= ISOWeek.GetWeeksInYear(year);
    }

    /// <summary>True when start and end are exactly the boundaries of one ISO week in the zone.</summary>
    public static bool IsWeek(TimeZoneInfo zone, DateTimeOffset start, DateTimeOffset end, out string key)
    {
        var (year, week) = WeekOf(zone, start);
        var (weekStart, weekEnd) = Week(zone, year, week);
        key = Key(year, week);
        return weekStart == start && weekEnd == end;
    }

    /// <summary>Local midnight as an instant; a skipped local time moves to the first valid moment after it.</summary>
    private static DateTimeOffset Instant(TimeZoneInfo zone, DateTime local)
    {
        while (zone.IsInvalidTime(local))
        {
            local = local.AddMinutes(15);
        }
        return new DateTimeOffset(local, zone.GetUtcOffset(local)).ToUniversalTime();
    }
}
