using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Sikkerheit.Host.Data;

namespace Sikkerheit.Host.Assessment;

/// <summary>
/// Reads of the platform tables windows_release and windows_release_month (03 «Правило SYS-003 и каталог выпусков»):
/// only verified months take part in an assessment; drafts wait for verifyWindowsReleaseMonth.
/// </summary>
public static class ReleaseCatalogStore
{
    /// <summary>The verified releases and the last month up to which every month since the first one is verified.</summary>
    public static async Task<ReleaseCatalogView> ViewAsync(DbScope scope, CancellationToken ct)
    {
        var releases = await scope.Db.WindowsReleases.AsNoTracking().Where(r => r.State == "verified" && r.Product == "client")
            .Select(r => new CatalogRelease(r.BranchBuild, r.Ubr, r.Kb, r.Kind, r.SecurityMonth, r.AutoOffered)).ToListAsync(ct);
        var months = await scope.Db.WindowsReleaseMonths.AsNoTracking().OrderBy(m => m.SecurityMonth)
            .Select(m => new { m.SecurityMonth, m.State }).ToListAsync(ct);
        return new ReleaseCatalogView(releases, VerifiedThrough(months.Select(m => (m.SecurityMonth, m.State == "verified")).ToList()));
    }

    /// <summary>
    /// Counted from the first month the catalog knows (a draft or verified one): a verified month after an unverified one
    /// does not extend the chain, so a missed month is visible as release_catalog_stale.
    /// </summary>
    public static string? VerifiedThrough(IReadOnlyList<(string Month, bool Verified)> months)
    {
        if (months.Count == 0)
        {
            return null;
        }
        var state = months.ToDictionary(m => m.Month, m => m.Verified, StringComparer.Ordinal);
        string? through = null;
        var latest = months.Max(m => m.Month)!;
        foreach (var month in ServerRules.MonthsBetween(months.Min(m => m.Month)!, latest))
        {
            if (!state.GetValueOrDefault(month))
            {
                break;
            }
            through = month;
        }
        return through;
    }

    /// <summary>
    /// Months verified in the last 24 hours: the scheduler queues patch_level_sweep for each of them in every organization,
    /// so that the devices lagging behind get their events soon after the month was put into effect (03).
    /// </summary>
    public static async Task<IReadOnlyList<(string Month, DateTimeOffset VerifiedAt)>> RecentlyVerifiedAsync(DbScope scope,
        DateTimeOffset now, CancellationToken ct) =>
        (await scope.Db.WindowsReleaseMonths.AsNoTracking().Where(m => m.State == "verified" && m.VerifiedAt > now - TimeSpan.FromHours(24))
            .Select(m => new { m.SecurityMonth, VerifiedAt = m.VerifiedAt!.Value }).ToListAsync(ct))
        .Select(m => (m.SecurityMonth, m.VerifiedAt)).ToList();

    /// <summary>The month label of a date in a form the catalog uses.</summary>
    public static string MonthOf(DateTimeOffset at) => at.UtcDateTime.ToString("yyyy-MM", CultureInfo.InvariantCulture);
}
