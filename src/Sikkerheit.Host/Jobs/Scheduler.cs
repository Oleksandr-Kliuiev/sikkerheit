using System.Globalization;
using System.Security.Cryptography;
using Npgsql;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Operations;
using Sikkerheit.Host.Reports;

namespace Sikkerheit.Host.Jobs;

/// <summary>
/// Inserts periodic jobs every 5 minutes with a unique (type, organizationId, periodKey) — 02 «Фоновые задания»:
/// daily M365 collection at collectionHourLocal with up to 30 minutes of random delay, hourly freshness and review
/// sweeps, weekly report of the completed week on Monday 06:00 local time with catch-up of 4 weeks, daily retention at
/// 02:00, hourly deletion of organizations past deletionDueAt and the Teams digest at 07:30 Europe/Oslo. Repeats and
/// several instances create each period once.
/// </summary>
public sealed class Scheduler(DbScopes scopes, TimeProvider clock, ILogger<Scheduler> logger) : BackgroundService
{
    public static readonly TimeSpan Tick = TimeSpan.FromMinutes(5);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RunOnceAsync(stoppingToken);
            }
            catch (Exception error) when (error is not OperationCanceledException)
            {
                logger.LogError(error, "Scheduler tick failed");
            }
            await Task.Delay(Tick, clock, stoppingToken);
        }
    }

    public const int ReportCatchUpWeeks = 4;

    private sealed record OrganizationPlan(Guid Id, string Timezone, int CollectionHour, bool M365Active, DateTimeOffset CreatedAt,
        string Status, DateTimeOffset? DeletionDueAt);

    private DateTimeOffset _lastPlatformPurge = DateTimeOffset.MinValue;

    public async Task RunOnceAsync(CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        var plans = new List<OrganizationPlan>();
        // The scheduler is in the closed list of components with the read-all scope (02 «Разделение клиентов»).
        await using (var all = await scopes.ReadAllAsync(ct))
        {
            await using var command = new NpgsqlCommand("""
                select o.id, o.timezone,
                       coalesce((select (p.configuration -> 'm365' ->> 'collectionHourLocal')::int from policy_revision p
                                 where p.organization_id = o.id order by p.version desc limit 1), 3),
                       coalesce(t.status = 'active', false), o.created_at, o.status, o.deletion_due_at
                from organization o left join tenant_connection t on t.organization_id = o.id
                """, all.Connection, all.Transaction);
            await using var reader = await command.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                plans.Add(new OrganizationPlan(reader.GetGuid(0), reader.GetString(1), reader.GetInt32(2), reader.GetBoolean(3),
                    reader.GetFieldValue<DateTimeOffset>(4), reader.GetString(5),
                    reader.IsDBNull(6) ? null : reader.GetFieldValue<DateTimeOffset>(6)));
            }
        }
        await using var platform = await scopes.PlatformAsync(ct);
        var hour = now.UtcDateTime.ToString("yyyy-MM-dd'T'HH", CultureInfo.InvariantCulture);
        foreach (var plan in plans)
        {
            var zone = TimeZoneInfo.FindSystemTimeZoneById(plan.Timezone);
            var local = TimeZoneInfo.ConvertTime(now, zone);
            var localDate = local.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            // Inactive organizations run only export, retention and deletion (05 «Жизненный цикл организации»).
            if (plan.Status == "active")
            {
                if (plan.M365Active && local.Hour >= plan.CollectionHour)
                {
                    var jitter = TimeSpan.FromSeconds(RandomNumberGenerator.GetInt32(0, 30 * 60));
                    await JobQueue.EnqueueAsync(platform, "m365_collect", plan.Id, null, localDate, now + jitter, ct);
                }
                await JobQueue.EnqueueAsync(platform, "freshness_sweep", plan.Id, null, hour, now, ct);
                await JobQueue.EnqueueAsync(platform, "review_expiry", plan.Id, null, hour, now, ct);
                foreach (var week in DueReportWeeks(zone, now, plan.CreatedAt))
                {
                    await JobQueue.EnqueueAsync(platform, "weekly_report", plan.Id, null, week, now, ct);
                }
            }
            if (local.Hour >= 2)
            {
                await JobQueue.EnqueueAsync(platform, "retention_purge", plan.Id, null, localDate, now, ct);
            }
            if (plan.Status == "deletion_scheduled" && plan.DeletionDueAt <= now)
            {
                await JobQueue.EnqueueAsync(platform, "organization_delete", plan.Id, null, hour, now, ct);
            }
        }
        if (TeamsDigestJob.DuePeriod(now) is { } day)
        {
            await JobQueue.EnqueueAsync(platform, "teams_digest", null, null, day, now, ct);
        }
        if (now - _lastPlatformPurge >= TimeSpan.FromHours(1))
        {
            await PurgePlatformAsync(platform, now, ct);
            _lastPlatformPurge = now;
        }
        await platform.CommitAsync(ct);
    }

    /// <summary>Platform rows past their terms (04 «Сроки хранения»): jobs, sessions, sign-in attempts, tombstones, digest marks.</summary>
    private static async Task PurgePlatformAsync(DbScope platform, DateTimeOffset now, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            delete from job where (state = 'succeeded' and completed_at < @now - interval '30 days')
                               or (state = 'failed' and completed_at < @now - interval '90 days');
            delete from staff_session where expires_at < @now;
            delete from staff_login where expires_at < @now;
            delete from organization_tombstone where deleted_at < @now - interval '365 days';
            delete from teams_digest where sent_at < @now - interval '90 days';
            """, platform.Connection, platform.Transaction);
        command.Parameters.AddWithValue("now", now);
        await command.ExecuteNonQueryAsync(ct);
    }

    /// <summary>
    /// Completed weeks whose report is due: the previous week from Monday 06:00 local time and up to 3 earlier ones
    /// (catch-up of 4 weeks), never a week that ended before the organization was created.
    /// </summary>
    public static IEnumerable<string> DueReportWeeks(TimeZoneInfo zone, DateTimeOffset now, DateTimeOffset createdAt)
    {
        var local = TimeZoneInfo.ConvertTime(now, zone);
        var (year, week) = ReportPeriod.Previous(ISOWeek.GetYear(local.DateTime), ISOWeek.GetWeekOfYear(local.DateTime));
        if (local.DayOfWeek == DayOfWeek.Monday && local.Hour < 6)
        {
            (year, week) = ReportPeriod.Previous(year, week);
        }
        for (var i = 0; i < ReportCatchUpWeeks; i++)
        {
            if (ReportPeriod.Week(zone, year, week).End <= createdAt)
            {
                yield break;
            }
            yield return ReportPeriod.Key(year, week);
            (year, week) = ReportPeriod.Previous(year, week);
        }
    }
}
