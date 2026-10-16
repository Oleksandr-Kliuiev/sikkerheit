using System.Globalization;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using Sikkerheit.Host.Assessment;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;

namespace Sikkerheit.Host.Reports;

public sealed class TeamsOptions
{
    /// <summary>Webhook of the Workflows flow «post to a channel when a webhook request is received» (Key Vault secret).</summary>
    public string? WebhookUrl { get; set; }

    /// <summary>Base address of the portal for links in the digest, e.g. https://sikkerheit.example.no.</summary>
    public string? PortalUrl { get; set; }

    /// <summary>An https address; an unresolved Key Vault reference or an empty value means «not configured».</summary>
    public Uri? Webhook => Uri.TryCreate(WebhookUrl, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps ? uri : null;
}

public sealed record DigestItem(Guid OrganizationId, string OrganizationName, string Kind, string Text);

/// <summary>
/// teams_digest (06 «Наблюдаемость»): once a day at 07:30 Europe/Oslo, in nb, for the staff channel: new critical
/// issues, failed collections and failed reports of the last day. Organization names, checks and counts only — no UPN
/// or computer names (04 «Минимизация данных»). Sent once per period: a sent mark is stored before the job completes.
/// </summary>
public sealed class TeamsDigestJob(DbScopes scopes, IHttpClientFactory http, TeamsOptions options, TimeProvider clock,
    ILogger<TeamsDigestJob> logger) : IJobHandler
{
    public const string HttpClientName = "teams";
    public static readonly TimeZoneInfo Oslo = TimeZoneInfo.FindSystemTimeZoneById("Europe/Oslo");

    public string Type => "teams_digest";

    public async Task ExecuteAsync(JobLease lease, CancellationToken ct)
    {
        var period = lease.PeriodKey ?? throw new InvalidOperationException("teams_digest needs a period key");
        var now = clock.GetUtcNow();
        if (!await AlreadySentAsync(period, ct))
        {
            var items = await CollectAsync(now - TimeSpan.FromDays(1), now, ct);
            if (options.Webhook is not { } webhook)
            {
                logger.LogWarning("Teams digest {Period} not sent: Teams:WebhookUrl is not configured ({Count} items)", period, items.Count);
            }
            else
            {
                var client = http.CreateClient(HttpClientName);
                using var response = await client.PostAsJsonAsync(webhook, Card(period, items, options.PortalUrl), ct);
                response.EnsureSuccessStatusCode();
            }
            await MarkSentAsync(period, now, ct);
        }
        await using var scope = await scopes.PlatformAsync(ct);
        if (!await lease.HoldAsync(scope, ct))
        {
            throw new JobLeaseLostException();
        }
        await lease.CompleteAsync(scope, ct);
        await scope.CommitAsync(ct);
    }

    private async Task<bool> AlreadySentAsync(string period, CancellationToken ct)
    {
        await using var scope = await scopes.PlatformAsync(ct);
        await using var command = new NpgsqlCommand("select 1 from teams_digest where period_key = @period", scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("period", period);
        return await command.ExecuteScalarAsync(ct) is not null;
    }

    private async Task MarkSentAsync(string period, DateTimeOffset now, CancellationToken ct)
    {
        await using var scope = await scopes.PlatformAsync(ct);
        await MarkSentAsync(scope, period, now, ct);
        await scope.CommitAsync(ct);
    }

    /// <summary>Marks a period sent in the platform scope; also used by the restore for the days after the restore point.</summary>
    public static async Task<bool> MarkSentAsync(DbScope platform, string period, DateTimeOffset now, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(
            "insert into teams_digest (period_key, sent_at) values (@period, @now) on conflict do nothing",
            platform.Connection, platform.Transaction);
        command.Parameters.AddWithValue("period", period);
        command.Parameters.AddWithValue("now", now);
        return await command.ExecuteNonQueryAsync(ct) > 0;
    }

    /// <summary>Periods whose sending time (07:30 Europe/Oslo) lies in (from, until].</summary>
    public static IReadOnlyList<string> PeriodsBetween(DateTimeOffset from, DateTimeOffset until)
    {
        var periods = new List<string>();
        var day = TimeZoneInfo.ConvertTime(from, Oslo).Date;
        for (; ; day = day.AddDays(1))
        {
            var local = day.AddHours(7).AddMinutes(30);
            var due = new DateTimeOffset(local, Oslo.GetUtcOffset(local));
            if (due > until)
            {
                return periods;
            }
            if (due > from)
            {
                periods.Add(day.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
            }
        }
    }

    /// <summary>The digest is in the closed list of read-all components (02 «Разделение клиентов»).</summary>
    public async Task<IReadOnlyList<DigestItem>> CollectAsync(DateTimeOffset since, DateTimeOffset until, CancellationToken ct)
    {
        var items = new List<DigestItem>();
        await using var scope = await scopes.ReadAllAsync(ct);
        await using (var command = new NpgsqlCommand("""
            select o.id, o.name, f.check_id, count(*)::int
            from finding_event e
            join finding f on f.organization_id = e.organization_id and f.id = e.finding_id
            join organization o on o.id = e.organization_id
            where e.occurred_at >= @since and e.occurred_at < @until and e.event_type in ('opened', 'reopened')
              and e.cause = 'source_change' and f.severity = 'critical' and o.status = 'active'
            group by o.id, o.name, f.check_id order by o.name, f.check_id
            """, scope.Connection, scope.Transaction))
        {
            command.Parameters.AddWithValue("since", since);
            command.Parameters.AddWithValue("until", until);
            await using var reader = await command.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                var check = reader.GetString(2);
                items.Add(new DigestItem(reader.GetGuid(0), reader.GetString(1), "critical",
                    $"{reader.GetInt32(3)} nye kritiske: {Texts.Title(check, "nb")} ({check})"));
            }
        }
        await using (var command = new NpgsqlCommand("""
            select o.id, o.name, r.failure_code, count(*)::int
            from collection_run r join organization o on o.id = r.organization_id
            where r.completed_at >= @since and r.completed_at < @until and r.state = 'failed' and o.status = 'active'
            group by o.id, o.name, r.failure_code order by o.name
            """, scope.Connection, scope.Transaction))
        {
            command.Parameters.AddWithValue("since", since);
            command.Parameters.AddWithValue("until", until);
            await using var reader = await command.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                var code = reader.IsDBNull(2) ? "temporary_error" : reader.GetString(2);
                items.Add(new DigestItem(reader.GetGuid(0), reader.GetString(1), "collection",
                    $"Innsamling mislyktes ({reader.GetInt32(3)}): {ReportTexts.Get("runFailure." + code, "nb")}"));
            }
        }
        await using (var command = new NpgsqlCommand("""
            select o.id, o.name, r.period_start, r.timezone, r.failure_code
            from report r join organization o on o.id = r.organization_id
            where r.state = 'failed' and r.created_at >= @since - interval '6 days'
            order by o.name, r.period_start
            """, scope.Connection, scope.Transaction))
        {
            command.Parameters.AddWithValue("since", since);
            await using var reader = await command.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                var zone = TimeZoneInfo.FindSystemTimeZoneById(reader.GetString(3));
                var (year, week) = ReportPeriod.WeekOf(zone, reader.GetFieldValue<DateTimeOffset>(2));
                items.Add(new DigestItem(reader.GetGuid(0), reader.GetString(1), "report",
                    $"Rapport for uke {week} {year} mislyktes ({reader.GetString(4)})"));
            }
        }
        return items;
    }

    /// <summary>
    /// An Adaptive Card with text elements only. Untrusted names go into TextRun elements, which render no markdown, so a
    /// name cannot become a link, emphasis or a list.
    /// </summary>
    public static JsonObject Card(string period, IReadOnlyList<DigestItem> items, string? portalUrl)
    {
        static JsonObject Text(string text, bool bold = false, string spacing = "Default") => new()
        {
            ["type"] = "RichTextBlock", ["spacing"] = spacing,
            ["inlines"] = new JsonArray
            {
                new JsonObject { ["type"] = "TextRun", ["text"] = Plain(text), ["weight"] = bold ? "Bolder" : "Default" },
            },
        };

        var body = new JsonArray { Text("Sikkerheit – daglig oppsummering " + period, bold: true) };
        if (items.Count == 0)
        {
            body.Add(Text("Ingen nye kritiske problemer, mislykkede innsamlinger eller rapporter siste døgn."));
        }
        foreach (var group in items.GroupBy(i => (i.OrganizationId, i.OrganizationName)))
        {
            body.Add(Text(group.Key.OrganizationName, bold: true, spacing: "Medium"));
            foreach (var item in group)
            {
                body.Add(Text("• " + item.Text, spacing: "None"));
            }
        }
        var card = new JsonObject
        {
            ["$schema"] = "http://adaptivecards.io/schemas/adaptive-card.json", ["type"] = "AdaptiveCard", ["version"] = "1.4",
            ["body"] = body,
        };
        if (!string.IsNullOrEmpty(portalUrl) && Uri.TryCreate(portalUrl, UriKind.Absolute, out var portal) && portal.Scheme == "https")
        {
            card["actions"] = new JsonArray
            {
                new JsonObject { ["type"] = "Action.OpenUrl", ["title"] = "Åpne problemkøen", ["url"] = new Uri(portal, "/findings").ToString() },
            };
        }
        return new JsonObject
        {
            ["type"] = "message",
            ["attachments"] = new JsonArray
            {
                new JsonObject { ["contentType"] = "application/vnd.microsoft.card.adaptive", ["contentUrl"] = null, ["content"] = card },
            },
        };
    }

    /// <summary>Control and bidirectional formatting characters of untrusted text become spaces.</summary>
    public static string Plain(string text)
    {
        var builder = new StringBuilder(text.Length);
        foreach (var c in text)
        {
            var hidden = char.IsControl(c) || c is >= '\u202A' and <= '\u202E' or >= '\u2066' and <= '\u2069' or >= '\u200B' and <= '\u200F';
            builder.Append(hidden ? ' ' : c);
        }
        return builder.ToString();
    }

    /// <summary>The period key of the digest: the Oslo date of 07:30 local time.</summary>
    public static string? DuePeriod(DateTimeOffset now)
    {
        var local = TimeZoneInfo.ConvertTime(now, Oslo);
        return local.TimeOfDay >= new TimeSpan(7, 30, 0) ? local.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : null;
    }
}
