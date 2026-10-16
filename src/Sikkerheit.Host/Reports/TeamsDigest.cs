using System.Globalization;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using Sikkerheit.Host.Assessment;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;
using Sikkerheit.Host.M365;
using Sikkerheit.Host.Operations;
using Sikkerheit.Host.Organizations;

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
                // Nothing was accepted, so the period is not marked as sent (05 «Фоновые задания и планировщик»).
                logger.LogWarning("Teams digest {Period} not sent: Teams:WebhookUrl is not configured ({Count} items)", period, items.Count);
            }
            else
            {
                var client = http.CreateClient(HttpClientName);
                using var response = await client.PostAsJsonAsync(webhook, Card(period, items, options.PortalUrl), ct);
                response.EnsureSuccessStatusCode();
                // Marked right after the webhook accepted the digest: a repeated job sends nothing (at least once).
                await MarkSentAsync(period, now, ct);
            }
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

    /// <summary>Sent marks older than 90 days (04 «Сроки хранения»), in the caller's platform scope.</summary>
    public static async Task PurgeMarksAsync(DbScope platform, DateTimeOffset now, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("delete from teams_digest where sent_at < @now - interval '90 days'",
            platform.Connection, platform.Transaction);
        command.Parameters.AddWithValue("now", now);
        await command.ExecuteNonQueryAsync(ct);
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
        await using var scope = await scopes.ReadAllAsync(ct);
        var organizations = await OrganizationDirectory.ListAsync(scope, ct);
        var byId = organizations.ToDictionary(o => o.Id);
        // Items of every kind go by organization name as the database orders names; organizations of the same name share
        // a place, so their items keep the order of the query.
        var place = new Dictionary<Guid, int>();
        for (var i = 0; i < organizations.Count; i++)
        {
            place[organizations[i].Id] = i > 0 && organizations[i].Name == organizations[i - 1].Name
                ? place[organizations[i - 1].Id]
                : i;
        }
        var critical = new List<DigestItem>();
        foreach (var count in await FindingHistory.NewCriticalAsync(scope, since, until, ct))
        {
            if (byId.TryGetValue(count.OrganizationId, out var organization) && organization.Status == "active")
            {
                critical.Add(new DigestItem(organization.Id, organization.Name, "critical",
                    $"{count.Count} nye kritiske: {Texts.Title(count.CheckId, "nb")} ({count.CheckId})"));
            }
        }
        var collection = new List<DigestItem>();
        foreach (var failed in await CollectionRuns.FailedAsync(scope, since, until, ct))
        {
            if (byId.TryGetValue(failed.OrganizationId, out var organization) && organization.Status == "active")
            {
                var code = failed.FailureCode ?? "temporary_error";
                collection.Add(new DigestItem(organization.Id, organization.Name, "collection",
                    $"Innsamling mislyktes ({failed.Count}): {ReportTexts.Get("runFailure." + code, "nb")}"));
            }
        }
        var reports = new List<DigestItem>();
        await using (var command = new NpgsqlCommand("""
            select r.organization_id, r.period_start, r.timezone, r.failure_code
            from report r
            where r.state = 'failed' and r.created_at >= @since - interval '6 days'
            order by r.period_start
            """, scope.Connection, scope.Transaction))
        {
            command.Parameters.AddWithValue("since", since);
            await using var reader = await command.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                if (byId.TryGetValue(reader.GetGuid(0), out var organization))
                {
                    var zone = TimeZoneInfo.FindSystemTimeZoneById(reader.GetString(2));
                    var (year, week) = ReportPeriod.WeekOf(zone, reader.GetFieldValue<DateTimeOffset>(1));
                    reports.Add(new DigestItem(organization.Id, organization.Name, "report",
                        $"Rapport for uke {week} {year} mislyktes ({reader.GetString(3)})"));
                }
            }
        }
        // Windows devices (P2): counts only, no computer names (04 «Минимизация данных»).
        var devices = new List<DigestItem>();
        foreach (var count in await AuditLog.CountsAsync(scope, ["device.enroll", "device.key_replaced"], since, until, ct))
        {
            if (byId.TryGetValue(count.OrganizationId, out var organization) && organization.Status == "active")
            {
                devices.Add(new DigestItem(organization.Id, organization.Name, "device", count.Action == "device.enroll"
                    ? $"{count.Count} nye enheter registrert"
                    : $"Enhetsnøkkel byttet på {count.Count} enheter"));
            }
        }
        IEnumerable<DigestItem> ByName(List<DigestItem> list) => list.OrderBy(i => place[i.OrganizationId]);
        var items = new List<DigestItem>([.. ByName(critical), .. ByName(collection), .. ByName(reports), .. ByName(devices)]);
        // The state of the release catalog is a fact of the platform, not of an organization.
        if (await ReleaseCatalogCheckJob.StateAsync(scope, until, ct) is { Verified: false } catalog)
        {
            items.Add(new DigestItem(Guid.Empty, "Windows-utgivelser", "catalog",
                $"Måneden {catalog.Month} i katalogen over Windows-utgivelser er ikke kontrollert (RB-13)"));
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
