using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Unicode;
using Sikkerheit.Host.Assessment;

namespace Sikkerheit.Host.Reports;

/// <summary>
/// Renders a report snapshot as one self-contained HTML file (05 «Отчёт и покрытие»): no scripts and no external
/// resources, a print stylesheet, every value escaped, one language for the whole document.
/// </summary>
public sealed class ReportHtml
{
    private static readonly HtmlEncoder Encoder = HtmlEncoder.Create(UnicodeRanges.All);
    private readonly ReportSnapshot _s;
    private readonly string _lang;
    private readonly TimeZoneInfo _zone;
    private readonly StringBuilder _html = new();

    private ReportHtml(ReportSnapshot snapshot)
    {
        _s = snapshot;
        _lang = snapshot.Language;
        _zone = TimeZoneInfo.FindSystemTimeZoneById(snapshot.Timezone);
    }

    /// <summary>Checks without a title or recommendation in the report language (failureCode translation_missing).</summary>
    public static IReadOnlyList<string> MissingTranslations(ReportSnapshot snapshot) =>
        snapshot.CheckIds.Where(c => !Texts.HasCheckTexts(c, snapshot.Language)).ToList();

    public static string Render(ReportSnapshot snapshot) => new ReportHtml(snapshot).Build();

    private string T(string key) => ReportTexts.Get(key, _lang);

    private static string E(string? value) => Encoder.Encode(Clean(value ?? ""));

    /// <summary>Control and bidirectional formatting characters of untrusted text become U+FFFD.</summary>
    private static string Clean(string value)
    {
        var builder = new StringBuilder(value.Length);
        foreach (var c in value)
        {
            var unsafeChar = (char.IsControl(c) && c is not ('\n' or '\t'))
                             || c is >= '\u202A' and <= '\u202E' or >= '\u2066' and <= '\u2069' or '\u200E' or '\u200F' or '\u061C';
            builder.Append(unsafeChar ? '\uFFFD' : c);
        }
        return builder.ToString();
    }

    private string Time(DateTimeOffset? value) => value is null ? "—"
        : TimeZoneInfo.ConvertTime(value.Value, _zone).ToString(_lang == "en" ? "yyyy-MM-dd HH:mm" : "dd.MM.yyyy HH:mm",
            CultureInfo.InvariantCulture);

    private string Date(DateTimeOffset value) =>
        TimeZoneInfo.ConvertTime(value, _zone).ToString(_lang == "en" ? "yyyy-MM-dd" : "dd.MM.yyyy", CultureInfo.InvariantCulture);

    private string Percent(double? value)
    {
        if (value is null)
        {
            return T("noData");
        }
        var text = (value.Value * 100).ToString("0.0", CultureInfo.InvariantCulture);
        return _lang == "en" ? text + "%" : text.Replace('.', ',') + "\u00A0%";
    }

    private string SubjectText(ReportSubject subject) =>
        subject.Type == "tenant" ? T("wholeTenant") : subject.Name ?? subject.Key;

    private string Severity(string severity) =>
        $"<span class=\"sev sev-{E(severity)}\">{E(T("severity." + severity))}</span>";

    private string Build()
    {
        var (start, end) = (_s.PeriodStart, _s.PeriodEnd);
        var title = $"{T("title")} — {_s.OrganizationName} — {T("week")} {_s.IsoWeek[6..]} {_s.IsoWeek[..4]}";
        _html.Append("<!doctype html>\n<html lang=\"").Append(_lang).Append("\">\n<head>\n<meta charset=\"utf-8\">\n")
            .Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
            .Append("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">\n")
            .Append("<meta name=\"referrer\" content=\"no-referrer\">\n<title>").Append(E(title)).Append("</title>\n<style>")
            .Append(Style).Append("</style>\n</head>\n<body>\n<header>\n<p class=\"brand\">Sikkerheit</p>\n<h1>")
            .Append(E(T("title"))).Append("</h1>\n<p class=\"org\">").Append(E(_s.OrganizationName)).Append("</p>\n<dl class=\"meta\">");
        Pair(T("week"), $"{int.Parse(_s.IsoWeek[6..], CultureInfo.InvariantCulture)} ({_s.IsoWeek[..4]})");
        Pair(T("period"), $"{Date(start)} – {Date(end.AddTicks(-1))}");
        Pair(T("timezone"), _s.Timezone);
        Pair(T("generated"), Time(_s.GeneratedAt));
        Pair(T("policyVersions"), string.Join(", ", _s.PolicyVersions.Select(v => v.ToString(CultureInfo.InvariantCulture))));
        _html.Append("</dl>\n</header>\n<main>\n");
        Summary();
        _html.Append("<h2>Microsoft 365</h2>\n");
        Connection();
        Findings();
        Decisions();
        OtherChanges();
        Unavailable();
        CoverageSection();
        _html.Append("<h2>").Append(E(T("windows"))).Append("</h2>\n<p>").Append(E(T("windowsNone"))).Append("</p>\n</main>\n<footer>\n<p>")
            .Append(E(T("footer"))).Append("</p>\n");
        if (_s.DetailsExpired)
        {
            _html.Append("<p>").Append(E(T("retentionNote"))).Append("</p>\n");
        }
        _html.Append("</footer>\n</body>\n</html>\n");
        return _html.ToString();
    }

    private void Pair(string term, string value) =>
        _html.Append("<dt>").Append(E(term)).Append("</dt><dd>").Append(E(value)).Append("</dd>");

    private void Summary()
    {
        var newCount = _s.Events.Count(e => e.EventType is "opened" or "reopened" && e.Cause == "source_change");
        var fixedCount = _s.Events.Count(e => e.EventType == "resolved" && e.Cause == "source_change");
        _html.Append("<section class=\"summary\" aria-label=\"").Append(E(T("summary"))).Append("\">\n");
        Card(T("openCritical"), _s.OpenAtEnd.Count(o => o.Severity == "critical").ToString(CultureInfo.InvariantCulture),
            _s.OpenAtEnd.Any(o => o.Severity == "critical") ? "bad" : "good");
        Card(T("openWarning"), _s.OpenAtEnd.Count(o => o.Severity == "warning").ToString(CultureInfo.InvariantCulture), "");
        Card(T("newFindings"), newCount.ToString(CultureInfo.InvariantCulture), "");
        Card(T("fixed"), fixedCount.ToString(CultureInfo.InvariantCulture), "");
        Card(T("coverageAt"), Percent(_s.Coverage.CoverageAt), "");
        Card(T("compliance"), Percent(_s.Coverage.Compliance), "");
        _html.Append("</section>\n");
    }

    private void Card(string label, string value, string tone) =>
        _html.Append("<div class=\"card ").Append(tone).Append("\"><div class=\"value\">").Append(E(value))
            .Append("</div><div class=\"label\">").Append(E(label)).Append("</div></div>\n");

    private void Connection()
    {
        var c = _s.Connection;
        _html.Append("<section>\n<h3>").Append(E(T("connection"))).Append("</h3>\n<dl class=\"facts\">");
        Pair(T("connection"), T("connection." + c.Status));
        if (c.TenantId is not null)
        {
            Pair(T("tenant"), string.Join(" · ", new[] { c.DisplayName, c.PrimaryDomain, c.TenantId.ToString() }
                .Where(v => !string.IsNullOrEmpty(v))));
        }
        Pair(T("entraP1"), c.EntraP1 switch { true => T("yes"), false => T("no"), null => T("unknownValue") });
        Pair(T("lastCollection"), Time(c.LastCollectedAt));
        _html.Append("</dl>\n</section>\n");
    }

    private void Findings()
    {
        var created = _s.Events.Where(e => e.EventType is "opened" or "reopened" && e.Cause == "source_change").ToList();
        EventTable(T("newFindings"), created, withEvent: true);
        EventTable(T("fixed"), _s.Events.Where(e => e.EventType == "resolved" && e.Cause == "source_change").ToList(), withEvent: false);
        OpenTable(T("criticalNow"), _s.OpenAtEnd.Where(o => o.Severity == "critical").ToList());
        OpenTable(T("ongoing"), _s.OpenAtEnd.Where(o => !o.NewInPeriod).ToList());
        var byCheck = _s.OpenAtEnd.GroupBy(o => o.CheckId).OrderBy(g => g.Key, StringComparer.Ordinal).ToList();
        if (byCheck.Count == 0)
        {
            return;
        }
        _html.Append("<section>\n<h3>").Append(E(T("recommendations"))).Append("</h3>\n<table>\n<thead><tr><th>")
            .Append(E(T("col.check"))).Append("</th><th class=\"num\">").Append(E(T("col.count"))).Append("</th><th>")
            .Append(E(T("col.recommendation"))).Append("</th></tr></thead>\n<tbody>\n");
        foreach (var group in byCheck)
        {
            _html.Append("<tr><td>").Append(E(Texts.Title(group.Key, _lang))).Append(" <span class=\"id\">").Append(E(group.Key))
                .Append("</span></td><td class=\"num\">").Append(group.Count()).Append("</td><td>")
                .Append(E(Texts.Recommendation(group.Key, _lang))).Append("</td></tr>\n");
        }
        _html.Append("</tbody>\n</table>\n</section>\n");
    }

    private void Heading(string title, int count) =>
        _html.Append("<section>\n<h3>").Append(E(title)).Append(" <span class=\"count\">").Append(count).Append("</span></h3>\n");

    private void None() => _html.Append("<p class=\"none\">").Append(E(T("none"))).Append("</p>\n</section>\n");

    private void EventTable(string title, IReadOnlyList<ReportEvent> events, bool withEvent)
    {
        Heading(title, events.Count);
        if (events.Count == 0)
        {
            None();
            return;
        }
        _html.Append("<table>\n<thead><tr><th>").Append(E(T("col.check"))).Append("</th><th>").Append(E(T("col.subject")))
            .Append("</th><th>").Append(E(T("col.severity"))).Append("</th>");
        if (withEvent)
        {
            _html.Append("<th>").Append(E(T("col.event"))).Append("</th>");
        }
        _html.Append("<th>").Append(E(T("col.time"))).Append("</th></tr></thead>\n<tbody>\n");
        foreach (var e in events)
        {
            _html.Append("<tr><td>").Append(E(Texts.Title(e.CheckId, _lang))).Append(" <span class=\"id\">").Append(E(e.CheckId))
                .Append("</span></td><td>").Append(E(SubjectText(e.Subject))).Append("</td><td>").Append(Severity(e.Severity))
                .Append("</td>");
            if (withEvent)
            {
                _html.Append("<td>").Append(E(T("event." + e.EventType))).Append("</td>");
            }
            _html.Append("<td>").Append(E(Time(e.OccurredAt))).Append("</td></tr>\n");
        }
        _html.Append("</tbody>\n</table>\n</section>\n");
    }

    private void OpenTable(string title, IReadOnlyList<ReportOpenFinding> items)
    {
        Heading(title, items.Count);
        if (items.Count == 0)
        {
            None();
            return;
        }
        _html.Append("<table>\n<thead><tr><th>").Append(E(T("col.check"))).Append("</th><th>").Append(E(T("col.subject")))
            .Append("</th><th>").Append(E(T("col.severity"))).Append("</th><th>").Append(E(T("col.status"))).Append("</th><th>")
            .Append(E(T("col.openedAt"))).Append("</th></tr></thead>\n<tbody>\n");
        foreach (var o in items)
        {
            _html.Append("<tr><td>").Append(E(Texts.Title(o.CheckId, _lang))).Append(" <span class=\"id\">").Append(E(o.CheckId))
                .Append("</span></td><td>").Append(E(SubjectText(o.Subject))).Append("</td><td>").Append(Severity(o.Severity))
                .Append("</td><td>").Append(E(T("workflow." + o.WorkflowState))).Append("</td><td>").Append(E(Time(o.OpenedAt)));
            if (o.NewInPeriod)
            {
                _html.Append(" <span class=\"tag\">").Append(E(T("newMarker"))).Append("</span>");
            }
            _html.Append("</td></tr>\n");
        }
        _html.Append("</tbody>\n</table>\n</section>\n");
    }

    private void Decisions()
    {
        _html.Append("<h3 class=\"group\">").Append(E(T("riskDecisions"))).Append("</h3>\n");
        foreach (var kind in new[] { "risk_accepted", "suppressed" })
        {
            var items = _s.Decisions.Where(d => d.Decision == kind).ToList();
            Heading(T(kind == "risk_accepted" ? "accepted" : "suppressed"), items.Count);
            if (items.Count == 0)
            {
                None();
                continue;
            }
            _html.Append("<table>\n<thead><tr><th>").Append(E(T("col.check"))).Append("</th><th>").Append(E(T("col.subject")))
                .Append("</th><th>").Append(E(T("col.reason"))).Append("</th><th>").Append(E(T("col.reviewAt"))).Append("</th><th>")
                .Append(E(T("col.decidedBy"))).Append("</th></tr></thead>\n<tbody>\n");
            foreach (var d in items)
            {
                _html.Append("<tr><td>").Append(E(Texts.Title(d.CheckId, _lang))).Append(" <span class=\"id\">").Append(E(d.CheckId))
                    .Append("</span></td><td>").Append(E(SubjectText(d.Subject))).Append("</td><td class=\"text\">")
                    .Append(E(d.Reason ?? "—")).Append("</td><td>").Append(E(Time(d.ReviewAt))).Append("</td><td>")
                    .Append(E(d.DecidedBy ?? "—")).Append(", ").Append(E(Time(d.DecidedAt)));
                if (d.InPeriod)
                {
                    _html.Append(" <span class=\"tag\">").Append(E(T("newMarker"))).Append("</span>");
                }
                _html.Append("</td></tr>\n");
            }
            _html.Append("</tbody>\n</table>\n</section>\n");
        }
    }

    private void OtherChanges()
    {
        _html.Append("<h3 class=\"group\">").Append(E(T("otherChanges"))).Append("</h3>\n<p class=\"note\">")
            .Append(E(T("otherChangesNote"))).Append("</p>\n");
        EventTable(T("ruleChanges"), _s.Events.Where(e => e.Cause == "rule_change").ToList(), withEvent: true);
        EventTable(T("policyChanges"), _s.Events.Where(e => e.Cause == "policy_change").ToList(), withEvent: true);
        EventTable(T("becameNotApplicable"),
            _s.Events.Where(e => e.EventType == "resolved" && e.Cause == "applicability_change").ToList(), withEvent: false);
        EventTable(T("retired"), _s.Events.Where(e => e.EventType == "subject_retired").ToList(), withEvent: false);
    }

    private void Unavailable()
    {
        _html.Append("<h3 class=\"group\">").Append(E(T("unavailable"))).Append("</h3>\n");
        var modules = _s.LastRun?.Modules ?? [];
        Heading(T("modules"), modules.Count(m => m.Status != "available"));
        if (_s.LastRun is null)
        {
            None();
        }
        else
        {
            _html.Append("<p class=\"note\">").Append(E(T("lastCollection"))).Append(": ").Append(E(Time(_s.LastRun.CompletedAt)))
                .Append(", ").Append(E(T("run." + _s.LastRun.State)));
            if (_s.LastRun.FailureCode is not null)
            {
                _html.Append(" (").Append(E(T("runFailure." + _s.LastRun.FailureCode))).Append(')');
            }
            _html.Append("</p>\n<table>\n<thead><tr><th>").Append(E(T("col.module"))).Append("</th><th>")
                .Append(E(T("col.status"))).Append("</th></tr></thead>\n<tbody>\n");
            foreach (var module in modules)
            {
                _html.Append("<tr").Append(module.Status == "available" ? "" : " class=\"warn\"").Append("><td>")
                    .Append(E(T("module." + module.Module))).Append("</td><td>").Append(E(T("capability." + module.Status)))
                    .Append("</td></tr>\n");
            }
            _html.Append("</tbody>\n</table>\n</section>\n");
        }
        Heading(T("unavailableChecks"), _s.Unavailable.Sum(u => u.Count));
        if (_s.Unavailable.Count == 0)
        {
            None();
        }
        else
        {
            _html.Append("<table>\n<thead><tr><th>").Append(E(T("col.check"))).Append("</th><th>").Append(E(T("col.reason")))
                .Append("</th><th class=\"num\">").Append(E(T("col.count"))).Append("</th></tr></thead>\n<tbody>\n");
            foreach (var u in _s.Unavailable)
            {
                _html.Append("<tr><td>").Append(E(Texts.Title(u.CheckId, _lang))).Append(" <span class=\"id\">").Append(E(u.CheckId))
                    .Append("</span></td><td>").Append(E(T("reason." + (u.ReasonCode ?? "none")))).Append("</td><td class=\"num\">")
                    .Append(u.Count).Append("</td></tr>\n");
            }
            _html.Append("</tbody>\n</table>\n</section>\n");
        }
        Heading(T("runs"), _s.Runs.Sum(r => r.Count));
        if (_s.Runs.Count == 0)
        {
            None();
            return;
        }
        _html.Append("<table>\n<thead><tr><th>").Append(E(T("col.state"))).Append("</th><th class=\"num\">")
            .Append(E(T("col.count"))).Append("</th></tr></thead>\n<tbody>\n");
        foreach (var run in _s.Runs)
        {
            _html.Append("<tr><td>").Append(E(T("run." + run.State)));
            if (run.FailureCode is not null)
            {
                _html.Append(" (").Append(E(T("runFailure." + run.FailureCode))).Append(')');
            }
            _html.Append("</td><td class=\"num\">").Append(run.Count).Append("</td></tr>\n");
        }
        _html.Append("</tbody>\n</table>\n</section>\n");
    }

    private void CoverageSection()
    {
        var c = _s.Coverage;
        _html.Append("<section>\n<h3>").Append(E(T("coverage"))).Append("</h3>\n<dl class=\"facts\">");
        Pair(T("coveragePeriod"), Percent(c.CoveragePeriod));
        Pair(T("coverageAt"), Percent(c.CoverageAt));
        Pair(T("compliance"), Percent(c.Compliance));
        Pair(T("staleShare"), Percent(c.StaleShare));
        Pair(T("pairs"), c.Pairs.ToString(CultureInfo.InvariantCulture));
        Pair(T("countUnknown"), c.Unknown.ToString(CultureInfo.InvariantCulture));
        Pair(T("countStale"), c.Stale.ToString(CultureInfo.InvariantCulture));
        Pair(T("countNoData"), c.NoData.ToString(CultureInfo.InvariantCulture));
        Pair(T("countInformational"), c.Informational.ToString(CultureInfo.InvariantCulture));
        Pair(T("countNotApplicable"), c.NotApplicable.ToString(CultureInfo.InvariantCulture));
        Pair(T("countNotConfigured"), c.NotConfigured.ToString(CultureInfo.InvariantCulture));
        Pair(T("measuredAt"), Time(c.At));
        Pair(T("source"), "Microsoft Graph");
        _html.Append("</dl>\n<p class=\"note\">").Append(E(T("coverageNote"))).Append("</p>\n</section>\n");
    }

    private const string Style = """

        :root { --ink: #1d2433; --muted: #5b6475; --line: #d9dee7; --bad: #b42318; --warn: #b54708; --good: #067647; --bg: #f6f8fb; }
        * { box-sizing: border-box; }
        body { margin: 0 auto; max-width: 980px; padding: 24px 16px 48px; color: var(--ink); background: #fff;
               font: 14px/1.5 -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
        header { border-bottom: 2px solid var(--ink); padding-bottom: 12px; margin-bottom: 20px; }
        .brand { margin: 0; font-size: 12px; letter-spacing: .12em; text-transform: uppercase; color: var(--muted); }
        h1 { margin: 4px 0 0; font-size: 26px; }
        .org { margin: 2px 0 10px; font-size: 18px; font-weight: 600; }
        h2 { margin: 32px 0 8px; font-size: 20px; border-bottom: 1px solid var(--line); padding-bottom: 4px; }
        h3 { margin: 20px 0 6px; font-size: 15px; }
        h3.group { margin-top: 28px; font-size: 16px; }
        .count { display: inline-block; min-width: 22px; padding: 0 6px; border-radius: 10px; background: var(--bg);
                 border: 1px solid var(--line); font-size: 12px; text-align: center; color: var(--muted); }
        dl.meta, dl.facts { display: grid; grid-template-columns: max-content 1fr; gap: 2px 16px; margin: 0; }
        dt { color: var(--muted); }
        dd { margin: 0; overflow-wrap: anywhere; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin: 8px 0 4px; }
        .card { border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; background: var(--bg); }
        .card .value { font-size: 22px; font-weight: 700; }
        .card .label { color: var(--muted); font-size: 12px; }
        .card.bad .value { color: var(--bad); }
        .card.good .value { color: var(--good); }
        table { width: 100%; border-collapse: collapse; margin: 4px 0 8px; }
        th, td { text-align: left; vertical-align: top; padding: 5px 8px; border-bottom: 1px solid var(--line); overflow-wrap: anywhere; }
        th { font-size: 12px; color: var(--muted); font-weight: 600; background: var(--bg); }
        td.num, th.num { text-align: right; white-space: nowrap; }
        td.text { white-space: pre-line; }
        tr.warn td { color: var(--warn); }
        .id { color: var(--muted); font-size: 11px; white-space: nowrap; }
        .sev { font-weight: 600; white-space: nowrap; }
        .sev-critical { color: var(--bad); }
        .sev-warning { color: var(--warn); }
        .tag { font-size: 11px; color: var(--muted); border: 1px solid var(--line); border-radius: 4px; padding: 0 4px; }
        .none, .note { color: var(--muted); margin: 2px 0 8px; }
        footer { margin-top: 36px; padding-top: 10px; border-top: 1px solid var(--line); color: var(--muted); font-size: 12px; }
        @page { size: A4; margin: 15mm; }
        @media print {
          body { max-width: none; padding: 0; font-size: 10pt; }
          .card { background: none; }
          th { background: none; }
          h2, h3 { break-after: avoid; }
          tr, .card { break-inside: avoid; }
        }

        """;
}
