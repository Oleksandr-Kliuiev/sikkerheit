using Sikkerheit.Contracts;
using Sikkerheit.Host.Reports;

namespace Sikkerheit.UnitTests.Reports;

/// <summary>The report HTML: self-contained, escaped, one language; labels exist for every closed value.</summary>
public sealed class ReportHtmlTests
{
    private static readonly DateTimeOffset Start = DateTimeOffset.Parse("2026-10-04T22:00:00Z");
    private static readonly DateTimeOffset End = DateTimeOffset.Parse("2026-10-11T22:00:00Z");

    private static ReportSnapshot Snapshot(string language, string organization = "Fjord AS", string? reason = "Kompenserende tiltak",
        string checkId = "M365-001", string subjectName = "kari@fjord.example")
    {
        var subject = new ReportSubject("user", Guid.NewGuid().ToString(), subjectName);
        var tenant = new ReportSubject("tenant", Guid.NewGuid().ToString(), null);
        var finding = Guid.NewGuid();
        var coverage = new CoverageResult(End, 2, 10, 6, 3, 1, 0, 0, 2, 1, 0, 0.9, 6.0 / 9, 0.1, 10, 9, 0.9, []);
        return new ReportSnapshot(ReportSnapshot.CurrentVersion, Guid.NewGuid(), Guid.NewGuid(), organization, "Europe/Oslo",
            language, "2026-W41", Start, End, End.AddHours(8), [1, 2],
            new ReportConnection("active", Guid.NewGuid(), "Fjord AS", "fjord.example", false, End.AddHours(-3)),
            new ReportLastRun("partial", null, End.AddHours(-3),
                Catalog.GraphModules.Select(m => new ReportModule(m, m == "conditional_access" ? "license_missing" : "available")).ToList()),
            [new ReportRunCount("completed", null, 6), new ReportRunCount("failed", "temporary_error", 1)],
            [
                new ReportEvent(finding, checkId, subject, "opened", "source_change", "warning", Start.AddDays(1)),
                new ReportEvent(Guid.NewGuid(), "M365-003", tenant, "resolved", "source_change", "critical", Start.AddDays(2)),
                new ReportEvent(Guid.NewGuid(), "M365-005", tenant, "policy_changed", "policy_change", "warning", Start.AddDays(3)),
                new ReportEvent(Guid.NewGuid(), "M365-001", subject, "subject_retired", "source_change", "warning", Start.AddDays(4)),
            ],
            [
                new ReportOpenFinding(finding, checkId, subject, "warning", "risk_accepted", Start.AddDays(1), true),
                new ReportOpenFinding(Guid.NewGuid(), "M365-002", subject, "critical", "in_progress", Start.AddDays(-20), false),
            ],
            [new ReportDecision(finding, checkId, subject, "risk_accepted", reason, End.AddDays(60), "Ola Tekniker", Start.AddDays(2), true)],
            [new ReportUnavailable("M365-003", "license_missing", 1), new ReportUnavailable("M365-001", null, 2)],
            coverage, DetailsExpired: true);
    }

    [Theory]
    [InlineData("nb", "Sikkerhetsrapport", "Aksepterte risikoer")]
    [InlineData("nn", "Sikkerheitsrapport", "Aksepterte risikoar")]
    [InlineData("en", "Security report", "Accepted risks")]
    public void Renders_every_section_in_one_language(string language, string title, string accepted)
    {
        var html = ReportHtml.Render(Snapshot(language));
        Assert.StartsWith($"<!doctype html>\n<html lang=\"{language}\">", html, StringComparison.Ordinal);
        Assert.Contains(title, html, StringComparison.Ordinal);
        Assert.Contains(accepted, html, StringComparison.Ordinal);
        Assert.Contains("default-src 'none'", html, StringComparison.Ordinal);
        Assert.Contains("@media print", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("src=", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("href=", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("://", html, StringComparison.Ordinal);
        Assert.Matches(language == "en" ? @"90\.0%" : @"90,0(&#xA0;|\u00A0)%", html);
    }

    [Fact]
    public void Untrusted_text_is_escaped_and_bidi_controls_are_replaced()
    {
        var html = ReportHtml.Render(Snapshot("nb", organization: "<img src=x onerror=alert(1)>",
            reason: "</td><script>alert(1)</script>\u202Egnp.exe", subjectName: "\"><svg onload=alert(1)>"));
        Assert.DoesNotContain("<img", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<script", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<svg", html, StringComparison.Ordinal);
        Assert.DoesNotContain("\u202E", html, StringComparison.Ordinal);
        Assert.Contains("&lt;script&gt;", html, StringComparison.Ordinal);
        Assert.Contains("\uFFFDgnp.exe", html, StringComparison.Ordinal);
    }

    [Fact]
    public void A_check_without_texts_in_the_language_is_a_missing_translation()
    {
        Assert.Empty(ReportHtml.MissingTranslations(Snapshot("nn")));
        Assert.Equal(["M365-999"], ReportHtml.MissingTranslations(Snapshot("nn", checkId: "M365-999")));
    }

    [Fact]
    public void Labels_cover_every_closed_value_the_report_shows()
    {
        var keys = Catalog.ReasonCodes.Select(r => "reason." + r)
            .Concat(Catalog.GraphModules.Select(m => "module." + m))
            .Concat(Catalog.CapabilityStatuses.Select(c => "capability." + c))
            .Concat(Catalog.WorkflowStates.Select(w => "workflow." + w))
            .Concat(new[] { "not_connected", "consent_pending", "active", "disconnected" }.Select(c => "connection." + c))
            .Concat(new[] { "queued", "running", "completed", "partial", "failed" }.Select(s => "run." + s))
            .Concat(new[] { "consent_missing", "tenant_mismatch", "credential_error", "cancelled", "run_timeout", "temporary_error" }
                .Select(f => "runFailure." + f))
            .Concat(new[] { "opened", "reopened", "resolved", "policy_changed", "subject_retired" }.Select(e => "event." + e))
            .Concat(["severity.critical", "severity.warning", "reason.none"]);
        Assert.All(keys, key => Assert.True(ReportTexts.Has(key), key));
        Assert.All(ReportTexts.Keys, key => Assert.All(Catalog.Languages,
            language => Assert.False(string.IsNullOrWhiteSpace(ReportTexts.Get(key, language)), key + "/" + language)));
    }
}
