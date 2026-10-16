using System.Text.Json;
using Sikkerheit.Host.Access;
using Sikkerheit.Host.Assessment;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.M365;
using Sikkerheit.Host.Organizations;

namespace Sikkerheit.Host.Reports;

public sealed record ReportSubject(string Type, string Key, string? Name);

public sealed record ReportEvent(Guid FindingId, string CheckId, ReportSubject Subject, string EventType, string Cause,
    string Severity, DateTimeOffset OccurredAt);

public sealed record ReportOpenFinding(Guid FindingId, string CheckId, ReportSubject Subject, string Severity,
    string WorkflowState, DateTimeOffset OpenedAt, bool NewInPeriod);

public sealed record ReportDecision(Guid FindingId, string CheckId, ReportSubject Subject, string Decision, string? Reason,
    DateTimeOffset? ReviewAt, string? DecidedBy, DateTimeOffset DecidedAt, bool InPeriod);

public sealed record ReportConnection(string Status, Guid? TenantId, string? DisplayName, string? PrimaryDomain, bool? EntraP1,
    DateTimeOffset? LastCollectedAt);

public sealed record ReportModule(string Module, string Status);

public sealed record ReportLastRun(string State, string? FailureCode, DateTimeOffset? CompletedAt, IReadOnlyList<ReportModule> Modules);

public sealed record ReportRunCount(string State, string? FailureCode, int Count);

public sealed record ReportUnavailable(string CheckId, string? ReasonCode, int Count);

/// <summary>
/// Immutable basis of a report (external review F08): pairs and results, events, decisions, policy versions and the
/// connection state at generation. The HTML is rendered from it; a ready report is never rebuilt.
/// </summary>
public sealed record ReportSnapshot(
    int SnapshotVersion, Guid ReportId, Guid OrganizationId, string OrganizationName, string Timezone, string Language,
    string IsoWeek, DateTimeOffset PeriodStart, DateTimeOffset PeriodEnd, DateTimeOffset GeneratedAt,
    IReadOnlyList<int> PolicyVersions, ReportConnection Connection, ReportLastRun? LastRun, IReadOnlyList<ReportRunCount> Runs,
    IReadOnlyList<ReportEvent> Events, IReadOnlyList<ReportOpenFinding> OpenAtEnd, IReadOnlyList<ReportDecision> Decisions,
    IReadOnlyList<ReportUnavailable> Unavailable, CoverageResult Coverage, bool DetailsExpired)
{
    public const int CurrentVersion = 1;

    public IEnumerable<string> CheckIds =>
        Events.Select(e => e.CheckId).Concat(OpenAtEnd.Select(o => o.CheckId)).Concat(Decisions.Select(d => d.CheckId))
            .Concat(Unavailable.Select(u => u.CheckId)).Distinct(StringComparer.Ordinal);
}

/// <summary>Reads everything a weekly report needs for [periodStart, periodEnd) in the organization scope.</summary>
public static class ReportBuilder
{
    public static readonly TimeSpan EvidenceRetention = TimeSpan.FromDays(90);

    public static async Task<ReportSnapshot> BuildAsync(DbScope scope, Organization organization, Report report,
        DateTimeOffset now, CancellationToken ct)
    {
        var org = organization.Id;
        var start = report.PeriodStart;
        var end = report.PeriodEnd;
        var zone = TimeZoneInfo.FindSystemTimeZoneById(report.Timezone);
        var (year, week) = ReportPeriod.WeekOf(zone, start);
        var coverage = await Coverage.PeriodAsync(scope, org, start, end, ct);
        var connection = await ConnectionAsync(scope, org, end, ct);
        var events = await EventsAsync(scope, org, start, end, ct);
        var open = await OpenAtEndAsync(scope, org, start, end, ct);
        var decisions = await DecisionsAsync(scope, org, start, end, open, ct);
        var unavailable = coverage.Rows
            .Where(r => r.ActiveAtEnd && ((r.Category == "required" && r.Result is null or "unknown")
                                          || (r.Category == "informational" && r.ReasonCode is not null)))
            .GroupBy(r => (r.CheckId, r.ReasonCode))
            .Select(g => new ReportUnavailable(g.Key.CheckId, g.Key.ReasonCode, g.Count()))
            .OrderBy(u => u.CheckId, StringComparer.Ordinal).ThenBy(u => u.ReasonCode, StringComparer.Ordinal).ToList();
        return new ReportSnapshot(ReportSnapshot.CurrentVersion, report.Id, org, organization.Name, report.Timezone,
            report.Language, ReportPeriod.Key(year, week), start, end, now,
            await PolicyVersionsAsync(scope, org, start, end, ct), connection, await LastRunAsync(scope, org, end, ct),
            await RunsAsync(scope, org, start, end, ct), events, open, decisions, unavailable, coverage,
            now - end > EvidenceRetention);
    }

    private static ReportSubject Subject(FindingSubject subject) => new(subject.Type, subject.Key, subject.Name);

    private static async Task<IReadOnlyList<int>> PolicyVersionsAsync(DbScope scope, Guid org, DateTimeOffset start,
        DateTimeOffset end, CancellationToken ct)
    {
        var (atStart, _) = await Policies.AtAsync(scope, org, start, ct);
        var versions = new List<int> { atStart };
        foreach (var version in await Policies.VersionsInPeriodAsync(scope, org, start, end, ct))
        {
            if (!versions.Contains(version))
            {
                versions.Add(version);
            }
        }
        return versions;
    }

    private static async Task<ReportConnection> ConnectionAsync(DbScope scope, Guid org, DateTimeOffset end, CancellationToken ct)
    {
        if (await TenantConnections.FindAsync(scope, org, ct) is not { } connection)
        {
            return new ReportConnection("not_connected", null, null, null, null, null);
        }
        return new ReportConnection(connection.Status, connection.EntraTenantId, connection.TenantDisplayName,
            connection.PrimaryDomain, connection.EntraP1, await CollectionRuns.LastCollectedBeforeAsync(scope, org, end, ct));
    }

    private static async Task<ReportLastRun?> LastRunAsync(DbScope scope, Guid org, DateTimeOffset end, CancellationToken ct)
    {
        if (await CollectionRuns.LastFinishedBeforeAsync(scope, org, end, ct) is not { } run)
        {
            return null;
        }
        using var capabilities = JsonDocument.Parse(run.Capabilities);
        var modules = capabilities.RootElement.EnumerateArray()
            .Select(m => new ReportModule(m.GetProperty("module").GetString()!, m.GetProperty("status").GetString()!)).ToList();
        return new ReportLastRun(run.State, run.FailureCode, run.CompletedAt, modules);
    }

    private static async Task<IReadOnlyList<ReportRunCount>> RunsAsync(DbScope scope, Guid org, DateTimeOffset start,
        DateTimeOffset end, CancellationToken ct) =>
        (await CollectionRuns.CountsAsync(scope, org, start, end, ct))
        .Select(r => new ReportRunCount(r.State, r.FailureCode, r.Count)).ToList();

    private static async Task<IReadOnlyList<ReportEvent>> EventsAsync(DbScope scope, Guid org, DateTimeOffset start,
        DateTimeOffset end, CancellationToken ct) =>
        (await FindingHistory.StateEventsAsync(scope, org, start, end, ct))
        .Select(e => new ReportEvent(e.FindingId, e.CheckId, Subject(e.Subject), e.EventType, e.Cause, e.Severity, e.OccurredAt))
        .ToList();

    /// <summary>Findings open at periodEnd, reconstructed from events: state, workflow and severity before the end.</summary>
    private static async Task<IReadOnlyList<ReportOpenFinding>> OpenAtEndAsync(DbScope scope, Guid org, DateTimeOffset start,
        DateTimeOffset end, CancellationToken ct) =>
        (await FindingHistory.OpenAtAsync(scope, org, end, ct))
        .Select(o => new ReportOpenFinding(o.FindingId, o.CheckId, Subject(o.Subject), o.Severity, o.WorkflowState, o.OpenedAt,
            o.OpenedAt >= start))
        .ToList();

    /// <summary>Risk decisions in force at periodEnd for findings open at the end (accepted and suppressed apart).</summary>
    private static async Task<IReadOnlyList<ReportDecision>> DecisionsAsync(DbScope scope, Guid org, DateTimeOffset start,
        DateTimeOffset end, IReadOnlyList<ReportOpenFinding> open, CancellationToken ct)
    {
        var workflow = open.ToDictionary(o => o.FindingId, o => o.WorkflowState);
        var inForce = (await RiskDecisions.LatestBeforeAsync(scope, org, end, ct))
            .Where(d => d.Decision is "risk_accepted" or "suppressed" && workflow.GetValueOrDefault(d.FindingId) == d.Decision
                        && !(d.ReviewAt <= end))
            .ToList();
        var names = await StaffDirectory.NamesAsync(scope, inForce.Select(d => d.DecidedBy).Distinct().ToList(), ct);
        return inForce
            .Select(d => new ReportDecision(d.FindingId, d.CheckId, Subject(d.Subject), d.Decision, d.Reason, d.ReviewAt,
                names.GetValueOrDefault(d.DecidedBy), d.DecidedAt, d.DecidedAt >= start))
            .OrderBy(d => d.CheckId, StringComparer.Ordinal).ThenBy(d => d.Subject.Name ?? d.Subject.Key, StringComparer.Ordinal)
            .ToList();
    }
}
