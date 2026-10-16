using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;
using Sikkerheit.Host.Operations;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Reports;

/// <summary>
/// Generation of a queued report (job report_generate): immutable snapshot, HTML in the report language, file under the
/// organization prefix. A ready report is never rebuilt (external review F09); a lost file is rendered again from the
/// snapshot (06 «Восстановление»).
/// </summary>
public sealed class ReportService(DbScopes scopes, IFileStore files, TimeProvider clock, ILogger<ReportService> logger)
    : IJobHandler
{
    public const string ContentType = "text/html; charset=utf-8";

    public string Type => "report_generate";

    public static string FileKey(Guid organizationId, Guid reportId) => $"{organizationId}/{reportId}.html";

    public async Task ExecuteAsync(JobLease lease, CancellationToken ct)
    {
        var organizationId = lease.OrganizationId ?? throw new InvalidOperationException("report_generate needs an organization");
        var reportId = Guid.Parse(lease.InputId!);
        try
        {
            await GenerateAsync(lease, organizationId, reportId, ct);
        }
        catch (Exception error) when (error is not (JobLeaseLostException or OperationCanceledException) && lease.IsLastAttempt)
        {
            logger.LogError(error, "Report {ReportId} failed with generation_error", reportId);
            await using var scope = await scopes.OrganizationAsync(organizationId, ct);
            if (!await lease.HoldAsync(scope, ct))
            {
                throw new JobLeaseLostException();
            }
            await scope.Db.Reports.Where(r => r.OrganizationId == organizationId && r.Id == reportId && r.State == "queued")
                .ExecuteUpdateAsync(u => u.SetProperty(r => r.State, "failed").SetProperty(r => r.FailureCode, "generation_error"), ct);
            await lease.CompleteAsync(scope, ct);
            await scope.CommitAsync(ct);
        }
    }

    private async Task GenerateAsync(JobLease lease, Guid organizationId, Guid reportId, CancellationToken ct)
    {
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        if (!await lease.HoldAsync(scope, ct))
        {
            throw new JobLeaseLostException();
        }
        var report = await scope.Db.Reports
            .FromSqlInterpolated($"select * from report where organization_id = {organizationId} and id = {reportId} for update")
            .SingleOrDefaultAsync(ct);
        var organization = await scope.Db.Organizations.SingleOrDefaultAsync(o => o.Id == organizationId, ct);
        // Only active organizations run report jobs (05 «Жизненный цикл организации»); the report stays queued.
        if (report is not { State: "queued" } || organization is not { Status: "active" })
        {
            await lease.CompleteAsync(scope, ct);
            await scope.CommitAsync(ct);
            return;
        }
        var snapshot = await ReportBuilder.BuildAsync(scope, organization, report, clock.GetUtcNow(), ct);
        var missing = ReportHtml.MissingTranslations(snapshot);
        if (missing.Count > 0)
        {
            // No fallback language (05): the report fails, raises an alert and appears in the Teams digest.
            logger.LogError("Report {ReportId} failed with translation_missing: no {Language} text for {Checks}",
                report.Id, report.Language, string.Join(", ", missing));
            report.State = "failed";
            report.FailureCode = "translation_missing";
        }
        else
        {
            var key = FileKey(organizationId, report.Id);
            await files.PutAsync(FileContainers.Reports, key, Encoding.UTF8.GetBytes(ReportHtml.Render(snapshot)), ContentType, ct);
            report.State = "ready";
            report.FailureCode = null;
            report.BlobKey = key;
            report.Snapshot = JsonSerializer.Serialize(snapshot, ApiJson.Options);
            report.PolicyVersions = [.. snapshot.PolicyVersions];
        }
        await scope.Db.SaveChangesAsync(ct);
        await lease.CompleteAsync(scope, ct);
        await scope.CommitAsync(ct);
    }

    /// <summary>The HTML of a ready report; a missing file is rendered again from the stored snapshot.</summary>
    public async Task<byte[]> ContentAsync(Report report, CancellationToken ct)
    {
        var key = report.BlobKey ?? FileKey(report.OrganizationId, report.Id);
        if (await files.GetAsync(FileContainers.Reports, key, ct) is { } content)
        {
            return content;
        }
        var snapshot = JsonSerializer.Deserialize<ReportSnapshot>(report.Snapshot!, ApiJson.Options)!;
        logger.LogWarning("Report {ReportId} file was missing; rendered again from the snapshot", report.Id);
        content = Encoding.UTF8.GetBytes(ReportHtml.Render(snapshot));
        await files.PutAsync(FileContainers.Reports, key, content, ContentType, ct);
        return content;
    }
}

/// <summary>
/// weekly_report: the report of a completed week for an active organization, Monday 06:00 local time (02). Creates the
/// report row and queues report_generate; an existing report for the week and language is left as it is.
/// </summary>
public sealed class WeeklyReportJob(DbScopes scopes, TimeProvider clock) : IJobHandler
{
    public string Type => "weekly_report";

    public async Task ExecuteAsync(JobLease lease, CancellationToken ct)
    {
        var organizationId = lease.OrganizationId ?? throw new InvalidOperationException("weekly_report needs an organization");
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        if (!await lease.HoldAsync(scope, ct))
        {
            throw new JobLeaseLostException();
        }
        var organization = await scope.Db.Organizations
            .FromSqlInterpolated($"select * from organization where id = {organizationId} for update").SingleOrDefaultAsync(ct);
        var now = clock.GetUtcNow();
        if (organization is { Status: "active" } && ReportPeriod.TryParseKey(lease.PeriodKey, out var year, out var week))
        {
            var zone = TimeZoneInfo.FindSystemTimeZoneById(organization.Timezone);
            var (start, end) = ReportPeriod.Week(zone, year, week);
            if (end <= now && end > organization.CreatedAt)
            {
                await ReportRequests.QueueAsync(scope, organization, start, end, null, now, ct);
            }
        }
        await lease.CompleteAsync(scope, ct);
        await scope.CommitAsync(ct);
    }
}

/// <summary>One report per week and language (05 «API портала»): a repeat returns the existing one, a failed one is queued again.</summary>
public static class ReportRequests
{
    public static async Task<Report> QueueAsync(DbScope scope, Organization organization, DateTimeOffset start,
        DateTimeOffset end, Guid? requestedBy, DateTimeOffset now, CancellationToken ct)
    {
        var report = await scope.Db.Reports.SingleOrDefaultAsync(r => r.OrganizationId == organization.Id
            && r.PeriodStart == start && r.Language == organization.ReportLanguage, ct);
        if (report is null)
        {
            report = new Report
            {
                OrganizationId = organization.Id, Id = Guid.CreateVersion7(), PeriodStart = start, PeriodEnd = end,
                Timezone = organization.Timezone, Language = organization.ReportLanguage, Format = "html", State = "queued",
                CreatedAt = now, CreatedBy = requestedBy,
            };
            scope.Db.Reports.Add(report);
            await scope.Db.SaveChangesAsync(ct);
        }
        else if (report.State == "failed")
        {
            report.State = "queued";
            report.FailureCode = null;
            await scope.Db.SaveChangesAsync(ct);
        }
        if (report.State == "queued")
        {
            await JobQueue.RequeueAsync(scope, "report_generate", organization.Id, report.Id.ToString(), now, ct);
        }
        return report;
    }
}
