using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Operations;
using Sikkerheit.Host.Organizations;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Reports;

public sealed record ReportDto(Guid Id, DateTimeOffset PeriodStart, DateTimeOffset PeriodEnd, string Timezone, string Language,
    string State, string Format, string? FailureCode)
{
    public static ReportDto From(Report r) =>
        new(r.Id, r.PeriodStart, r.PeriodEnd, r.Timezone, r.Language, r.State, r.Format, r.FailureCode);
}

public sealed record ReportCreateBody(DateTimeOffset PeriodStart, DateTimeOffset PeriodEnd, string Format);

/// <summary>listReports, createReport and downloadReport (05 «API портала», «Выдача файлов»).</summary>
public static class ReportEndpoints
{
    public const string ContentSecurityPolicy = "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:";

    public static void Map(IEndpointRouteBuilder app)
    {
        var org = app.MapGroup("/api/v1/organizations/{organizationId:guid}");
        org.MapGet("/reports", List).RequireStaff(StaffRoles.All);
        org.MapPost("/reports", Create).RequireStaff(StaffRoles.Work);
        org.MapGet("/reports/{reportId:guid}/download", Download).RequireStaff(StaffRoles.All);
    }

    private static async Task<IResult> List(Guid organizationId, DbScopes scopes, Cursors cursors, string? cursor,
        string? limit, CancellationToken ct)
    {
        var size = OrganizationEndpoints.Limit(limit);
        var position = cursors.Read(cursor, "listReports", organizationId, "");
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        await OrganizationEndpoints.RequireOrganizationAsync(scope, forUpdate: false, ct);
        var take = size + 1;
        var query = position is null
            ? scope.Db.Reports.FromSqlInterpolated($"""
                select * from report where organization_id = {organizationId}
                order by period_start desc, id desc limit {take}
                """)
            : scope.Db.Reports.FromSqlInterpolated($"""
                select * from report where organization_id = {organizationId}
                  and (period_start, id) < ({DateTimeOffset.Parse(position[0], CultureInfo.InvariantCulture).ToUniversalTime()},
                                            {Guid.Parse(position[1])})
                order by period_start desc, id desc limit {take}
                """);
        var rows = await query.AsNoTracking().ToListAsync(ct);
        string? next = null;
        if (rows.Count > size)
        {
            rows.RemoveAt(size);
            next = cursors.Create("listReports", organizationId, "",
                [rows[^1].PeriodStart.ToString("O", CultureInfo.InvariantCulture), rows[^1].Id.ToString()]);
        }
        return Results.Json(new Page<ReportDto>(rows.Select(ReportDto.From).ToList(), next), ApiJson.Options);
    }

    private static async Task<IResult> Create(Guid organizationId, HttpContext http, RequestBodies bodies, DbScopes scopes,
        TimeProvider clock, CancellationToken ct)
    {
        var actor = Actor.From(http.User);
        var body = (await bodies.ReadAsync<ReportCreateBody>(http, "ReportCreate")).Value;
        var now = clock.GetUtcNow();
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        var organization = await OrganizationEndpoints.RequireOrganizationAsync(scope, forUpdate: true, ct);
        OrganizationEndpoints.RequireActive(organization);
        var zone = TimeZoneInfo.FindSystemTimeZoneById(organization.Timezone);
        var start = body.PeriodStart.ToUniversalTime();
        var end = body.PeriodEnd.ToUniversalTime();
        if (!ReportPeriod.IsWeek(zone, start, end, out _))
        {
            throw new ApiProblemException(ProblemCodes.ValidationFailed,
                "periodStart and periodEnd must be Monday 00:00 of one ISO week in " + organization.Timezone);
        }
        if (end > now)
        {
            throw new ApiProblemException(ProblemCodes.ValidationFailed, "only a completed week can be reported");
        }
        var report = await ReportRequests.QueueAsync(scope, organization, start, end, actor.EntraUserId, now, ct);
        // Audit details are a closed contract (AuditEvent): report.create carries none.
        AuditLog.Staff(scope, actor, "report.create", "report", report.Id.ToString(), http.TraceIdentifier);
        await scope.Db.SaveChangesAsync(ct);
        await scope.CommitAsync(ct);
        return Results.Json(ReportDto.From(report), ApiJson.Options, statusCode: StatusCodes.Status202Accepted);
    }

    private static async Task Download(Guid organizationId, Guid reportId, HttpContext http, DbScopes scopes,
        ReportService reports, CancellationToken ct)
    {
        var actor = Actor.From(http.User);
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        await OrganizationEndpoints.RequireOrganizationAsync(scope, forUpdate: false, ct);
        var report = await scope.Db.Reports.AsNoTracking()
            .SingleOrDefaultAsync(r => r.OrganizationId == organizationId && r.Id == reportId, ct)
            ?? throw new ApiProblemException(ProblemCodes.NotFound);
        if (report.State != "ready")
        {
            throw new ApiProblemException(ProblemCodes.ResourceNotReady, "report is " + report.State);
        }
        var content = await reports.ContentAsync(report, ct);
        // Every read of a report is audited before the file leaves the service (04 «Аудит»).
        AuditLog.Staff(scope, actor, "report.download", "report", report.Id.ToString(), http.TraceIdentifier);
        await scope.Db.SaveChangesAsync(ct);
        await scope.CommitAsync(ct);
        var headers = http.Response.Headers;
        headers.ContentType = ReportService.ContentType;
        headers.ContentDisposition = $"attachment; filename=\"report-{report.Id}.html\"";
        headers.XContentTypeOptions = "nosniff";
        headers.ContentSecurityPolicy = ContentSecurityPolicy;
        headers.CacheControl = "private, no-store";
        http.Response.ContentLength = content.Length;
        await http.Response.Body.WriteAsync(content, ct);
    }
}
