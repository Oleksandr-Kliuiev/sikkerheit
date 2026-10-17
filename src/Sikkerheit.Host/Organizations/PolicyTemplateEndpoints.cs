using System.Globalization;
using System.Text.Json;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Organizations;

public static class PolicyTemplateEndpoints
{
    public static void Map(IEndpointRouteBuilder app)
    {
        var api = app.MapGroup("/api/v1/policy-templates");
        api.MapGet("", List).RequireStaff(StaffRoles.All);
        api.MapPost("", Create).RequireStaff(StaffRoles.AdminOnly);
        api.MapGet("/{templateId:guid}", Get).RequireStaff(StaffRoles.All);
        api.MapGet("/{templateId:guid}/revisions", History).RequireStaff(StaffRoles.All);
        api.MapPost("/{templateId:guid}/revisions", Revise).RequireStaff(StaffRoles.AdminOnly);
    }

    private static async Task<IResult> List(DbScopes scopes, Cursors cursors, string? cursor, string? limit,
        string? includeArchived, CancellationToken ct)
    {
        if (includeArchived is not (null or "true")) throw new ApiProblemException(ProblemCodes.SchemaViolation);
        var position = cursors.Read(cursor, "listPolicyTemplates", null, includeArchived ?? "");
        var size = OrganizationEndpoints.Limit(limit);
        await using var scope = await scopes.PlatformAsync(ct);
        var rows = await PolicyTemplateStore.ListAsync(scope, null, includeArchived == "true",
            position is null ? null : Guid.Parse(position[0]), null, size + 1, ct);
        string? next = null;
        if (rows.Count > size)
        {
            rows.RemoveAt(size);
            next = cursors.Create("listPolicyTemplates", null, includeArchived ?? "", [rows[^1].Id.ToString()]);
        }
        return Results.Json(new Page<PolicyTemplateDto>(rows, next), ApiJson.Options);
    }

    private static async Task<IResult> Get(Guid templateId, HttpContext http, DbScopes scopes, CancellationToken ct)
    {
        await using var scope = await scopes.PlatformAsync(ct);
        return Response(http, await PolicyTemplateStore.GetAsync(scope, templateId, false, ct), 200);
    }

    private static async Task<IResult> History(Guid templateId, DbScopes scopes, Cursors cursors,
        string? cursor, string? limit, CancellationToken ct)
    {
        var position = cursors.Read(cursor, "listPolicyTemplateRevisions", null, templateId.ToString());
        var size = OrganizationEndpoints.Limit(limit);
        await using var scope = await scopes.PlatformAsync(ct);
        _ = await PolicyTemplateStore.GetAsync(scope, templateId, false, ct);
        var rows = await PolicyTemplateStore.ListAsync(scope, templateId, true, null,
            position is null ? null : int.Parse(position[0], CultureInfo.InvariantCulture), size + 1, ct);
        string? next = null;
        if (rows.Count > size)
        {
            rows.RemoveAt(size);
            next = cursors.Create("listPolicyTemplateRevisions", null, templateId.ToString(), [rows[^1].Revision.ToString(CultureInfo.InvariantCulture)]);
        }
        return Results.Json(new Page<PolicyTemplateDto>(rows, next), ApiJson.Options);
    }

    private static async Task<IResult> Create(HttpContext http, RequestBodies bodies, DbScopes scopes,
        ContractSchemas schemas, PolicyRules defaults, TimeProvider clock, CancellationToken ct)
    {
        var body = (await bodies.ReadAsync<PolicyTemplateCreate>(http, "PolicyTemplateCreate")).Value;
        Validate(schemas, defaults, body.Name, body.Content);
        await using var scope = await scopes.PlatformAsync(ct);
        var dto = await PolicyTemplateStore.SaveAsync(scope, null, null, body.Name.Trim(), body.Description.Trim(),
            body.Content, false, Actor.From(http.User).EntraUserId, clock.GetUtcNow(), ct);
        await scope.CommitAsync(ct);
        return Response(http, dto, 201);
    }

    private static async Task<IResult> Revise(Guid templateId, HttpContext http, RequestBodies bodies, DbScopes scopes,
        ContractSchemas schemas, PolicyRules defaults, TimeProvider clock, CancellationToken ct)
    {
        var ifMatch = http.Request.Headers.IfMatch.ToString();
        if (ifMatch.Length == 0) throw new ApiProblemException(ProblemCodes.IfMatchRequired);
        var body = (await bodies.ReadAsync<PolicyTemplateRevisionCreate>(http, "PolicyTemplateRevisionCreate")).Value;
        Validate(schemas, defaults, body.Name, body.Content);
        await using var scope = await scopes.PlatformAsync(ct);
        var dto = await PolicyTemplateStore.SaveAsync(scope, templateId, ifMatch, body.Name.Trim(), body.Description.Trim(),
            body.Content, body.Archived, Actor.From(http.User).EntraUserId, clock.GetUtcNow(), ct);
        await scope.CommitAsync(ct);
        return Response(http, dto, 201);
    }

    private static void Validate(ContractSchemas schemas, PolicyRules defaults, string name, JsonElement content)
    {
        if (string.IsNullOrWhiteSpace(name)) throw new ApiProblemException(ProblemCodes.ValidationFailed);
        using var baseline = JsonDocument.Parse(defaults.DefaultConfiguration);
        _ = PolicyTemplateContent.Merge(schemas, baseline.RootElement, content);
    }

    private static IResult Response(HttpContext http, PolicyTemplateDto dto, int status)
    {
        http.Response.Headers.ETag = $"\"{dto.Revision}\"";
        return Results.Json(dto, ApiJson.Options, statusCode: status);
    }
}
