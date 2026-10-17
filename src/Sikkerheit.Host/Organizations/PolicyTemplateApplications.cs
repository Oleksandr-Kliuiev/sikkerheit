using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Operations;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Organizations;

/// <summary>Stateless signed previews; per-client atomic writes and durable retry receipts.</summary>
public static class PolicyTemplateApplications
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(30);
    private const string TokenOperation = "applyPolicyTemplate";

    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapPost("/api/v1/policy-templates/{templateId:guid}/preview", Preview).RequireStaff(StaffRoles.AdminOnly);
        app.MapPost("/api/v1/organizations/{organizationId:guid}/policy-template-applications", Apply).RequireStaff(StaffRoles.AdminOnly);
    }

    private static string Filter(Guid template, int revision, Guid actor) => $"{template}:{revision}:{actor}";

    private static async Task<IResult> Preview(Guid templateId, HttpContext http, RequestBodies bodies, DbScopes scopes,
        ContractSchemas schemas, Cursors tokens, TimeProvider clock, CancellationToken ct)
    {
        var body = (await bodies.ReadAsync<PolicyTemplatePreviewRequest>(http, "PolicyTemplatePreviewRequest")).Value;
        PolicyTemplateDto template;
        await using (var platform = await scopes.PlatformAsync(ct)) template = await PolicyTemplateStore.GetAsync(platform, templateId, false, ct);
        PolicyTemplateStore.RequireVersion(http.Request.Headers.IfMatch.ToString(), template.Revision);
        if (template.Archived) throw new ApiProblemException(ProblemCodes.ValidationFailed, "template is archived");
        var expires = clock.GetUtcNow().Add(Lifetime);
        var actor = Actor.From(http.User).EntraUserId;
        var items = new List<PolicyTemplatePreviewItem>();
        foreach (var org in body.OrganizationIds)
        {
            string? name = null;
            try
            {
                await using var scope = await scopes.OrganizationSnapshotAsync(org, ct);
                var organization = await OrganizationEndpoints.RequireOrganizationAsync(scope, false, ct);
                name = organization.Name;
                OrganizationEndpoints.RequireActive(organization);
                var current = (await Policies.CurrentAsync(scope, ct))!;
                using var document = JsonDocument.Parse(current.Configuration);
                var before = document.RootElement.Clone();
                var after = PolicyTemplateContent.Merge(schemas, before, template.Content);
                var unchanged = PolicyTemplateContent.Hash(before) == PolicyTemplateContent.Hash(after);
                var token = unchanged ? null : tokens.Create(TokenOperation, org, Filter(templateId, template.Revision, actor),
                    [current.Version.ToString(CultureInfo.InvariantCulture), PolicyTemplateContent.Hash(after),
                     expires.ToString("O", CultureInfo.InvariantCulture), Guid.NewGuid().ToString()]);
                items.Add(new(org, name, unchanged ? "unchanged" : "ready", current.Version, before, after, token, null));
            }
            catch (ApiProblemException error)
            {
                items.Add(new(org, name, "unavailable", null, null, null, null, error.Code));
            }
        }
        http.Response.Headers.ETag = $"\"{template.Revision}\"";
        return Results.Json(new PolicyTemplatePreview(templateId, template.Revision, expires, items), ApiJson.Options);
    }

    private static async Task<IResult> Apply(Guid organizationId, HttpContext http, RequestBodies bodies, DbScopes scopes,
        ContractSchemas schemas, Cursors tokens, TimeProvider clock, CancellationToken ct)
    {
        var body = (await bodies.ReadAsync<PolicyTemplateApplyRequest>(http, "PolicyTemplateApplyRequest")).Value;
        var actor = Actor.From(http.User);
        var position = tokens.Read(body.PreviewToken, TokenOperation, organizationId,
            Filter(body.TemplateId, body.TemplateRevision, actor.EntraUserId));
        if (position is not { Count: 4 }) throw new ApiProblemException(ProblemCodes.InvalidCursor);
        var viewedVersion = int.Parse(position[0], CultureInfo.InvariantCulture);
        PolicyTemplateStore.RequireVersion(http.Request.Headers.IfMatch.ToString(), viewedVersion);
        var tokenHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(body.PreviewToken)));
        await using var scope = await scopes.OrganizationAsync(organizationId, ct);
        var organization = await OrganizationEndpoints.RequireOrganizationAsync(scope, true, ct);
        OrganizationEndpoints.RequireActive(organization);
        // Locking the organization serializes concurrent retries as well as every other policy writer.
        if (await PolicyTemplateReceipts.ReadAsync(scope, tokenHash, ct) is { } receipt) return Results.Json(receipt, ApiJson.Options);
        if (clock.GetUtcNow() >= DateTimeOffset.Parse(position[2], CultureInfo.InvariantCulture))
            throw new ApiProblemException(ProblemCodes.ValidationFailed, "preview expired; review again");
        var template = await PolicyTemplateStore.GetAsync(scope, body.TemplateId, true, ct);
        PolicyTemplateStore.RequireVersion($"\"{body.TemplateRevision}\"", template.Revision);
        if (template.Archived) throw new ApiProblemException(ProblemCodes.ValidationFailed, "template is archived");
        var current = (await Policies.CurrentAsync(scope, ct))!;
        PolicyTemplateStore.RequireVersion($"\"{viewedVersion}\"", current.Version);
        using var document = JsonDocument.Parse(current.Configuration);
        var after = PolicyTemplateContent.Merge(schemas, document.RootElement, template.Content);
        if (PolicyTemplateContent.Hash(after) != position[1]) throw new ApiProblemException(ProblemCodes.RevisionMismatch);
        var now = clock.GetUtcNow();
        var revision = await PolicyWriting.CreateAsync(scope, organization, http.Request.Headers.IfMatch.ToString(),
            after, actor, http.TraceIdentifier, now, ct);
        var result = new PolicyTemplateApplication(body.TemplateId, body.TemplateRevision, revision.Version, now, false);
        await scope.Db.SaveChangesAsync(ct);
        await PolicyTemplateReceipts.InsertAsync(scope, tokenHash, actor.EntraUserId, result, ct);
        AuditLog.Staff(scope, actor, "policy.template_apply", "policy_template", body.TemplateId.ToString(), http.TraceIdentifier,
            new { body.TemplateId, body.TemplateRevision, PolicyVersion = revision.Version });
        await scope.CommitAsync(ct);
        return Results.Json(result, ApiJson.Options);
    }
}
