using System.Text.Json;

namespace Sikkerheit.Host.Organizations;

public sealed record PolicyTemplateDto(Guid Id, int Revision, string Name, string Description, JsonElement Content,
    bool Archived, DateTimeOffset CreatedAt, Guid CreatedBy);
public sealed record PolicyTemplateCreate(string Name, string Description, JsonElement Content);
public sealed record PolicyTemplateRevisionCreate(string Name, string Description, JsonElement Content, bool Archived);
public sealed record PolicyTemplatePreviewRequest(Guid[] OrganizationIds);
public sealed record PolicyTemplatePreviewItem(Guid OrganizationId, string? OrganizationName, string Status,
    int? PolicyVersion, JsonElement? Before, JsonElement? After, string? PreviewToken, string? ProblemCode);
public sealed record PolicyTemplatePreview(Guid TemplateId, int TemplateRevision, DateTimeOffset ExpiresAt,
    IReadOnlyList<PolicyTemplatePreviewItem> Items);
public sealed record PolicyTemplateApplyRequest(Guid TemplateId, int TemplateRevision, string PreviewToken);
public sealed record PolicyTemplateApplication(Guid TemplateId, int TemplateRevision, int PolicyVersion,
    DateTimeOffset AppliedAt, bool Replayed);
