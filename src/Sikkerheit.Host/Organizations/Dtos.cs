using System.Text.Json;
using Sikkerheit.Host.Data;

namespace Sikkerheit.Host.Organizations;

// Wire shapes of the OpenAPI components; contract tests validate every response against the schema.

public sealed record OrganizationDto(
    Guid Id, string Name, string Timezone, string ReportLanguage, string Status, DateTimeOffset? DeletionDueAt,
    DateTimeOffset CreatedAt)
{
    public static OrganizationDto From(Organization o) =>
        new(o.Id, o.Name, o.Timezone, o.ReportLanguage, o.Status, o.DeletionDueAt, o.CreatedAt);
}

public sealed record OrganizationOverviewDto(
    OrganizationDto Organization, string M365Status, DateTimeOffset? LastCollectedAt, int OpenCritical,
    int OpenWarning, int ActiveDevices, double? CoverageAt);

public sealed record OrganizationCreateBody(string Name, string Timezone, string ReportLanguage);

public sealed record OrganizationUpdateBody(string? Name, string? Timezone, string? ReportLanguage);

public sealed record LifecycleChangeBody(string Action, string Reason, Guid IdempotencyKey, bool? ExportWaived);

public sealed record LifecycleAuditDetails(string LifecycleAction, string Reason, bool ExportWaived);

public sealed record PolicyRevisionDto(
    int Version, DateTimeOffset EffectiveFrom, DateTimeOffset CreatedAt, Guid? CreatedBy, JsonElement Configuration)
{
    public static PolicyRevisionDto From(PolicyRevision r) =>
        new(r.Version, r.EffectiveFrom, r.CreatedAt, r.CreatedBy, JsonDocument.Parse(r.Configuration).RootElement.Clone());
}

public sealed record PolicyRevisionCreateBody(JsonElement Configuration);

public sealed record AuditEventDto(
    Guid Id, DateTimeOffset OccurredAt, string ActorType, Guid? ActorId, string Action, string TargetType,
    string TargetId, string Outcome, string CorrelationId, JsonElement? Details)
{
    public static AuditEventDto From(AuditEvent e) => new(
        e.Id, e.OccurredAt, e.ActorType, e.ActorId, e.Action, e.TargetType, e.TargetId, e.Outcome, e.CorrelationId,
        e.Details is null ? null : JsonDocument.Parse(e.Details).RootElement.Clone());
}
