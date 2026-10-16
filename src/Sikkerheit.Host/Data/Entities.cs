namespace Sikkerheit.Host.Data;

// Persistence model of 05 «Сущности и ограничения». JSON columns are kept as raw jsonb strings.

public sealed class StaffUser
{
    public Guid EntraUserId { get; set; }
    public string? DisplayName { get; set; }
    public string[] Roles { get; set; } = [];
    public DateTimeOffset? LastSignInAt { get; set; }
    public bool LastRefreshOk { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; }
}

public sealed class StaffSession
{
    public string IdHash { get; set; } = "";
    public Guid EntraUserId { get; set; }
    public string[] Roles { get; set; } = [];
    public string CsrfToken { get; set; } = "";
    public byte[]? TokenCache { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset LastSeenAt { get; set; }
    public DateTimeOffset RefreshDueAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
}

public sealed class OrganizationTombstone
{
    public Guid Id { get; set; }
    public DateTimeOffset DeletedAt { get; set; }
}

public sealed class Job
{
    public Guid Id { get; set; }
    public string Type { get; set; } = "";
    public Guid? OrganizationId { get; set; }
    public string? InputId { get; set; }
    public string? PeriodKey { get; set; }
    public string State { get; set; } = "queued";
    public string? LeaseOwner { get; set; }
    public long LeaseToken { get; set; }
    public DateTimeOffset? LeaseUntil { get; set; }
    public int Attempts { get; set; }
    public DateTimeOffset NextAttemptAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }
    public string? LastError { get; set; }
}

public sealed class Organization
{
    public Guid Id { get; set; }
    public string Name { get; set; } = "";
    public string Timezone { get; set; } = "";
    public string ReportLanguage { get; set; } = "nb";
    public string Status { get; set; } = "active";
    public DateTimeOffset? DeletionDueAt { get; set; }
    public DateTimeOffset? DisabledAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public int NextPolicyVersion { get; set; } = 2;
}

public sealed class PolicyRevision
{
    public Guid OrganizationId { get; set; }
    public int Version { get; set; }
    public DateTimeOffset EffectiveFrom { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public Guid? CreatedBy { get; set; }
    public string Configuration { get; set; } = "{}";
}

public sealed class TenantConnection
{
    public Guid OrganizationId { get; set; }
    public string Status { get; set; } = "not_connected";
    public Guid? EntraTenantId { get; set; }
    public string? TenantDisplayName { get; set; }
    public string? PrimaryDomain { get; set; }
    public Guid? PendingTenantId { get; set; }
    public DateTimeOffset? PendingExpiresAt { get; set; }
    public bool AllowCompanyTenant { get; set; }
    public bool? EntraP1 { get; set; }
    public DateTimeOffset? ConnectedAt { get; set; }
    public Guid? ConnectedBy { get; set; }
    public DateTimeOffset? DisconnectedAt { get; set; }
    public DateTimeOffset? LastCollectedAt { get; set; }
    public string? LastCollectionState { get; set; }
    public string Capabilities { get; set; } = "[]";
}

public sealed class IdempotencyRecord
{
    public Guid OrganizationId { get; set; }
    public string OperationId { get; set; } = "";
    public Guid Key { get; set; }
    public string RequestHash { get; set; } = "";
    public int ResponseStatus { get; set; }
    public string? ResultId { get; set; }
    public string? ResponseBody { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
}

public sealed class CollectionRun
{
    public Guid OrganizationId { get; set; }
    public Guid Id { get; set; }
    public string Trigger { get; set; } = "scheduled";
    public string State { get; set; } = "queued";
    public DateTimeOffset QueuedAt { get; set; }
    public DateTimeOffset? StartedAt { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }
    public string? FailureCode { get; set; }
    public string Capabilities { get; set; } = "[]";
    public bool UsersComplete { get; set; }
    public bool? EntraP1 { get; set; }
    public int? PolicyVersion { get; set; }
}

public sealed class Subject
{
    public Guid OrganizationId { get; set; }
    public Guid Id { get; set; }
    public string Type { get; set; } = "";
    public string Key { get; set; } = "";
    public string? DisplayName { get; set; }
    public Guid? DeviceId { get; set; }
    public DateTimeOffset FirstSeenAt { get; set; }
    public DateTimeOffset LastSeenAt { get; set; }
    public DateTimeOffset? RetiredAt { get; set; }
}

public sealed class Observation
{
    public Guid OrganizationId { get; set; }
    public Guid Id { get; set; }
    public Guid SubjectId { get; set; }
    public string CheckId { get; set; } = "";
    public string Source { get; set; } = "graph";
    public Guid? ScanBatchId { get; set; }
    public Guid? CollectionRunId { get; set; }
    public Guid? InputObservationId { get; set; }
    public DateTimeOffset ObservedAt { get; set; }
    public DateTimeOffset ReceivedAt { get; set; }
    public string CollectionStatus { get; set; } = "collected";
    public string? Evidence { get; set; }
    public string? ReasonCode { get; set; }
}

public sealed class Assessment
{
    public Guid OrganizationId { get; set; }
    public Guid Id { get; set; }
    public Guid? ObservationId { get; set; }
    public Guid SubjectId { get; set; }
    public string CheckId { get; set; } = "";
    public string RuleId { get; set; } = "";
    public string RuleVersion { get; set; } = "";
    public int SourcePolicyVersion { get; set; }
    public int EvaluatedPolicyVersion { get; set; }
    public string AssessmentScope { get; set; } = "current";
    public string AssessmentMode { get; set; } = "assessed";
    public string? Result { get; set; }
    public string? Severity { get; set; }
    public string? ReasonCode { get; set; }
    public DateTimeOffset ObservedAt { get; set; }
    public DateTimeOffset ReceivedAt { get; set; }
    public DateTimeOffset EvaluatedAt { get; set; }
    public string BasisSnapshot { get; set; } = "{}";
    public string EvidenceAvailability { get; set; } = "available";
}

public sealed class Finding
{
    public Guid OrganizationId { get; set; }
    public Guid Id { get; set; }
    public Guid SubjectId { get; set; }
    public string CheckId { get; set; } = "";
    public string TechnicalState { get; set; } = "open";
    public string WorkflowState { get; set; } = "new";
    public string AssessmentResult { get; set; } = "fail";
    public string Severity { get; set; } = "warning";
    public string Quality { get; set; } = "fresh_fail";
    public Guid? LatestAssessmentId { get; set; }
    public DateTimeOffset? LatestObservedAt { get; set; }
    public Guid? AssigneeId { get; set; }
    public DateTimeOffset? DueAt { get; set; }
    public string? WorkflowReason { get; set; }
    public DateTimeOffset? ReviewAt { get; set; }
    public Guid? WorkflowDecidedBy { get; set; }
    public int Revision { get; set; } = 1;
    public DateTimeOffset OpenedAt { get; set; }
    public DateTimeOffset? ResolvedAt { get; set; }
}

public sealed class FindingEvent
{
    public Guid OrganizationId { get; set; }
    public Guid FindingId { get; set; }
    public Guid Id { get; set; }
    public string EventType { get; set; } = "";
    public string Cause { get; set; } = "";
    public Guid? AssessmentId { get; set; }
    public Guid? ActorId { get; set; }
    public string? FromWorkflowState { get; set; }
    public string? ToWorkflowState { get; set; }
    public DateTimeOffset OccurredAt { get; set; }
}

public sealed class Report
{
    public Guid OrganizationId { get; set; }
    public Guid Id { get; set; }
    public DateTimeOffset PeriodStart { get; set; }
    public DateTimeOffset PeriodEnd { get; set; }
    public string Timezone { get; set; } = "";
    public string Language { get; set; } = "nb";
    public string Format { get; set; } = "html";
    public string State { get; set; } = "queued";
    public string? FailureCode { get; set; }
    public string? BlobKey { get; set; }
    public int[] PolicyVersions { get; set; } = [];
    public string? Snapshot { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public Guid? CreatedBy { get; set; }
}

public sealed class RiskDecision
{
    public Guid OrganizationId { get; set; }
    public Guid Id { get; set; }
    public Guid FindingId { get; set; }
    public string Decision { get; set; } = "";
    public string? Reason { get; set; }
    public DateTimeOffset? ReviewAt { get; set; }
    public Guid DecidedBy { get; set; }
    public DateTimeOffset DecidedAt { get; set; }
    public Guid FindingEventId { get; set; }
}

public sealed class OrganizationExport
{
    public Guid OrganizationId { get; set; }
    public Guid Id { get; set; }
    public string State { get; set; } = "queued";
    public string? BlobKey { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
    public Guid RequestedBy { get; set; }
}

public sealed class AuditEvent
{
    public Guid OrganizationId { get; set; }
    public Guid Id { get; set; }
    public DateTimeOffset OccurredAt { get; set; }
    public string ActorType { get; set; } = "staff";
    public Guid? ActorId { get; set; }
    public string Action { get; set; } = "";
    public string TargetType { get; set; } = "";
    public string TargetId { get; set; } = "";
    public string Outcome { get; set; } = "success";
    public string CorrelationId { get; set; } = "";
    public string? Details { get; set; }
}
