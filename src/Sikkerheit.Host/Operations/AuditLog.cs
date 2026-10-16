using Sikkerheit.Host.Data;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Operations;

/// <summary>Writes audit_event rows in the transaction of the change (05 «API портала», «Аудит»).</summary>
public static class AuditLog
{
    public static void Staff(DbScope scope, Actor actor, string action, string targetType, string targetId,
        string correlationId, object? details = null, string outcome = "success") =>
        Add(scope, "staff", actor.EntraUserId, action, targetType, targetId, correlationId, details, outcome);

    public static void System(DbScope scope, string action, string targetType, string targetId, string correlationId,
        object? details = null) =>
        Add(scope, "system", null, action, targetType, targetId, correlationId, details, "success");

    private static void Add(DbScope scope, string actorType, Guid? actorId, string action, string targetType,
        string targetId, string correlationId, object? details, string outcome)
    {
        var organizationId = scope.OrganizationId
            ?? throw new InvalidOperationException("Audit events are written only in an organization scope");
        scope.Db.AuditEvents.Add(new AuditEvent
        {
            OrganizationId = organizationId, Id = Guid.CreateVersion7(), OccurredAt = DateTimeOffset.UtcNow,
            ActorType = actorType, ActorId = actorId, Action = action, TargetType = targetType, TargetId = targetId,
            Outcome = outcome, CorrelationId = correlationId, Details = details is null ? null : ApiJson.Serialize(details),
        });
    }
}
