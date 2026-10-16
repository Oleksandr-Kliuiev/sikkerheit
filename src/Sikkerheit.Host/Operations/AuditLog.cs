using Microsoft.EntityFrameworkCore;
using Npgsql;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Operations;

/// <summary>The number of audit events of an action in an organization.</summary>
public sealed record AuditCount(Guid OrganizationId, string Action, int Count);

/// <summary>Writes audit_event rows in the transaction of the change (05 «API портала», «Аудит»).</summary>
public static class AuditLog
{
    /// <summary>Removes the journal of the scope's organization (its deletion).</summary>
    public static Task DeleteOrganizationDataAsync(DbScope scope, CancellationToken ct) =>
        OrganizationRows.DeleteAsync(scope, ["audit_event"], ct);

    /// <summary>The journal for the organization export.</summary>
    public static Task ExportAsync(DbScope scope, TableRowsWriter write, CancellationToken ct) =>
        OrganizationRows.ExportAsync(scope, [("audit_event", "occurred_at, id")], write, ct);

    /// <summary>Events older than 12 months (04 «Сроки хранения»).</summary>
    public static async Task PurgeAsync(DbScope scope, RetentionCuts cuts, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(
            "delete from audit_event where organization_id = @org and occurred_at < @history_cut", scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("org", scope.OrganizationId!.Value);
        command.Parameters.AddWithValue("history_cut", cuts.History);
        await command.ExecuteNonQueryAsync(ct);
    }

    /// <summary>Events of the actions in [since, until) per organization; for the Teams digest in the read-all scope.</summary>
    public static async Task<IReadOnlyList<AuditCount>> CountsAsync(DbScope scope, string[] actions, DateTimeOffset since,
        DateTimeOffset until, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            select organization_id, action, count(*) from audit_event
            where action = any(@actions) and occurred_at >= @since and occurred_at < @until
            group by organization_id, action order by organization_id, action
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("actions", actions);
        command.Parameters.AddWithValue("since", since);
        command.Parameters.AddWithValue("until", until);
        var counts = new List<AuditCount>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            counts.Add(new AuditCount(reader.GetGuid(0), reader.GetString(1), (int)reader.GetInt64(2)));
        }
        return counts;
    }

    /// <summary>
    /// Targets of the scope's organization with an event of the action on at least minDays different UTC days since the
    /// moment (a device with device.sequence_resync on 2 of the last 3 days may be an exact clone).
    /// </summary>
    public static async Task<IReadOnlyList<string>> TargetsWithEventsOnDaysAsync(DbScope scope, string action, DateTimeOffset since,
        int minDays, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            select target_id from audit_event
            where organization_id = @org and action = @action and occurred_at >= @since
            group by target_id having count(distinct (occurred_at at time zone 'UTC')::date) >= @days
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("org", scope.OrganizationId!.Value);
        command.Parameters.AddWithValue("action", action);
        command.Parameters.AddWithValue("since", since);
        command.Parameters.AddWithValue("days", minDays);
        var targets = new List<string>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            targets.Add(reader.GetString(0));
        }
        return targets;
    }

    public static void Staff(DbScope scope, Actor actor, string action, string targetType, string targetId,
        string correlationId, object? details = null, string outcome = "success") =>
        Add(scope, "staff", actor.EntraUserId, action, targetType, targetId, correlationId, details, outcome);

    /// <summary>An event caused by a device: the actor is the deviceId (05 «Сущности и ограничения»).</summary>
    public static void Device(DbScope scope, Guid deviceId, string action, string targetType, string targetId,
        string correlationId, object? details = null) =>
        Add(scope, "device", deviceId, action, targetType, targetId, correlationId, details, "success");

    public static void System(DbScope scope, string action, string targetType, string targetId, string correlationId,
        object? details = null) =>
        Add(scope, "system", null, action, targetType, targetId, correlationId, details, "success");

    /// <summary>
    /// The journal of the scope's organization, newest first: events before the cursor position (time, id), at most take
    /// of them (listAuditEvents).
    /// </summary>
    public static async Task<List<AuditEvent>> ListAsync(DbScope scope, (DateTimeOffset OccurredAt, Guid Id)? before, int take,
        CancellationToken ct)
    {
        var organizationId = scope.OrganizationId!.Value;
        var query = scope.Db.AuditEvents.AsNoTracking().Where(e => e.OrganizationId == organizationId);
        if (before is { } position)
        {
            var (at, beforeId) = position;
            query = query.Where(e => e.OccurredAt < at || (e.OccurredAt == at && e.Id.CompareTo(beforeId) < 0));
        }
        return await query.OrderByDescending(e => e.OccurredAt).ThenByDescending(e => e.Id).Take(take).ToListAsync(ct);
    }

    /// <summary>True when the organization of the scope has an event with this action and correlation id (restore markers).</summary>
    public static Task<bool> ExistsAsync(DbScope scope, string action, string correlationId, CancellationToken ct)
    {
        var organizationId = scope.OrganizationId!.Value;
        return scope.Db.AuditEvents.AnyAsync(
            e => e.OrganizationId == organizationId && e.Action == action && e.CorrelationId == correlationId, ct);
    }

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
