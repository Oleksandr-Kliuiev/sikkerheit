using Microsoft.EntityFrameworkCore;
using Sikkerheit.Host.Data;

namespace Sikkerheit.Host.M365;

/// <summary>
/// State changes of the Microsoft 365 connection shared by disconnectTenant and the restore replay. The connection and
/// collection run tables belong to this module.
/// </summary>
public static class TenantConnections
{
    /// <summary>
    /// Ends an active or pending connection in the organization scope and cancels its open runs (failed/cancelled).
    /// The caller writes the security log first. False when there was nothing to disconnect.
    /// </summary>
    public static async Task<bool> DisconnectAsync(DbScope scope, DateTimeOffset now, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        var connection = await scope.Db.TenantConnections
            .FromSqlInterpolated($"select * from tenant_connection where organization_id = {org} for update")
            .SingleOrDefaultAsync(ct);
        if (connection is not { Status: "active" or "consent_pending" })
        {
            return false;
        }
        connection.Status = connection.EntraTenantId is null ? "not_connected" : "disconnected";
        connection.PendingTenantId = null;
        connection.PendingExpiresAt = null;
        connection.DisconnectedAt = now;
        foreach (var run in await scope.Db.CollectionRuns
                     .Where(r => r.OrganizationId == org && (r.State == "queued" || r.State == "running"))
                     .ToListAsync(ct))
        {
            run.State = "failed";
            run.FailureCode = "cancelled";
            run.CompletedAt = now;
        }
        return true;
    }

    /// <summary>True while the connection of the scope's organization is active or waits for consent.</summary>
    public static async Task<bool> IsOpenAsync(DbScope scope, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        return await scope.Db.TenantConnections.AnyAsync(
            c => c.OrganizationId == org && (c.Status == "active" || c.Status == "consent_pending"), ct);
    }
}
