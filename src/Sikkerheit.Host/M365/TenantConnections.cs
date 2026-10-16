using Microsoft.EntityFrameworkCore;
using Npgsql;
using Sikkerheit.Host.Data;

namespace Sikkerheit.Host.M365;

/// <summary>The connection of an organization as lists show it.</summary>
public sealed record TenantConnectionState(string Status, DateTimeOffset? LastCollectedAt);

/// <summary>
/// State changes of the Microsoft 365 connection shared by disconnectTenant and the restore replay, and its reads for
/// other modules. The connection and collection run tables belong to this module.
/// </summary>
public static class TenantConnections
{
    /// <summary>Tables of this module in the organization export, with their stable order.</summary>
    private static readonly (string Table, string Order)[] ExportTables =
        [("tenant_connection", "organization_id"), ("collection_run", "queued_at, id")];

    /// <summary>Removes the runs and the connection of the scope's organization; the observations of the runs go first.</summary>
    public static Task DeleteOrganizationDataAsync(DbScope scope, CancellationToken ct) =>
        OrganizationRows.DeleteAsync(scope, ["collection_run", "tenant_connection"], ct);

    /// <summary>The connection and the runs for the organization export.</summary>
    public static Task ExportAsync(DbScope scope, TableRowsWriter write, CancellationToken ct) =>
        OrganizationRows.ExportAsync(scope, ExportTables, write, ct);

    /// <summary>The connection row of a new organization, not connected; written in the organization's transaction.</summary>
    public static void Create(DbScope scope) =>
        scope.Db.TenantConnections.Add(new TenantConnection { OrganizationId = scope.OrganizationId!.Value, Status = "not_connected" });

    /// <summary>
    /// Locks the connection row of the scope's organization: recalculate_policy serializes with the final transaction of a
    /// collection run, which locks the same row.
    /// </summary>
    public static async Task LockAsync(DbScope scope, CancellationToken ct)
    {
        var org = scope.OrganizationId!.Value;
        await scope.Db.TenantConnections
            .FromSqlInterpolated($"select * from tenant_connection where organization_id = {org} for update").ToListAsync(ct);
    }

    /// <summary>The connection of an organization, or null.</summary>
    public static async Task<TenantConnection?> FindAsync(DbScope scope, Guid organizationId, CancellationToken ct) =>
        await scope.Db.TenantConnections.AsNoTracking().SingleOrDefaultAsync(c => c.OrganizationId == organizationId, ct);

    /// <summary>The connection of every organization; only for components with the read-all scope.</summary>
    public static async Task<IReadOnlyDictionary<Guid, TenantConnectionState>> StatesAsync(DbScope all, CancellationToken ct) =>
        (await all.Db.TenantConnections.AsNoTracking()
            .Select(c => new { c.OrganizationId, State = new TenantConnectionState(c.Status, c.LastCollectedAt) }).ToListAsync(ct))
        .ToDictionary(c => c.OrganizationId, c => c.State);

    /// <summary>The tenant of a connection active since the moment or earlier, or null.</summary>
    public static async Task<Guid?> ActiveTenantAtAsync(DbScope scope, Guid organizationId, DateTimeOffset at, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            select entra_tenant_id from tenant_connection
            where organization_id = @org and status = 'active' and connected_at <= @at and entra_tenant_id is not null
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("org", organizationId);
        command.Parameters.AddWithValue("at", at);
        return await command.ExecuteScalarAsync(ct) is Guid tenant ? tenant : null;
    }

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
