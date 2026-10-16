using Microsoft.EntityFrameworkCore;
using Npgsql;
using Sikkerheit.Host.Data;

namespace Sikkerheit.Host.Organizations;

/// <summary>
/// Policy revisions of 05 «Политика клиента». The policy_revision table belongs to this module; other modules read the
/// revisions only here.
/// </summary>
public static class Policies
{
    /// <summary>The newest revision of the scope's organization, or null before the first one.</summary>
    public static async Task<PolicyRevision?> CurrentAsync(DbScope scope, CancellationToken ct)
    {
        var id = scope.OrganizationId!.Value;
        return await scope.Db.PolicyRevisions.AsNoTracking().Where(p => p.OrganizationId == id)
            .OrderByDescending(p => p.Version).FirstOrDefaultAsync(ct);
    }

    /// <summary>The revision with this version of the scope's organization, or null when it has none.</summary>
    public static async Task<PolicyRevision?> GetAsync(DbScope scope, int version, CancellationToken ct)
    {
        var id = scope.OrganizationId!.Value;
        return await scope.Db.PolicyRevisions.AsNoTracking().SingleOrDefaultAsync(p => p.OrganizationId == id && p.Version == version, ct);
    }

    /// <summary>The newest revision of every organization the scope sees: its own one, or all in the read-all scope.</summary>
    public static async Task<IReadOnlyDictionary<Guid, PolicyRevision>> CurrentByOrganizationAsync(DbScope scope,
        CancellationToken ct) =>
        (await scope.Db.PolicyRevisions
            .FromSql($"select distinct on (organization_id) * from policy_revision order by organization_id, version desc")
            .AsNoTracking().ToListAsync(ct))
        .ToDictionary(p => p.OrganizationId);

    /// <summary>The revision in effect at the moment; before the first revision — the first one.</summary>
    public static async Task<(int Version, string Configuration)> AtAsync(DbScope scope, Guid organizationId,
        DateTimeOffset at, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            select version, configuration::text from policy_revision
            where organization_id = @org
            order by (effective_from <= @at) desc, case when effective_from <= @at then version end desc, version
            limit 1
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("org", organizationId);
        command.Parameters.AddWithValue("at", at);
        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
        {
            throw new InvalidOperationException("Organization has no policy revision");
        }
        return (reader.GetInt32(0), reader.GetString(1));
    }

    /// <summary>Versions of the revisions that took effect in [start, end), in order.</summary>
    public static async Task<IReadOnlyList<int>> VersionsInPeriodAsync(DbScope scope, Guid organizationId,
        DateTimeOffset start, DateTimeOffset end, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            select version from policy_revision
            where organization_id = @org and effective_from >= @start and effective_from < @end
            order by version
            """, scope.Connection, scope.Transaction);
        command.Parameters.AddWithValue("org", organizationId);
        command.Parameters.AddWithValue("start", start);
        command.Parameters.AddWithValue("end", end);
        var versions = new List<int>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            versions.Add(reader.GetInt32(0));
        }
        return versions;
    }
}
