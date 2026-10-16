using Microsoft.EntityFrameworkCore;
using Sikkerheit.Host.Data;

namespace Sikkerheit.Host.Organizations;

/// <summary>An organization as other modules read it.</summary>
public sealed record OrganizationSummary(Guid Id, string Name, string Timezone, string Status, DateTimeOffset CreatedAt,
    DateTimeOffset? DeletionDueAt);

/// <summary>Lists of organizations for other modules, which do not query the organization table themselves.</summary>
public static class OrganizationDirectory
{
    /// <summary>
    /// Every organization ordered by name in the collation of the database, then by id; only for components with the
    /// read-all scope (02 «Разделение клиентов»).
    /// </summary>
    public static async Task<IReadOnlyList<OrganizationSummary>> ListAsync(DbScope all, CancellationToken ct) =>
        await all.Db.Organizations.AsNoTracking().OrderBy(o => o.Name).ThenBy(o => o.Id)
            .Select(o => new OrganizationSummary(o.Id, o.Name, o.Timezone, o.Status, o.CreatedAt, o.DeletionDueAt))
            .ToListAsync(ct);
}
