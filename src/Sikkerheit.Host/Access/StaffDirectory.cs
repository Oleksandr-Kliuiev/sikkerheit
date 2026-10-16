using Microsoft.EntityFrameworkCore;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Access;

/// <summary>Reads of staff members for other modules; the staff tables belong to this module.</summary>
public static class StaffDirectory
{
    /// <summary>An active Admin or Technician: signed in within the active window, with the last refresh accepted.</summary>
    public static async Task<bool> CanBeAssignedAsync(DbScope scope, Guid entraUserId, DateTimeOffset now, CancellationToken ct)
    {
        var since = now - AccessEndpoints.ActiveWindow;
        return await scope.Db.StaffUsers.AnyAsync(s => s.EntraUserId == entraUserId && s.LastRefreshOk
            && s.LastSignInAt > since && (s.Roles.Contains(StaffRoles.Admin) || s.Roles.Contains(StaffRoles.Technician)), ct);
    }

    /// <summary>Display names of staff members by Entra user id; an unknown id is missing from the result.</summary>
    public static async Task<IReadOnlyDictionary<Guid, string?>> NamesAsync(DbScope scope, IReadOnlyCollection<Guid> ids,
        CancellationToken ct) =>
        await scope.Db.StaffUsers.AsNoTracking().Where(s => ids.Contains(s.EntraUserId))
            .ToDictionaryAsync(s => s.EntraUserId, s => s.DisplayName, ct);
}
