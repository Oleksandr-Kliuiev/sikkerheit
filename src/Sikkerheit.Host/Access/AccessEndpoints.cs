using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Organizations;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Access;

public sealed record CurrentStaffDto(Guid EntraUserId, string? DisplayName, IReadOnlyList<string> Roles, string CsrfToken);

public sealed record StaffUserDto(Guid EntraUserId, string? DisplayName, IReadOnlyList<string> Roles,
    DateTimeOffset? LastSignInAt, bool Active);

public sealed record DevelopmentLoginBody(Guid EntraUserId, string? DisplayName, string[] Roles);

/// <summary>getCurrentStaff, listStaff, logout and the development-only login (FR-02).</summary>
public static class AccessEndpoints
{
    public static readonly TimeSpan ActiveWindow = TimeSpan.FromDays(30);

    public static void Map(IEndpointRouteBuilder app, bool developmentLogin)
    {
        app.MapGet("/api/v1/me", Me).RequireStaff(StaffRoles.All);
        app.MapGet("/api/v1/staff", ListStaff).RequireStaff(StaffRoles.All);
        app.MapPost("/auth/logout", Logout);
        if (developmentLogin)
        {
            app.MapPost("/auth/dev/login", DevelopmentLogin);
        }
    }

    public static void WriteSessionCookie(HttpContext http, string sessionId) =>
        http.Response.Cookies.Append(StaffSessions.CookieName, sessionId, new CookieOptions
        {
            HttpOnly = true, Secure = true, SameSite = SameSiteMode.Lax, Path = "/", IsEssential = true,
        });

    private static async Task<IResult> Me(HttpContext http, DbScopes scopes, CancellationToken ct)
    {
        var actor = Actor.From(http.User);
        await using var scope = await scopes.PlatformAsync(ct);
        var staff = await scope.Db.StaffUsers.AsNoTracking().SingleAsync(s => s.EntraUserId == actor.EntraUserId, ct);
        return Results.Json(new CurrentStaffDto(actor.EntraUserId, staff.DisplayName, actor.Roles, actor.CsrfToken), ApiJson.Options);
    }

    private static async Task<IResult> ListStaff(DbScopes scopes, Cursors cursors, TimeProvider clock, string? cursor,
        string? limit, CancellationToken ct)
    {
        var size = OrganizationEndpoints.Limit(limit);
        var position = cursors.Read(cursor, "listStaff", null, "");
        var now = clock.GetUtcNow();
        await using var scope = await scopes.PlatformAsync(ct);
        var query = scope.Db.StaffUsers.AsNoTracking();
        if (position is not null)
        {
            var after = Guid.Parse(position[0]);
            query = query.Where(s => s.EntraUserId.CompareTo(after) > 0);
        }
        var rows = await query.OrderBy(s => s.EntraUserId).Take(size + 1).ToListAsync(ct);
        string? next = null;
        if (rows.Count > size)
        {
            rows.RemoveAt(size);
            next = cursors.Create("listStaff", null, "", [rows[^1].EntraUserId.ToString()]);
        }
        var items = rows.Select(s => new StaffUserDto(s.EntraUserId, s.DisplayName, s.Roles, s.LastSignInAt,
            s.LastRefreshOk && s.LastSignInAt is { } at && at > now - ActiveWindow)).ToList();
        return Results.Json(new Page<StaffUserDto>(items, next), ApiJson.Options);
    }

    private static async Task<IResult> Logout(HttpContext http, StaffSessions sessions, CancellationToken ct)
    {
        if (http.Request.Cookies.TryGetValue(StaffSessions.CookieName, out var sessionId) && sessionId.Length > 0)
        {
            await sessions.EndAsync(sessionId, ct);
        }
        http.Response.Cookies.Delete(StaffSessions.CookieName, new CookieOptions { Secure = true, Path = "/" });
        return Results.NoContent();
    }

    /// <summary>Development and tests only: signs in a staff member without Entra (refused in Production).</summary>
    private static async Task<IResult> DevelopmentLogin(HttpContext http, StaffSessions sessions, CancellationToken ct)
    {
        var body = await http.Request.ReadFromJsonAsync<DevelopmentLoginBody>(ApiJson.Options, ct)
            ?? throw new ApiProblemException(ProblemCodes.InvalidJson);
        if (body.Roles.Length == 0 || body.Roles.Any(r => !StaffRoles.All.Contains(r)))
        {
            throw new ApiProblemException(ProblemCodes.ValidationFailed, "roles must be Admin, Technician or Reader");
        }
        var (sessionId, session) = await sessions.CreateAsync(body.EntraUserId, body.DisplayName, body.Roles, null, ct);
        WriteSessionCookie(http, sessionId);
        return Results.Json(new CurrentStaffDto(body.EntraUserId, body.DisplayName, session.Roles, session.CsrfToken), ApiJson.Options);
    }

    internal static string Invariant(int value) => value.ToString(CultureInfo.InvariantCulture);
}
