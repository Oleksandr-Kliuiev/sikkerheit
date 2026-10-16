using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Sikkerheit.Host.Data;

namespace Sikkerheit.Host.Access;

/// <summary>
/// Server-side staff sessions (04 «Вход сотрудников и роли»): the cookie holds a random id, the database keeps
/// its SHA-256, roles, the CSRF token and the encrypted token cache. Absolute lifetime 8 hours, idle timeout
/// 60 minutes, refresh every 60 minutes: a disabled account or a removed role ends the session within the hour.
/// </summary>
public sealed class StaffSessions(DbScopes scopes, TimeProvider clock, IDataProtectionProvider protection,
    IStaffIdentityProvider identity, ILogger<StaffSessions> logger)
{
    private readonly IDataProtector _protector = protection.CreateProtector("Sikkerheit.StaffTokenCache.v1");

    public const string CookieName = "__Host-sikkerheit-session";
    public static readonly TimeSpan Absolute = TimeSpan.FromHours(8);
    public static readonly TimeSpan Idle = TimeSpan.FromMinutes(60);
    public static readonly TimeSpan Refresh = TimeSpan.FromMinutes(60);
    private static readonly TimeSpan TouchInterval = TimeSpan.FromMinutes(1);

    public async Task<(string SessionId, StaffSession Session)> CreateAsync(
        Guid entraUserId, string? displayName, IReadOnlyList<string> roles, byte[]? tokenCache, CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        var sessionId = Random(32);
        var session = new StaffSession
        {
            IdHash = Hash(sessionId), EntraUserId = entraUserId, Roles = [.. roles], CsrfToken = Random(32),
            TokenCache = tokenCache is null ? null : _protector.Protect(tokenCache), CreatedAt = now, LastSeenAt = now,
            RefreshDueAt = now + Refresh,
            ExpiresAt = now + Absolute,
        };
        await using var scope = await scopes.PlatformAsync(ct);
        var staff = await scope.Db.StaffUsers.SingleOrDefaultAsync(s => s.EntraUserId == entraUserId, ct);
        if (staff is null)
        {
            staff = new StaffUser { EntraUserId = entraUserId, CreatedAt = now };
            scope.Db.StaffUsers.Add(staff);
        }
        staff.DisplayName = displayName;
        staff.Roles = [.. roles];
        staff.LastSignInAt = now;
        staff.LastRefreshOk = true;
        scope.Db.StaffSessions.Add(session);
        await scope.CommitAsync(ct);
        return (sessionId, session);
    }

    public async Task<StaffSession?> ValidateAsync(string sessionId, CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        var hash = Hash(sessionId);
        await using var scope = await scopes.PlatformAsync(ct);
        var session = await scope.Db.StaffSessions.SingleOrDefaultAsync(s => s.IdHash == hash, ct);
        if (session is null)
        {
            return null;
        }
        if (session.ExpiresAt <= now || session.LastSeenAt + Idle <= now)
        {
            scope.Db.StaffSessions.Remove(session);
            await scope.CommitAsync(ct);
            return null;
        }
        if (now - session.LastSeenAt >= TouchInterval)
        {
            session.LastSeenAt = now;
            await scope.CommitAsync(ct);
        }
        return session;
    }

    /// <summary>
    /// Refreshes a session whose refresh is due: new roles from a new token, or the end of the session and an inactive
    /// staff member when Entra refuses. One request refreshes; parallel requests keep the current session meanwhile.
    /// </summary>
    public async Task<StaffSession?> RefreshIfDueAsync(StaffSession session, CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        if (session.RefreshDueAt > now)
        {
            return session;
        }
        await using var scope = await scopes.PlatformAsync(ct);
        var locked = await scope.Db.StaffSessions
            .FromSqlInterpolated($"select * from staff_session where id_hash = {session.IdHash} and refresh_due_at <= {now} for update skip locked")
            .SingleOrDefaultAsync(ct);
        if (locked is null)
        {
            return session;
        }
        var staff = await scope.Db.StaffUsers.SingleAsync(s => s.EntraUserId == locked.EntraUserId, ct);
        if (locked.TokenCache is null)
        {
            // A development session has no tokens to refresh.
            locked.RefreshDueAt = now + Refresh;
            await scope.CommitAsync(ct);
            return locked;
        }
        try
        {
            var refreshed = await identity.RefreshAsync(locked.EntraUserId, _protector.Unprotect(locked.TokenCache), ct);
            locked.Roles = [.. refreshed.Roles];
            locked.TokenCache = _protector.Protect(refreshed.TokenCache);
            locked.RefreshDueAt = now + Refresh;
            staff.Roles = [.. refreshed.Roles];
            staff.LastRefreshOk = true;
            await scope.CommitAsync(ct);
            return locked;
        }
        catch (Exception error) when (error is StaffSignInException or CryptographicException)
        {
            logger.LogWarning("Staff session of {EntraUserId} ended: refresh refused", locked.EntraUserId);
            scope.Db.StaffSessions.Remove(locked);
            staff.LastRefreshOk = false;
            await scope.CommitAsync(ct);
            return null;
        }
    }

    public async Task EndAsync(string sessionId, CancellationToken ct)
    {
        var hash = Hash(sessionId);
        await using var scope = await scopes.PlatformAsync(ct);
        await scope.Db.StaffSessions.Where(s => s.IdHash == hash).ExecuteDeleteAsync(ct);
        await scope.CommitAsync(ct);
    }

    /// <summary>Sessions and sign-in attempts past their expiry (04 «Сроки хранения»), in the caller's platform scope.</summary>
    public static async Task PurgeExpiredAsync(DbScope platform, DateTimeOffset now, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            delete from staff_session where expires_at < @now;
            delete from staff_login where expires_at < @now;
            """, platform.Connection, platform.Transaction);
        command.Parameters.AddWithValue("now", now);
        await command.ExecuteNonQueryAsync(ct);
    }

    internal static string Hash(string sessionId) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(sessionId)));

    private static string Random(int bytes) =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(bytes)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
