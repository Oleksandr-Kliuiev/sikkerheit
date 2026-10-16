using System.Security.Cryptography;
using System.Text;
using Npgsql;
using Sikkerheit.Host.Data;

namespace Sikkerheit.Host.Access;

/// <summary>
/// Staff sign-in outside the JSON API (04 «Вход сотрудников и роли»): /auth/login starts the authorization code flow
/// with PKCE, /auth/callback redeems the code on the server and creates a new server-side session. The browser holds
/// only the state cookie of the attempt and then the session cookie.
/// </summary>
public static class LoginEndpoints
{
    public const string AttemptCookie = "__Host-sikkerheit-login";
    public static readonly TimeSpan AttemptLifetime = TimeSpan.FromMinutes(10);

    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapGet("/auth/login", Login);
        app.MapGet("/auth/callback", Callback);
    }

    private static async Task<IResult> Login(HttpContext http, IStaffIdentityProvider identity, DbScopes scopes,
        TimeProvider clock, string? returnUrl, CancellationToken ct)
    {
        var state = Random(32);
        var nonce = Random(32);
        var verifier = Random(64);
        var challenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var now = clock.GetUtcNow();
        await using (var scope = await scopes.PlatformAsync(ct))
        {
            await using var command = new NpgsqlCommand("""
                delete from staff_login where expires_at < @now;
                insert into staff_login (state_hash, code_verifier, nonce, return_path, expires_at)
                values (@state, @verifier, @nonce, @path, @expires);
                """, scope.Connection, scope.Transaction);
            command.Parameters.AddWithValue("now", now);
            command.Parameters.AddWithValue("state", StaffSessions.Hash(state));
            command.Parameters.AddWithValue("verifier", verifier);
            command.Parameters.AddWithValue("nonce", nonce);
            command.Parameters.AddWithValue("path", LocalPath(returnUrl));
            command.Parameters.AddWithValue("expires", now + AttemptLifetime);
            await command.ExecuteNonQueryAsync(ct);
            await scope.CommitAsync(ct);
        }
        http.Response.Cookies.Append(AttemptCookie, state, new CookieOptions
        {
            HttpOnly = true, Secure = true, SameSite = SameSiteMode.Lax, Path = "/", IsEssential = true, MaxAge = AttemptLifetime,
        });
        http.Response.Headers.CacheControl = "no-store";
        return Results.Redirect(identity.AuthorizeUrl(state, nonce, challenge).ToString());
    }

    private static async Task<IResult> Callback(HttpContext http, IStaffIdentityProvider identity, StaffSessions sessions,
        DbScopes scopes, TimeProvider clock, ILoggerFactory loggers, string? code, string? state, string? error,
        CancellationToken ct)
    {
        var logger = loggers.CreateLogger("Sikkerheit.StaffSignIn");
        http.Response.Headers.CacheControl = "no-store";
        var cookie = http.Request.Cookies[AttemptCookie];
        http.Response.Cookies.Delete(AttemptCookie, new CookieOptions { Secure = true, Path = "/" });
        if (error is not null)
        {
            logger.LogWarning("Staff sign-in returned an error from Entra: {Error}", error.Length > 64 ? error[..64] : error);
            return Failed(error == "access_denied" ? "cancelled" : "error");
        }
        // The attempt is bound to this browser by the cookie: a code injected into another browser is refused.
        if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state) || string.IsNullOrEmpty(cookie)
            || !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(state), Encoding.UTF8.GetBytes(cookie)))
        {
            return Failed("error");
        }
        string verifier, nonce, path;
        await using (var scope = await scopes.PlatformAsync(ct))
        {
            await using var command = new NpgsqlCommand(
                "delete from staff_login where state_hash = @state and expires_at > @now returning code_verifier, nonce, return_path",
                scope.Connection, scope.Transaction);
            command.Parameters.AddWithValue("state", StaffSessions.Hash(state));
            command.Parameters.AddWithValue("now", clock.GetUtcNow());
            await using (var reader = await command.ExecuteReaderAsync(ct))
            {
                if (!await reader.ReadAsync(ct))
                {
                    return Failed("expired");
                }
                (verifier, nonce, path) = (reader.GetString(0), reader.GetString(1), reader.GetString(2));
            }
            await scope.CommitAsync(ct);
        }
        StaffIdentity staff;
        try
        {
            staff = await identity.RedeemAsync(code, verifier, nonce, ct);
        }
        catch (StaffSignInException refused)
        {
            logger.LogWarning(refused, "Staff sign-in refused: {Reason}", refused.Reason);
            return Failed(refused.Reason);
        }
        if (http.Request.Cookies.TryGetValue(StaffSessions.CookieName, out var previous) && !string.IsNullOrEmpty(previous))
        {
            await sessions.EndAsync(previous, ct);
        }
        var (sessionId, _) = await sessions.CreateAsync(staff.EntraUserId, staff.DisplayName, staff.Roles, staff.TokenCache, ct);
        AccessEndpoints.WriteSessionCookie(http, sessionId);
        logger.LogInformation("Staff sign-in {EntraUserId} with roles {Roles}", staff.EntraUserId, string.Join(",", staff.Roles));
        return Results.Redirect(path);
    }

    /// <summary>Only a local absolute path may be the target after sign-in (no open redirect).</summary>
    public static string LocalPath(string? returnUrl) =>
        returnUrl is { Length: > 0 and <= 512 } && returnUrl[0] == '/' && !returnUrl.StartsWith("//", StringComparison.Ordinal)
        && !returnUrl.StartsWith("/\\", StringComparison.Ordinal) && !returnUrl.Any(char.IsControl)
            ? returnUrl
            : "/";

    private static IResult Failed(string reason) => Results.Redirect("/?signin=failed&reason=" + Uri.EscapeDataString(reason));

    private static string Random(int bytes) => Base64Url(RandomNumberGenerator.GetBytes(bytes));

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

/// <summary>Until Auth:Entra is configured nobody can sign in through Entra (development uses /auth/dev/login).</summary>
public sealed class UnconfiguredStaffIdentityProvider : IStaffIdentityProvider
{
    public Uri AuthorizeUrl(string state, string nonce, string codeChallenge) =>
        throw new InvalidOperationException("Auth:Entra is not configured");

    public Task<StaffIdentity> RedeemAsync(string code, string codeVerifier, string nonce, CancellationToken ct) =>
        throw new StaffSignInException("error", "Auth:Entra is not configured");

    public Task<StaffIdentity> RefreshAsync(Guid entraUserId, byte[] tokenCache, CancellationToken ct) =>
        throw new StaffSignInException("refresh_failed", "Auth:Entra is not configured");
}
