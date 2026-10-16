using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Access;

/// <summary>Authenticates portal requests by the server-side session cookie.</summary>
public sealed class SessionAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, StaffSessions sessions)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "StaffSession";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Cookies.TryGetValue(StaffSessions.CookieName, out var sessionId) || string.IsNullOrEmpty(sessionId))
        {
            return AuthenticateResult.NoResult();
        }
        var session = await sessions.ValidateAsync(sessionId, Context.RequestAborted);
        if (session is not null)
        {
            session = await sessions.RefreshIfDueAsync(session, Context.RequestAborted);
        }
        if (session is null)
        {
            return AuthenticateResult.NoResult();
        }
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, session.EntraUserId.ToString()),
            new(Actor.CsrfClaim, session.CsrfToken),
        };
        claims.AddRange(session.Roles.Select(role => new Claim(ClaimTypes.Role, role)));
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, SchemeName));
        return AuthenticateResult.Success(new AuthenticationTicket(principal, SchemeName));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties) =>
        Problems.WriteAsync(Context, ProblemCodes.SessionRequired);

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties) =>
        Problems.WriteAsync(Context, ProblemCodes.Forbidden);
}

/// <summary>Portal mutations need X-CSRF-Token equal to the token of the session (403 csrf_failed).</summary>
public sealed class CsrfMiddleware(RequestDelegate next)
{
    public const string Header = "X-CSRF-Token";

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path;
        var mutation = !HttpMethods.IsGet(context.Request.Method) && !HttpMethods.IsHead(context.Request.Method)
                       && !HttpMethods.IsOptions(context.Request.Method);
        var portal = (path.StartsWithSegments("/api/v1") && !path.StartsWithSegments("/api/v1/agent"))
                     || path.StartsWithSegments("/auth/logout");
        if (mutation && portal && context.User.Identity?.IsAuthenticated == true)
        {
            var expected = context.User.FindFirstValue(Actor.CsrfClaim) ?? "";
            var provided = context.Request.Headers[Header].ToString();
            if (provided.Length == 0 || !CryptographicOperations.FixedTimeEquals(
                    Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(provided)))
            {
                await Problems.WriteAsync(context, ProblemCodes.CsrfFailed);
                return;
            }
        }
        await next(context);
    }
}
