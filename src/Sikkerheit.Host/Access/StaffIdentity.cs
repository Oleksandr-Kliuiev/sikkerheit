using System.Text;
using System.Text.Json;
using Microsoft.Identity.Client;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Access;

/// <summary>The single-tenant staff application in the company tenant (04 «Вход сотрудников и роли»).</summary>
public sealed class EntraOptions
{
    public string Instance { get; set; } = "https://login.microsoftonline.com/";
    public string? TenantId { get; set; }
    public string? ClientId { get; set; }

    /// <summary>https://&lt;portal&gt;/auth/callback, registered as a web redirect URI of the application.</summary>
    public string? RedirectUri { get; set; }

    /// <summary>Scope of the application's own API; its access token carries amr.</summary>
    public string? ApiScope { get; set; }

    /// <summary>ManagedIdentity (workload identity federation, production), Certificate (Key Vault) or Secret (development).</summary>
    public string Credential { get; set; } = "ManagedIdentity";

    public string? ManagedIdentityClientId { get; set; }
    public string? KeyVaultUri { get; set; }
    public string? CertificateName { get; set; }
    public string? ClientSecret { get; set; }

    /// <summary>Fallback proof of MFA: a Conditional Access authentication context id in the acrs claim (e.g. c1).</summary>
    public string? AuthenticationContext { get; set; }

    public bool Configured => !string.IsNullOrEmpty(TenantId) && !string.IsNullOrEmpty(ClientId) && !string.IsNullOrEmpty(RedirectUri);

    public string Scope => ApiScope ?? $"api://{ClientId}/access_as_user";
}

/// <summary>A signed-in staff member as the identity provider vouches for them.</summary>
public sealed record StaffIdentity(Guid EntraUserId, string? DisplayName, IReadOnlyList<string> Roles, byte[] TokenCache);

/// <summary>Why a sign-in or a refresh was refused; shown to the person as a short code only.</summary>
public sealed class StaffSignInException(string reason, string message, Exception? inner = null) : Exception(message, inner)
{
    public string Reason { get; } = reason;
}

/// <summary>OIDC authorization code flow with PKCE against Entra; the portal never sees tokens.</summary>
public interface IStaffIdentityProvider
{
    Uri AuthorizeUrl(string state, string nonce, string codeChallenge);

    Task<StaffIdentity> RedeemAsync(string code, string codeVerifier, string nonce, CancellationToken ct);

    /// <summary>Hourly refresh: current roles from a new token; an account that is disabled or lost its role fails.</summary>
    Task<StaffIdentity> RefreshAsync(Guid entraUserId, byte[] tokenCache, CancellationToken ct);
}

public sealed class EntraStaffIdentityProvider(EntraOptions options, TimeProvider clock, ILogger<EntraStaffIdentityProvider> logger)
    : IStaffIdentityProvider
{
    private readonly IClientAssertion? _assertion = options.Credential switch
    {
        "ManagedIdentity" => new ManagedIdentityAssertion(options.ManagedIdentityClientId),
        "Certificate" => new KeyVaultClientAssertion(options.ClientId!, new Uri(options.KeyVaultUri!), options.CertificateName!, clock),
        _ => null,
    };

    private string[] Scopes => [options.Scope];

    public Uri AuthorizeUrl(string state, string nonce, string codeChallenge)
    {
        var query = new Dictionary<string, string>
        {
            ["client_id"] = options.ClientId!, ["response_type"] = "code", ["redirect_uri"] = options.RedirectUri!,
            ["response_mode"] = "query", ["scope"] = "openid profile offline_access " + options.Scope, ["state"] = state,
            ["nonce"] = nonce, ["code_challenge"] = codeChallenge, ["code_challenge_method"] = "S256",
        };
        var text = string.Join('&', query.Select(p => p.Key + "=" + Uri.EscapeDataString(p.Value)));
        return new Uri($"{options.Instance.TrimEnd('/')}/{options.TenantId}/oauth2/v2.0/authorize?{text}");
    }

    public async Task<StaffIdentity> RedeemAsync(string code, string codeVerifier, string nonce, CancellationToken ct)
    {
        var (application, cache) = Application(null);
        AuthenticationResult result;
        try
        {
            result = await application.AcquireTokenByAuthorizationCode(Scopes, code).WithPkceCodeVerifier(codeVerifier).ExecuteAsync(ct);
        }
        catch (MsalException error)
        {
            throw new StaffSignInException("error", "the authorization code was refused: " + error.ErrorCode, error);
        }
        var idToken = Claims(result.IdToken);
        if (Text(idToken, "nonce") != nonce)
        {
            throw new StaffSignInException("error", "the nonce of the ID token does not match");
        }
        return StaffTokens.Verify(options, Claims(result.AccessToken), idToken, cache.Bytes);
    }

    public async Task<StaffIdentity> RefreshAsync(Guid entraUserId, byte[] tokenCache, CancellationToken ct)
    {
        var (application, cache) = Application(tokenCache);
        // The home account id of a work account is «oid.tid».
        var account = await application.GetAccountAsync($"{entraUserId}.{options.TenantId}")
            ?? throw new StaffSignInException("refresh_failed", "the session has no account to refresh");
        AuthenticationResult result;
        try
        {
            result = await application.AcquireTokenSilent(Scopes, account).WithForceRefresh(true).ExecuteAsync(ct);
        }
        catch (MsalException error)
        {
            logger.LogWarning("Staff token refresh refused for {EntraUserId}: {Error}", entraUserId, error.ErrorCode);
            throw new StaffSignInException("refresh_failed", "the refresh token was refused: " + error.ErrorCode, error);
        }
        var identity = StaffTokens.Verify(options, Claims(result.AccessToken), result.IdToken is null ? null : Claims(result.IdToken),
            cache.Bytes);
        return identity.EntraUserId == entraUserId ? identity
            : throw new StaffSignInException("refresh_failed", "the refreshed token belongs to another user");
    }

    private (IConfidentialClientApplication Application, CacheHolder Cache) Application(byte[]? tokenCache)
    {
        var builder = ConfidentialClientApplicationBuilder.Create(options.ClientId)
            .WithAuthority($"{options.Instance.TrimEnd('/')}/{options.TenantId}/")
            .WithRedirectUri(options.RedirectUri);
        builder = _assertion is not null
            ? builder.WithClientAssertion(a => _assertion.CreateAsync(a.TokenEndpoint, a.CancellationToken))
            : builder.WithClientSecret(options.ClientSecret ?? throw new InvalidOperationException("Auth:Entra:ClientSecret is required"));
        var application = builder.Build();
        var holder = new CacheHolder { Bytes = tokenCache ?? [] };
        // The user token cache of one session lives only in that session row (encrypted).
        application.UserTokenCache.SetBeforeAccess(args => args.TokenCache.DeserializeMsalV3(holder.Bytes.Length == 0 ? null : holder.Bytes));
        application.UserTokenCache.SetAfterAccess(args =>
        {
            if (args.HasStateChanged)
            {
                holder.Bytes = args.TokenCache.SerializeMsalV3();
            }
        });
        return (application, holder);
    }

    private sealed class CacheHolder
    {
        public byte[] Bytes { get; set; } = [];
    }

    /// <summary>Claims of a token received directly from the token endpoint over TLS (OIDC Core 3.1.3.7).</summary>
    private static JsonElement Claims(string? jwt)
    {
        var parts = (jwt ?? "").Split('.');
        if (parts.Length != 3)
        {
            throw new StaffSignInException("error", "a token is missing or malformed");
        }
        var payload = parts[1].Replace('-', '+').Replace('_', '/');
        payload += new string('=', (4 - payload.Length % 4) % 4);
        using var document = JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(payload)));
        return document.RootElement.Clone();
    }

    private static string? Text(JsonElement claims, string name) => StaffTokens.Text(claims, name);
}

/// <summary>
/// The checks of 04 «Вход сотрудников и роли» on the claims of the tokens Entra returned: tenant, user, MFA in the access
/// token of the own API (amr mfa or the configured acrs) and app roles. The ID token, when the response has one, must name
/// the same tenant and user. Separate from MSAL so that tests run the same checks behind the sign-in endpoints.
/// </summary>
public static class StaffTokens
{
    public static StaffIdentity Verify(EntraOptions options, JsonElement access, JsonElement? idToken, byte[] tokenCache)
    {
        var oid = Text(access, "oid");
        if (Text(access, "tid") != options.TenantId || (idToken is { } id && Text(id, "tid") != options.TenantId))
        {
            throw new StaffSignInException("error", "the token was issued by another tenant");
        }
        if (!Guid.TryParse(oid, out var entraUserId) || (idToken is { } named && Text(named, "oid") != oid))
        {
            throw new StaffSignInException("error", "the user of the tokens is missing or differs");
        }
        // Only «mfa» proves MFA; «wiaormfa» does not (04).
        var mfa = Values(access, "amr").Contains("mfa")
                  || (options.AuthenticationContext is { } context && Values(access, "acrs").Contains(context));
        if (!mfa)
        {
            throw new StaffSignInException("mfa_required", "the access token has no proof of MFA");
        }
        var roles = Values(access, "roles").Concat(idToken is { } withRoles ? Values(withRoles, "roles") : [])
            .Where(StaffRoles.All.Contains).Distinct().Order(StringComparer.Ordinal).ToList();
        if (roles.Count == 0)
        {
            throw new StaffSignInException("no_role", "the user has no Sikkerheit role");
        }
        var display = idToken is { } profile ? Text(profile, "name") ?? Text(profile, "preferred_username") : Text(access, "name");
        return new StaffIdentity(entraUserId, display, roles, tokenCache);
    }

    internal static string? Text(JsonElement claims, string name) =>
        claims.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static IReadOnlyList<string> Values(JsonElement claims, string name) =>
        claims.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()!).ToList()
            : [];
}
