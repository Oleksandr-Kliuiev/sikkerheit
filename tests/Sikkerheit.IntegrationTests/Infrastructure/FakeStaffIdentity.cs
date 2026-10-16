using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Sikkerheit.Host.Access;

namespace Sikkerheit.IntegrationTests.Infrastructure;

/// <summary>Entra stand-in: issues codes for staff members and answers refreshes as the test decides.</summary>
public sealed class FakeStaffIdentity : IStaffIdentityProvider
{
    private readonly Dictionary<string, (StaffIdentity? Identity, string? Refusal)> _codes = [];

    public string? LastChallenge { get; private set; }
    public string? LastVerifier { get; private set; }

    /// <summary>The answer of the next refresh: roles, or a refusal reason.</summary>
    public Func<Guid, StaffIdentity>? Refresh { get; set; }

    public void Issue(string code, StaffIdentity identity) => _codes[code] = (identity, null);

    /// <summary>
    /// Issues a code whose tokens carry these claims: redeeming it runs the real checks of StaffTokens on them, as the
    /// Entra provider does after the token endpoint answers.
    /// </summary>
    public void IssueTokens(string code, EntraOptions options, string accessClaims, string? idClaims = null) =>
        _tokens[code] = (options, accessClaims, idClaims);

    private readonly Dictionary<string, (EntraOptions Options, string Access, string? Id)> _tokens = [];

    public void Refuse(string code, string reason) => _codes[code] = (null, reason);

    public Uri AuthorizeUrl(string state, string nonce, string codeChallenge)
    {
        LastChallenge = codeChallenge;
        return new Uri(QueryHelpers.AddQueryString("https://login.test/authorize",
            new Dictionary<string, string?> { ["state"] = state, ["nonce"] = nonce, ["code_challenge"] = codeChallenge }));
    }

    public Task<StaffIdentity> RedeemAsync(string code, string codeVerifier, string nonce, CancellationToken ct)
    {
        LastVerifier = codeVerifier;
        var expected = Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        if (expected == LastChallenge && _tokens.Remove(code, out var tokens))
        {
            using var access = System.Text.Json.JsonDocument.Parse(tokens.Access);
            using var id = tokens.Id is null ? null : System.Text.Json.JsonDocument.Parse(tokens.Id);
            return Task.FromResult(StaffTokens.Verify(tokens.Options, access.RootElement, id?.RootElement, [1, 2, 3]));
        }
        if (expected != LastChallenge || !_codes.Remove(code, out var answer))
        {
            throw new StaffSignInException("error", "unknown code or PKCE mismatch");
        }
        return answer.Identity is { } identity ? Task.FromResult(identity) : throw new StaffSignInException(answer.Refusal!, "refused");
    }

    /// <summary>The token caches the refreshes received, in order: each one redeems the refresh token of the previous.</summary>
    public List<byte[]> RefreshedCaches { get; } = [];

    public Task<StaffIdentity> RefreshAsync(Guid entraUserId, byte[] tokenCache, CancellationToken ct)
    {
        lock (RefreshedCaches)
        {
            RefreshedCaches.Add(tokenCache);
        }
        return Refresh is { } refresh ? Task.FromResult(refresh(entraUserId))
            : throw new StaffSignInException("refresh_failed", "no refresh configured");
    }
}
