using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;

namespace Sikkerheit.Host.Platform;

/// <summary>Builds the client assertion an Entra application presents instead of a secret.</summary>
public interface IClientAssertion
{
    Task<string> CreateAsync(string tokenEndpoint, CancellationToken ct);
}

/// <summary>
/// A JWT assertion (PS256, header x5t#S256) signed by Key Vault with the non-exportable key of the application
/// certificate: the private key never enters the process (04 «Ключ приложения»).
/// </summary>
public sealed class KeyVaultClientAssertion(string clientId, Uri keyVault, string certificateName, TimeProvider clock)
    : IClientAssertion
{
    private readonly SemaphoreSlim _lock = new(1, 1);
    private (CryptographyClient Signer, string Thumbprint, DateTimeOffset LoadedAt)? _certificate;

    public async Task<string> CreateAsync(string tokenEndpoint, CancellationToken ct)
    {
        var (signer, thumbprint) = await CertificateAsync(ct);
        var now = clock.GetUtcNow();
        var header = JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, string>
        {
            ["alg"] = "PS256", ["typ"] = "JWT", ["x5t#S256"] = thumbprint,
        });
        var payload = JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object>
        {
            ["aud"] = tokenEndpoint, ["iss"] = clientId, ["sub"] = clientId, ["jti"] = Guid.NewGuid().ToString(),
            ["nbf"] = now.ToUnixTimeSeconds(), ["iat"] = now.ToUnixTimeSeconds(), ["exp"] = now.AddMinutes(10).ToUnixTimeSeconds(),
        });
        var signingInput = Base64Url(header) + "." + Base64Url(payload);
        var digest = SHA256.HashData(Encoding.ASCII.GetBytes(signingInput));
        var signature = await signer.SignAsync(SignatureAlgorithm.PS256, digest, ct);
        return signingInput + "." + Base64Url(signature.Signature);
    }

    private async Task<(CryptographyClient Signer, string Thumbprint)> CertificateAsync(CancellationToken ct)
    {
        await _lock.WaitAsync(ct);
        try
        {
            // The certificate is read again every 6 hours so a renewed version is picked up without a restart.
            if (_certificate is { } cached && clock.GetUtcNow() - cached.LoadedAt < TimeSpan.FromHours(6))
            {
                return (cached.Signer, cached.Thumbprint);
            }
            var credential = new DefaultAzureCredential();
            var certificates = new CertificateClient(keyVault, credential);
            var certificate = (await certificates.GetCertificateAsync(certificateName, ct)).Value;
            var signer = new CryptographyClient(certificate.KeyId, credential);
            var thumbprint = Base64Url(SHA256.HashData(certificate.Cer));
            _certificate = (signer, thumbprint, clock.GetUtcNow());
            return (signer, thumbprint);
        }
        finally
        {
            _lock.Release();
        }
    }

    internal static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

/// <summary>
/// Workload identity federation: a token of the App Service managed identity for api://AzureADTokenExchange is the
/// assertion of an application that trusts this identity. No secret or certificate exists at all.
/// </summary>
public sealed class ManagedIdentityAssertion(string? managedIdentityClientId) : IClientAssertion
{
    private static readonly TokenRequestContext Exchange = new(["api://AzureADTokenExchange/.default"]);
    private readonly ManagedIdentityCredential _credential = string.IsNullOrEmpty(managedIdentityClientId)
        ? new ManagedIdentityCredential(ManagedIdentityId.SystemAssigned)
        : new ManagedIdentityCredential(ManagedIdentityId.FromUserAssignedClientId(managedIdentityClientId));

    public async Task<string> CreateAsync(string tokenEndpoint, CancellationToken ct) =>
        (await _credential.GetTokenAsync(Exchange, ct)).Token;
}
