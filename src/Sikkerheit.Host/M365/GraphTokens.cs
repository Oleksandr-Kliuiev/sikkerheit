using System.Collections.Concurrent;
using Azure;
using Microsoft.Identity.Client;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.M365;

/// <summary>
/// App-only Graph tokens by client credentials. The client assertion (PS256, header x5t#S256) is signed by Key Vault
/// with the non-exportable key of the application certificate, so the private key never enters the process (02).
/// </summary>
public sealed class KeyVaultGraphTokenProvider(M365Options options, TimeProvider clock) : IGraphTokenProvider
{
    private static readonly string[] Scopes = ["https://graph.microsoft.com/.default"];
    private readonly ConcurrentDictionary<Guid, IConfidentialClientApplication> _applications = new();
    private readonly KeyVaultClientAssertion _assertion = new(
        options.ClientId ?? throw new InvalidOperationException("M365:ClientId is required"),
        new Uri(options.KeyVaultUri ?? throw new InvalidOperationException("M365:KeyVaultUri is required")),
        options.CertificateName ?? throw new InvalidOperationException("M365:CertificateName is required"), clock);

    public async Task<string> GetTokenAsync(Guid tenantId, CancellationToken ct)
    {
        var application = _applications.GetOrAdd(tenantId, tenant => ConfidentialClientApplicationBuilder
            .Create(options.ClientId ?? throw new InvalidOperationException("M365:ClientId is required"))
            .WithAuthority(AzureCloudInstance.AzurePublic, tenant)
            .WithClientAssertion(assertion => AssertionAsync(assertion.TokenEndpoint, assertion.CancellationToken))
            .Build());
        try
        {
            var result = await application.AcquireTokenForClient(Scopes).ExecuteAsync(ct);
            return result.AccessToken;
        }
        catch (MsalServiceException error)
        {
            var message = error.Message;
            if (message.Contains("AADSTS700016", StringComparison.Ordinal) || message.Contains("AADSTS65001", StringComparison.Ordinal)
                || message.Contains("AADSTS90002", StringComparison.Ordinal) || message.Contains("AADSTS500011", StringComparison.Ordinal))
            {
                throw new GraphTokenException("consent_missing", "consent is missing or the application was removed", error);
            }
            if (message.Contains("AADSTS7000215", StringComparison.Ordinal) || message.Contains("AADSTS700027", StringComparison.Ordinal)
                || message.Contains("AADSTS700024", StringComparison.Ordinal))
            {
                throw new GraphTokenException("credential_error", "client assertion was refused", error);
            }
            throw new GraphTokenException("temporary_error", "token service failure", error);
        }
        catch (MsalClientException error)
        {
            throw new GraphTokenException("credential_error", "client assertion could not be built", error);
        }
        catch (RequestFailedException error)
        {
            throw new GraphTokenException("credential_error", "Key Vault signing failed", error);
        }
        catch (HttpRequestException error)
        {
            throw new GraphTokenException("temporary_error", "token request failed", error);
        }
    }

    private Task<string> AssertionAsync(string audience, CancellationToken ct) => _assertion.CreateAsync(audience, ct);
}

/// <summary>Used until the Graph application is configured: every token request is a credential error.</summary>
public sealed class UnconfiguredGraphTokenProvider : IGraphTokenProvider
{
    public Task<string> GetTokenAsync(Guid tenantId, CancellationToken ct) =>
        throw new GraphTokenException("credential_error", "the Graph application is not configured");
}
