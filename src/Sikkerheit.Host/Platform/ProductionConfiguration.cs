using System.Security.Cryptography;

namespace Sikkerheit.Host.Platform;

/// <summary>Fail before starting jobs when a deployment omitted a required setting or a Key Vault reference is unresolved.</summary>
public static class ProductionConfiguration
{
    // tools/iac/deployment_checks.py checks this list against every deployed slot's settings.
    public static readonly string[] RequiredSettings =
    [
        "ConnectionStrings:Sikkerheit", "Auth:Entra:TenantId", "Auth:Entra:ClientId", "Auth:Entra:RedirectUri",
        "M365:ClientId", "M365:CompanyTenantId", "M365:KeyVaultUri", "M365:CertificateName", "M365:ConsentRedirectUri",
        "DataProtection:BlobUri", "DataProtection:KeyVaultKeyId", "SecurityLog:ContainerUri", "Storage:BlobServiceUri",
        "Cursors:Key", "Agents:NonceKey", "Hosting:PortalHosts:0", "Hosting:AgentHosts:0",
    ];

    public static void Validate(IConfiguration configuration, IHostEnvironment environment)
    {
        if (!environment.IsProduction())
        {
            return;
        }
        var missing = RequiredSettings.Where(key => string.IsNullOrWhiteSpace(configuration[key])).ToArray();
        if (missing.Length > 0)
        {
            throw new InvalidOperationException("Required Production settings: " + string.Join(", ", missing));
        }
        _ = HmacKey(configuration, environment, "Cursors:Key");
        _ = HmacKey(configuration, environment, "Agents:NonceKey");
        var version = configuration["Agents:MinimumAgentVersion"] ?? "0.1.0";
        if (!System.Text.RegularExpressions.Regex.IsMatch(version, @"^\d+\.\d+\.\d+$") || !Version.TryParse(version, out _))
        {
            throw new InvalidOperationException("Agents:MinimumAgentVersion must be x.y.z");
        }
        var portal = configuration.GetSection("Hosting:PortalHosts").Get<string[]>() ?? [];
        var agent = configuration.GetSection("Hosting:AgentHosts").Get<string[]>() ?? [];
        if (portal.Concat(agent).Any(host => host.Length > 253 || !System.Text.RegularExpressions.Regex.IsMatch(host,
            @"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")))
        {
            throw new InvalidOperationException("Hosting hostnames must be DNS names without scheme, path or wildcard");
        }
        if (portal.Intersect(agent, StringComparer.OrdinalIgnoreCase).Any())
        {
            // The staging slot is isolated by App Service and needs both routes for deployment smoke tests.
            if (!string.Equals(configuration["WEBSITE_SLOT_NAME"], "staging", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Production portal and agent hostnames must be different");
            }
        }
    }

    public static byte[] HmacKey(IConfiguration configuration, IHostEnvironment environment, string name)
    {
        var value = configuration[name];
        if (string.IsNullOrEmpty(value) && !environment.IsProduction())
        {
            return RandomNumberGenerator.GetBytes(32);
        }
        if (value is not null && !value.StartsWith("@Microsoft.KeyVault(", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var bytes = Convert.FromBase64String(value);
                if (bytes.Length == 32)
                {
                    return bytes;
                }
            }
            catch (FormatException)
            {
                // Never include the supplied value in diagnostics.
            }
        }
        throw new InvalidOperationException($"{name} must resolve to a base64-encoded 32-byte key");
    }
}
