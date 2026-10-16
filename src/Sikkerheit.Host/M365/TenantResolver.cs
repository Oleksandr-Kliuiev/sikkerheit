using System.Text.Json;
using System.Text.RegularExpressions;

namespace Sikkerheit.Host.M365;

public interface ITenantResolver
{
    /// <summary>Tenant ID from a tenant ID or a verified domain; null when the domain is unknown.</summary>
    Task<Guid?> ResolveAsync(string tenantHint, CancellationToken ct);
}

/// <summary>Resolves a domain through OpenID discovery of Microsoft (05 «Подключение M365 и сбор»).</summary>
public sealed partial class OpenIdTenantResolver(HttpClient http) : ITenantResolver
{
    [GeneratedRegex("^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)+$")]
    private static partial Regex Domain();

    public async Task<Guid?> ResolveAsync(string tenantHint, CancellationToken ct)
    {
        if (Guid.TryParse(tenantHint, out var tenant))
        {
            return tenant;
        }
        if (!Domain().IsMatch(tenantHint))
        {
            return null;
        }
        using var response = await http.GetAsync(
            $"https://login.microsoftonline.com/{tenantHint}/v2.0/.well-known/openid-configuration", ct);
        if (!response.IsSuccessStatusCode)
        {
            return null;
        }
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        var issuer = document.RootElement.TryGetProperty("issuer", out var value) ? value.GetString() : null;
        var segment = issuer?.Split('/', StringSplitOptions.RemoveEmptyEntries).ElementAtOrDefault(2);
        return Guid.TryParse(segment, out var id) ? id : null;
    }
}
