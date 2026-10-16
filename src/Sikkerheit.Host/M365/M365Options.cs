namespace Sikkerheit.Host.M365;

/// <summary>Configuration of the read-only multi-tenant Graph application (04 «Доступ к Microsoft 365»).</summary>
public sealed class M365Options
{
    /// <summary>Application (client) id of «Sikkerheit Graph Reader».</summary>
    public string? ClientId { get; set; }

    /// <summary>Tenant of the company itself: consent there needs allowCompanyTenant=true.</summary>
    public Guid? CompanyTenantId { get; set; }

    /// <summary>Public passive page that Microsoft returns the browser to after admin consent.</summary>
    public string? ConsentRedirectUri { get; set; }

    /// <summary>Key Vault with the non-exportable certificate key of the application.</summary>
    public string? KeyVaultUri { get; set; }

    public string? CertificateName { get; set; }

    public bool PerUserMfa { get; set; } = true;
}
