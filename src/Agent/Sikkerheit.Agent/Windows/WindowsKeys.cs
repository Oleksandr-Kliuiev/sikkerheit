using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Sikkerheit.Agent.Keys;
using Sikkerheit.Agent.Protocol;

namespace Sikkerheit.Agent.Windows;

/// <summary>
/// Device key P-256 in CNG (04): Microsoft Platform Crypto Provider (TPM 2.0) if creation and a trial signature succeed, otherwise a
/// non-exportable machine key of Microsoft Software Key Storage Provider with a DACL for SYSTEM only. Checked by SP-04 (H-KEY).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class CngDeviceKeyStore : IDeviceKeyStore
{
    private const string KeyName = "Sikkerheit.Agent.DeviceKey";
    private static readonly CngProvider TpmProvider = new("Microsoft Platform Crypto Provider");
    private static readonly CngProvider SoftwareProvider = CngProvider.MicrosoftSoftwareKeyStorageProvider;

    public IDeviceKey? Open()
    {
        foreach (var (provider, protection) in new[] { (TpmProvider, KeyProtections.Tpm), (SoftwareProvider, KeyProtections.Software) })
        {
            try
            {
                if (CngKey.Exists(KeyName, provider, CngKeyOpenOptions.MachineKey))
                {
                    return new CngDeviceKey(CngKey.Open(KeyName, provider, CngKeyOpenOptions.MachineKey), protection);
                }
            }
            catch (CryptographicException)
            {
                // The provider is not available (no TPM): the next provider is tried.
            }
        }
        return null;
    }

    public IDeviceKey Create()
    {
        Delete();
        try
        {
            var key = CngKey.Create(CngAlgorithm.ECDsaP256, KeyName, Parameters(TpmProvider));
            var tpm = new CngDeviceKey(key, KeyProtections.Tpm);
            tpm.Sign([1]); // a trial signature: not every TPM supports P-256
            return tpm;
        }
        catch (CryptographicException)
        {
            DeleteFrom(TpmProvider);
        }
        var software = CngKey.Create(CngAlgorithm.ECDsaP256, KeyName, Parameters(SoftwareProvider));
        RestrictToSystem(software);
        return new CngDeviceKey(software, KeyProtections.Software);
    }

    public void Delete()
    {
        DeleteFrom(TpmProvider);
        DeleteFrom(SoftwareProvider);
    }

    private static CngKeyCreationParameters Parameters(CngProvider provider) => new()
    {
        Provider = provider,
        KeyUsage = CngKeyUsages.Signing,
        ExportPolicy = CngExportPolicies.None,
        KeyCreationOptions = CngKeyCreationOptions.MachineKey | CngKeyCreationOptions.OverwriteExistingKey,
    };

    private static void DeleteFrom(CngProvider provider)
    {
        try
        {
            if (CngKey.Exists(KeyName, provider, CngKeyOpenOptions.MachineKey))
            {
                using var key = CngKey.Open(KeyName, provider, CngKeyOpenOptions.MachineKey);
                key.Delete();
            }
        }
        catch (CryptographicException)
        {
            // Provider unavailable: there is nothing to delete.
        }
    }

    /// <summary>DACL of the software key: SYSTEM only. NCRYPT_SECURITY_DESCR_PROPERTY with DACL_SECURITY_INFORMATION (4).</summary>
    private static void RestrictToSystem(CngKey key)
    {
        var descriptor = new RawSecurityDescriptor("D:P(A;;GA;;;SY)");
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        key.SetProperty(new CngProperty("Security Descr", bytes, (CngPropertyOptions)4 | CngPropertyOptions.Persist));
    }
}

[SupportedOSPlatform("windows")]
internal sealed class CngDeviceKey : IDeviceKey
{
    private readonly CngKey _key;
    private readonly ECDsaCng _ecdsa;

    public CngDeviceKey(CngKey key, string protection)
    {
        _key = key;
        _ecdsa = new ECDsaCng(key);
        KeyProtection = protection;
        PublicKey = PublicKeyJwk.FromParameters(_ecdsa.ExportParameters(false));
    }

    public string KeyProtection { get; }

    public PublicKeyJwk PublicKey { get; }

    public byte[] Sign(byte[] data) =>
        _ecdsa.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    public void Dispose()
    {
        _ecdsa.Dispose();
        _key.Dispose();
    }
}

/// <summary>DPAPI, scope LocalMachine: the registration key is readable on this machine only (04).</summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiSecretProtector : ISecretProtector
{
    private static readonly byte[] Entropy = "sikkerheit-enrollment-key-v1"u8.ToArray();

    public byte[] Protect(byte[] secret) => ProtectedData.Protect(secret, Entropy, DataProtectionScope.LocalMachine);

    public byte[] Unprotect(byte[] protectedSecret) => ProtectedData.Unprotect(protectedSecret, Entropy, DataProtectionScope.LocalMachine);
}

/// <summary>The data directory is available to SYSTEM only (02): inheritance is removed, a single ACE is left.</summary>
[SupportedOSPlatform("windows")]
public static class DataDirectorySecurity
{
    public static void Restrict(string directory)
    {
        Directory.CreateDirectory(directory);
        var info = new DirectoryInfo(directory);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        security.AddAccessRule(new FileSystemAccessRule(
            system, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        security.SetOwner(system);
        info.SetAccessControl(security);
    }
}
