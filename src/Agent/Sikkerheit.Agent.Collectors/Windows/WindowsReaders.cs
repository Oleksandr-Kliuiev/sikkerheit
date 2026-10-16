using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32;

namespace Sikkerheit.Agent.Collectors.Windows;

/// <summary>Creates the readers of the current machine. Only Windows is supported; the content of this folder is checked by SP-04.</summary>
public static class WindowsReaderFactory
{
    public static WindowsReaders Create()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("The agent collects facts on Windows only");
        }
        return CreateWindows();
    }

    [SupportedOSPlatform("windows")]
    private static WindowsReaders CreateWindows() => new(
        new VolumeSpaceReader(), new BitLockerReader(), new SecurityCenterReader(), new DefenderReader(), new FirewallReader(),
        new UpdateReader(), new RebootReader(), new LocalAdminReader(), new SecureBootReader(), new JoinReader(),
        new OsInventoryReader(), new MachineIdentityReader(), new OsVolumeResolver());
}

[SupportedOSPlatform("windows")]
internal sealed unsafe class OsVolumeResolver : IOsVolumeResolver
{
    public VolumeRef? Resolve()
    {
        var root = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.System));
        if (string.IsNullOrEmpty(root))
        {
            return null;
        }
        var buffer = stackalloc char[64];
        if (!Native.GetVolumeNameForVolumeMountPoint(root, buffer, 64))
        {
            return null;
        }
        var mount = root.Length >= 2 && root[1] == ':' ? root[..2].ToUpperInvariant() : null;
        return new VolumeRef(new string(buffer), mount);
    }
}

[SupportedOSPlatform("windows")]
internal sealed class VolumeSpaceReader : IVolumeSpaceReader
{
    public VolumeSpace Read(VolumeRef volume)
    {
        if (!Native.GetDiskFreeSpaceEx(volume.VolumeId, out _, out var total, out var free))
        {
            throw new IOException("GetDiskFreeSpaceEx failed: " + Marshal.GetLastWin32Error());
        }
        return new VolumeSpace(checked((long)total), checked((long)free));
    }
}

/// <summary>Win32_EncryptableVolume through its methods. The recovery password is never read.</summary>
[SupportedOSPlatform("windows")]
internal sealed class BitLockerReader : IBitLockerReader
{
    private const string Scope = @"root\CIMV2\Security\MicrosoftVolumeEncryption";

    public BitLockerRaw? Read(VolumeRef volume)
    {
        var id = volume.VolumeId.Replace(@"\", @"\\", StringComparison.Ordinal).Replace("'", @"\'", StringComparison.Ordinal);
        var rows = Wmi.Select(Scope, $"SELECT * FROM Win32_EncryptableVolume WHERE DeviceID = '{id}'", row =>
        {
            var conversion = row.InvokeMethod("GetConversionStatus", null, null);
            var protection = row.InvokeMethod("GetProtectionStatus", null, null);
            return new BitLockerRaw(
                Convert.ToInt32(conversion["ConversionStatus"], System.Globalization.CultureInfo.InvariantCulture),
                Convert.ToInt32(protection["ProtectionStatus"], System.Globalization.CultureInfo.InvariantCulture),
                Convert.ToInt32(conversion["EncryptionPercentage"], System.Globalization.CultureInfo.InvariantCulture));
        });
        return rows.Count == 0 ? null : rows[0];
    }
}

[SupportedOSPlatform("windows")]
internal sealed class SecurityCenterReader : ISecurityCenterReader
{
    private const string Scope = @"root\SecurityCenter2";

    public IReadOnlyList<SecurityProductRaw> AntivirusProducts() => Read("AntiVirusProduct");

    public IReadOnlyList<SecurityProductRaw> FirewallProducts() => Read("FirewallProduct");

    private static List<SecurityProductRaw> Read(string cls)
    {
        // The namespace exists on client editions only; on a server edition the check is "unsupported" by the matrix of 03.
        try
        {
            return Wmi.Select(Scope, $"SELECT displayName, productState FROM {cls}", row => new SecurityProductRaw(
                Convert.ToString(row["displayName"], System.Globalization.CultureInfo.InvariantCulture) ?? "unknown",
                Convert.ToUInt32(row["productState"], System.Globalization.CultureInfo.InvariantCulture)));
        }
        catch (ManagementException exception)
        {
            throw new CollectorException(ReasonCodes.TemporaryError, "Security Center query failed", exception);
        }
    }
}

[SupportedOSPlatform("windows")]
internal sealed class DefenderReader : IDefenderReader
{
    public DefenderRaw? Read()
    {
        var rows = Wmi.Select(@"root\Microsoft\Windows\Defender",
            "SELECT AMRunningMode, RealTimeProtectionEnabled, AntivirusEnabled, AntivirusSignatureLastUpdated FROM MSFT_MpComputerStatus",
            row => new DefenderRaw(
                Convert.ToString(row["AMRunningMode"], System.Globalization.CultureInfo.InvariantCulture) ?? "",
                row["RealTimeProtectionEnabled"] is true,
                row["AntivirusEnabled"] is true,
                Wmi.Date(row["AntivirusSignatureLastUpdated"])));
        return rows.Count == 0 ? null : rows[0];
    }
}

/// <summary>Late-bound COM: the interop assemblies are not needed and nothing is loaded from disk besides system libraries.</summary>
[SupportedOSPlatform("windows")]
internal static class Com
{
    public static object Create(string progId)
    {
        var type = Type.GetTypeFromProgID(progId, throwOnError: false)
            ?? throw new CollectorException(ReasonCodes.Unsupported, "COM class is not registered: " + progId);
        return Activator.CreateInstance(type) ?? throw new CollectorException(ReasonCodes.TemporaryError, "COM object not created: " + progId);
    }

    public static object? Get(object target, string property, params object[] args) =>
        target.GetType().InvokeMember(property, System.Reflection.BindingFlags.GetProperty, null, target, args,
            System.Globalization.CultureInfo.InvariantCulture);

    public static void Release(object? target)
    {
        if (target is not null && Marshal.IsComObject(target))
        {
            Marshal.FinalReleaseComObject(target);
        }
    }

    public static DateTimeOffset? Date(object? value) =>
        value is DateTime date && date.Year >= 2000 ? new DateTimeOffset(date.ToUniversalTime()) : null;
}

[SupportedOSPlatform("windows")]
internal sealed class FirewallReader : IFirewallReader
{
    public FirewallProfiles Read()
    {
        var policy = Com.Create("HNetCfg.FwPolicy2");
        try
        {
            // NET_FW_PROFILE2_DOMAIN = 1, PRIVATE = 2, PUBLIC = 4.
            return new FirewallProfiles(
                Com.Get(policy, "FirewallEnabled", 1) is true,
                Com.Get(policy, "FirewallEnabled", 2) is true,
                Com.Get(policy, "FirewallEnabled", 4) is true);
        }
        finally
        {
            Com.Release(policy);
        }
    }
}

[SupportedOSPlatform("windows")]
internal sealed class UpdateReader : IUpdateReader
{
    private const string Policies = @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";

    public UpdateState Read()
    {
        var auto = Com.Create("Microsoft.Update.AutoUpdate");
        object? results = null;
        try
        {
            results = Com.Get(auto, "Results");
            return new UpdateState(
                Com.Date(Com.Get(results!, "LastSearchSuccessDate")),
                Com.Date(Com.Get(results!, "LastInstallationSuccessDate")),
                WsusConfigured());
        }
        finally
        {
            Com.Release(results);
            Com.Release(auto);
        }
    }

    private static bool WsusConfigured()
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var policy = root.OpenSubKey(Policies);
        using var auto = root.OpenSubKey(Policies + @"\AU");
        var server = policy?.GetValue("WUServer") as string;
        return !string.IsNullOrWhiteSpace(server) && auto?.GetValue("UseWUServer") is 1;
    }
}

[SupportedOSPlatform("windows")]
internal sealed class RebootReader : IRebootReader
{
    public RebootState Read()
    {
        var info = Com.Create("Microsoft.Update.SystemInfo");
        try
        {
            var required = Com.Get(info, "RebootRequired") is true;
            var boot = Wmi.Select(@"root\CIMV2", "SELECT LastBootUpTime FROM Win32_OperatingSystem",
                row => Wmi.Date(row["LastBootUpTime"]));
            if (boot.Count == 0 || boot[0] is not { } last)
            {
                throw new CollectorException(ReasonCodes.TemporaryError, "LastBootUpTime is unavailable");
            }
            return new RebootState(required, last);
        }
        finally
        {
            Com.Release(info);
        }
    }
}

/// <summary>Direct members of the local Administrators group by the well-known SID S-1-5-32-544; classes via LSA and SID structure.</summary>
[SupportedOSPlatform("windows")]
internal sealed class LocalAdminReader : ILocalAdminReader
{
    private const int Success = 0;

    public AdminGroupRaw Read()
    {
        var group = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var account = group.Translate(typeof(NTAccount)).Value;
        var name = account[(account.IndexOf('\\', StringComparison.Ordinal) + 1)..];
        var members = new List<string>();
        var resume = IntPtr.Zero;
        var status = Native.NetLocalGroupGetMembers(null, name, 0, out var buffer, -1, out var read, out _, ref resume);
        if (status != Success)
        {
            throw status == 5
                ? new CollectorException(ReasonCodes.PermissionDenied, "NetLocalGroupGetMembers: access denied")
                : new IOException("NetLocalGroupGetMembers failed: " + status);
        }
        try
        {
            for (var i = 0; i < read; i++)
            {
                // LOCALGROUP_MEMBERS_INFO_0 is one PSID.
                var sid = Marshal.ReadIntPtr(buffer, i * IntPtr.Size);
                members.Add(new SecurityIdentifier(sid).Value);
            }
        }
        finally
        {
            Native.NetApiBufferFree(buffer);
        }
        return new AdminGroupRaw(members, MachineSid(), DomainSid());
    }

    /// <summary>SID of the local account domain: USER_MODALS_INFO_2.usrmod2_domain_id.</summary>
    private static string? MachineSid()
    {
        if (Native.NetUserModalsGet(null, 2, out var buffer) != Success)
        {
            return null;
        }
        try
        {
            var sid = Marshal.ReadIntPtr(buffer, IntPtr.Size);
            return sid == IntPtr.Zero ? null : new SecurityIdentifier(sid).Value;
        }
        finally
        {
            Native.NetApiBufferFree(buffer);
        }
    }

    /// <summary>SID of the domain of the computer: LSA PolicyDnsDomainInformation, the domain controller is not contacted.</summary>
    private static string? DomainSid()
    {
        var attributes = new Native.LsaObjectAttributes { Length = (uint)Marshal.SizeOf<Native.LsaObjectAttributes>() };
        if (Native.LsaOpenPolicy(IntPtr.Zero, ref attributes, 0x1, out var policy) != 0)
        {
            return null;
        }
        try
        {
            if (Native.LsaQueryInformationPolicy(policy, 12, out var buffer) != 0)
            {
                return null;
            }
            try
            {
                var info = Marshal.PtrToStructure<Native.PolicyDnsDomainInfo>(buffer);
                return info.Sid == IntPtr.Zero ? null : new SecurityIdentifier(info.Sid).Value;
            }
            finally
            {
                Native.LsaFreeMemory(buffer);
            }
        }
        finally
        {
            Native.LsaClose(policy);
        }
    }
}

[SupportedOSPlatform("windows")]
internal sealed class SecureBootReader : ISecureBootReader
{
    public SecureBootRaw Read()
    {
        if (!Native.GetFirmwareType(out var type))
        {
            throw new IOException("GetFirmwareType failed: " + Marshal.GetLastWin32Error());
        }
        // FirmwareTypeBios = 1, FirmwareTypeUefi = 2.
        if (type == 1)
        {
            return new SecureBootRaw(FirmwareKind.LegacyBios, false);
        }
        if (type != 2)
        {
            throw new CollectorException(ReasonCodes.Unsupported, "Unknown firmware type " + type);
        }
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var state = root.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
        return new SecureBootRaw(FirmwareKind.Uefi, state?.GetValue("UEFISecureBootEnabled") is int value ? value == 1 : null);
    }
}

[SupportedOSPlatform("windows")]
internal sealed class JoinReader : IJoinReader
{
    private const int NetSetupDomainName = 3;

    public JoinRaw Read()
    {
        var domain = false;
        if (Native.NetGetJoinInformation(null, out var name, out var status) == 0)
        {
            domain = status == NetSetupDomainName;
            Native.NetApiBufferFree(name);
        }
        var hr = Native.NetGetAadJoinInformation(null, out var info);
        if (hr != 0 || info == IntPtr.Zero)
        {
            return new JoinRaw(domain, false, null, null);
        }
        try
        {
            // DSREG_JOIN_INFO: joinType (padded to a pointer), pJoinCertificate, pszDeviceId, pszIdpDomain, pszTenantId.
            var joinType = Marshal.ReadInt32(info);
            var device = Marshal.PtrToStringUni(Marshal.ReadIntPtr(info, IntPtr.Size * 2));
            var tenant = Marshal.PtrToStringUni(Marshal.ReadIntPtr(info, IntPtr.Size * 4));
            // DSREG_DEVICE_JOIN = 1; DSREG_WORKPLACE_JOIN (2) is a user-level registration and is not observed.
            return new JoinRaw(domain, joinType == 1, tenant, device);
        }
        finally
        {
            Native.NetFreeAadJoinInformation(info);
        }
    }
}

[SupportedOSPlatform("windows")]
internal sealed class OsInventoryReader : IOsInventoryReader
{
    public OsInventoryRaw Read()
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = root.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            ?? throw new CollectorException(ReasonCodes.Unsupported, "CurrentVersion key is missing");
        var build = int.TryParse(key.GetValue("CurrentBuild") as string ?? key.GetValue("CurrentBuildNumber") as string,
            System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var value) ? value : 0;
        var architecture = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture switch
        {
            Architecture.X64 => "x64",
            Architecture.Arm64 => "arm64",
            var other => other.ToString().ToLowerInvariant(),
        };
        return new OsInventoryRaw(
            key.GetValue("EditionID") as string ?? "",
            key.GetValue("DisplayVersion") as string,
            key.GetValue("ReleaseId") as string,
            build,
            key.GetValue("UBR") is int ubr ? ubr : 0,
            architecture);
    }
}

[SupportedOSPlatform("windows")]
internal sealed class MachineIdentityReader : IMachineIdentityReader
{
    public MachineIdentityRaw Read()
    {
        var uuid = Wmi.Select(@"root\CIMV2", "SELECT UUID FROM Win32_ComputerSystemProduct",
            row => Convert.ToString(row["UUID"], System.Globalization.CultureInfo.InvariantCulture));
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = root.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
        var guid = key?.GetValue("MachineGuid") as string
            ?? throw new CollectorException(ReasonCodes.TemporaryError, "MachineGuid is missing");
        return new MachineIdentityRaw(uuid.Count == 0 ? null : uuid[0], guid);
    }
}
