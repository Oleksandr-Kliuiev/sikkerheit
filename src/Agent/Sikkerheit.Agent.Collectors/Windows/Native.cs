using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Sikkerheit.Agent.Collectors.Windows;

/// <summary>Win32 functions of the collectors (03, "Сбор данных и источники"). Calls happen only on Windows.</summary>
[SupportedOSPlatform("windows")]
internal static unsafe partial class Native
{
    [LibraryImport("kernel32.dll", EntryPoint = "GetDiskFreeSpaceExW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetDiskFreeSpaceEx(string directory, out ulong freeAvailable, out ulong total, out ulong totalFree);

    [LibraryImport("kernel32.dll", EntryPoint = "GetVolumeNameForVolumeMountPointW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetVolumeNameForVolumeMountPoint(string mountPoint, char* volumeName, uint length);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetFirmwareType(out uint firmwareType);

    [LibraryImport("netapi32.dll", EntryPoint = "NetLocalGroupGetMembers", StringMarshalling = StringMarshalling.Utf16)]
    internal static partial int NetLocalGroupGetMembers(
        string? server, string groupName, int level, out IntPtr buffer, int preferredMaximum, out int entriesRead, out int totalEntries, ref IntPtr resume);

    [LibraryImport("netapi32.dll", EntryPoint = "NetUserModalsGet", StringMarshalling = StringMarshalling.Utf16)]
    internal static partial int NetUserModalsGet(string? server, int level, out IntPtr buffer);

    [LibraryImport("netapi32.dll", EntryPoint = "NetGetJoinInformation", StringMarshalling = StringMarshalling.Utf16)]
    internal static partial int NetGetJoinInformation(string? server, out IntPtr name, out int status);

    [LibraryImport("netapi32.dll", EntryPoint = "NetGetAadJoinInformation", StringMarshalling = StringMarshalling.Utf16)]
    internal static partial int NetGetAadJoinInformation(string? tenantId, out IntPtr joinInfo);

    [LibraryImport("netapi32.dll")]
    internal static partial void NetFreeAadJoinInformation(IntPtr joinInfo);

    [LibraryImport("netapi32.dll")]
    internal static partial int NetApiBufferFree(IntPtr buffer);

    [LibraryImport("advapi32.dll")]
    internal static partial uint LsaOpenPolicy(IntPtr systemName, ref LsaObjectAttributes attributes, uint access, out IntPtr policy);

    [LibraryImport("advapi32.dll")]
    internal static partial uint LsaQueryInformationPolicy(IntPtr policy, int informationClass, out IntPtr buffer);

    [LibraryImport("advapi32.dll")]
    internal static partial uint LsaFreeMemory(IntPtr buffer);

    [LibraryImport("advapi32.dll")]
    internal static partial uint LsaClose(IntPtr policy);

    [StructLayout(LayoutKind.Sequential)]
    internal struct LsaObjectAttributes
    {
        public uint Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LsaUnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    /// <summary>POLICY_DNS_DOMAIN_INFO (PolicyDnsDomainInformation = 12).</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct PolicyDnsDomainInfo
    {
        public LsaUnicodeString Name;
        public LsaUnicodeString DnsDomainName;
        public LsaUnicodeString DnsForestName;
        public Guid DomainGuid;
        public IntPtr Sid;
    }
}
