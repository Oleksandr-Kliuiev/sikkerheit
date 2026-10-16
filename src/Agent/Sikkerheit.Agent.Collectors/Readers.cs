namespace Sikkerheit.Agent.Collectors;

// Raw readers of Windows facts. Implementations live in Windows/ and run only on Windows; tests substitute them.
// A reader throws on failure; CollectorErrors maps the exception to the reason of the unavailable observation.

public sealed record VolumeSpace(long TotalBytes, long FreeBytes);

public interface IVolumeSpaceReader
{
    VolumeSpace Read(VolumeRef volume);
}

/// <summary>Win32_EncryptableVolume: ConversionStatus (0-5), ProtectionStatus (0-2), EncryptionPercentage.</summary>
public sealed record BitLockerRaw(int ConversionStatus, int ProtectionStatus, int EncryptionPercentage);

public interface IBitLockerReader
{
    /// <summary>Null when the volume is unknown to the BitLocker provider (feature absent in the edition).</summary>
    BitLockerRaw? Read(VolumeRef volume);
}

/// <summary>Product of Windows Security Center: display name and the raw productState.</summary>
public sealed record SecurityProductRaw(string DisplayName, uint ProductState);

public interface ISecurityCenterReader
{
    IReadOnlyList<SecurityProductRaw> AntivirusProducts();

    IReadOnlyList<SecurityProductRaw> FirewallProducts();
}

/// <summary>MSFT_MpComputerStatus; <c>null</c> from <see cref="IDefenderReader.Read"/> means the class is absent.</summary>
public sealed record DefenderRaw(
    string AmRunningMode, bool RealTimeProtectionEnabled, bool AntivirusEnabled, DateTimeOffset? SignatureLastUpdated);

public interface IDefenderReader
{
    DefenderRaw? Read();
}

public sealed record FirewallProfiles(bool Domain, bool Private, bool Public);

public interface IFirewallReader
{
    FirewallProfiles Read();
}

public sealed record UpdateState(DateTimeOffset? LastSearchSuccess, DateTimeOffset? LastInstallSuccess, bool WsusConfigured);

public interface IUpdateReader
{
    UpdateState Read();
}

public sealed record RebootState(bool RebootRequired, DateTimeOffset LastBoot);

public interface IRebootReader
{
    RebootState Read();
}

/// <summary>SID of a direct member of the local Administrators group.</summary>
public sealed record AdminGroupRaw(IReadOnlyList<string> MemberSids, string? MachineSid, string? JoinedDomainSid);

public interface ILocalAdminReader
{
    AdminGroupRaw Read();
}

public enum FirmwareKind
{
    LegacyBios,
    Uefi,
}

/// <summary>Firmware type and the Secure Boot flag (null when the UEFI variable cannot be read).</summary>
public sealed record SecureBootRaw(FirmwareKind Firmware, bool? Enabled);

public interface ISecureBootReader
{
    SecureBootRaw Read();
}

public enum JoinKind
{
    None,
    Domain,
    EntraDevice,
}

public sealed record JoinRaw(bool DomainJoined, bool EntraJoined, string? TenantId, string? EntraDeviceId);

public interface IJoinReader
{
    JoinRaw Read();
}

public sealed record OsInventoryRaw(string EditionId, string? DisplayVersion, string? ReleaseId, int Build, int Ubr, string Architecture);

public interface IOsInventoryReader
{
    OsInventoryRaw Read();
}

/// <summary>Inputs of the machine fingerprint (05, "Субъекты и идентичность устройства").</summary>
public sealed record MachineIdentityRaw(string? ProductUuid, string MachineGuid);

public interface IMachineIdentityReader
{
    MachineIdentityRaw Read();
}

/// <summary>Resolves the OS volume independently of the collectors, so a collector failure keeps the same subject.</summary>
public interface IOsVolumeResolver
{
    VolumeRef? Resolve();
}

/// <summary>Set of readers of the current platform.</summary>
public sealed record WindowsReaders(
    IVolumeSpaceReader VolumeSpace,
    IBitLockerReader BitLocker,
    ISecurityCenterReader SecurityCenter,
    IDefenderReader Defender,
    IFirewallReader Firewall,
    IUpdateReader Updates,
    IRebootReader Reboot,
    ILocalAdminReader LocalAdmins,
    ISecureBootReader SecureBoot,
    IJoinReader Join,
    IOsInventoryReader OsInventory,
    IMachineIdentityReader MachineIdentity,
    IOsVolumeResolver OsVolume);
