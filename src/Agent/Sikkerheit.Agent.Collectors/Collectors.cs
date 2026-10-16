using System.Text.Json.Nodes;
using Sikkerheit.Agent.Collectors.Mapping;

namespace Sikkerheit.Agent.Collectors;

/// <summary>Base of the collectors: version, STA flag and one place for the check id.</summary>
public abstract class CollectorBase(string checkId, bool requiresSta = false) : ICollector
{
    public string CheckId { get; } = checkId;

    public string CollectorVersion => CollectorVersions.Current;

    public bool RequiresSta { get; } = requiresSta;

    public abstract CollectorOutcome Collect(CollectionContext context);

    protected static VolumeRef OsVolume(CollectionContext context) =>
        context.OsVolume ?? throw new CollectorException(ReasonCodes.TemporaryError, "OS volume is unknown");
}

/// <summary>WIN-001: free space of the OS volume.</summary>
public sealed class DiskSpaceCollector(IVolumeSpaceReader reader) : CollectorBase("WIN-001")
{
    public override CollectorOutcome Collect(CollectionContext context)
    {
        var space = reader.Read(OsVolume(context));
        if (space.TotalBytes < 1 || space.FreeBytes < 0 || space.FreeBytes > space.TotalBytes)
        {
            return CollectorOutcome.Unavailable(ReasonCodes.TemporaryError);
        }
        return CollectorOutcome.Collected(new JsonObject { ["totalBytes"] = space.TotalBytes, ["freeBytes"] = space.FreeBytes });
    }
}

/// <summary>WIN-002: BitLocker of the OS volume. The recovery password is never read.</summary>
public sealed class BitLockerCollector(IBitLockerReader reader) : CollectorBase("WIN-002")
{
    private static readonly string[] Conversion =
        ["fully_decrypted", "fully_encrypted", "encrypting", "decrypting", "encryption_paused", "decryption_paused"];

    private static readonly string[] Protection = ["off", "on", "unknown"];

    public override CollectorOutcome Collect(CollectionContext context)
    {
        var raw = reader.Read(OsVolume(context));
        if (raw is null)
        {
            return CollectorOutcome.Unavailable(ReasonCodes.Unsupported);
        }
        if (raw.ConversionStatus is < 0 or > 5 || raw.ProtectionStatus is < 0 or > 2 || raw.EncryptionPercentage is < 0 or > 100)
        {
            return CollectorOutcome.Unavailable(ReasonCodes.Unsupported);
        }
        return CollectorOutcome.Collected(new JsonObject
        {
            ["volumeStatus"] = Conversion[raw.ConversionStatus],
            ["protectionStatus"] = Protection[raw.ProtectionStatus],
            ["encryptionPercentage"] = raw.EncryptionPercentage,
        });
    }
}

/// <summary>WIN-003: antivirus products of Windows Security Center and the Defender object.</summary>
public sealed class AntivirusCollector(ISecurityCenterReader center, IDefenderReader defender) : CollectorBase("WIN-003")
{
    public override CollectorOutcome Collect(CollectionContext context)
    {
        var raw = defender.Read();
        var products = new JsonArray();
        foreach (var product in center.AntivirusProducts().Where(p => !SecurityProducts.IsDefenderName(p.DisplayName)))
        {
            products.Add(SecurityProducts.AntivirusItem(product));
        }
        if (raw is not null)
        {
            products.Add(SecurityProducts.DefenderItem(raw));
        }
        // 03, WIN-003: more than 10 products are not truncated; the observation is unavailable/unsupported.
        if (products.Count > SecurityProducts.MaxProducts)
        {
            return CollectorOutcome.Unavailable(ReasonCodes.Unsupported);
        }
        var defenderNode = raw is null
            ? null
            : new JsonObject
            {
                ["amRunningMode"] = SecurityProducts.AmRunningMode(raw.AmRunningMode),
                ["realTimeProtectionEnabled"] = raw.RealTimeProtectionEnabled,
            };
        return CollectorOutcome.Collected(new JsonObject { ["products"] = products, ["defender"] = defenderNode });
    }
}

/// <summary>WIN-004: age of the Defender signatures.</summary>
public sealed class DefenderSignatureCollector(IDefenderReader reader) : CollectorBase("WIN-004")
{
    public override CollectorOutcome Collect(CollectionContext context)
    {
        var raw = reader.Read();
        if (raw?.SignatureLastUpdated is not { } updated)
        {
            return CollectorOutcome.Unavailable(ReasonCodes.Unsupported);
        }
        return CollectorOutcome.Collected(new JsonObject { ["signatureLastUpdatedAt"] = Iso.Format(updated) });
    }
}

/// <summary>WIN-005: Windows Firewall profiles and third-party firewalls.</summary>
public sealed class FirewallCollector(IFirewallReader reader, ISecurityCenterReader center) : CollectorBase("WIN-005", requiresSta: true)
{
    public override CollectorOutcome Collect(CollectionContext context)
    {
        var profiles = reader.Read();
        var products = new JsonArray();
        foreach (var product in center.FirewallProducts())
        {
            products.Add(SecurityProducts.FirewallItem(product));
        }
        if (products.Count > SecurityProducts.MaxProducts)
        {
            return CollectorOutcome.Unavailable(ReasonCodes.Unsupported);
        }
        return CollectorOutcome.Collected(new JsonObject
        {
            ["domainEnabled"] = profiles.Domain,
            ["privateEnabled"] = profiles.Private,
            ["publicEnabled"] = profiles.Public,
            ["firewallProducts"] = products,
        });
    }
}

/// <summary>WIN-006: Windows Update service.</summary>
public sealed class UpdateServiceCollector(IUpdateReader reader) : CollectorBase("WIN-006", requiresSta: true)
{
    public override CollectorOutcome Collect(CollectionContext context)
    {
        var state = reader.Read();
        return CollectorOutcome.Collected(new JsonObject
        {
            ["lastSearchSuccessAt"] = Iso.FormatOrNull(state.LastSearchSuccess),
            ["lastInstallSuccessAt"] = Iso.FormatOrNull(state.LastInstallSuccess),
            ["wsusConfigured"] = state.WsusConfigured,
        });
    }
}

/// <summary>WIN-007: pending reboot.</summary>
public sealed class RebootCollector(IRebootReader reader) : CollectorBase("WIN-007", requiresSta: true)
{
    public override CollectorOutcome Collect(CollectionContext context)
    {
        var state = reader.Read();
        return CollectorOutcome.Collected(new JsonObject
        {
            ["rebootRequired"] = state.RebootRequired,
            ["lastBootAt"] = Iso.Format(state.LastBoot),
        });
    }
}

/// <summary>WIN-008: direct members of the local Administrators group.</summary>
public sealed class LocalAdminCollector(ILocalAdminReader reader) : CollectorBase("WIN-008")
{
    public override CollectorOutcome Collect(CollectionContext context)
    {
        var raw = reader.Read();
        var sids = raw.MemberSids.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (sids.Count > AdminMembers.MaxMembers)
        {
            return CollectorOutcome.Unavailable(ReasonCodes.Unsupported);
        }
        var members = new JsonArray();
        foreach (var sid in sids)
        {
            members.Add(AdminMembers.Describe(sid, raw.MachineSid, raw.JoinedDomainSid));
        }
        return CollectorOutcome.Collected(new JsonObject { ["members"] = members, ["membershipScope"] = "direct_members" });
    }
}

/// <summary>WIN-009: Secure Boot.</summary>
public sealed class SecureBootCollector(ISecureBootReader reader) : CollectorBase("WIN-009")
{
    public override CollectorOutcome Collect(CollectionContext context)
    {
        var raw = reader.Read();
        if (raw.Firmware == FirmwareKind.LegacyBios)
        {
            return CollectorOutcome.Collected(new JsonObject { ["enabled"] = false, ["platform"] = "legacy_bios" });
        }
        return raw.Enabled is { } enabled
            ? CollectorOutcome.Collected(new JsonObject { ["enabled"] = enabled, ["platform"] = "uefi" })
            : CollectorOutcome.Unavailable(ReasonCodes.Unsupported);
    }
}

/// <summary>WIN-010: join of the device to Entra ID and the domain. Workplace join is not observed.</summary>
public sealed class JoinCollector(IJoinReader reader) : CollectorBase("WIN-010")
{
    public override CollectorOutcome Collect(CollectionContext context)
    {
        var raw = reader.Read();
        var joinType = (raw.EntraJoined, raw.DomainJoined) switch
        {
            (true, true) => "hybrid_joined",
            (true, false) => "entra_joined",
            (false, true) => "domain_joined",
            _ => "not_joined",
        };
        var entra = raw.EntraJoined;
        return CollectorOutcome.Collected(new JsonObject
        {
            ["joinType"] = joinType,
            ["tenantId"] = entra && Guid.TryParse(raw.TenantId, out var tenant) ? tenant.ToString("D") : null,
            ["entraDeviceId"] = entra && Guid.TryParse(raw.EntraDeviceId, out var device) ? device.ToString("D") : null,
        });
    }
}

/// <summary>WIN-011: operating system inventory.</summary>
public sealed class OsInventoryCollector(IOsInventoryReader reader) : CollectorBase("WIN-011")
{
    public override CollectorOutcome Collect(CollectionContext context)
    {
        var raw = reader.Read();
        if (raw.Architecture is not ("x64" or "arm64") || raw.Build < 1 || raw.Ubr < 0 || raw.EditionId.Length == 0)
        {
            return CollectorOutcome.Unavailable(ReasonCodes.Unsupported);
        }
        // Older builds have no DisplayVersion: ReleaseId replaces it (03, WIN-011).
        var version = string.IsNullOrWhiteSpace(raw.DisplayVersion) ? raw.ReleaseId : raw.DisplayVersion;
        return CollectorOutcome.Collected(new JsonObject
        {
            ["editionId"] = raw.EditionId,
            ["displayVersion"] = string.IsNullOrWhiteSpace(version) ? null : version,
            ["build"] = raw.Build,
            ["ubr"] = raw.Ubr,
            ["architecture"] = raw.Architecture,
        });
    }
}

/// <summary>The fixed set of collectors: WIN-001…WIN-011. A collector cannot be added at run time (ADR-08).</summary>
public static class CollectorSet
{
    public static IReadOnlyList<ICollector> Create(WindowsReaders readers) =>
    [
        new DiskSpaceCollector(readers.VolumeSpace),
        new BitLockerCollector(readers.BitLocker),
        new AntivirusCollector(readers.SecurityCenter, readers.Defender),
        new DefenderSignatureCollector(readers.Defender),
        new FirewallCollector(readers.Firewall, readers.SecurityCenter),
        new UpdateServiceCollector(readers.Updates),
        new RebootCollector(readers.Reboot),
        new LocalAdminCollector(readers.LocalAdmins),
        new SecureBootCollector(readers.SecureBoot),
        new JoinCollector(readers.Join),
        new OsInventoryCollector(readers.OsInventory),
    ];
}
