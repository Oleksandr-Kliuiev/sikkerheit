using Sikkerheit.Agent.Collectors;

namespace Sikkerheit.Agent.Tests;

internal static class FakeReaders
{
    private static readonly DateTimeOffset At = new(2026, 10, 14, 6, 0, 0, TimeSpan.Zero);

    public static WindowsReaders Good() => new(
        new FixedSpace(256_000_000_000, 18_000_000_000),
        new FakeBitLocker(new BitLockerRaw(1, 0, 100)),
        new FakeCenter([new SecurityProductRaw("Windows Defender", 0x061100), new SecurityProductRaw("VendorX Antivirus", 0x061000)],
            [new SecurityProductRaw("VendorX Firewall", 0x061000)]),
        new FakeDefender(new DefenderRaw("Normal", true, true, At)),
        new FakeFirewall(new FirewallProfiles(true, true, false)),
        new FakeUpdates(new UpdateState(At, At.AddHours(-3), false)),
        new FakeReboot(new RebootState(false, At.AddHours(-5))),
        new FakeAdmins(new AdminGroupRaw(
            ["S-1-5-21-1000-2000-3000-500", "S-1-5-21-1000-2000-3000-1001", "S-1-12-1-1-2-3-4", "S-1-5-21-7-8-9-512"],
            "S-1-5-21-1000-2000-3000", "S-1-5-21-7-8-9")),
        new FakeSecureBoot(new SecureBootRaw(FirmwareKind.Uefi, true)),
        new FakeJoin(new JoinRaw(false, true, "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333")),
        new FakeInventory(new OsInventoryRaw("Professional", "25H2", "2009", 26200, 9711, "x64")),
        new FakeIdentity(),
        new FakeVolume());
}

internal sealed class FakeBitLocker(BitLockerRaw? value) : IBitLockerReader
{
    public BitLockerRaw? Read(VolumeRef volume) => value;
}

internal sealed class FakeFirewall(FirewallProfiles value) : IFirewallReader
{
    public FirewallProfiles Read() => value;
}

internal sealed class FakeUpdates(UpdateState value) : IUpdateReader
{
    public UpdateState Read() => value;
}

internal sealed class FakeReboot(RebootState value) : IRebootReader
{
    public RebootState Read() => value;
}

internal sealed class FakeAdmins(AdminGroupRaw value) : ILocalAdminReader
{
    public AdminGroupRaw Read() => value;
}

internal sealed class FakeSecureBoot(SecureBootRaw value) : ISecureBootReader
{
    public SecureBootRaw Read() => value;
}

internal sealed class FakeJoin(JoinRaw value) : IJoinReader
{
    public JoinRaw Read() => value;
}

internal sealed class FakeInventory(OsInventoryRaw value) : IOsInventoryReader
{
    public OsInventoryRaw Read() => value;
}
