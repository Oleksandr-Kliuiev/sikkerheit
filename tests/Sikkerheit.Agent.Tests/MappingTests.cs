using Sikkerheit.Agent.Collectors;
using Sikkerheit.Agent.Collectors.Mapping;

namespace Sikkerheit.Agent.Tests;

/// <summary>Pure mappings of the raw Windows facts to the contract: everything the collectors decide without Windows.</summary>
public sealed class MappingTests
{
    private static readonly CollectionContext Context = new(AgentFixture.Start, FakeVolume.Os, CancellationToken.None);

    [Theory]
    [InlineData(0x061000u, "on")]
    [InlineData(0x060000u, "off")]
    [InlineData(0x060100u, "snoozed")]
    [InlineData(0x061100u, "expired")]
    [InlineData(0x063300u, "unknown")]
    public void Security_center_state_is_decoded_by_the_table_of_sp_04(uint raw, string expected) =>
        Assert.Equal(expected, SecurityProducts.ProductState(raw));

    [Fact]
    public void Unknown_product_state_goes_to_the_evidence_with_the_raw_state_as_the_schema_requires()
    {
        var item = SecurityProducts.AntivirusItem(new SecurityProductRaw("Strange AV", 0x063300));

        Assert.Equal("unknown", item["productState"]!.GetValue<string>());
        Assert.Equal(0x063300, item["rawState"]!.GetValue<long>());
        Assert.Null(SecurityProducts.AntivirusItem(new SecurityProductRaw("AV", 0x061000))["rawState"]);
    }

    [Theory]
    [InlineData("Normal", "normal")]
    [InlineData("Passive mode", "passive")]
    [InlineData("EDR Block Mode", "edr_block")]
    [InlineData("SxS Passive Mode", "sxs_passive")]
    [InlineData("Not running", "not_running")]
    [InlineData("something new", "other")]
    public void Defender_running_mode_is_mapped_to_the_closed_enumeration(string raw, string expected) =>
        Assert.Equal(expected, SecurityProducts.AmRunningMode(raw));

    [Fact]
    public void Defender_in_the_security_center_list_is_replaced_with_one_item_of_the_defender_source()
    {
        var center = new FakeCenter([new SecurityProductRaw("Windows Defender", 0x061000), new SecurityProductRaw("VendorX", 0x061000)]);
        var defender = new FakeDefender(new DefenderRaw("Normal", true, true, AgentFixture.Start));

        var evidence = new AntivirusCollector(center, defender).Collect(Context).Evidence!;
        var products = evidence["products"]!.AsArray();

        Assert.Equal(2, products.Count);
        Assert.Single(products, p => p!["statusSource"]!.GetValue<string>() == "defender");
        Assert.Equal("normal", evidence["defender"]!["amRunningMode"]!.GetValue<string>());
    }

    [Fact]
    public void Bitlocker_reference_case_of_03_fully_encrypted_with_protection_off()
    {
        var outcome = new BitLockerCollector(new FakeBitLocker(new BitLockerRaw(1, 0, 100))).Collect(Context);

        Assert.Equal("fully_encrypted", outcome.Evidence!["volumeStatus"]!.GetValue<string>());
        Assert.Equal("off", outcome.Evidence["protectionStatus"]!.GetValue<string>());
        Assert.Equal(100, outcome.Evidence["encryptionPercentage"]!.GetValue<int>());
    }

    [Theory]
    [InlineData(0, 2, "fully_decrypted", "unknown")]
    [InlineData(2, 1, "encrypting", "on")]
    [InlineData(4, 1, "encryption_paused", "on")]
    public void Bitlocker_codes_are_mapped(int conversion, int protection, string status, string protectionName)
    {
        var outcome = new BitLockerCollector(new FakeBitLocker(new BitLockerRaw(conversion, protection, 42))).Collect(Context);

        Assert.Equal(status, outcome.Evidence!["volumeStatus"]!.GetValue<string>());
        Assert.Equal(protectionName, outcome.Evidence["protectionStatus"]!.GetValue<string>());
    }

    [Fact]
    public void Bitlocker_is_unsupported_when_the_edition_has_no_provider_and_for_a_code_outside_the_tables()
    {
        Assert.Equal("unsupported", new BitLockerCollector(new FakeBitLocker(null)).Collect(Context).ReasonCode);
        Assert.Equal("unsupported", new BitLockerCollector(new FakeBitLocker(new BitLockerRaw(9, 0, 1))).Collect(Context).ReasonCode);
    }

    [Fact]
    public void Disk_space_with_free_greater_than_total_is_not_collected()
    {
        Assert.Equal("temporary_error", new DiskSpaceCollector(new FixedSpace(10, 11)).Collect(Context).ReasonCode);
    }

    [Fact]
    public void Volume_collectors_need_the_os_volume_and_do_not_invent_one()
    {
        var withoutVolume = new CollectionContext(AgentFixture.Start, null, CancellationToken.None);

        Assert.Throws<CollectorException>(() => new DiskSpaceCollector(new FixedSpace(1, 1)).Collect(withoutVolume));
    }

    [Theory]
    [InlineData("S-1-5-21-1000-2000-3000-500", "builtin_administrator", 500)]
    [InlineData("S-1-5-21-1000-2000-3000-1001", "local_account", 1001)]
    [InlineData("S-1-5-21-7-8-9-512", "domain", 512)]
    [InlineData("S-1-5-21-5-5-5-1100", "unknown", null)]
    [InlineData("S-1-12-1-1-2-3-4", "entra", null)]
    [InlineData("S-1-5-32-544", "well_known", null)]
    [InlineData("S-1-1-0", "well_known", null)]
    [InlineData("S-1-9-9-9", "unknown", null)]
    public void Members_of_the_administrators_group_are_classified_by_the_sid_of_the_machine_and_of_the_domain(string sid, string kind, int? rid)
    {
        var (actualKind, actualRid) = AdminMembers.Classify(sid, "S-1-5-21-1000-2000-3000", "S-1-5-21-7-8-9");

        Assert.Equal(kind, actualKind);
        Assert.Equal(rid, actualRid);
    }

    [Fact]
    public void More_than_100_members_of_the_group_are_unsupported_and_duplicates_are_merged()
    {
        var many = Enumerable.Range(1, 101).Select(i => $"S-1-5-21-1000-2000-3000-{1000 + i}").ToList();
        var tooMany = new LocalAdminCollector(new FakeAdmins(new AdminGroupRaw(many, "S-1-5-21-1000-2000-3000", null))).Collect(Context);
        var duplicates = new LocalAdminCollector(new FakeAdmins(new AdminGroupRaw(["S-1-5-32-544", "s-1-5-32-544"], null, null))).Collect(Context);

        Assert.Equal("unsupported", tooMany.ReasonCode);
        Assert.Single(duplicates.Evidence!["members"]!.AsArray());
    }

    [Theory]
    [InlineData(true, true, "hybrid_joined")]
    [InlineData(true, false, "entra_joined")]
    [InlineData(false, true, "domain_joined")]
    [InlineData(false, false, "not_joined")]
    public void Join_type_combines_the_entra_and_the_domain_join(bool entra, bool domain, string expected)
    {
        var raw = new JoinRaw(domain, entra, "22222222-2222-4222-8222-222222222222", "not a guid");
        var evidence = new JoinCollector(new FakeJoin(raw)).Collect(Context).Evidence!;

        Assert.Equal(expected, evidence["joinType"]!.GetValue<string>());
        Assert.Equal(entra ? "22222222-2222-4222-8222-222222222222" : null, evidence["tenantId"]?.GetValue<string>());
        Assert.Null(evidence["entraDeviceId"]); // a value that is not a guid is not passed on
    }

    [Fact]
    public void Os_inventory_uses_the_release_id_when_there_is_no_display_version_and_rejects_an_unknown_architecture()
    {
        var old = new OsInventoryCollector(new FakeInventory(new OsInventoryRaw("Professional", null, "1809", 17763, 5000, "x64"))).Collect(Context);
        var strange = new OsInventoryCollector(new FakeInventory(new OsInventoryRaw("Professional", "25H2", null, 26200, 1, "x86"))).Collect(Context);

        Assert.Equal("1809", old.Evidence!["displayVersion"]!.GetValue<string>());
        Assert.Equal("unsupported", strange.ReasonCode);
    }

    [Fact]
    public void Secure_boot_on_legacy_bios_is_disabled_and_an_unreadable_uefi_state_is_unsupported()
    {
        var legacy = new SecureBootCollector(new FakeSecureBoot(new SecureBootRaw(FirmwareKind.LegacyBios, null))).Collect(Context);
        var unreadable = new SecureBootCollector(new FakeSecureBoot(new SecureBootRaw(FirmwareKind.Uefi, null))).Collect(Context);

        Assert.False(legacy.Evidence!["enabled"]!.GetValue<bool>());
        Assert.Equal("legacy_bios", legacy.Evidence["platform"]!.GetValue<string>());
        Assert.Equal("unsupported", unreadable.ReasonCode);
    }

    [Fact]
    public void The_fixed_set_of_collectors_is_win_001_to_win_011_once_each()
    {
        var ids = CollectorSet.Create(FakeReaders.Good()).Select(c => c.CheckId).ToList();

        Assert.Equal(StubCollectors.CheckIds, ids);
    }

    [Fact]
    public void Windows_readers_are_not_created_on_other_platforms()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        Assert.Throws<PlatformNotSupportedException>(Collectors.Windows.WindowsReaderFactory.Create);
    }
}
