using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Sikkerheit.Agent.Collectors;
using Sikkerheit.Agent.Collectors.Runtime;
using Sikkerheit.Agent.Collectors.Windows;
using Sikkerheit.Agent.Protocol;
using Sikkerheit.Agent.Windows;

namespace Sikkerheit.Agent.Tests;

/// <summary>
/// Smoke tests of the Windows layer. They are skipped on macOS and Linux and run in the CI job on windows-latest. This is not SP-04:
/// there is no TPM, no domain and no third-party antivirus there (docs/dev/agent-windows-verification.md).
/// </summary>
public sealed class WindowsSmokeTests
{
    public static bool IsWindows => OperatingSystem.IsWindows();

    [Fact(SkipUnless = nameof(IsWindows), Skip = "Windows only")]
    [SupportedOSPlatform("windows")]
    public void Dpapi_protects_and_restores_a_secret_and_the_protected_form_does_not_contain_it()
    {
        var protector = new DpapiSecretProtector();
        var secret = Encoding.UTF8.GetBytes("sikk_" + new string('A', 43));

        var blob = protector.Protect(secret);

        Assert.DoesNotContain("sikk_", Encoding.Latin1.GetString(blob));
        Assert.Equal(secret, protector.Unprotect(blob));
    }

    [Fact(SkipUnless = nameof(IsWindows), Skip = "Windows only")]
    [SupportedOSPlatform("windows")]
    public void Cng_key_is_created_non_exportable_signs_in_p1363_and_is_found_again()
    {
        var store = new CngDeviceKeyStore();
        try
        {
            using var created = store.Create();
            var data = Encoding.UTF8.GetBytes("sikkerheit");
            var signature = created.Sign(data);

            using var reopened = store.Open();
            Assert.NotNull(reopened);
            Assert.Equal(created.PublicKey, reopened!.PublicKey);
            Assert.Equal(64, signature.Length);
            Assert.Contains(created.KeyProtection, new[] { "tpm", "software" });
            using var verifier = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = Base64Url.Decode(created.PublicKey.X), Y = Base64Url.Decode(created.PublicKey.Y) },
            });
            Assert.True(verifier.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        }
        finally
        {
            store.Delete();
        }
        Assert.Null(store.Open());
    }

    [Fact(SkipUnless = nameof(IsWindows), Skip = "Windows only")]
    [SupportedOSPlatform("windows")]
    public async Task Collectors_of_the_machine_return_a_fact_or_a_reason_of_the_contract_and_never_throw()
    {
        var readers = WindowsReaderFactory.Create();
        var volume = readers.OsVolume.Resolve();
        Assert.NotNull(volume);
        Assert.Matches(@"^\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\$", volume!.VolumeId);

        var items = await new CollectorRunner().RunAsync(
            CollectorSet.Create(readers), new CollectionContext(DateTimeOffset.UtcNow, volume, CancellationToken.None), CollectorLimits.Default);

        Assert.Equal(11, items.Count);
        foreach (var item in items)
        {
            Assert.True(item.Outcome.IsCollected || item.Outcome.ReasonCode is "permission_denied" or "unsupported" or "collector_timeout" or "temporary_error",
                $"{item.Collector.CheckId}: {item.Outcome.ReasonCode}");
        }
        // The inventory and the disk are there on any Windows.
        Assert.True(items.Single(i => i.Collector.CheckId == "WIN-011").Outcome.IsCollected);
        Assert.True(items.Single(i => i.Collector.CheckId == "WIN-001").Outcome.IsCollected);
    }

    [Fact(SkipUnless = nameof(IsWindows), Skip = "Windows only")]
    [SupportedOSPlatform("windows")]
    public void Machine_identity_gives_a_stable_fingerprint()
    {
        var reader = WindowsReaderFactory.Create().MachineIdentity;
        var installation = Guid.NewGuid();

        var first = MachineFingerprint.Compute(installation, reader.Read().ProductUuid, reader.Read().MachineGuid);
        var second = MachineFingerprint.Compute(installation, reader.Read().ProductUuid, reader.Read().MachineGuid);

        Assert.Equal(first, second);
        Assert.Matches("^[0-9a-f]{64}$", first);
    }
}
