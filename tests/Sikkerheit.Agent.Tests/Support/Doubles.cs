using System.Security.Cryptography;
using Sikkerheit.Agent.Collectors;
using Sikkerheit.Agent.Keys;
using Sikkerheit.Agent.Protocol;
using Sikkerheit.Agent.Runtime;

namespace Sikkerheit.Agent.Tests;

/// <summary>Clock of the tests: time moves only by <see cref="Advance"/>.</summary>
public sealed class ManualTimeProvider(DateTimeOffset start) : TimeProvider
{
    private DateTimeOffset _now = start;

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;
}

/// <summary>Software device key (ECDSA P-256) instead of CNG/TPM; tests only.</summary>
public sealed class SoftwareKeyStore : IDeviceKeyStore
{
    private ECDsa? _key;

    public int Created { get; private set; }

    public IDeviceKey? Open() => _key is null ? null : new SoftwareKey(_key, KeyProtections.Software);

    public IDeviceKey Create()
    {
        _key?.Dispose();
        _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Created++;
        return new SoftwareKey(_key, KeyProtections.Software);
    }

    public void Delete()
    {
        _key?.Dispose();
        _key = null;
    }

    public bool Exists => _key is not null;
}

internal sealed class SoftwareKey(ECDsa key, string protection) : IDeviceKey
{
    public string KeyProtection { get; } = protection;

    public PublicKeyJwk PublicKey { get; } = PublicKeyJwk.FromParameters(key.ExportParameters(false));

    public byte[] Sign(byte[] data) => key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    public void Dispose()
    {
        // The key belongs to the store.
    }
}

/// <summary>Replaces DPAPI in the tests: reversible, not a protection.</summary>
public sealed class ReversingProtector : ISecretProtector
{
    public byte[] Protect(byte[] secret) => [.. secret.Reverse()];

    public byte[] Unprotect(byte[] protectedSecret) => [.. protectedSecret.Reverse()];
}

public sealed class FakeProbe(DateTimeOffset boot) : ISystemProbe
{
    public string MachineName { get; set; } = "PC-TEST-01";

    public long WorkingSetMb { get; set; } = 42;

    public long CpuSeconds { get; set; } = 7;

    public DateTimeOffset BootTime { get; set; } = boot;
}

public sealed class FakeIdentity : IMachineIdentityReader
{
    public MachineIdentityRaw Raw { get; set; } = new("4C4C4544-0042-3510-8058-B4C04F4E3732", "{8C1F7A2E-3B4D-4E5F-9A6B-7C8D9E0F1A2B}");

    public MachineIdentityRaw Read() => Raw;
}

public sealed class FakeVolume : IOsVolumeResolver
{
    public static readonly VolumeRef Os = new(@"\\?\Volume{5f1c2c1e-8a8f-4b3e-9a51-3c1d2e4f6a7b}\", "C:");

    public VolumeRef? Value { get; set; } = Os;

    public VolumeRef? Resolve() => Value;
}

/// <summary>A collector whose outcome the test chooses.</summary>
public sealed class StubCollector(string checkId, Func<CollectionContext, CollectorOutcome> collect, bool sta = false) : ICollector
{
    public string CheckId { get; } = checkId;

    public string CollectorVersion => CollectorVersions.Current;

    public bool RequiresSta { get; } = sta;

    public CollectorOutcome Collect(CollectionContext context) => collect(context);
}
