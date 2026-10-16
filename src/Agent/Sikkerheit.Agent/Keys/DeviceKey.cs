using Sikkerheit.Agent.Protocol;

namespace Sikkerheit.Agent.Keys;

public static class KeyProtections
{
    public const string Tpm = "tpm";
    public const string Software = "software";
}

/// <summary>The device key P-256. The private key never leaves its provider (04, "Ключ устройства и сессия").</summary>
public interface IDeviceKey : IDisposable
{
    /// <summary><c>tpm</c> or <c>software</c>: a claim of the agent without attestation.</summary>
    string KeyProtection { get; }

    PublicKeyJwk PublicKey { get; }

    /// <summary>ECDSA P-256 SHA-256, IEEE P1363 (r||s, 64 bytes).</summary>
    byte[] Sign(byte[] data);
}

/// <summary>Storage of the device key: CNG on Windows (TPM first), a software key in tests.</summary>
public interface IDeviceKeyStore
{
    IDeviceKey? Open();

    /// <summary>Creates a new key; an existing one is replaced.</summary>
    IDeviceKey Create();

    void Delete();
}

/// <summary>Protection of the stored registration key: DPAPI LocalMachine on Windows.</summary>
public interface ISecretProtector
{
    byte[] Protect(byte[] secret);

    byte[] Unprotect(byte[] protectedSecret);
}
