using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Sikkerheit.Host.Agents;

/// <summary>
/// The cryptography of the agent API (05 «Регистрация и сессия»): ECDSA P-256 signatures in IEEE P1363 format, JWK
/// thumbprints by RFC 7638 and the stateless nonce protected by HMAC.
/// </summary>
public static class AgentCrypto
{
    public static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[]? FromBase64Url(string text)
    {
        try
        {
            var padded = text.Replace('-', '+').Replace('_', '/');
            padded += new string('=', (4 - padded.Length % 4) % 4);
            return Convert.FromBase64String(padded);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    public static string Sha256Hex(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    /// <summary>Thumbprint of an EC JWK by RFC 7638: SHA-256 of the members crv, kty, x, y in this order, base64url.</summary>
    public static string Thumbprint(string x, string y) =>
        Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes($$"""{"crv":"P-256","kty":"EC","x":"{{x}}","y":"{{y}}"}""")));

    /// <summary>The canonical JWK of a P-256 public key as the server stores it.</summary>
    public static string CanonicalJwk(string x, string y) => $$"""{"kty":"EC","crv":"P-256","x":"{{x}}","y":"{{y}}"}""";

    /// <summary>The public key of a JWK, or null when the point is not on the curve.</summary>
    public static ECDsa? ImportPublicKey(string x, string y)
    {
        var xBytes = FromBase64Url(x);
        var yBytes = FromBase64Url(y);
        if (xBytes is not { Length: 32 } || yBytes is not { Length: 32 })
        {
            return null;
        }
        try
        {
            var key = ECDsa.Create();
            key.ImportParameters(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = xBytes, Y = yBytes },
            });
            return key;
        }
        catch (Exception error) when (error is CryptographicException or ArgumentException)
        {
            return null;
        }
    }

    /// <summary>Verifies a base64url P1363 signature of the UTF-8 text.</summary>
    public static bool Verify(ECDsa key, string text, string signature)
    {
        var bytes = FromBase64Url(signature);
        return bytes is { Length: 64 }
               && key.VerifyData(Encoding.UTF8.GetBytes(text), bytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    /// <summary>The string a new key signs at registration.</summary>
    public static string EnrollmentString(string nonce, string registrationRequestId, string installationId, string fingerprint,
        string keyProtection, string thumbprint) =>
        string.Join('\n', "sikkerheit-enroll-v1", nonce, registrationRequestId, installationId, fingerprint, keyProtection, thumbprint);

    public static string EnrollmentString(string nonce, Guid registrationRequestId, Guid installationId, string fingerprint,
        string keyProtection, string thumbprint) =>
        EnrollmentString(nonce, registrationRequestId.ToString("D"), installationId.ToString("D"), fingerprint, keyProtection, thumbprint);

    /// <summary>The string a device key signs for a session.</summary>
    public static string SessionString(string nonce, string deviceId) => string.Join('\n', "sikkerheit-session-v1", nonce, deviceId);

    public static string SessionString(string nonce, Guid deviceId) => SessionString(nonce, deviceId.ToString("D"));

    public static (string X, string Y) ParseJwk(string json)
    {
        using var document = JsonDocument.Parse(json);
        return (document.RootElement.GetProperty("x").GetString()!, document.RootElement.GetProperty("y").GetString()!);
    }
}

/// <summary>
/// Nonce of 05: 32 bytes — 12 random, 4 bytes of the expiry (Unix seconds) and the first 16 bytes of HMAC-SHA256 over
/// the random part, the expiry, the purpose and the device. Issuing writes nothing; the nonce is checked statelessly and
/// redeemed by inserting its hash.
/// </summary>
public sealed class Nonces(byte[] key, TimeProvider clock)
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    public (string Nonce, DateTimeOffset ExpiresAt) Create(string purpose, Guid? deviceId)
    {
        var expires = clock.GetUtcNow() + Lifetime;
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes.AsSpan(0, 12));
        var seconds = (uint)expires.ToUnixTimeSeconds();
        bytes[12] = (byte)(seconds >> 24);
        bytes[13] = (byte)(seconds >> 16);
        bytes[14] = (byte)(seconds >> 8);
        bytes[15] = (byte)seconds;
        Mac(bytes, purpose, deviceId).AsSpan(0, 16).CopyTo(bytes.AsSpan(16));
        return (AgentCrypto.Base64Url(bytes), DateTimeOffset.FromUnixTimeSeconds(seconds));
    }

    /// <summary>The expiry of a nonce that is genuine, unexpired and issued for the purpose and the device; null otherwise.</summary>
    public DateTimeOffset? Check(string nonce, string purpose, Guid? deviceId)
    {
        var bytes = AgentCrypto.FromBase64Url(nonce);
        if (bytes is not { Length: 32 })
        {
            return null;
        }
        var expected = Mac(bytes, purpose, deviceId).AsSpan(0, 16);
        if (!CryptographicOperations.FixedTimeEquals(expected, bytes.AsSpan(16, 16)))
        {
            return null;
        }
        var seconds = ((long)bytes[12] << 24) | ((long)bytes[13] << 16) | ((long)bytes[14] << 8) | bytes[15];
        var expires = DateTimeOffset.FromUnixTimeSeconds(seconds);
        return expires > clock.GetUtcNow() ? expires : null;
    }

    private byte[] Mac(byte[] nonce, string purpose, Guid? deviceId)
    {
        var message = new MemoryStream();
        message.Write(Encoding.UTF8.GetBytes("sikkerheit-nonce-v1\n"));
        message.Write(nonce.AsSpan(0, 12));
        message.Write(nonce.AsSpan(12, 4));
        message.Write(Encoding.UTF8.GetBytes("\n" + purpose + "\n" + (deviceId?.ToString("D") ?? "")));
        return HMACSHA256.HashData(key, message.ToArray());
    }
}
