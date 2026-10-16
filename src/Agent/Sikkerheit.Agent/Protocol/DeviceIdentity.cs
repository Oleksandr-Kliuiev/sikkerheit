using System.Security.Cryptography;
using System.Text;

namespace Sikkerheit.Agent.Protocol;

/// <summary>Public key of the device in JWK form (kty=EC, crv=P-256). x and y are base64url of 32 bytes.</summary>
public sealed record PublicKeyJwk(string X, string Y)
{
    /// <summary>Thumbprint by RFC 7638: SHA-256 of the canonical JSON, base64url. Members in lexicographic order, no whitespace.</summary>
    public string Thumbprint()
    {
        var canonical = $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{X}\",\"y\":\"{Y}\"}}";
        return Base64Url.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    public static PublicKeyJwk FromParameters(ECParameters parameters) =>
        new(Base64Url.Encode(parameters.Q.X!), Base64Url.Encode(parameters.Q.Y!));
}

/// <summary>The signed strings of the registration and the session (05, "Регистрация и сессия"): UTF-8, separator <c>\n</c>.</summary>
public static class SignedStrings
{
    public const string EnrollPrefix = "sikkerheit-enroll-v1";
    public const string SessionPrefix = "sikkerheit-session-v1";

    public static byte[] Enroll(
        string nonce, string registrationRequestId, string installationId, string machineFingerprint, string keyProtection, PublicKeyJwk key) =>
        Encoding.UTF8.GetBytes(string.Join('\n', EnrollPrefix, nonce, registrationRequestId, installationId, machineFingerprint, keyProtection, key.Thumbprint()));

    public static byte[] Session(string nonce, string deviceId) =>
        Encoding.UTF8.GetBytes(string.Join('\n', SessionPrefix, nonce, deviceId));
}

/// <summary>
/// Machine fingerprint (05, "Идентичность устройства"): HMAC-SHA256, key — 16 bytes of installationId in RFC 4122 order, message —
/// lowercase SMBIOS UUID, a zero byte and lowercase MachineGuid without braces. Hex in lowercase.
/// </summary>
public static class MachineFingerprint
{
    public static string Compute(Guid installationId, string? productUuid, string machineGuid)
    {
        var key = installationId.ToByteArray(bigEndian: true);
        var message = Encoding.UTF8.GetBytes(NormalizeUuid(productUuid) + "\0" + machineGuid.Trim('{', '}').ToLowerInvariant());
        return Convert.ToHexStringLower(HMACSHA256.HashData(key, message));
    }

    /// <summary>UUID in the form 8-4-4-4-12; the empty string if the value is absent or consists of zeros or of F only.</summary>
    public static string NormalizeUuid(string? uuid)
    {
        if (string.IsNullOrWhiteSpace(uuid) || !Guid.TryParse(uuid.Trim('{', '}'), out var parsed))
        {
            return "";
        }
        var text = parsed.ToString("D").ToLowerInvariant();
        var digits = text.Replace("-", "", StringComparison.Ordinal);
        return digits.All(c => c == '0') || digits.All(c => c == 'f') ? "" : text;
    }
}
