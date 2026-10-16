namespace Sikkerheit.Agent.Protocol;

/// <summary>base64url without padding (RFC 4648, section 5), the encoding of nonces, signatures and JWK coordinates.</summary>
public static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> data) => System.Buffers.Text.Base64Url.EncodeToString(data);

    public static byte[] Decode(string text) => System.Buffers.Text.Base64Url.DecodeFromChars(text);
}
