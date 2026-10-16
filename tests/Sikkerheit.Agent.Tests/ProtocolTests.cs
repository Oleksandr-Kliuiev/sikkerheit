using System.Security.Cryptography;
using System.Text;
using Sikkerheit.Agent.Protocol;

namespace Sikkerheit.Agent.Tests;

public sealed class ProtocolTests
{
    [Fact]
    public void Machine_fingerprint_matches_the_test_vector_of_05()
    {
        var value = MachineFingerprint.Compute(
            Guid.Parse("6f1c2d3e-4a5b-4c6d-8e7f-9a0b1c2d3e4f"),
            "4C4C4544-0042-3510-8058-B4C04F4E3732",
            "{8C1F7A2E-3B4D-4E5F-9A6B-7C8D9E0F1A2B}");

        Assert.Equal("150364374d6891dc5194327d8c0500ed000a876f0d7da212e8f1b67ae6a39bd9", value);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    [InlineData("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF")]
    public void Empty_all_zero_and_all_f_smbios_uuid_is_the_empty_string(string? uuid) =>
        Assert.Equal("", MachineFingerprint.NormalizeUuid(uuid));

    [Fact]
    public void Base64url_has_no_padding_and_round_trips()
    {
        var bytes = RandomNumberGenerator.GetBytes(33);
        var text = Base64Url.Encode(bytes);
        Assert.DoesNotContain('=', text);
        Assert.DoesNotContain('+', text);
        Assert.Equal(bytes, Base64Url.Decode(text));
    }

    [Fact]
    public void Jwk_thumbprint_is_sha256_of_the_canonical_json_of_rfc7638()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwk = PublicKeyJwk.FromParameters(ecdsa.ExportParameters(false));
        var canonical = $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{jwk.X}\",\"y\":\"{jwk.Y}\"}}";

        Assert.Equal(Base64Url.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))), jwk.Thumbprint());
        Assert.Equal(43, jwk.X.Length);
        Assert.Equal(43, jwk.Y.Length);
    }

    [Fact]
    public void Signed_strings_have_the_lines_of_05()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwk = PublicKeyJwk.FromParameters(ecdsa.ExportParameters(false));

        var enroll = Encoding.UTF8.GetString(SignedStrings.Enroll("N", "R", "I", "F", "tpm", jwk));
        var session = Encoding.UTF8.GetString(SignedStrings.Session("N", "D"));

        Assert.Equal($"sikkerheit-enroll-v1\nN\nR\nI\nF\ntpm\n{jwk.Thumbprint()}", enroll);
        Assert.Equal("sikkerheit-session-v1\nN\nD", session);
    }

    [Fact]
    public void Software_key_signs_in_ieee_p1363_format_of_86_base64url_characters()
    {
        var store = new SoftwareKeyStore();
        using var key = store.Create();
        var data = Encoding.UTF8.GetBytes("x");

        var signature = key.Sign(data);

        Assert.Equal(64, signature.Length);
        Assert.Equal(86, Base64Url.Encode(signature).Length);
    }
}
