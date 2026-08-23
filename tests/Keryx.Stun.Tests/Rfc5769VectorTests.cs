using System.Net;
using System.Text;
using FluentAssertions;

using Xunit;

namespace Keryx.Stun.Tests;

/// <summary>
/// The complete set of STUN test vectors from RFC 5769. Each vector is decoded from the exact
/// bytes in the RFC and its MESSAGE-INTEGRITY and FINGERPRINT are re-derived, which exercises the
/// dummy-length rules of RFC 5389 sections 15.4 and 15.5.
/// </summary>
/// <remarks>
/// Sections 2.1-2.3 pad attribute values with ASCII spaces (RFC 5389 allows any padding byte),
/// while Keryx writes zero padding as RFC 8489 later mandated. Those vectors are therefore
/// verified by decoding and validating rather than by re-encoding byte-for-byte; section 2.4,
/// which uses nul padding, is additionally checked for byte-exact re-encoding.
/// </remarks>
public sealed class Rfc5769VectorTests
{
    private const string ShortTermPassword = "VOkJxbRl1RmTxUk/WvJxBt";

    // RFC 5769 section 2.1: Sample Request.
    private static readonly byte[] SampleRequest = Hex.Parse("""
        00 01 00 58
        21 12 a4 42
        b7 e7 a7 01
        bc 34 d6 86
        fa 87 df ae
        80 22 00 10
        53 54 55 4e
        20 74 65 73
        74 20 63 6c
        69 65 6e 74
        00 24 00 04
        6e 00 01 ff
        80 29 00 08
        93 2f f9 b1
        51 26 3b 36
        00 06 00 09
        65 76 74 6a
        3a 68 36 76
        59 20 20 20
        00 08 00 14
        9a ea a7 0c
        bf d8 cb 56
        78 1e f2 b5
        b2 d3 f2 49
        c1 b5 71 a2
        80 28 00 04
        e5 7a 3b cf
        """);

    // RFC 5769 section 2.2: Sample IPv4 Response.
    private static readonly byte[] SampleIPv4Response = Hex.Parse("""
        01 01 00 3c
        21 12 a4 42
        b7 e7 a7 01
        bc 34 d6 86
        fa 87 df ae
        80 22 00 0b
        74 65 73 74
        20 76 65 63
        74 6f 72 20
        00 20 00 08
        00 01 a1 47
        e1 12 a6 43
        00 08 00 14
        2b 91 f5 99
        fd 9e 90 c3
        8c 74 89 f9
        2a f9 ba 53
        f0 6b e7 d7
        80 28 00 04
        c0 7d 4c 96
        """);

    // RFC 5769 section 2.3: Sample IPv6 Response.
    private static readonly byte[] SampleIPv6Response = Hex.Parse("""
        01 01 00 48
        21 12 a4 42
        b7 e7 a7 01
        bc 34 d6 86
        fa 87 df ae
        80 22 00 0b
        74 65 73 74
        20 76 65 63
        74 6f 72 20
        00 20 00 14
        00 02 a1 47
        01 13 a9 fa
        a5 d3 f1 79
        bc 25 f4 b5
        be d2 b9 d9
        00 08 00 14
        a3 82 95 4e
        4b e6 7b f1
        17 84 c9 7c
        82 92 c2 75
        bf e3 ed 41
        80 28 00 04
        c8 fb 0b 4c
        """);

    // RFC 5769 section 2.4: Sample Request with Long-Term Authentication.
    private static readonly byte[] SampleLongTermRequest = Hex.Parse("""
        00 01 00 60
        21 12 a4 42
        78 ad 34 33
        c6 ad 72 c0
        29 da 41 2e
        00 06 00 12
        e3 83 9e e3
        83 88 e3 83
        aa e3 83 83
        e3 82 af e3
        82 b9 00 00
        00 15 00 1c
        66 2f 2f 34
        39 39 6b 39
        35 34 64 36
        4f 4c 33 34
        6f 4c 39 46
        53 54 76 79
        36 34 73 41
        00 14 00 0b
        65 78 61 6d
        70 6c 65 2e
        6f 72 67 00
        00 08 00 14
        f6 70 24 65
        6d d6 4a 3e
        02 b8 e0 71
        2e 85 c9 a2
        8c a8 96 66
        """);

    [Fact]
    public void Rfc5769Section21_SampleRequest_DecodesToTheDocumentedAttributes()
    {
        var message = StunMessage.Decode(SampleRequest);

        message.Class.Should().Be(StunClass.Request);
        message.Method.Should().Be(StunMethod.Binding);
        message.TransactionId.ToString().Should().Be("b7e7a701bc34d686fa87dfae");

        message.GetAttribute<StunSoftwareAttribute>()!.Value.Should().Be("STUN test client");
        message.GetAttribute<StunPriorityAttribute>()!.Priority.Should().Be(0x6e0001ffu);
        message.GetAttribute<StunIceControlledAttribute>()!.TieBreaker.Should().Be(0x932ff9b151263b36ul);
        message.Username.Should().Be("evtj:h6vY");
        message.Attributes.Should().HaveCount(6);
        message.UnknownComprehensionRequiredTypes.Should().BeEmpty();
    }

    [Fact]
    public void Rfc5769Section21_SampleRequest_MessageIntegrityAndFingerprintValidate()
    {
        var message = StunMessage.Decode(SampleRequest);

        message.ValidateMessageIntegrity(ShortTermPassword).Should().BeTrue();
        message.ValidateFingerprint().Should().BeTrue();
        message.ValidateMessageIntegrity("the wrong password").Should().BeFalse();
    }

    [Fact]
    public void Rfc5769Section22_SampleIPv4Response_DecodesTheXorMappedAddress()
    {
        var message = StunMessage.Decode(SampleIPv4Response);

        message.Class.Should().Be(StunClass.SuccessResponse);
        message.Method.Should().Be(StunMethod.Binding);
        message.GetAttribute<StunSoftwareAttribute>()!.Value.Should().Be("test vector");
        message.MappedAddress.Should().Be(new IPEndPoint(IPAddress.Parse("192.0.2.1"), 32853));
    }

    [Fact]
    public void Rfc5769Section22_SampleIPv4Response_MessageIntegrityAndFingerprintValidate()
    {
        var message = StunMessage.Decode(SampleIPv4Response);

        message.ValidateMessageIntegrity(ShortTermPassword).Should().BeTrue();
        message.ValidateFingerprint().Should().BeTrue();
    }

    [Fact]
    public void Rfc5769Section23_SampleIPv6Response_DecodesTheXorMappedAddress()
    {
        var message = StunMessage.Decode(SampleIPv6Response);

        message.MappedAddress.Should().Be(
            new IPEndPoint(IPAddress.Parse("2001:db8:1234:5678:11:2233:4455:6677"), 32853));
    }

    [Fact]
    public void Rfc5769Section23_SampleIPv6Response_MessageIntegrityAndFingerprintValidate()
    {
        var message = StunMessage.Decode(SampleIPv6Response);

        message.ValidateMessageIntegrity(ShortTermPassword).Should().BeTrue();
        message.ValidateFingerprint().Should().BeTrue();
    }

    [Fact]
    public void Rfc5769Section23_SampleIPv6Response_ReEncodesTheXorMappedAddressIdentically()
    {
        // The IPv6 XOR mask spans the magic cookie and the transaction id, so a round trip of the
        // address attribute alone is a meaningful check even though the whole message is padded
        // with spaces in the RFC.
        var decoded = StunMessage.Decode(SampleIPv6Response);
        var address = decoded.GetAttribute<StunXorMappedAddressAttribute>()!;

        var rebuilt = new StunMessage(StunClass.SuccessResponse, StunMethod.Binding, decoded.TransactionId)
            .Add(new StunXorMappedAddressAttribute(address.EndPoint));

        var encoded = rebuilt.Encode();
        encoded.AsSpan(20).ToArray().Should().Equal(SampleIPv6Response.AsSpan(36, 24).ToArray());
    }

    [Fact]
    public void Rfc5769Section24_LongTermCredentialRequest_DecodesToTheDocumentedAttributes()
    {
        var message = StunMessage.Decode(SampleLongTermRequest);

        // The username is the katakana string U+30DE U+30C8 U+30EA U+30C3 U+30AF U+30B9, which
        // SASLprep leaves unchanged.
        message.Username.Should().Be("マトリックス");
        Encoding.UTF8.GetByteCount(message.Username!).Should().Be(18);
        message.GetAttribute<StunNonceAttribute>()!.Value.Should().Be("f//499k954d6OL34oL9FSTvy64sA");
        message.GetAttribute<StunRealmAttribute>()!.Value.Should().Be("example.org");
        message.HasAttribute(StunAttributeType.Fingerprint).Should().BeFalse();
    }

    [Fact]
    public void Rfc5769Section24_LongTermCredentialRequest_MessageIntegrityValidatesWithTheMd5Key()
    {
        var message = StunMessage.Decode(SampleLongTermRequest);

        // RFC 5389 section 15.4 long-term key: MD5(username ":" realm ":" password). The RFC's
        // password is "The<U+00AD>M<U+00AA>tr<U+2168>", which is "TheMatrIX" after SASLprep.
        var key = StunCredentials.LongTermKey(
            "マトリックス", "example.org", "TheMatrIX");

        message.ValidateMessageIntegrity(key).Should().BeTrue();
        message.ValidateMessageIntegrity(StunCredentials.LongTermKey("someone", "example.org", "TheMatrIX"))
            .Should().BeFalse();
    }

    [Fact]
    public void Rfc5769Section24_LongTermCredentialRequest_ReEncodesByteForByte()
    {
        // This vector pads with nul bytes, matching what Keryx writes, so the whole message must
        // round-trip exactly - including the recomputed MESSAGE-INTEGRITY.
        var decoded = StunMessage.Decode(SampleLongTermRequest);
        var key = StunCredentials.LongTermKey(
            "マトリックス", "example.org", "TheMatrIX");

        var rebuilt = new StunMessage(StunClass.Request, StunMethod.Binding, decoded.TransactionId)
            .Add(new StunUsernameAttribute(decoded.Username!))
            .Add(new StunNonceAttribute(decoded.GetAttribute<StunNonceAttribute>()!.Value))
            .Add(new StunRealmAttribute(decoded.GetAttribute<StunRealmAttribute>()!.Value));

        rebuilt.Encode(key).Should().Equal(SampleLongTermRequest);
    }

    [Fact]
    public void Rfc8489Sha256PasswordAlgorithm_KeyMatchesAnIndependentlyComputedDigest()
    {
        // RFC 8489 publishes no worked SHA-256 long-term-key vector the way RFC 5769 does for MD5
        // (its Appendix B.1 vector is a full encoded message, not a standalone key), so this reuses
        // the section 2.4 username/realm/password and checks the SHA-256(username ":" realm ":"
        // password) key against a digest computed independently with `openssl dgst -sha256` and
        // Python's hashlib, rather than against Keryx's own SHA256.HashData call.
        var key = StunCredentials.LongTermKey(
            "マトリックス", "example.org", "TheMatrIX", StunPasswordAlgorithm.Sha256);

        Convert.ToHexStringLower(key).Should().Be(
            "dd295a613b9058c3c23d6dc7165bda072304d989c9d0af3a8c7e184b4f9bb4a1");
        key.Should().HaveCount(32);
    }
}
