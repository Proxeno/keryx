using System.Net;
using FluentAssertions;
using Keryx.Core;

using Xunit;

namespace Keryx.Stun.Tests;

/// <summary>Encoding, decoding, classification and robustness tests for <see cref="StunMessage"/>.</summary>
public sealed class StunMessageTests
{
    [Theory]
    [InlineData(StunClass.Request, 0x0001)]
    [InlineData(StunClass.Indication, 0x0011)]
    [InlineData(StunClass.SuccessResponse, 0x0101)]
    [InlineData(StunClass.ErrorResponse, 0x0111)]
    public void MessageType_InterleavesClassBitsWithMethodBits(StunClass messageClass, int expected)
    {
        // RFC 5389 section 6: the class bits C1 and C0 sit at bit 8 and bit 4 of the type field.
        StunMessage.EncodeMessageType(messageClass, StunMethod.Binding).Should().Be((ushort)expected);

        var message = new StunMessage(messageClass, StunMethod.Binding);
        var decoded = StunMessage.Decode(message.Encode());
        decoded.Class.Should().Be(messageClass);
        decoded.Method.Should().Be(StunMethod.Binding);
    }

    [Fact]
    public void RoundTrip_PreservesEveryModelledAttribute()
    {
        var message = new StunMessage(StunClass.Request, StunMethod.Binding)
            .Add(new StunSoftwareAttribute("Keryx"))
            .Add(new StunUsernameAttribute("remote:local"))
            .Add(new StunRealmAttribute("example.org"))
            .Add(new StunNonceAttribute("nonce-value"))
            .Add(new StunPriorityAttribute(0x7E7F00FFu))
            .Add(new StunUseCandidateAttribute())
            .Add(new StunIceControllingAttribute(0x0123456789ABCDEFul))
            .Add(new StunMappedAddressAttribute(new IPEndPoint(IPAddress.Parse("198.51.100.7"), 5004)))
            .Add(new StunXorMappedAddressAttribute(new IPEndPoint(IPAddress.Parse("198.51.100.7"), 5004)))
            .Add(new StunAlternateServerAttribute(new IPEndPoint(IPAddress.Parse("203.0.113.9"), 3478)));

        var encoded = message.Encode();
        var decoded = StunMessage.Decode(encoded);

        decoded.TransactionId.Should().Be(message.TransactionId);
        decoded.GetAttribute<StunSoftwareAttribute>()!.Value.Should().Be("Keryx");
        decoded.Username.Should().Be("remote:local");
        decoded.GetAttribute<StunRealmAttribute>()!.Value.Should().Be("example.org");
        decoded.GetAttribute<StunNonceAttribute>()!.Value.Should().Be("nonce-value");
        decoded.GetAttribute<StunPriorityAttribute>()!.Priority.Should().Be(0x7E7F00FFu);
        decoded.HasAttribute(StunAttributeType.UseCandidate).Should().BeTrue();
        decoded.GetAttribute<StunIceControllingAttribute>()!.TieBreaker.Should().Be(0x0123456789ABCDEFul);
        decoded.GetAttribute<StunMappedAddressAttribute>()!.EndPoint
            .Should().Be(new IPEndPoint(IPAddress.Parse("198.51.100.7"), 5004));
        decoded.GetAttribute<StunXorMappedAddressAttribute>()!.EndPoint
            .Should().Be(new IPEndPoint(IPAddress.Parse("198.51.100.7"), 5004));
        decoded.GetAttribute<StunAlternateServerAttribute>()!.EndPoint
            .Should().Be(new IPEndPoint(IPAddress.Parse("203.0.113.9"), 3478));

        decoded.Encode().Should().Equal(encoded);
    }

    [Fact]
    public void RoundTrip_PreservesErrorCodeAndUnknownAttributes()
    {
        var request = StunMessage.CreateBindingRequest();
        var response = StunMessage.CreateErrorResponse(request, StunErrorCodeAttribute.RoleConflict, "Role Conflict")
            .Add(new StunUnknownAttributesAttribute([0x0001, 0xBEEF, 0x1234]));

        var decoded = StunMessage.Decode(response.Encode());

        decoded.Class.Should().Be(StunClass.ErrorResponse);
        decoded.TransactionId.Should().Be(request.TransactionId);
        decoded.ErrorCode.Should().Be(487);
        decoded.GetAttribute<StunErrorCodeAttribute>()!.Reason.Should().Be("Role Conflict");
        decoded.GetAttribute<StunUnknownAttributesAttribute>()!.Types.Should().Equal(new ushort[] { 0x0001, 0xBEEF, 0x1234 });
    }

    [Fact]
    public void RoundTrip_PreservesUnrecognisedAttributesVerbatim()
    {
        var message = new StunMessage(StunClass.Request, StunMethod.Binding)
            .Add(new StunRawAttribute((StunAttributeType)0x7FFF, [1, 2, 3]))
            .Add(new StunRawAttribute((StunAttributeType)0xFFFE, [9]));

        var decoded = StunMessage.Decode(message.Encode());

        decoded.Attributes.Should().HaveCount(2);
        decoded.Attributes[0].Should().BeOfType<StunRawAttribute>().Which.Value.Should().Equal(new byte[] { 1, 2, 3 });
        decoded.Attributes[0].IsComprehensionRequired.Should().BeTrue();
        decoded.Attributes[1].IsComprehensionRequired.Should().BeFalse();
        decoded.UnknownComprehensionRequiredTypes.Should().Equal(new ushort[] { 0x7FFF });
        decoded.Encode().Should().Equal(message.Encode());
    }

    [Fact]
    public void Encode_AppliesTheDummyLengthRuleForIntegrityAndFingerprint()
    {
        // RFC 5389 sections 15.4 and 15.5: while each value is computed, the header length must
        // already count the attribute being computed - but the final length counts everything.
        var key = StunCredentials.ShortTermKey("password");
        var encoded = new StunMessage(StunClass.Request, StunMethod.Binding)
            .Add(new StunUsernameAttribute("a:b"))
            .Encode(key, appendFingerprint: true);

        var declaredLength = (encoded[2] << 8) | encoded[3];
        (declaredLength + StunMessage.HeaderLength).Should().Be(encoded.Length);

        StunMessage.ValidateMessageIntegrity(encoded, key).Should().BeTrue();
        StunMessage.ValidateFingerprint(encoded).Should().BeTrue();

        var decoded = StunMessage.Decode(encoded);
        decoded.GetAttribute<StunMessageIntegrityAttribute>()!.Digest.Should().HaveCount(20);
        decoded.GetAttribute<StunFingerprintAttribute>().Should().NotBeNull();
        decoded.ValidateMessageIntegrity("password").Should().BeTrue();
        decoded.ValidateMessageIntegrity("other").Should().BeFalse();
        decoded.ValidateFingerprint().Should().BeTrue();
    }

    [Fact]
    public void ValidateFingerprint_FailsWhenAnyByteIsFlipped()
    {
        var encoded = new StunMessage(StunClass.Request, StunMethod.Binding)
            .Add(new StunSoftwareAttribute("Keryx"))
            .Encode(appendFingerprint: true);

        encoded[21] ^= 0x01;

        StunMessage.ValidateFingerprint(encoded).Should().BeFalse();
    }

    [Fact]
    public void ValidateFingerprint_FailsWhenTheAttributeIsAbsent()
    {
        var encoded = StunMessage.CreateBindingRequest().Encode();

        StunMessage.ValidateFingerprint(encoded).Should().BeFalse();
    }

    [Theory]
    [InlineData(1)]
    [InlineData(19)]
    [InlineData(21)]
    [InlineData(23)]
    public void Decode_RejectsTruncatedMessages(int keepBytes)
    {
        var encoded = new StunMessage(StunClass.Request, StunMethod.Binding)
            .Add(new StunSoftwareAttribute("Keryx"))
            .Encode(appendFingerprint: true);
        var truncated = encoded[..keepBytes];

        StunMessage.TryDecode(truncated, out var message).Should().BeFalse();
        message.Should().BeNull();

        var caught = Record.Exception(() => { StunMessage.Decode(truncated); });
        caught.Should().Match<Exception>(e => e is ByteBufferException || e is StunFormatException);
    }

    [Fact]
    public void Decode_RejectsAnAttributeThatOverrunsTheBody()
    {
        var encoded = new StunMessage(StunClass.Request, StunMethod.Binding)
            .Add(new StunSoftwareAttribute("Keryx"))
            .Encode();

        // Inflate the SOFTWARE attribute's length beyond the declared body length.
        encoded[22] = 0xFF;
        encoded[23] = 0xF0;

        StunMessage.TryDecode(encoded, out _).Should().BeFalse();
    }

    [Fact]
    public void Decode_RejectsABadMagicCookie()
    {
        var encoded = StunMessage.CreateBindingRequest().Encode();
        encoded[6] ^= 0xFF;

        StunMessage.TryDecode(encoded, out _).Should().BeFalse();
        var act = () => StunMessage.Decode(encoded);
        act.Should().Throw<StunFormatException>();
    }

    [Fact]
    public void Decode_RejectsALengthThatIsNotAMultipleOfFour()
    {
        var encoded = StunMessage.CreateBindingRequest().Encode();
        encoded[3] = 0x02;

        var act = () => StunMessage.Decode(encoded);
        act.Should().Throw<StunFormatException>();
    }

    [Fact]
    public void LooksLikeStun_AcceptsAWellFormedMessage()
    {
        var encoded = StunMessage.CreateBindingRequest().Encode(appendFingerprint: true);

        StunMessage.LooksLikeStun(encoded).Should().BeTrue();
    }

    [Theory]
    [InlineData(20)]   // DTLS ChangeCipherSpec
    [InlineData(22)]   // DTLS Handshake
    [InlineData(23)]   // DTLS ApplicationData
    [InlineData(63)]
    public void LooksLikeStun_RejectsDtlsRecordsThatShareTheLeadingZeroBits(byte contentType)
    {
        // DTLS content types 20-63 also start with two zero bits (RFC 7983), so the magic cookie
        // is what actually separates the two multiplexed protocols.
        var datagram = new byte[64];
        datagram[0] = contentType;
        datagram[1] = 0xFE;
        datagram[2] = 0xFD;

        StunMessage.LooksLikeStun(datagram).Should().BeFalse();
    }

    [Theory]
    [InlineData(128)]  // RTP
    [InlineData(191)]  // RTCP upper bound
    public void LooksLikeStun_RejectsRtpAndRtcp(byte firstByte)
    {
        var datagram = new byte[64];
        datagram[0] = firstByte;
        datagram[4] = 0x21;
        datagram[5] = 0x12;
        datagram[6] = 0xA4;
        datagram[7] = 0x42;

        StunMessage.LooksLikeStun(datagram).Should().BeFalse();
    }

    [Fact]
    public void LooksLikeStun_RejectsShortDatagramsAndMisalignedLengths()
    {
        StunMessage.LooksLikeStun([]).Should().BeFalse();
        StunMessage.LooksLikeStun(new byte[19]).Should().BeFalse();

        var encoded = StunMessage.CreateBindingRequest().Encode(appendFingerprint: true);
        encoded[3] += 1;
        StunMessage.LooksLikeStun(encoded).Should().BeFalse();

        var truncated = encoded[..(encoded.Length - 4)];
        StunMessage.LooksLikeStun(truncated).Should().BeFalse();
    }

    [Fact]
    public void TransactionId_IsTwelveRandomBytesAndRoundTrips()
    {
        var id = StunTransactionId.NewRandom();
        var bytes = id.ToArray();

        bytes.Should().HaveCount(12);
        new StunTransactionId(bytes).Should().Be(id);
        (new StunTransactionId(bytes) == id).Should().BeTrue();
        id.ToString().Should().HaveLength(24);
        StunTransactionId.NewRandom().Should().NotBe(id);

        var act = () => new StunTransactionId(new byte[11]);
        act.Should().Throw<ByteBufferException>();
    }
}
