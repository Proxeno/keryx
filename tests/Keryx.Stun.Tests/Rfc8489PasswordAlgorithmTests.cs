using FluentAssertions;
using Keryx.Core;

using Xunit;

namespace Keryx.Stun.Tests;

/// <summary>
/// Wire-layout tests for RFC 8489's password-algorithm negotiation: PASSWORD-ALGORITHM,
/// PASSWORD-ALGORITHMS and MESSAGE-INTEGRITY-SHA256.
/// </summary>
/// <remarks>
/// RFC 8489 publishes no standalone byte-level test vectors for these attributes the way RFC 5769
/// does for Binding and long-term authentication (its one worked example, Appendix B.1, is a full
/// encoded message using USERHASH, which Keryx does not implement). The expectations here are
/// therefore assembled by hand from the field diagrams in RFC 8489 sections 14.6 and 14.11-14.12
/// and the IANA STUN Password Algorithms registry (section 18.5.1: MD5 = 0x0001, SHA-256 = 0x0002,
/// both with empty parameters), the same approach <see cref="StunTurnAttributeTests"/> takes for
/// RFC 8656.
/// </remarks>
public sealed class Rfc8489PasswordAlgorithmTests
{
    [Theory]
    [InlineData(StunPasswordAlgorithm.Md5, 0x0001)]
    [InlineData(StunPasswordAlgorithm.Sha256, 0x0002)]
    public void PasswordAlgorithm_UsesTheCodesFromTheIanaRegistry(StunPasswordAlgorithm algorithm, int expected)
        => ((int)algorithm).Should().Be(expected);

    [Theory]
    [InlineData(StunAttributeType.MessageIntegritySha256, 0x001C)]
    [InlineData(StunAttributeType.PasswordAlgorithm, 0x001D)]
    [InlineData(StunAttributeType.PasswordAlgorithms, 0x8002)]
    public void AttributeTypes_UseTheCodesFromRfc8489Section18(StunAttributeType type, int expected)
        => ((int)type).Should().Be(expected);

    [Fact]
    public void PasswordAlgorithm_IsAFourByteAlgorithmAndZeroParametersLengthForTheRegisteredAlgorithms()
    {
        // Both registered algorithms carry no parameters, so the value is just the two-byte
        // algorithm code followed by a zero parameters-length - no padding required.
        Encoded(new StunPasswordAlgorithmAttribute(StunPasswordAlgorithm.Md5))
            .Should().Equal(Hex.Parse("00 1d 00 04 00 01 00 00"));
        Encoded(new StunPasswordAlgorithmAttribute(StunPasswordAlgorithm.Sha256))
            .Should().Equal(Hex.Parse("00 1d 00 04 00 02 00 00"));
    }

    [Fact]
    public void PasswordAlgorithm_RoundTrips()
        => RoundTrip(new StunPasswordAlgorithmAttribute(StunPasswordAlgorithm.Sha256))
            .Should().BeOfType<StunPasswordAlgorithmAttribute>()
            .Which.Algorithm.Should().Be((ushort)StunPasswordAlgorithm.Sha256);

    [Fact]
    public void PasswordAlgorithm_PreservesAnUnrecognisedAlgorithmAndItsParameters()
    {
        // A future or vendor-specific algorithm code must round-trip untouched, parameters and all,
        // so a client that cannot use it can still echo PASSWORD-ALGORITHMS back unmodified.
        var entry = new StunPasswordAlgorithmEntry(0x00FF, [0xAA, 0xBB, 0xCC]);
        var decoded = RoundTrip(new StunPasswordAlgorithmAttribute(entry))
            .Should().BeOfType<StunPasswordAlgorithmAttribute>().Subject;

        decoded.Algorithm.Should().Be(0x00FF);
        decoded.Parameters.Should().Equal(0xAA, 0xBB, 0xCC);
    }

    [Fact]
    public void PasswordAlgorithms_ListsEveryOfferedAlgorithmInOrder()
    {
        var attribute = StunPasswordAlgorithmsAttribute.Offering(StunPasswordAlgorithm.Sha256, StunPasswordAlgorithm.Md5);

        Encoded(attribute).Should().Equal(Hex.Parse("80 02 00 08 00 02 00 00 00 01 00 00"));

        var decoded = RoundTrip(attribute).Should().BeOfType<StunPasswordAlgorithmsAttribute>().Subject;
        decoded.Algorithms.Should().Equal((ushort)StunPasswordAlgorithm.Sha256, (ushort)StunPasswordAlgorithm.Md5);
        decoded.Supports(StunPasswordAlgorithm.Sha256).Should().BeTrue();
        decoded.Supports(StunPasswordAlgorithm.Md5).Should().BeTrue();
    }

    [Fact]
    public void PasswordAlgorithms_EchoedAttributeReEncodesByteForByte()
    {
        // RFC 8489 section 9.2.5: the client must echo a challenge's PASSWORD-ALGORITHMS back
        // unmodified, which only works if decoding and re-encoding are exact inverses.
        var original = StunPasswordAlgorithmsAttribute.Offering(StunPasswordAlgorithm.Sha256, StunPasswordAlgorithm.Md5);
        var encodedOnce = Encoded(original);

        var message = new StunMessage(StunClass.ErrorResponse, StunMethod.Allocate).Add(original);
        var decoded = StunMessage.Decode(message.Encode());
        var echoed = decoded.GetAttribute<StunPasswordAlgorithmsAttribute>()!;

        Encoded(echoed).Should().Equal(encodedOnce);
    }

    [Fact]
    public void MessageIntegritySha256_StoresTheFullThirtyTwoByteDigest()
    {
        // Unlike the other attributes in this file, MESSAGE-INTEGRITY-SHA256 is never written from
        // StunMessage.Attributes - like MESSAGE-INTEGRITY and FINGERPRINT, it is computed and
        // appended by Encode itself (covered by StunMessageTests), so this only checks the
        // constructor and property, not a message round trip.
        var digest = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();

        new StunMessageIntegritySha256Attribute(digest).Digest.Should().Equal(digest);
    }

    [Fact]
    public void MessageIntegritySha256_RejectsAnyLengthOtherThanThirtyTwoBytes()
    {
        var construct = () => new StunMessageIntegritySha256Attribute(new byte[16]);
        construct.Should().Throw<ByteBufferException>();
    }

    /// <summary>Encodes one attribute inside a throwaway message and returns just its bytes.</summary>
    private static byte[] Encoded(StunAttribute attribute)
    {
        var message = new StunMessage(StunClass.Request, StunMethod.Allocate).Add(attribute);
        return message.Encode().AsSpan(StunMessage.HeaderLength).ToArray();
    }

    private static StunAttribute RoundTrip(StunAttribute attribute)
    {
        var message = new StunMessage(StunClass.Request, StunMethod.Allocate).Add(attribute);
        return StunMessage.Decode(message.Encode()).Attributes.Single();
    }
}
