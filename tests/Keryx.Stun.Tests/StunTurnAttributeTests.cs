using System.Net;
using System.Net.Sockets;
using FluentAssertions;

using Xunit;

namespace Keryx.Stun.Tests;

/// <summary>
/// Wire-layout tests for the RFC 8656 TURN methods and attributes.
/// </summary>
/// <remarks>
/// <para>
/// RFC 8656 publishes no byte-level test vectors of its own - the only STUN vectors the RFC series
/// carries are RFC 5769's, which cover Binding and long-term authentication and are already
/// exercised by <see cref="Rfc5769VectorTests"/>. The expectations here are therefore assembled by
/// hand straight from the field diagrams in RFC 8656 section 18, one attribute at a time, so a
/// wrong type code, a missing reserved byte or a forgotten pad shows up as a byte difference.
/// </para>
/// <para>
/// The XOR-PEER-ADDRESS and XOR-RELAYED-ADDRESS cases reuse the endpoint and the exact encoded
/// value from the RFC 5769 section 2.2 vector: XOR-MAPPED-ADDRESS, XOR-PEER-ADDRESS and
/// XOR-RELAYED-ADDRESS share one value format, and for IPv4 the obfuscation depends only on the
/// magic cookie, so the RFC's own bytes apply unchanged under a different type code.
/// </para>
/// </remarks>
public sealed class StunTurnAttributeTests
{
    // RFC 5769 section 2.2: 192.0.2.1 port 32853, XOR-obfuscated.
    private static readonly IPEndPoint Rfc5769Address = new(IPAddress.Parse("192.0.2.1"), 32853);
    private const string Rfc5769XoredValue = "00 01 a1 47 e1 12 a6 43";

    [Theory]
    [InlineData(StunMethod.Allocate, 0x003)]
    [InlineData(StunMethod.Refresh, 0x004)]
    [InlineData(StunMethod.Send, 0x006)]
    [InlineData(StunMethod.Data, 0x007)]
    [InlineData(StunMethod.CreatePermission, 0x008)]
    [InlineData(StunMethod.ChannelBind, 0x009)]
    public void TurnMethods_UseTheCodesFromTheStunMethodRegistry(StunMethod method, int expected)
        => ((int)method).Should().Be(expected);

    [Theory]
    [InlineData(StunAttributeType.ChannelNumber, 0x000C)]
    [InlineData(StunAttributeType.Lifetime, 0x000D)]
    [InlineData(StunAttributeType.XorPeerAddress, 0x0012)]
    [InlineData(StunAttributeType.Data, 0x0013)]
    [InlineData(StunAttributeType.XorRelayedAddress, 0x0016)]
    [InlineData(StunAttributeType.RequestedAddressFamily, 0x0017)]
    [InlineData(StunAttributeType.EvenPort, 0x0018)]
    [InlineData(StunAttributeType.RequestedTransport, 0x0019)]
    [InlineData(StunAttributeType.DontFragment, 0x001A)]
    [InlineData(StunAttributeType.ReservationToken, 0x0022)]
    [InlineData(StunAttributeType.AdditionalAddressFamily, 0x8000)]
    [InlineData(StunAttributeType.AddressErrorCode, 0x8001)]
    [InlineData(StunAttributeType.Icmp, 0x8004)]
    public void TurnAttributes_UseTheCodesFromRfc8656Section18(StunAttributeType type, int expected)
        => ((int)type).Should().Be(expected);

    [Theory]
    [InlineData(StunAttributeType.ChannelNumber, true)]
    [InlineData(StunAttributeType.Lifetime, true)]
    [InlineData(StunAttributeType.XorRelayedAddress, true)]
    [InlineData(StunAttributeType.RequestedTransport, true)]
    [InlineData(StunAttributeType.DontFragment, true)]
    [InlineData(StunAttributeType.AdditionalAddressFamily, false)]
    [InlineData(StunAttributeType.AddressErrorCode, false)]
    [InlineData(StunAttributeType.Icmp, false)]
    public void TurnAttributes_SplitComprehensionRequiredAtTheRfc5389Boundary(StunAttributeType type, bool required)
        => ((ushort)type < 0x8000).Should().Be(required);

    [Fact]
    public void Lifetime_IsAFourByteSecondsCount()
        => Encoded(new StunLifetimeAttribute(600u)).Should().Equal(Hex.Parse("00 0d 00 04 00 00 02 58"));

    [Fact]
    public void Lifetime_RoundTrips()
    {
        var decoded = RoundTrip(new StunLifetimeAttribute(TimeSpan.FromMinutes(10)));
        decoded.Should().BeOfType<StunLifetimeAttribute>()
            .Which.Seconds.Should().Be(600);
    }

    [Fact]
    public void RequestedTransport_IsTheIanaProtocolNumberFollowedByThreeReservedBytes()
        => Encoded(new StunRequestedTransportAttribute()).Should().Equal(Hex.Parse("00 19 00 04 11 00 00 00"));

    [Fact]
    public void RequestedTransport_RoundTrips()
        => RoundTrip(new StunRequestedTransportAttribute(TurnTransportProtocol.Tcp))
            .Should().BeOfType<StunRequestedTransportAttribute>()
            .Which.Protocol.Should().Be(TurnTransportProtocol.Tcp);

    [Fact]
    public void ChannelNumber_IsTwoBytesFollowedByTwoReservedBytes()
        => Encoded(new StunChannelNumberAttribute(0x4000)).Should().Equal(Hex.Parse("00 0c 00 04 40 00 00 00"));

    [Fact]
    public void ChannelNumber_RoundTrips()
        => RoundTrip(new StunChannelNumberAttribute(0x4A5F))
            .Should().BeOfType<StunChannelNumberAttribute>()
            .Which.ChannelNumber.Should().Be(0x4A5F);

    [Theory]
    [InlineData(0x0000)]
    [InlineData(0x3FFF)]
    [InlineData(0x5000)]
    [InlineData(0xFFFF)]
    public void ChannelNumber_RejectsNumbersOutsideTheRangeRfc8656Section12Allocates(int number)
    {
        StunChannelNumberAttribute.IsValid((ushort)number).Should().BeFalse();
        var construct = () => new StunChannelNumberAttribute((ushort)number);
        construct.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Theory]
    [InlineData(0x4000)]
    [InlineData(0x4001)]
    [InlineData(0x4FFF)]
    public void ChannelNumber_AcceptsTheAllocatedRange(int number)
        => StunChannelNumberAttribute.IsValid((ushort)number).Should().BeTrue();

    [Fact]
    public void DontFragment_IsAZeroLengthFlag()
        => Encoded(StunDontFragmentAttribute.Instance).Should().Equal(Hex.Parse("00 1a 00 00"));

    [Fact]
    public void DontFragment_RoundTrips()
        => RoundTrip(StunDontFragmentAttribute.Instance).Should().BeOfType<StunDontFragmentAttribute>();

    [Fact]
    public void XorPeerAddress_SharesTheXorMappedAddressValueFormat()
        => Encoded(new StunXorPeerAddressAttribute(Rfc5769Address))
            .Should().Equal(Hex.Parse("00 12 00 08 " + Rfc5769XoredValue));

    [Fact]
    public void XorRelayedAddress_SharesTheXorMappedAddressValueFormat()
        => Encoded(new StunXorRelayedAddressAttribute(Rfc5769Address))
            .Should().Equal(Hex.Parse("00 16 00 08 " + Rfc5769XoredValue));

    [Fact]
    public void XorRelayedAddress_RoundTripsThroughAMessage()
    {
        var message = new StunMessage(StunClass.SuccessResponse, StunMethod.Allocate)
            .Add(new StunXorRelayedAddressAttribute(Rfc5769Address));
        var decoded = StunMessage.Decode(message.Encode());

        decoded.RelayedAddress.Should().Be(Rfc5769Address);
        decoded.GetAttribute<StunXorRelayedAddressAttribute>().Should().NotBeNull();
    }

    [Fact]
    public void Data_CarriesThePayloadAndIsPaddedToFourBytes()
    {
        byte[] payload = [0xDE, 0xAD, 0xBE, 0xEF, 0x01];
        Encoded(new StunDataAttribute(payload))
            .Should().Equal(Hex.Parse("00 13 00 05 de ad be ef 01 00 00 00"));
    }

    [Fact]
    public void Data_RoundTrips()
    {
        byte[] payload = [1, 2, 3, 4, 5, 6, 7];
        RoundTrip(new StunDataAttribute(payload))
            .Should().BeOfType<StunDataAttribute>()
            .Which.Value.Should().Equal(payload);
    }

    [Fact]
    public void EvenPort_PutsTheReserveFlagInTheTopBitOfASingleByte()
    {
        Encoded(new StunEvenPortAttribute(reserveNext: true)).Should().Equal(Hex.Parse("00 18 00 01 80 00 00 00"));
        Encoded(new StunEvenPortAttribute()).Should().Equal(Hex.Parse("00 18 00 01 00 00 00 00"));
    }

    [Fact]
    public void EvenPort_RoundTrips()
        => RoundTrip(new StunEvenPortAttribute(reserveNext: true))
            .Should().BeOfType<StunEvenPortAttribute>()
            .Which.ReserveNext.Should().BeTrue();

    [Fact]
    public void RequestedAddressFamily_IsAFamilyByteFollowedByThreeReservedBytes()
    {
        Encoded(new StunRequestedAddressFamilyAttribute(AddressFamily.InterNetwork))
            .Should().Equal(Hex.Parse("00 17 00 04 01 00 00 00"));
        Encoded(new StunRequestedAddressFamilyAttribute(AddressFamily.InterNetworkV6))
            .Should().Equal(Hex.Parse("00 17 00 04 02 00 00 00"));
    }

    [Fact]
    public void RequestedAddressFamily_RoundTrips()
        => RoundTrip(new StunRequestedAddressFamilyAttribute(AddressFamily.InterNetworkV6))
            .Should().BeOfType<StunRequestedAddressFamilyAttribute>()
            .Which.AddressFamily.Should().Be(AddressFamily.InterNetworkV6);

    [Fact]
    public void ReservationToken_IsEightOpaqueBytes()
    {
        byte[] token = [1, 2, 3, 4, 5, 6, 7, 8];
        Encoded(new StunReservationTokenAttribute(token)).Should().Equal(Hex.Parse("00 22 00 08 01 02 03 04 05 06 07 08"));
        RoundTrip(new StunReservationTokenAttribute(token))
            .Should().BeOfType<StunReservationTokenAttribute>()
            .Which.Token.Should().Equal(token);
    }

    [Fact]
    public void AllocateRequest_EncodesTheHeaderAndAttributesRfc8656Section7RequiresAndDecodesBack()
    {
        var request = new StunMessage(StunClass.Request, StunMethod.Allocate)
            .Add(new StunRequestedTransportAttribute())
            .Add(new StunLifetimeAttribute(600u))
            .Add(StunDontFragmentAttribute.Instance);

        var encoded = request.Encode();

        // Class Request (bits C1C0 = 00) with method 0x003 gives a message type of 0x0003.
        encoded.AsSpan(0, 2).ToArray().Should().Equal(Hex.Parse("00 03"));
        encoded.AsSpan(20).ToArray().Should().Equal(
            Hex.Parse("00 19 00 04 11 00 00 00  00 0d 00 04 00 00 02 58  00 1a 00 00"));

        var decoded = StunMessage.Decode(encoded);
        decoded.Method.Should().Be(StunMethod.Allocate);
        decoded.Class.Should().Be(StunClass.Request);
        decoded.GetAttribute<StunRequestedTransportAttribute>()!.Protocol.Should().Be(TurnTransportProtocol.Udp);
        decoded.GetAttribute<StunLifetimeAttribute>()!.Seconds.Should().Be(600);
        decoded.HasAttribute(StunAttributeType.DontFragment).Should().BeTrue();
        decoded.UnknownComprehensionRequiredTypes.Should().BeEmpty();
    }

    [Fact]
    public void AllocateSuccessResponse_ExposesTheRelayedAndReflexiveAddressesSeparately()
    {
        var relayed = new IPEndPoint(IPAddress.Parse("198.51.100.7"), 50000);
        var reflexive = new IPEndPoint(IPAddress.Parse("203.0.113.9"), 41234);

        var response = new StunMessage(StunClass.SuccessResponse, StunMethod.Allocate)
            .Add(new StunXorRelayedAddressAttribute(relayed))
            .Add(new StunXorMappedAddressAttribute(reflexive))
            .Add(new StunLifetimeAttribute(600u));

        var decoded = StunMessage.Decode(response.Encode());
        decoded.RelayedAddress.Should().Be(relayed);
        decoded.MappedAddress.Should().Be(reflexive);
        decoded.GetAttribute<StunLifetimeAttribute>()!.Lifetime.Should().Be(TimeSpan.FromSeconds(600));
    }

    [Fact]
    public void CreatePermissionRequest_CarriesOneXorPeerAddressPerPeer()
    {
        IPEndPoint[] peers =
        [
            new(IPAddress.Parse("192.0.2.1"), 1000),
            new(IPAddress.Parse("192.0.2.2"), 2000),
            new(IPAddress.Parse("192.0.2.3"), 3000),
        ];

        var request = new StunMessage(StunClass.Request, StunMethod.CreatePermission);
        foreach (var peer in peers)
        {
            request.Add(new StunXorPeerAddressAttribute(peer));
        }

        var decoded = StunMessage.Decode(request.Encode());
        decoded.Attributes.OfType<StunXorPeerAddressAttribute>().Select(a => a.EndPoint).Should().Equal(peers);
    }

    [Theory]
    [InlineData(StunErrorCodeAttribute.Forbidden, 403)]
    [InlineData(StunErrorCodeAttribute.AllocationMismatch, 437)]
    [InlineData(StunErrorCodeAttribute.StaleNonce, 438)]
    [InlineData(StunErrorCodeAttribute.AddressFamilyNotSupported, 440)]
    [InlineData(StunErrorCodeAttribute.WrongCredentials, 441)]
    [InlineData(StunErrorCodeAttribute.UnsupportedTransportProtocol, 442)]
    [InlineData(StunErrorCodeAttribute.PeerAddressFamilyMismatch, 443)]
    [InlineData(StunErrorCodeAttribute.AllocationQuotaReached, 486)]
    [InlineData(StunErrorCodeAttribute.InsufficientCapacity, 508)]
    public void TurnErrorCodes_MatchRfc8656Section17(int constant, int expected)
        => constant.Should().Be(expected);

    [Fact]
    public void TurnErrorCode_RoundTripsThroughTheErrorCodeAttribute()
    {
        var response = new StunMessage(StunClass.ErrorResponse, StunMethod.Allocate)
            .Add(new StunErrorCodeAttribute(StunErrorCodeAttribute.AllocationQuotaReached, "Allocation Quota Reached"));

        var decoded = StunMessage.Decode(response.Encode());
        decoded.ErrorCode.Should().Be(486);
        decoded.GetAttribute<StunErrorCodeAttribute>()!.Reason.Should().Be("Allocation Quota Reached");
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
