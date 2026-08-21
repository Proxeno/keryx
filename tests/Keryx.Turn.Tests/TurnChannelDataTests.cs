using System.Net;
using FluentAssertions;
using Keryx.Stun;
using Xunit;

namespace Keryx.Turn.Tests;

/// <summary>
/// The ChannelData framing of RFC 8656 section 12.4 and the RFC 7983 / RFC 8656 Table 3
/// demultiplexing rule that lets it share a socket with STUN, DTLS and RTP.
/// </summary>
public sealed class TurnChannelDataTests
{
    [Fact]
    public void Encode_WritesTheChannelNumberThenTheLengthThenThePayload()
    {
        byte[] payload = [0xAA, 0xBB, 0xCC];
        var buffer = new byte[16];

        var written = TurnChannelData.Encode(buffer, 0x4001, payload);

        written.Should().Be(TurnChannelData.HeaderLength + payload.Length);
        buffer.AsSpan(0, written).ToArray().Should().Equal([0x40, 0x01, 0x00, 0x03, 0xAA, 0xBB, 0xCC]);
    }

    [Fact]
    public void Encode_DoesNotPadOverUdp()
    {
        // RFC 8656 section 12.5 requires four-byte padding only over TCP and TLS-over-TCP; over UDP
        // "the padding is not required". Keryx allocations are UDP, so a five-byte payload produces
        // a nine-byte datagram, not twelve.
        var buffer = new byte[32];
        var written = TurnChannelData.Encode(buffer, 0x4000, [1, 2, 3, 4, 5]);
        written.Should().Be(9);
    }

    [Fact]
    public void Decode_RoundTripsTheChannelNumberAndPayload()
    {
        byte[] payload = [.. Enumerable.Range(0, 200).Select(i => (byte)i)];
        var buffer = new byte[512];
        var written = TurnChannelData.Encode(buffer, 0x4ABC, payload);

        TurnChannelData.TryDecode(buffer.AsSpan(0, written), out var channel, out var decoded).Should().BeTrue();
        channel.Should().Be(0x4ABC);
        decoded.ToArray().Should().Equal(payload);
    }

    [Fact]
    public void Decode_AcceptsAZeroLengthPayload()
    {
        // RFC 8656 section 12.4: "Note that 0 is a valid length."
        var buffer = new byte[8];
        var written = TurnChannelData.Encode(buffer, 0x4000, []);

        written.Should().Be(TurnChannelData.HeaderLength);
        TurnChannelData.TryDecode(buffer.AsSpan(0, written), out _, out var payload).Should().BeTrue();
        payload.Length.Should().Be(0);
    }

    [Fact]
    public void Decode_IgnoresTrailingPaddingAServerMayHaveIncluded()
    {
        byte[] datagram = [0x40, 0x00, 0x00, 0x02, 0xDE, 0xAD, 0x00, 0x00];

        TurnChannelData.TryDecode(datagram, out var channel, out var payload).Should().BeTrue();
        channel.Should().Be(0x4000);
        payload.ToArray().Should().Equal([0xDE, 0xAD]);
    }

    [Fact]
    public void Decode_RejectsADatagramTruncatedBeforeTheDeclaredLength()
    {
        byte[] datagram = [0x40, 0x00, 0x00, 0x10, 1, 2, 3];
        TurnChannelData.TryDecode(datagram, out _, out _).Should().BeFalse();
    }

    [Theory]
    [InlineData(0x0000)]
    [InlineData(0x3FFF)]
    [InlineData(0x5000)]
    [InlineData(0x7FFF)]
    [InlineData(0xFFFF)]
    public void LooksLikeChannelData_RejectsChannelNumbersOutsideTheRfc8656Range(int channel)
    {
        byte[] datagram = [(byte)(channel >> 8), (byte)channel, 0x00, 0x00];
        TurnChannelData.LooksLikeChannelData(datagram).Should().BeFalse();
    }

    [Fact]
    public void Encode_RejectsChannelNumbersOutsideTheRfc8656Range()
    {
        var buffer = new byte[16];
        var encode = () => TurnChannelData.Encode(buffer, 0x5000, [1]);
        encode.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void ChannelData_NeverLooksLikeStun()
    {
        var buffer = new byte[64];
        var written = TurnChannelData.Encode(buffer, 0x4000, [.. Enumerable.Repeat((byte)0, 16)]);
        var datagram = buffer.AsSpan(0, written);

        // A STUN message's two most significant bits are zero (RFC 8489 section 5), so a first byte
        // of 0x40-0x4F can never be STUN, and the magic cookie would have to be at offset 4.
        StunMessage.LooksLikeStun(datagram).Should().BeFalse();
        TurnChannelData.LooksLikeChannelData(datagram).Should().BeTrue();
    }

    [Fact]
    public void StunMessages_NeverLookLikeChannelData()
    {
        var binding = StunMessage.CreateBindingRequest().Encode(appendFingerprint: true);
        var allocate = new StunMessage(StunClass.Request, StunMethod.Allocate)
            .Add(new StunRequestedTransportAttribute())
            .Encode();
        var data = new StunMessage(StunClass.Indication, StunMethod.Data)
            .Add(new StunXorPeerAddressAttribute(new IPEndPoint(IPAddress.Loopback, 1234)))
            .Add(new StunDataAttribute([1, 2, 3]))
            .Encode();

        TurnChannelData.LooksLikeChannelData(binding).Should().BeFalse();
        TurnChannelData.LooksLikeChannelData(allocate).Should().BeFalse();
        TurnChannelData.LooksLikeChannelData(data).Should().BeFalse();
    }

    [Theory]
    [InlineData(0x14)] // DTLS: 20-63.
    [InlineData(0x3F)]
    [InlineData(0x80)] // RTP/RTCP: 128-191.
    [InlineData(0xBF)]
    public void ChannelDataRange_DoesNotCollideWithTheOtherProtocolsOnTheSameSocket(int firstByte)
    {
        // RFC 8656 Table 3 / RFC 7983: STUN 0-3, DTLS 20-63, TURN Channel 64-79, RTP 128-191.
        byte[] datagram = [(byte)firstByte, 0x00, 0x00, 0x00, 0x00];
        TurnChannelData.LooksLikeChannelData(datagram).Should().BeFalse();
    }

    [Fact]
    public void ChannelDataRange_IsExactlyTheSixteenValuesRfc7983AllocatesToTurn()
    {
        for (var firstByte = 0; firstByte <= 0xFF; firstByte++)
        {
            byte[] datagram = [(byte)firstByte, 0x00, 0x00, 0x00];
            var expected = firstByte is >= 0x40 and <= 0x4F;
            TurnChannelData.LooksLikeChannelData(datagram).Should().Be(
                expected,
                $"first byte 0x{firstByte:X2} is {(expected ? string.Empty : "not ")}in the TURN Channel range of RFC 7983");
        }
    }

    [Fact]
    public void ChannelDataOverhead_IsAFractionOfASendIndications()
    {
        var payload = new byte[1200];
        var buffer = new byte[2048];

        var channelBytes = TurnChannelData.Encode(buffer, 0x4000, payload);
        var indicationBytes = new StunMessage(StunClass.Indication, StunMethod.Send)
            .Add(new StunXorPeerAddressAttribute(new IPEndPoint(IPAddress.Parse("203.0.113.1"), 50000)))
            .Add(new StunDataAttribute(payload))
            .Encode()
            .Length;

        (channelBytes - payload.Length).Should().Be(4);
        (indicationBytes - payload.Length).Should().Be(36);
    }
}
