using FluentAssertions;
using Keryx.Core;
using Keryx.Sctp;
using Xunit;

namespace Keryx.Sctp.Tests;

/// <summary>DCEP (RFC 8832) message codec, checked against hand-built byte vectors.</summary>
public class DcepTests
{
    [Fact]
    public void OpenMessageMatchesHandBuiltBytes()
    {
        // RFC 8832 §5.1 layout:
        //   byte  0      Message Type = 0x03 (DATA_CHANNEL_OPEN)
        //   byte  1      Channel Type = 0x81 (PARTIAL_RELIABLE_REXMIT_UNORDERED)
        //   bytes 2-3    Priority               = 0x0000
        //   bytes 4-7    Reliability Parameter  = 0x00000000 (maxRetransmits = 0)
        //   bytes 8-9    Label Length           = 0x000A ("controller")
        //   bytes 10-11  Protocol Length        = 0x0000
        //   bytes 12+    Label, then Protocol
        var expected = new byte[]
        {
            0x03, 0x81,
            0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x0A,
            0x00, 0x00,
            (byte)'c', (byte)'o', (byte)'n', (byte)'t', (byte)'r', (byte)'o', (byte)'l', (byte)'l', (byte)'e', (byte)'r',
        };

        var message = new DcepOpenMessage(DcepChannelType.PartialReliableRexmitUnordered, "controller");
        message.Encode().Should().Equal(expected);
    }

    [Fact]
    public void OpenMessageWithProtocolAndReliabilityMatchesHandBuiltBytes()
    {
        var expected = new byte[]
        {
            0x03, 0x01,
            0x00, 0x07,
            0x00, 0x00, 0x00, 0x05,
            0x00, 0x09,
            0x00, 0x04,
            (byte)'t', (byte)'e', (byte)'l', (byte)'e', (byte)'m', (byte)'e', (byte)'t', (byte)'r', (byte)'y',
            (byte)'p', (byte)'r', (byte)'o', (byte)'x',
        };

        var message = new DcepOpenMessage(DcepChannelType.PartialReliableRexmit, "telemetry", "prox", priority: 7, reliabilityParameter: 5);
        message.Encode().Should().Equal(expected);

        var parsed = DcepOpenMessage.Parse(expected);
        parsed.ChannelType.Should().Be(DcepChannelType.PartialReliableRexmit);
        parsed.Label.Should().Be("telemetry");
        parsed.Protocol.Should().Be("prox");
        parsed.Priority.Should().Be(7);
        parsed.ReliabilityParameter.Should().Be(5);
        parsed.Unordered.Should().BeFalse();
        parsed.MaxRetransmits.Should().Be(5);
    }

    [Fact]
    public void OpenMessageWithPacketLifetimeRoundTrips()
    {
        // RFC 8832 §5.1 layout, channel type 0x82 (PARTIAL_RELIABLE_TIMED_UNORDERED), reliability
        // parameter = maxPacketLifetime in milliseconds.
        var expected = new byte[]
        {
            0x03, 0x82,
            0x00, 0x00,
            0x00, 0x00, 0x01, 0xF4,
            0x00, 0x09,
            0x00, 0x00,
            (byte)'t', (byte)'e', (byte)'l', (byte)'e', (byte)'m', (byte)'e', (byte)'t', (byte)'r', (byte)'y',
        };

        var message = new DcepOpenMessage(DcepChannelType.PartialReliableTimedUnordered, "telemetry", reliabilityParameter: 500);
        message.Encode().Should().Equal(expected);

        var parsed = DcepOpenMessage.Parse(expected);
        parsed.ChannelType.Should().Be(DcepChannelType.PartialReliableTimedUnordered);
        parsed.Unordered.Should().BeTrue();
        parsed.MaxRetransmits.Should().BeNull();
        parsed.MaxPacketLifetime.Should().Be(500);
    }

    [Fact]
    public void OpenMessageRoundTripsWithUnicodeLabel()
    {
        var message = new DcepOpenMessage(DcepChannelType.Reliable, "kanál-π", "sub");
        var parsed = DcepOpenMessage.Parse(message.Encode());
        parsed.Label.Should().Be("kanál-π");
        parsed.Protocol.Should().Be("sub");
        parsed.Unordered.Should().BeFalse();
        parsed.MaxRetransmits.Should().BeNull();
        parsed.MaxPacketLifetime.Should().BeNull();
    }

    [Fact]
    public void AckIsASingleByte()
    {
        DcepOpenMessage.EncodeAck().Should().Equal((byte)0x02);
        ((byte)DcepMessageType.DataChannelAck).Should().Be(0x02);
        ((byte)DcepMessageType.DataChannelOpen).Should().Be(0x03);
    }

    [Theory]
    [InlineData(true, null, null, DcepChannelType.Reliable)]
    [InlineData(false, null, null, DcepChannelType.ReliableUnordered)]
    [InlineData(true, (ushort)0, null, DcepChannelType.PartialReliableRexmit)]
    [InlineData(false, (ushort)0, null, DcepChannelType.PartialReliableRexmitUnordered)]
    [InlineData(true, null, (ushort)3000, DcepChannelType.PartialReliableTimed)]
    [InlineData(false, null, (ushort)3000, DcepChannelType.PartialReliableTimedUnordered)]
    public void ChannelTypeMapping(bool ordered, ushort? maxRetransmits, ushort? maxPacketLifetime, DcepChannelType expected)
    {
        DcepOpenMessage.ChannelTypeFor(ordered, maxRetransmits, maxPacketLifetime).Should().Be(expected);
    }

    [Fact]
    public void ChannelTypeForRejectsBothReliabilityLimitsAtOnce()
    {
        var act = () => DcepOpenMessage.ChannelTypeFor(true, maxRetransmits: 0, maxPacketLifetime: 500);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void UnorderedFlagIsTheHighBitOfChannelType()
    {
        DcepOpenMessage.Parse(new DcepOpenMessage(DcepChannelType.ReliableUnordered, "x").Encode())
            .Unordered.Should().BeTrue();
        ((byte)DcepChannelType.ReliableUnordered).Should().Be(0x80);
        ((byte)DcepChannelType.PartialReliableRexmitUnordered).Should().Be(0x81);
    }

    [Fact]
    public void ParseRejectsWrongMessageType()
    {
        var act = () => DcepOpenMessage.Parse(new byte[] { 0x02 });
        act.Should().Throw<ByteBufferException>().WithMessage("*DATA_CHANNEL_OPEN*");
    }

    [Fact]
    public void ParseRejectsTruncatedLabel()
    {
        var bytes = new DcepOpenMessage(DcepChannelType.Reliable, "controller").Encode();
        var act = () => DcepOpenMessage.Parse(bytes.AsSpan(0, bytes.Length - 3).ToArray());
        act.Should().Throw<ByteBufferException>();
    }
}
