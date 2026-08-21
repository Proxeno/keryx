using FluentAssertions;
using Keryx.Rtp.Packetization;
using Xunit;

namespace Keryx.Rtp.Tests.Packetization;

/// <summary>Coverage for the Opus payload format (RFC 7587) over the shared packetizer seam.</summary>
public class OpusPacketizerTests
{
    [Fact]
    public void Clock_rate_is_forty_eight_kilohertz()
    {
        // RFC 7587 §4.1: "The RTP timestamp is incremented with a 48000 Hz clock rate for all modes."
        new OpusPacketizer().ClockRate.Should().Be(48_000);
    }

    [Fact]
    public void One_opus_packet_becomes_one_rtp_payload_with_no_marker()
    {
        // RFC 7587 §4.2: the payload is the Opus packet itself; no aggregation or fragmentation.
        byte[] frame = [0xF8, 0x01, 0x02, 0x03, 0x04];
        var writer = new CollectingRtpPayloadWriter();

        new OpusPacketizer().Packetize(frame, 1200, writer).Should().Be(1);

        writer.Payloads.Should().ContainSingle();
        writer.Payloads[0].Data.Should().Equal(frame);
        writer.Payloads[0].Marker.Should().BeFalse();
    }

    [Theory]
    [InlineData(0x00, 480)]   // config 0:  SILK NB,  10 ms
    [InlineData(0x08, 960)]   // config 1:  SILK NB,  20 ms
    [InlineData(0x10, 1920)]  // config 2:  SILK NB,  40 ms
    [InlineData(0x18, 2880)]  // config 3:  SILK NB,  60 ms
    [InlineData(0x20, 480)]   // config 4:  SILK MB,  10 ms
    [InlineData(0x60, 480)]   // config 12: hybrid SWB, 10 ms
    [InlineData(0x68, 960)]   // config 13: hybrid SWB, 20 ms
    [InlineData(0x70, 480)]   // config 14: hybrid FB,  10 ms
    [InlineData(0x78, 960)]   // config 15: hybrid FB,  20 ms
    [InlineData(0x80, 120)]   // config 16: CELT NB,  2.5 ms
    [InlineData(0x88, 240)]   // config 17: CELT NB,  5 ms
    [InlineData(0xF8, 960)]   // config 31: CELT FB,  20 ms
    public void Timestamp_increment_comes_from_the_toc_byte(byte toc, uint expectedTicks)
    {
        // RFC 6716 §3.1 defines the configuration numbers; RFC 7587 §4.1 fixes the clock at 48 kHz.
        byte[] frame = [toc, 0x00];
        new OpusPacketizer().GetTimestampIncrement(frame).Should().Be(expectedTicks);
    }

    [Fact]
    public void Two_frame_codes_double_the_timestamp_increment()
    {
        // RFC 6716 §3.1: TOC code 1 and 2 both mean two frames per packet.
        new OpusPacketizer().GetTimestampIncrement([0xF9, 0x00]).Should().Be(1920);
        new OpusPacketizer().GetTimestampIncrement([0xFA, 0x00]).Should().Be(1920);
    }

    [Fact]
    public void Code_three_reads_the_frame_count_from_the_second_octet()
    {
        // RFC 6716 §3.2.5: code 3 packets carry the frame count in the low six bits of the next octet.
        new OpusPacketizer().GetTimestampIncrement([0xFB, 0x03]).Should().Be(2880); // 3 × 20 ms
    }

    [Fact]
    public void An_empty_frame_produces_nothing()
    {
        var writer = new CollectingRtpPayloadWriter();
        new OpusPacketizer().Packetize([], 1200, writer).Should().Be(0);
        writer.Payloads.Should().BeEmpty();
        new OpusPacketizer().GetTimestampIncrement([]).Should().Be(0);
    }

    [Fact]
    public void A_packet_larger_than_the_payload_limit_is_rejected()
    {
        // RFC 7587 §4.2 gives no fragmentation mechanism, so this is a configuration error.
        var writer = new CollectingRtpPayloadWriter();
        var frame = new byte[1300];
        var act = () => new OpusPacketizer().Packetize(frame, 1200, writer);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Drives_a_stream_sender_through_the_shared_seam()
    {
        var packetizer = (IRtpPayloadizer)new OpusPacketizer();
        var sender = new Keryx.Rtp.RtpStreamSender(1, 111, packetizer.ClockRate, initialSequenceNumber: 0, initialTimestamp: 0);
        var writer = new CollectingRtpPayloadWriter();

        byte[] frame = [0xF8, 0xAA, 0xBB];
        packetizer.Packetize(frame, 1200, writer);
        sender.AdvanceTimestamp(packetizer.GetTimestampIncrement(frame));
        packetizer.Packetize(frame, 1200, writer);

        writer.Payloads.Should().HaveCount(2);
        sender.Timestamp.Should().Be(960);
    }
}
