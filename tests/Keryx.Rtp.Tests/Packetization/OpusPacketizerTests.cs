using System.Linq;
using System.Threading;
using FluentAssertions;
using Keryx.Rtp.Packetization;
using Xunit;

namespace Keryx.Rtp.Tests.Packetization;

/// <summary>Coverage for the Opus payload format (RFC 7587) over the shared packetizer seam.</summary>
public class OpusPacketizerTests
{
    // A CELT fullband 20 ms packet: TOC config 31, code 0. RFC 6716 §3.1 gives it a 960-tick duration
    // at the 48 kHz Opus clock, so it is a convenient "one frame" for media-clock gap assertions.
    private const byte Toc20Ms = 0xF8;
    private const uint Frame20MsTicks = 960;

    [Fact]
    public void Clock_rate_is_forty_eight_kilohertz()
    {
        // RFC 7587 §4.1: "The RTP timestamp is incremented with a 48000 Hz clock rate for all modes."
        new OpusPacketizer().ClockRate.Should().Be(48_000);
    }

    [Fact]
    public void One_opus_packet_becomes_one_rtp_payload()
    {
        // RFC 7587 §4.2: the payload is the Opus packet itself; no aggregation or fragmentation.
        byte[] frame = [0xF8, 0x01, 0x02, 0x03, 0x04];
        var writer = new CollectingRtpPayloadWriter();

        new OpusPacketizer().Packetize(frame, rtpTimestamp: 0, 1200, writer).Should().Be(1);

        writer.Payloads.Should().ContainSingle();
        writer.Payloads[0].Data.Should().Equal(frame);
    }

    [Fact]
    public void The_first_packet_of_a_stream_opens_a_talkspurt_and_is_marked()
    {
        // RFC 7587 §4.2: the very first packet of a stream is a talkspurt start, so marker = 1.
        byte[] frame = [Toc20Ms, 0x01, 0x02];
        var writer = new CollectingRtpPayloadWriter();

        new OpusPacketizer().Packetize(frame, rtpTimestamp: 12_345, 1200, writer);

        writer.Payloads[0].Marker.Should().BeTrue();
    }

    [Fact]
    public void Contiguous_frames_are_marked_only_on_the_first()
    {
        // Back-to-back frames advance the RTP timestamp by exactly one frame's duration each, so only
        // the opening packet carries the talkspurt marker.
        byte[] frame = [Toc20Ms, 0xAA, 0xBB];
        var packetizer = new OpusPacketizer();
        var writer = new CollectingRtpPayloadWriter();

        packetizer.Packetize(frame, rtpTimestamp: 0, 1200, writer);
        packetizer.Packetize(frame, rtpTimestamp: Frame20MsTicks, 1200, writer);
        packetizer.Packetize(frame, rtpTimestamp: 2 * Frame20MsTicks, 1200, writer);

        writer.Payloads.Select(p => p.Marker).Should().Equal(true, false, false);
    }

    [Fact]
    public void A_timestamp_jump_past_one_frame_duration_marks_the_talkspurt_start()
    {
        // A silence/DTX gap shows up as an RTP timestamp that has advanced by more than one frame's
        // worth of ticks: that packet reopens a talkspurt and is marked.
        byte[] frame = [Toc20Ms, 0xAA, 0xBB];
        var packetizer = new OpusPacketizer();
        var writer = new CollectingRtpPayloadWriter();

        packetizer.Packetize(frame, rtpTimestamp: 0, 1200, writer);
        packetizer.Packetize(frame, rtpTimestamp: Frame20MsTicks, 1200, writer);
        // Skip a frame: the next contiguous timestamp would be 2 × 960; arriving at 3 × 960 is a gap.
        packetizer.Packetize(frame, rtpTimestamp: 3 * Frame20MsTicks, 1200, writer);

        writer.Payloads.Select(p => p.Marker).Should().Equal(true, false, true);
    }

    [Fact]
    public void The_marker_ignores_elapsed_wall_clock_time()
    {
        // The decision rests on the media clock alone: a long real pause between calls (mimicking a GC
        // or scheduling stall) must NOT be mistaken for silence when the RTP timestamps stay contiguous.
        byte[] frame = [Toc20Ms, 0xAA, 0xBB];
        var packetizer = new OpusPacketizer();
        var writer = new CollectingRtpPayloadWriter();

        packetizer.Packetize(frame, rtpTimestamp: 0, 1200, writer);
        Thread.Sleep(60);
        packetizer.Packetize(frame, rtpTimestamp: Frame20MsTicks, 1200, writer);

        writer.Payloads.Select(p => p.Marker).Should().Equal(true, false);
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
        new OpusPacketizer().Packetize([], rtpTimestamp: 0, 1200, writer).Should().Be(0);
        writer.Payloads.Should().BeEmpty();
        new OpusPacketizer().GetTimestampIncrement([]).Should().Be(0);
    }

    [Fact]
    public void A_packet_larger_than_the_payload_limit_is_rejected()
    {
        // RFC 7587 §4.2 gives no fragmentation mechanism, so this is a configuration error.
        var writer = new CollectingRtpPayloadWriter();
        var frame = new byte[1300];
        var act = () => new OpusPacketizer().Packetize(frame, rtpTimestamp: 0, 1200, writer);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Drives_a_stream_sender_through_the_shared_seam()
    {
        var packetizer = (IRtpPayloadizer)new OpusPacketizer();
        var sender = new Keryx.Rtp.RtpStreamSender(1, 111, packetizer.ClockRate, initialSequenceNumber: 0, initialTimestamp: 0);
        var writer = new CollectingRtpPayloadWriter();

        byte[] frame = [0xF8, 0xAA, 0xBB];
        packetizer.Packetize(frame, sender.Timestamp, 1200, writer);
        sender.AdvanceTimestamp(packetizer.GetTimestampIncrement(frame));
        packetizer.Packetize(frame, sender.Timestamp, 1200, writer);

        writer.Payloads.Should().HaveCount(2);
        sender.Timestamp.Should().Be(960);
    }
}
