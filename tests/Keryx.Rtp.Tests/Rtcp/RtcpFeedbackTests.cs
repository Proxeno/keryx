using FluentAssertions;
using Keryx.Rtp.Rtcp;
using Xunit;

namespace Keryx.Rtp.Tests.Rtcp;

/// <summary>
/// Coverage for the feedback messages of RFC 4585, RFC 5104 and <c>draft-alvestrand-rmcat-remb-03</c>.
/// </summary>
public class RtcpFeedbackTests
{
    [Fact]
    public void Pli_is_twelve_octets_with_no_fci()
    {
        // RFC 4585 §6.3.1: "The PLI FB message is identified by PT=PSFB and FMT=1. There MUST be no
        // parameters, i.e. the length is 2."
        var pli = new RtcpPictureLossIndication(0x1111_1111, 0x2222_2222);
        var bytes = pli.ToByteArray();

        bytes.Should().Equal(
            0x81, 206, 0x00, 0x02,
            0x11, 0x11, 0x11, 0x11,
            0x22, 0x22, 0x22, 0x22);

        RtcpPictureLossIndication.TryParse(bytes, out var parsed).Should().BeTrue();
        parsed!.SenderSsrc.Should().Be(0x1111_1111);
        parsed.MediaSsrc.Should().Be(0x2222_2222);
    }

    [Fact]
    public void Fir_carries_target_ssrc_and_command_sequence_number()
    {
        // RFC 5104 §4.3.1.1: the FCI is SSRC (32 bits), Seq nr (8 bits), Reserved (24 bits).
        var fir = new RtcpFullIntraRequest(0x1111_1111, 0, 0x3333_3333, 9);
        var bytes = fir.ToByteArray();

        bytes.Should().Equal(
            0x84, 206, 0x00, 0x04,
            0x11, 0x11, 0x11, 0x11,
            0x00, 0x00, 0x00, 0x00,
            0x33, 0x33, 0x33, 0x33,
            0x09, 0x00, 0x00, 0x00);

        RtcpFullIntraRequest.TryParse(bytes, out var parsed).Should().BeTrue();
        parsed!.Entries.Should().ContainSingle();
        parsed.Entries[0].Ssrc.Should().Be(0x3333_3333);
        parsed.Entries[0].SequenceNumber.Should().Be(9);
    }

    [Fact]
    public void Fir_round_trips_multiple_entries()
    {
        var fir = new RtcpFullIntraRequest { SenderSsrc = 1, MediaSsrc = 0 };
        fir.Entries.Add(new RtcpFullIntraRequestEntry(10, 1));
        fir.Entries.Add(new RtcpFullIntraRequestEntry(20, 2));

        var bytes = fir.ToByteArray();
        bytes.Length.Should().Be(12 + 16);

        RtcpFullIntraRequest.TryParse(bytes, out var parsed).Should().BeTrue();
        parsed!.Entries.Should().HaveCount(2);
        parsed.Entries[1].Ssrc.Should().Be(20);
        parsed.Entries[1].SequenceNumber.Should().Be(2);
    }

    [Fact]
    public void Remb_parses_the_exponent_mantissa_bitrate_and_ssrc_list()
    {
        // draft-alvestrand-rmcat-remb-03 §2.2: 'R','E','M','B' | num SSRC | 6-bit exp | 18-bit mantissa.
        // exp = 10, mantissa = 1000 -> 1000 * 2^10 = 1 024 000 bit/s.
        // packed = (10 << 18) | 1000 = 0x2803E8
        byte[] bytes =
        [
            0x8F, 206, 0x00, 0x06,
            0x11, 0x11, 0x11, 0x11,
            0x00, 0x00, 0x00, 0x00,
            (byte)'R', (byte)'E', (byte)'M', (byte)'B',
            0x02, 0x28, 0x03, 0xE8,
            0xAA, 0xAA, 0xAA, 0xAA,
            0xBB, 0xBB, 0xBB, 0xBB,
        ];

        RtcpReceiverEstimatedMaxBitrate.TryParse(bytes, out var parsed).Should().BeTrue();
        parsed!.SenderSsrc.Should().Be(0x1111_1111);
        parsed.BitrateBitsPerSecond.Should().Be(1_024_000);
        parsed.Ssrcs.Should().Equal(0xAAAA_AAAAu, 0xBBBB_BBBBu);
    }

    [Fact]
    public void Remb_rejects_application_layer_feedback_with_another_identifier()
    {
        byte[] bytes =
        [
            0x8F, 206, 0x00, 0x04,
            0x11, 0x11, 0x11, 0x11,
            0x00, 0x00, 0x00, 0x00,
            (byte)'N', (byte)'O', (byte)'P', (byte)'E',
            0x00, 0x00, 0x00, 0x00,
        ];

        RtcpReceiverEstimatedMaxBitrate.TryParse(bytes, out _).Should().BeFalse();
        RtcpPacket.TryParse(bytes, out var generic).Should().BeTrue();
        generic.Should().BeOfType<RtcpUnknownPacket>();
    }

    [Fact]
    public void Nack_expands_the_bitmask_of_following_lost_packets()
    {
        // RFC 4585 §6.2.1: "bit i of the bitmask ... set to 1 if the receiver has not received RTP
        // packet number (PID+i+1)". BLP 0b1010 sets bits 1 and 3, i.e. PID+2 and PID+4.
        var nack = new RtcpGenericNack { SenderSsrc = 1, MediaSsrc = 2 };
        nack.Entries.Add(new RtcpNackEntry(100, 0b1010));

        nack.ExpandedSequenceNumbers.Should().Equal((ushort)100, (ushort)102, (ushort)104);
    }

    [Theory]
    [InlineData((ushort)0x0000, new int[0])]
    [InlineData((ushort)0x0001, new[] { 1 })]
    [InlineData((ushort)0x8000, new[] { 16 })]
    [InlineData((ushort)0xFFFF, new[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 })]
    public void Nack_bitmask_vectors(ushort bitmask, int[] expectedOffsets)
    {
        var nack = new RtcpGenericNack { SenderSsrc = 1, MediaSsrc = 2 };
        nack.Entries.Add(new RtcpNackEntry(1000, bitmask));

        var expected = new List<ushort> { 1000 };
        foreach (var offset in expectedOffsets)
        {
            expected.Add((ushort)(1000 + offset));
        }

        nack.ExpandedSequenceNumbers.Should().Equal(expected);
    }

    [Fact]
    public void Nack_packs_lost_sequence_numbers_into_the_fewest_entries()
    {
        // 100 and 116 are 16 apart, so both fit one entry (bit 15); 200 needs a second.
        var nack = new RtcpGenericNack(1, 2, [116, 100, 200]);

        nack.Entries.Should().HaveCount(2);
        nack.Entries[0].PacketId.Should().Be(100);
        nack.Entries[0].Bitmask.Should().Be(0x8000);
        nack.Entries[1].PacketId.Should().Be(200);
        nack.Entries[1].Bitmask.Should().Be(0);
        nack.ExpandedSequenceNumbers.Should().Equal((ushort)100, (ushort)116, (ushort)200);
    }

    [Fact]
    public void Nack_round_trips()
    {
        var nack = new RtcpGenericNack(0xAAAA_AAAA, 0xBBBB_BBBB, [10, 11, 13, 40]);
        var bytes = nack.ToByteArray();

        bytes[0].Should().Be(0x81); // V=2, FMT=1
        bytes[1].Should().Be(205);
        bytes.Length.Should().Be(12 + 8);

        RtcpGenericNack.TryParse(bytes, out var parsed).Should().BeTrue();
        parsed!.SenderSsrc.Should().Be(0xAAAA_AAAA);
        parsed.MediaSsrc.Should().Be(0xBBBB_BBBB);
        parsed.ExpandedSequenceNumbers.Should().Equal((ushort)10, (ushort)11, (ushort)13, (ushort)40);
    }

    [Fact]
    public void Nack_writes_expanded_sequence_numbers_without_allocating()
    {
        var nack = new RtcpGenericNack(1, 2, [10, 11, 13]);
        Span<ushort> destination = stackalloc ushort[8];
        var count = nack.WriteExpandedSequenceNumbers(destination);
        count.Should().Be(3);
        destination[..count].ToArray().Should().Equal((ushort)10, (ushort)11, (ushort)13);
    }

    [Fact]
    public void Nack_rejects_a_packet_whose_length_field_runs_past_the_buffer()
    {
        byte[] bytes = [0x81, 205, 0x00, 0x03, 1, 1, 1, 1, 2, 2, 2, 2, 0, 10, 0, 0];
        RtcpGenericNack.TryParse(bytes.AsSpan(0, 14), out _).Should().BeFalse();
    }

    [Fact]
    public void Nack_rejects_a_packet_with_no_fci_entries()
    {
        // RFC 4585 §6.2.1: a NACK carries at least one FCI entry.
        byte[] bytes = [0x81, 205, 0x00, 0x02, 1, 1, 1, 1, 2, 2, 2, 2];
        RtcpGenericNack.TryParse(bytes, out _).Should().BeFalse();
    }
}
