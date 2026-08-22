using FluentAssertions;
using Keryx.Rtp.Rtcp;
using Xunit;

namespace Keryx.Rtp.Tests.Rtcp;

/// <summary>
/// Coverage for transport-wide congestion control feedback,
/// <c>draft-holmer-rmcat-transport-wide-cc-extensions-01</c> §3.1.
/// </summary>
public class RtcpTransportCcTests
{
    /// <summary>
    /// A hand-built feedback packet mixing a run-length chunk with a two-bit status-vector chunk.
    ///
    /// base seq 100, 10 statuses, reference time 291 (× 64 ms = 18 624 000 µs), fb count 7.
    /// chunk 1 = 0x2005: run length, symbol 1 (small delta), run 5   -> seq 100..104
    /// chunk 2 = 0xE140: status vector, 2-bit symbols [2,0,1,1,0,0,0] -> seq 105..109 uses the first 5
    /// deltas    = 10, 20, 30, 40, 50 (small) | 400 (large) | 5, 6 (small)
    /// </summary>
    private static readonly byte[] MixedChunkVector =
    [
        0x8F, 205, 0x00, 0x08,              // V=2 P=0 FMT=15, PT=205, length = 9 words - 1
        0x11, 0x22, 0x33, 0x44,             // sender SSRC
        0x55, 0x66, 0x77, 0x88,             // media SSRC
        0x00, 0x64,                         // base sequence number = 100
        0x00, 0x0A,                         // packet status count = 10
        0x00, 0x01, 0x23,                   // reference time = 291
        0x07,                               // feedback packet count
        0x20, 0x05,                         // run-length chunk: symbol 1, run 5
        0xE1, 0x40,                         // status-vector chunk: 2-bit symbols
        10, 20, 30, 40, 50,                 // small deltas for 100..104
        0x01, 0x90,                         // large delta 400 for 105
        5, 6,                               // small deltas for 107, 108
        0x00, 0x00, 0x00,                   // padding to a 32-bit boundary
    ];

    [Fact]
    public void Parses_a_mixed_run_length_and_status_vector_vector()
    {
        RtcpTransportCcFeedback.TryParse(MixedChunkVector, out var feedback).Should().BeTrue();

        feedback!.SenderSsrc.Should().Be(0x1122_3344);
        feedback.MediaSsrc.Should().Be(0x5566_7788);
        feedback.BaseSequenceNumber.Should().Be(100);
        feedback.FeedbackPacketCount.Should().Be(7);
        feedback.ReferenceTime.Should().Be(291);
        feedback.ReferenceTimeMicroseconds.Should().Be(18_624_000);
        feedback.PacketStatusCount.Should().Be(10);

        feedback.PacketStatuses.Select(s => s.SequenceNumber)
            .Should().Equal((ushort)100, (ushort)101, (ushort)102, (ushort)103, (ushort)104,
                            (ushort)105, (ushort)106, (ushort)107, (ushort)108, (ushort)109);

        feedback.PacketStatuses.Select(s => s.Symbol).Should().Equal(
            TransportCcStatusSymbol.ReceivedSmallDelta,
            TransportCcStatusSymbol.ReceivedSmallDelta,
            TransportCcStatusSymbol.ReceivedSmallDelta,
            TransportCcStatusSymbol.ReceivedSmallDelta,
            TransportCcStatusSymbol.ReceivedSmallDelta,
            TransportCcStatusSymbol.ReceivedLargeOrNegativeDelta,
            TransportCcStatusSymbol.NotReceived,
            TransportCcStatusSymbol.ReceivedSmallDelta,
            TransportCcStatusSymbol.ReceivedSmallDelta,
            TransportCcStatusSymbol.NotReceived);
    }

    [Fact]
    public void Reconstructs_arrival_times_by_accumulating_receive_deltas()
    {
        // §3.1.5: "The delta ... in multiples of 250 µs", accumulated onto the reference time.
        RtcpTransportCcFeedback.TryParse(MixedChunkVector, out var feedback).Should().BeTrue();
        var statuses = feedback!.PacketStatuses;

        statuses[0].ArrivalTimeMicroseconds.Should().Be(18_624_000 + 2_500);
        statuses[1].ArrivalTimeMicroseconds.Should().Be(18_624_000 + 2_500 + 5_000);
        statuses[4].ArrivalTimeMicroseconds.Should().Be(18_661_500);
        statuses[5].DeltaTicks.Should().Be(400);
        statuses[5].ArrivalTimeMicroseconds.Should().Be(18_761_500);
        statuses[6].Received.Should().BeFalse();
        statuses[7].ArrivalTimeMicroseconds.Should().Be(18_762_750);
        statuses[8].ArrivalTimeMicroseconds.Should().Be(18_764_250);
    }

    [Fact]
    public void Parses_a_one_bit_status_vector_chunk()
    {
        // §3.1.4: T=1, S=0 -> 14 one-bit symbols, 0 = not received, 1 = received small delta.
        // 0xA800 = 1 0 | 1 0 1 0 0 0 0 0 0 0 0 0 0 0 -> symbols: recv, none, recv, none, ...
        byte[] bytes =
        [
            0x8F, 205, 0x00, 0x05,
            0, 0, 0, 1,
            0, 0, 0, 2,
            0x00, 0x00,     // base sequence number 0
            0x00, 0x04,     // four statuses
            0x00, 0x00, 0x00,
            0x00,
            0xA8, 0x00,     // one-bit status-vector chunk
            7, 8,           // two small deltas
        ];

        RtcpTransportCcFeedback.TryParse(bytes, out var feedback).Should().BeTrue();
        feedback!.PacketStatuses.Select(s => s.Symbol).Should().Equal(
            TransportCcStatusSymbol.ReceivedSmallDelta,
            TransportCcStatusSymbol.NotReceived,
            TransportCcStatusSymbol.ReceivedSmallDelta,
            TransportCcStatusSymbol.NotReceived);
        feedback.PacketStatuses[0].DeltaTicks.Should().Be(7);
        feedback.PacketStatuses[2].DeltaTicks.Should().Be(8);
    }

    [Fact]
    public void Sign_extends_a_negative_reference_time()
    {
        // §3.1: the reference time is a signed 24-bit value.
        var bytes = (byte[])MixedChunkVector.Clone();
        bytes[16] = 0xFF; bytes[17] = 0xFF; bytes[18] = 0xFF; // -1
        RtcpTransportCcFeedback.TryParse(bytes, out var feedback).Should().BeTrue();
        feedback!.ReferenceTime.Should().Be(-1);
        feedback.ReferenceTimeMicroseconds.Should().Be(-64_000);
    }

    [Fact]
    public void Reads_a_negative_large_delta_as_signed()
    {
        var bytes = (byte[])MixedChunkVector.Clone();
        bytes[29] = 0xFF; bytes[30] = 0x9C; // -100 ticks = -25 000 µs
        RtcpTransportCcFeedback.TryParse(bytes, out var feedback).Should().BeTrue();
        feedback!.PacketStatuses[5].DeltaTicks.Should().Be(-100);
    }

    [Fact]
    public void Rejects_a_packet_truncated_inside_its_receive_deltas()
    {
        RtcpTransportCcFeedback.TryParse(MixedChunkVector.AsSpan(0, 24).ToArray(), out _)
            .Should().BeFalse();
    }

    [Fact]
    public void Rejects_a_packet_that_is_not_transport_cc_feedback()
    {
        var pli = new RtcpPictureLossIndication(1, 2).ToByteArray();
        RtcpTransportCcFeedback.TryParse(pli, out _).Should().BeFalse();
    }

    [Fact]
    public void Builder_round_trips_through_the_parser()
    {
        var feedback = new RtcpTransportCcFeedback { SenderSsrc = 0xAAAA_AAAA, MediaSsrc = 0xBBBB_BBBB, FeedbackPacketCount = 3 };
        var baseTime = 1_000_064_000L; // an exact multiple of the 64 ms reference-time tick

        feedback.AddPacket(500, baseTime);
        feedback.AddPacket(501, baseTime + 5_000);
        feedback.AddPacket(502, baseTime + 10_000);
        feedback.AddPacket(505, baseTime + 25_000);   // 503 and 504 were lost
        feedback.AddPacket(506, baseTime + 125_000);  // needs a large delta

        feedback.PacketStatusCount.Should().Be(7);

        var bytes = feedback.ToByteArray();
        (bytes.Length % 4).Should().Be(0);
        bytes[0].Should().Be(0x8F);
        bytes[1].Should().Be(205);

        RtcpTransportCcFeedback.TryParse(bytes, out var parsed).Should().BeTrue();
        parsed!.BaseSequenceNumber.Should().Be(500);
        parsed.FeedbackPacketCount.Should().Be(3);
        parsed.PacketStatusCount.Should().Be(7);
        parsed.PacketStatuses.Where(s => s.Received).Select(s => s.SequenceNumber)
            .Should().Equal((ushort)500, (ushort)501, (ushort)502, (ushort)505, (ushort)506);
        parsed.PacketStatuses[3].Received.Should().BeFalse();
        parsed.PacketStatuses[4].Received.Should().BeFalse();

        parsed.PacketStatuses[0].ArrivalTimeMicroseconds.Should().Be(baseTime);
        parsed.PacketStatuses[1].ArrivalTimeMicroseconds.Should().Be(baseTime + 5_000);
        parsed.PacketStatuses[6].ArrivalTimeMicroseconds.Should().Be(baseTime + 125_000);
        parsed.PacketStatuses[6].Symbol.Should().Be(TransportCcStatusSymbol.ReceivedLargeOrNegativeDelta);
    }

    [Fact]
    public void Builder_emits_a_run_length_chunk_for_a_long_run_of_identical_symbols()
    {
        var feedback = new RtcpTransportCcFeedback { SenderSsrc = 1, MediaSsrc = 2 };
        var baseTime = 64_000L;
        for (var i = 0; i < 20; i++)
        {
            feedback.AddPacket((ushort)(1000 + i), baseTime + (i * 5_000));
        }

        var bytes = feedback.ToByteArray();

        // 8 octets of fixed FCI + one 16-bit run-length chunk + 20 one-octet deltas = 30, padded to 32.
        bytes.Length.Should().Be(12 + 32);
        var chunk = (bytes[20] << 8) | bytes[21];
        (chunk & 0x8000).Should().Be(0);            // run-length chunk
        ((chunk >> 13) & 0x03).Should().Be(1);      // symbol: received, small delta
        (chunk & 0x1FFF).Should().Be(20);           // run length

        RtcpTransportCcFeedback.TryParse(bytes, out var parsed).Should().BeTrue();
        parsed!.PacketStatusCount.Should().Be(20);
        parsed.PacketStatuses.Should().OnlyContain(s => s.Received);
    }

    [Fact]
    public void Builder_records_explicitly_missing_trailing_packets()
    {
        var feedback = new RtcpTransportCcFeedback { SenderSsrc = 1, MediaSsrc = 2 };
        feedback.AddPacket(10, 64_000);
        feedback.AddMissingPacket(12);

        feedback.PacketStatusCount.Should().Be(3);

        RtcpTransportCcFeedback.TryParse(feedback.ToByteArray(), out var parsed).Should().BeTrue();
        parsed!.PacketStatuses.Select(s => s.Received).Should().Equal(true, false, false);
    }

    [Fact]
    public void Packet_is_recognised_by_the_generic_dispatcher()
    {
        RtcpPacket.TryParse(MixedChunkVector, out var packet).Should().BeTrue();
        packet.Should().BeOfType<RtcpTransportCcFeedback>();
    }
}
