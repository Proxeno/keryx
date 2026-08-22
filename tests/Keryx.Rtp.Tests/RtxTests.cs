using FluentAssertions;
using Keryx.Core;
using Xunit;

namespace Keryx.Rtp.Tests;

/// <summary>
/// Coverage for the RTP retransmission payload format of RFC 4588 §4 and for the NACK-driven
/// retransmitter built on it.
/// </summary>
public class RtxTests
{
    private const uint MediaSsrc = 0x0A0B_0C0D;
    private const uint RtxSsrc = 0x1122_3344;
    private const byte MediaPayloadType = 96;
    private const byte RtxPayloadType = 97;

    private static byte[] Original(
        ushort sequenceNumber,
        uint timestamp = 90_000,
        bool marker = false,
        int payloadLength = 20)
    {
        var sender = new RtpStreamSender(MediaSsrc, MediaPayloadType, 90_000, sequenceNumber, timestamp);
        var payload = new byte[payloadLength];
        for (var i = 0; i < payloadLength; i++)
        {
            payload[i] = (byte)(i + 1);
        }

        var buffer = new byte[RtpHeader.FixedLength + payloadLength];
        var length = sender.WritePacket(payload, marker, buffer);
        return buffer[..length];
    }

    private static (RtxRetransmitter Retransmitter, RtpSendHistory History, TestTimeProvider Clock) NewSender(
        RtxRetransmitOptions? options = null,
        RtpSendHistoryOptions? historyOptions = null,
        ushort initialSequenceNumber = 500)
    {
        var clock = new TestTimeProvider();
        var history = new RtpSendHistory(
            1200,
            historyOptions ?? new RtpSendHistoryOptions { Capacity = 64 },
            clock);
        var retransmitter = new RtxRetransmitter(
            RtxSsrc,
            RtxPayloadType,
            90_000,
            history,
            options,
            initialSequenceNumber,
            clock);
        return (retransmitter, history, clock);
    }

    // ------------------------------------------------------------------ RFC 4588 §4 payload format

    [Fact]
    public void The_rtx_payload_opens_with_the_original_sequence_number_in_network_byte_order()
    {
        // RFC 4588 §4: "The RTX packet ... OSN: 16 bits. The sequence number of the original RTP packet."
        Span<byte> destination = stackalloc byte[16];

        var written = RtxPacket.WritePayload(0xBEEF, [1, 2, 3], destination);

        written.Should().Be(RtxPacket.OriginalSequenceNumberLength + 3);
        destination[0].Should().Be(0xBE);
        destination[1].Should().Be(0xEF);
        destination[2..5].ToArray().Should().Equal(1, 2, 3);
    }

    [Fact]
    public void Reading_the_original_sequence_number_needs_the_two_octet_field()
    {
        RtxPacket.TryReadOriginalSequenceNumber([0x00, 0x2A], out var osn).Should().BeTrue();
        osn.Should().Be(42);
        RtxPacket.TryReadOriginalSequenceNumber([0x00], out _).Should().BeFalse();
    }

    [Fact]
    public void Writing_a_payload_that_does_not_fit_throws()
    {
        var act = () => RtxPacket.WritePayload(1, new byte[10], new byte[4]);
        act.Should().Throw<ByteBufferException>();
    }

    // ------------------------------------------------------------------ RFC 4588 §4 packet rules

    [Fact]
    public void A_retransmission_carries_the_rtx_ssrc_payload_type_and_the_original_timestamp()
    {
        // RFC 4588 §4: the RTX packet uses the retransmission stream's SSRC and payload type, and
        // "the RTP timestamp ... MUST be the same as the timestamp of the original packet".
        var (rtx, history, _) = NewSender();
        var original = Original(1000, timestamp: 123_456, marker: true);
        history.Store(1000, original);

        var destination = new byte[1500];
        rtx.TryRetransmit(1000, destination, out var length).Should().Be(RtxRetransmitResult.Retransmitted);

        RtpPacket.TryParse(destination.AsSpan(0, length), out var packet).Should().BeTrue();
        packet.Header.Ssrc.Should().Be(RtxSsrc);
        packet.Header.PayloadType.Should().Be(RtxPayloadType);
        packet.Header.Timestamp.Should().Be(123_456u);
        packet.Header.Marker.Should().BeTrue();
        packet.Header.SequenceNumber.Should().Be(500);
        packet.Payload.Length.Should().Be(RtxPacket.OriginalSequenceNumberLength + 20);
    }

    [Fact]
    public void A_retransmission_prefixes_the_original_payload_with_the_original_sequence_number()
    {
        var (rtx, history, _) = NewSender();
        var original = Original(4321);
        history.Store(4321, original);

        var destination = new byte[1500];
        rtx.TryRetransmit(4321, destination, out var length).Should().Be(RtxRetransmitResult.Retransmitted);

        RtpPacket.TryParse(destination.AsSpan(0, length), out var packet).Should().BeTrue();
        RtxPacket.TryReadOriginalSequenceNumber(packet.Payload, out var osn).Should().BeTrue();
        osn.Should().Be(4321);
        packet.Payload[RtxPacket.OriginalSequenceNumberLength..].ToArray()
            .Should().Equal(original[RtpHeader.FixedLength..]);
    }

    [Fact]
    public void The_retransmission_stream_has_its_own_monotonic_sequence_number_space()
    {
        // RFC 4588 §4: "The RTX ... uses a separate sequence number space", so out-of-order repairs
        // still leave the retransmission stream gap free.
        var (rtx, history, _) = NewSender(initialSequenceNumber: 65_534);
        foreach (var seq in new ushort[] { 10, 11, 12 })
        {
            history.Store(seq, Original(seq));
        }

        var destination = new byte[1500];
        var sequenceNumbers = new List<ushort>();
        foreach (var seq in new ushort[] { 12, 10, 11 })
        {
            rtx.TryRetransmit(seq, destination, out var length).Should().Be(RtxRetransmitResult.Retransmitted);
            RtpPacket.TryParse(destination.AsSpan(0, length), out var packet).Should().BeTrue();
            sequenceNumbers.Add(packet.Header.SequenceNumber);
        }

        sequenceNumbers.Should().Equal((ushort)65_534, (ushort)65_535, (ushort)0);
        rtx.NextSequenceNumber.Should().Be(1);
    }

    [Fact]
    public void A_retransmission_decapsulates_back_to_the_original_packet()
    {
        var (rtx, history, _) = NewSender();
        var original = Original(2048, timestamp: 777, marker: true, payloadLength: 300);
        history.Store(2048, original);

        var destination = new byte[1500];
        rtx.TryRetransmit(2048, destination, out var length).Should().Be(RtxRetransmitResult.Retransmitted);

        var recovered = new byte[1500];
        RtxPacket.TryDecapsulate(
                destination.AsSpan(0, length),
                MediaSsrc,
                MediaPayloadType,
                recovered,
                out var recoveredLength,
                out var osn)
            .Should().BeTrue();

        osn.Should().Be(2048);
        recovered[..recoveredLength].Should().Equal(original);
    }

    [Fact]
    public void Decapsulating_a_packet_without_an_osn_field_fails()
    {
        var sender = new RtpStreamSender(RtxSsrc, RtxPayloadType, 90_000, 1, 1);
        var buffer = new byte[64];
        var length = sender.WritePacket([0x01], marker: false, buffer);

        RtxPacket.TryDecapsulate(buffer.AsSpan(0, length), MediaSsrc, MediaPayloadType, new byte[64], out _, out _)
            .Should().BeFalse();
    }

    // ------------------------------------------------------------------ NACK service policy

    [Fact]
    public void A_sequence_number_that_left_the_history_is_counted_as_a_miss()
    {
        var (rtx, history, _) = NewSender(historyOptions: new RtpSendHistoryOptions { Capacity = 2 });
        history.Store(1, Original(1));
        history.Store(2, Original(2));
        history.Store(3, Original(3));

        rtx.TryRetransmit(1, new byte[1500], out _).Should().Be(RtxRetransmitResult.HistoryMiss);

        var stats = rtx.GetStats();
        stats.RequestedPackets.Should().Be(1);
        stats.HistoryMisses.Should().Be(1);
        stats.PacketsRetransmitted.Should().Be(0);
    }

    [Fact]
    public void A_repeated_nack_inside_the_minimum_interval_is_suppressed()
    {
        var (rtx, history, clock) = NewSender(
            new RtxRetransmitOptions { MinimumResendInterval = TimeSpan.FromMilliseconds(60) });
        history.Store(9, Original(9));
        var destination = new byte[1500];

        rtx.TryRetransmit(9, destination, out _).Should().Be(RtxRetransmitResult.Retransmitted);
        clock.Advance(TimeSpan.FromMilliseconds(30));
        rtx.TryRetransmit(9, destination, out _).Should().Be(RtxRetransmitResult.RateLimited);
        clock.Advance(TimeSpan.FromMilliseconds(40));
        rtx.TryRetransmit(9, destination, out _).Should().Be(RtxRetransmitResult.Retransmitted);

        var stats = rtx.GetStats();
        stats.RequestedPackets.Should().Be(3);
        stats.PacketsRetransmitted.Should().Be(2);
        stats.Suppressed.Should().Be(1);
    }

    [Fact]
    public void The_bandwidth_budget_bounds_a_retransmission_storm()
    {
        var (rtx, history, clock) = NewSender(
            new RtxRetransmitOptions
            {
                MinimumResendInterval = TimeSpan.Zero,
                MaxBytesPerSecond = 10_000,
                MaxBurstBytes = 1_000,
            },
            new RtpSendHistoryOptions { Capacity = 256 });

        for (ushort seq = 0; seq < 100; seq++)
        {
            history.Store(seq, Original(seq, payloadLength: 200));
        }

        var destination = new byte[1500];
        var sent = 0;
        var limited = 0;
        for (ushort seq = 0; seq < 100; seq++)
        {
            if (rtx.TryRetransmit(seq, destination, out _) == RtxRetransmitResult.Retransmitted)
            {
                sent++;
            }
            else
            {
                limited++;
            }
        }

        // A 1000-byte burst allowance covers four 214-byte RTX packets and no more.
        sent.Should().Be(4);
        limited.Should().Be(96);
        rtx.GetStats().Suppressed.Should().Be(96);

        // The budget refills, so the next second's worth of repairs is served again.
        clock.Advance(TimeSpan.FromSeconds(1));
        rtx.TryRetransmit(50, destination, out _).Should().Be(RtxRetransmitResult.Retransmitted);
    }

    [Fact]
    public void A_repair_the_budget_refused_does_not_spend_the_packets_first_resend()
    {
        // A 40-byte burst allowance covers one 34-byte RTX packet and not two, so the second request
        // is refused by the budget rather than by the interval.
        var (rtx, history, clock) = NewSender(
            new RtxRetransmitOptions
            {
                MinimumResendInterval = TimeSpan.FromMilliseconds(50),
                MaxBytesPerSecond = 3_400,
                MaxBurstBytes = 40,
            });
        history.Store(9, Original(9));
        history.Store(10, Original(10));
        var destination = new byte[1500];

        rtx.TryRetransmit(9, destination, out _).Should().Be(RtxRetransmitResult.Retransmitted);
        rtx.TryRetransmit(10, destination, out _).Should().Be(RtxRetransmitResult.BandwidthLimited);

        // Packet 10 was never sent, so the peer has still never seen it. Ten milliseconds later — well
        // inside the fifty-millisecond resend interval — the budget has refilled, and the next NACK
        // must be served rather than rate limited for a resend that never happened.
        clock.Advance(TimeSpan.FromMilliseconds(10));
        rtx.TryRetransmit(10, destination, out _).Should().Be(RtxRetransmitResult.Retransmitted);

        var stats = rtx.GetStats();
        stats.PacketsRetransmitted.Should().Be(2);
        stats.Suppressed.Should().Be(1);
    }

    [Fact]
    public void An_unlimited_budget_serves_every_request()
    {
        var (rtx, history, _) = NewSender(
            new RtxRetransmitOptions { MinimumResendInterval = TimeSpan.Zero, MaxBytesPerSecond = 0 },
            new RtpSendHistoryOptions { Capacity = 128 });

        for (ushort seq = 0; seq < 100; seq++)
        {
            history.Store(seq, Original(seq, payloadLength: 200));
        }

        var destination = new byte[1500];
        for (ushort seq = 0; seq < 100; seq++)
        {
            rtx.TryRetransmit(seq, destination, out _).Should().Be(RtxRetransmitResult.Retransmitted);
        }

        var stats = rtx.GetStats();
        stats.PacketsRetransmitted.Should().Be(100);
        stats.Suppressed.Should().Be(0);
        stats.BytesRetransmitted.Should().Be(100 * (RtpHeader.FixedLength + 2 + 200));
    }

    [Fact]
    public void Counters_expose_the_ssrc_and_payload_type_the_answer_settled_on()
    {
        var (rtx, _, _) = NewSender();
        var stats = rtx.GetStats();

        stats.Ssrc.Should().Be(RtxSsrc);
        stats.PayloadType.Should().Be(RtxPayloadType);
        rtx.Ssrc.Should().Be(RtxSsrc);
        rtx.PayloadType.Should().Be(RtxPayloadType);
        rtx.MaxPacketSize.Should().Be(1200 + RtxPacket.OriginalSequenceNumberLength);
    }

    [Fact]
    public void A_destination_that_cannot_hold_the_rtx_packet_throws()
    {
        var (rtx, history, _) = NewSender();
        history.Store(1, Original(1, payloadLength: 400));

        var act = () => rtx.TryRetransmit(1, new byte[64], out _);
        act.Should().Throw<ByteBufferException>();
    }

    [Fact]
    public void The_retransmission_stream_reports_separately_from_the_media_stream()
    {
        // RFC 4588 §4 makes the RTX stream its own source, so it carries its own sender report.
        var (rtx, history, _) = NewSender();
        history.Store(1, Original(1));
        rtx.TryRetransmit(1, new byte[1500], out _).Should().Be(RtxRetransmitResult.Retransmitted);

        var report = rtx.CreateSenderReport(DateTimeOffset.UnixEpoch);
        report.SenderSsrc.Should().Be(RtxSsrc);
        report.PacketCount.Should().Be(1);
        rtx.PacketCount.Should().Be(1);
    }
}
