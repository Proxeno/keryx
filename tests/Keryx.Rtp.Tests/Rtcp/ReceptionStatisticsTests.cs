using FluentAssertions;
using Keryx.Rtp.Rtcp;
using Xunit;

namespace Keryx.Rtp.Tests.Rtcp;

/// <summary>
/// Hand-computed coverage for the reception statistics of RFC 3550: sequence validation (A.1),
/// cumulative and fractional loss (A.3), interarrival jitter (A.8), and the LSR/DLSR echo (§6.4.1).
/// </summary>
public class ReceptionStatisticsTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 23, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void In_order_stream_with_no_loss_reports_zero_loss()
    {
        var stats = new ReceptionStatistics();

        // Ten packets 100..109, arrival tracking the RTP timestamp exactly (constant transit => no jitter).
        for (ushort i = 0; i < 10; i++)
        {
            var seq = (ushort)(100 + i);
            var ts = (uint)(i * 160);
            stats.OnRtpPacket(seq, ts, ts);
        }

        stats.PacketsReceived.Should().Be(10);
        stats.ExtendedHighestSequenceNumber.Should().Be(109);
        stats.CumulativePacketsLost.Should().Be(0);
        stats.Jitter.Should().Be(0);

        var block = stats.BuildReportBlock(0x1234, Now);
        block.FractionLost.Should().Be(0);
        block.CumulativePacketsLost.Should().Be(0);
        block.ExtendedHighestSequenceNumber.Should().Be(109);
        block.Jitter.Should().Be(0);
    }

    [Fact]
    public void Dropped_packets_produce_cumulative_and_fractional_loss()
    {
        var stats = new ReceptionStatistics();

        // Sequence 100..109 with 103 and 104 dropped: eight received across an expected span of ten.
        foreach (var seq in new ushort[] { 100, 101, 102, 105, 106, 107, 108, 109 })
        {
            stats.OnRtpPacket(seq, seq * 160u, seq * 160u);
        }

        stats.PacketsReceived.Should().Be(8);
        stats.ExtendedHighestSequenceNumber.Should().Be(109);

        // RFC 3550 A.3: expected = 109 - 100 + 1 = 10, lost = 10 - 8 = 2.
        stats.CumulativePacketsLost.Should().Be(2);

        var block = stats.BuildReportBlock(0x1234, Now);
        block.CumulativePacketsLost.Should().Be(2);

        // Fraction lost over the whole (only) interval: (lost_interval << 8) / expected_interval
        // = (2 << 8) / 10 = 512 / 10 = 51.
        block.FractionLost.Should().Be(51);
    }

    [Fact]
    public void Reordered_packets_are_counted_and_do_not_register_as_loss()
    {
        var stats = new ReceptionStatistics();

        // 102 arrives after 103: still within the misorder window, so counted, not lost.
        foreach (var seq in new ushort[] { 100, 101, 103, 102, 104 })
        {
            stats.OnRtpPacket(seq, seq * 160u, seq * 160u);
        }

        stats.PacketsReceived.Should().Be(5);
        stats.ExtendedHighestSequenceNumber.Should().Be(104);
        stats.CumulativePacketsLost.Should().Be(0);
    }

    [Fact]
    public void Duplicates_can_drive_cumulative_loss_negative()
    {
        var stats = new ReceptionStatistics();

        // 101 delivered twice: four received across an expected span of three (100..102).
        foreach (var seq in new ushort[] { 100, 101, 101, 102 })
        {
            stats.OnRtpPacket(seq, seq * 160u, seq * 160u);
        }

        stats.PacketsReceived.Should().Be(4);
        stats.ExtendedHighestSequenceNumber.Should().Be(102);

        // expected = 3, received = 4, lost = -1 (RFC 3550 §6.4.1: the count is signed).
        stats.CumulativePacketsLost.Should().Be(-1);
    }

    [Fact]
    public void Sequence_wrap_accumulates_a_cycle_in_the_extended_highest()
    {
        var stats = new ReceptionStatistics();

        foreach (var seq in new ushort[] { 65534, 65535, 0, 1 })
        {
            stats.OnRtpPacket(seq, seq * 160u, seq * 160u);
        }

        // One full cycle of 2^16 accumulated in the high 16 bits: (1 << 16) + 1 = 65537.
        stats.ExtendedHighestSequenceNumber.Should().Be(65537);
        stats.CumulativePacketsLost.Should().Be(0);
        stats.PacketsReceived.Should().Be(4);
    }

    [Fact]
    public void Interarrival_jitter_follows_the_rfc_3550_a8_recurrence()
    {
        var stats = new ReceptionStatistics();

        // p1: transit 0. Jitter undefined for the first packet.
        stats.OnRtpPacket(1, 0, 0);
        stats.Jitter.Should().Be(0);

        // p2: transit = 180 - 160 = 20, D = 20.
        // J16 += 20 - ((0 + 8) >> 4) = 20 - 0 = 20 => reported 20 >> 4 = 1.
        stats.OnRtpPacket(2, 160, 180);
        stats.Jitter.Should().Be(1);

        // p3: transit = 360 - 320 = 40, D = |40 - 20| = 20.
        // J16 += 20 - ((20 + 8) >> 4) = 20 - 1 = 19 => J16 = 39, reported 39 >> 4 = 2.
        stats.OnRtpPacket(3, 320, 360);
        stats.Jitter.Should().Be(2);

        stats.BuildReportBlock(0x1234, Now).Jitter.Should().Be(2);
    }

    [Fact]
    public void Report_block_carries_no_sender_report_echo_until_one_is_received()
    {
        var stats = new ReceptionStatistics();
        stats.OnRtpPacket(100, 0, 0);

        var block = stats.BuildReportBlock(0x1234, Now);
        block.LastSenderReport.Should().Be(0);
        block.DelaySinceLastSenderReport.Should().Be(0);
    }

    [Fact]
    public void Report_block_echoes_the_last_sender_report_and_delay()
    {
        var stats = new ReceptionStatistics();
        stats.OnRtpPacket(100, 0, 0);

        var senderReportArrival = Now;
        stats.OnSenderReport(0xAABBCCDD, senderReportArrival);

        // Build the block two seconds later: DLSR is that delay in units of 1/65536 s.
        var block = stats.BuildReportBlock(0x1234, senderReportArrival + TimeSpan.FromSeconds(2));
        block.LastSenderReport.Should().Be(0xAABBCCDD);
        block.DelaySinceLastSenderReport.Should().Be(2u * 65536);
    }

    [Fact]
    public void Fraction_lost_is_measured_per_interval_between_reports()
    {
        var stats = new ReceptionStatistics();

        // First interval: 100..103 with no loss => fraction 0.
        foreach (var seq in new ushort[] { 100, 101, 102, 103 })
        {
            stats.OnRtpPacket(seq, seq * 160u, seq * 160u);
        }

        stats.BuildReportBlock(0x1234, Now).FractionLost.Should().Be(0);

        // Second interval: expect 104..107 but 105 and 106 are lost => 2 of 4 lost.
        foreach (var seq in new ushort[] { 104, 107 })
        {
            stats.OnRtpPacket(seq, seq * 160u, seq * 160u);
        }

        // (lost_interval << 8) / expected_interval = (2 << 8) / 4 = 128.
        var block = stats.BuildReportBlock(0x1234, Now);
        block.FractionLost.Should().Be(128);
        block.CumulativePacketsLost.Should().Be(2);
    }
}
