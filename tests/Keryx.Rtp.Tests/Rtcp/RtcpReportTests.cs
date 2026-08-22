using FluentAssertions;
using Keryx.Rtp.Rtcp;
using Xunit;

namespace Keryx.Rtp.Tests.Rtcp;

/// <summary>Round-trip coverage for the sender and receiver reports of RFC 3550 §6.4.</summary>
public class RtcpReportTests
{
    private static RtcpReportBlock SampleBlock(uint ssrc, int cumulativeLost) => new(
        sourceSsrc: ssrc,
        fractionLost: 0x20,
        cumulativePacketsLost: cumulativeLost,
        extendedHighestSequenceNumber: 0x0001_0203,
        jitter: 4242,
        lastSenderReport: 0xAABBCCDD,
        delaySinceLastSenderReport: 65536);

    [Fact]
    public void Sender_report_round_trips()
    {
        // RFC 3550 §6.4.1: header + 20-octet sender information + RC report blocks.
        var report = new RtcpSenderReport
        {
            SenderSsrc = 0x11223344,
            NtpTimestamp = 0xE5F1_2345_6789_ABCD,
            RtpTimestamp = 0x0000_2710,
            PacketCount = 1234,
            OctetCount = 567890,
        };
        report.ReportBlocks.Add(SampleBlock(0xAAAA_0001, 17));
        report.ReportBlocks.Add(SampleBlock(0xAAAA_0002, -3));

        var bytes = report.ToByteArray();

        bytes.Length.Should().Be(4 + 24 + (2 * 24));
        bytes[0].Should().Be(0x82); // V=2, P=0, RC=2
        bytes[1].Should().Be(200);
        ((bytes[2] << 8) | bytes[3]).Should().Be((bytes.Length / 4) - 1);

        RtcpSenderReport.TryParse(bytes, out var parsed).Should().BeTrue();
        parsed!.SenderSsrc.Should().Be(0x11223344);
        parsed.NtpTimestamp.Should().Be(0xE5F1_2345_6789_ABCD);
        parsed.RtpTimestamp.Should().Be(0x2710u);
        parsed.PacketCount.Should().Be(1234);
        parsed.OctetCount.Should().Be(567890);
        parsed.ReportBlocks.Should().HaveCount(2);
        parsed.ReportBlocks[0].SourceSsrc.Should().Be(0xAAAA_0001);
        parsed.ReportBlocks[0].CumulativePacketsLost.Should().Be(17);
        parsed.ReportBlocks[1].CumulativePacketsLost.Should().Be(-3);
    }

    [Fact]
    public void Receiver_report_round_trips()
    {
        // RFC 3550 §6.4.2: header + reporter SSRC + RC report blocks; no sender information.
        var report = new RtcpReceiverReport { SenderSsrc = 0x0BADF00D };
        report.ReportBlocks.Add(SampleBlock(0x1234_5678, 5));

        var bytes = report.ToByteArray();
        bytes.Length.Should().Be(4 + 4 + 24);
        bytes[0].Should().Be(0x81);
        bytes[1].Should().Be(201);

        RtcpReceiverReport.TryParse(bytes, out var parsed).Should().BeTrue();
        parsed!.SenderSsrc.Should().Be(0x0BADF00D);
        parsed.ReportBlocks.Should().ContainSingle();
        parsed.ReportBlocks[0].Jitter.Should().Be(4242);
        parsed.ReportBlocks[0].LastSenderReport.Should().Be(0xAABBCCDD);
        parsed.ReportBlocks[0].DelaySinceLastSenderReport.Should().Be(65536);
    }

    [Fact]
    public void Empty_receiver_report_is_eight_octets()
    {
        // RFC 3550 §6.4.2: a receiver that has received nothing still sends an empty RR.
        var report = new RtcpReceiverReport { SenderSsrc = 42 };
        var bytes = report.ToByteArray();
        bytes.Length.Should().Be(8);
        bytes[0].Should().Be(0x80);
        RtcpReceiverReport.TryParse(bytes, out var parsed).Should().BeTrue();
        parsed!.ReportBlocks.Should().BeEmpty();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(-1)]
    [InlineData(8_388_607)]   // 2^23 - 1, the largest positive value
    [InlineData(-8_388_608)]  // -2^23, the most negative value
    public void Cumulative_packets_lost_is_a_signed_twenty_four_bit_field(int cumulativeLost)
    {
        // RFC 3550 §6.4.1: "the number of packets lost ... defined to be a signed 24-bit value".
        var block = SampleBlock(1, cumulativeLost);
        var bytes = new byte[RtcpReportBlock.Length];
        block.WriteTo(bytes);

        RtcpReportBlock.TryParse(bytes, out var parsed).Should().BeTrue();
        parsed.CumulativePacketsLost.Should().Be(cumulativeLost);
    }

    [Fact]
    public void Report_block_splits_the_extended_sequence_number_into_cycles_and_sequence()
    {
        var block = SampleBlock(1, 0);
        block.SequenceNumberCycles.Should().Be(1);
        block.HighestSequenceNumber.Should().Be(0x0203);
    }

    [Fact]
    public void Rejects_a_sender_report_truncated_inside_its_report_blocks()
    {
        var report = new RtcpSenderReport { SenderSsrc = 1 };
        report.ReportBlocks.Add(SampleBlock(2, 0));
        var bytes = report.ToByteArray();

        RtcpSenderReport.TryParse(bytes.AsSpan(0, bytes.Length - 4), out _).Should().BeFalse();
    }

    [Fact]
    public void Rejects_a_report_whose_length_field_disagrees_with_its_report_count()
    {
        // RC says three blocks but the length field only covers one.
        var report = new RtcpReceiverReport { SenderSsrc = 1 };
        report.ReportBlocks.Add(SampleBlock(2, 0));
        var bytes = report.ToByteArray();
        bytes[0] = 0x83;

        RtcpReceiverReport.TryParse(bytes, out _).Should().BeFalse();
    }
}
