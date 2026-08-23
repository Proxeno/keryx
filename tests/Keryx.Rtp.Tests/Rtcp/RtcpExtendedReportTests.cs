using FluentAssertions;
using Keryx.Rtp.Rtcp;
using Xunit;

namespace Keryx.Rtp.Tests.Rtcp;

/// <summary>Round-trip coverage for the RTCP extended report and its block types (RFC 3611).</summary>
public class RtcpExtendedReportTests
{
    private static RtcpExtendedReport ParseSingle(byte[] bytes)
    {
        RtcpExtendedReport.TryParse(bytes, out var parsed).Should().BeTrue();
        return parsed!;
    }

    [Fact]
    public void Header_encodes_the_reserved_count_as_zero_and_the_correct_length()
    {
        var report = new RtcpExtendedReport { SenderSsrc = 0x1122_3344 };
        report.ReportBlocks.Add(new RtcpReceiverReferenceTimeReportBlock { NtpTimestamp = 0x1234_5678_9ABC_DEF0 });

        var bytes = report.ToByteArray();

        bytes[0].Should().Be(0x80); // V=2, P=0, reserved=0
        bytes[1].Should().Be(207);
        ((bytes[2] << 8) | bytes[3]).Should().Be((bytes.Length / 4) - 1);
        bytes.Length.Should().Be(4 + 4 + 12);
    }

    [Fact]
    public void Loss_rle_block_round_trips()
    {
        var report = new RtcpExtendedReport { SenderSsrc = 0xAAAA_0001 };
        var block = new RtcpLossRleReportBlock
        {
            SourceSsrc = 0xBBBB_0002,
            Thinning = 3,
            BeginSequence = 100,
            EndSequence = 200,
        };
        block.Chunks.Add(0xC001);
        block.Chunks.Add(0x0064);
        report.ReportBlocks.Add(block);

        var parsed = ParseSingle(report.ToByteArray());

        var roundTripped = parsed.ReportBlocks.Should().ContainSingle().Which
            .Should().BeOfType<RtcpLossRleReportBlock>().Subject;
        roundTripped.BlockType.Should().Be((byte)RtcpExtendedReportBlockType.LossRle);
        roundTripped.SourceSsrc.Should().Be(0xBBBB_0002);
        roundTripped.Thinning.Should().Be(3);
        roundTripped.BeginSequence.Should().Be(100);
        roundTripped.EndSequence.Should().Be(200);
        roundTripped.Chunks.Should().Equal((ushort)0xC001, (ushort)0x0064);
    }

    [Fact]
    public void Loss_rle_block_with_odd_chunk_count_is_padded_to_a_word_boundary()
    {
        var report = new RtcpExtendedReport { SenderSsrc = 0xAAAA_0001 };
        var block = new RtcpLossRleReportBlock { SourceSsrc = 0xBBBB_0002, BeginSequence = 1, EndSequence = 5 };
        block.Chunks.Add(0xABCD);
        report.ReportBlocks.Add(block);

        var bytes = report.ToByteArray();

        bytes.Length.Should().Be(4 + 4 + (4 + 8 + 4)); // block content padded from 10 to 12 bytes
        var parsed = ParseSingle(bytes);
        var roundTripped = (RtcpLossRleReportBlock)parsed.ReportBlocks[0];
        roundTripped.Chunks.Should().Equal((ushort)0xABCD, (ushort)0x0000); // trailing null chunk preserved
    }

    [Fact]
    public void Duplicate_rle_block_round_trips()
    {
        var report = new RtcpExtendedReport { SenderSsrc = 0xAAAA_0001 };
        var block = new RtcpDuplicateRleReportBlock
        {
            SourceSsrc = 0xCCCC_0003,
            Thinning = 0,
            BeginSequence = 10,
            EndSequence = 42,
        };
        block.Chunks.Add(0x0001);
        block.Chunks.Add(0x0002);
        report.ReportBlocks.Add(block);

        var parsed = ParseSingle(report.ToByteArray());

        var roundTripped = parsed.ReportBlocks.Should().ContainSingle().Which
            .Should().BeOfType<RtcpDuplicateRleReportBlock>().Subject;
        roundTripped.BlockType.Should().Be((byte)RtcpExtendedReportBlockType.DuplicateRle);
        roundTripped.SourceSsrc.Should().Be(0xCCCC_0003);
        roundTripped.EndSequence.Should().Be(42);
        roundTripped.Chunks.Should().Equal((ushort)0x0001, (ushort)0x0002);
    }

    [Fact]
    public void Packet_receipt_times_block_round_trips()
    {
        var report = new RtcpExtendedReport { SenderSsrc = 0xAAAA_0001 };
        var block = new RtcpPacketReceiptTimesReportBlock
        {
            SourceSsrc = 0xDDDD_0004,
            Thinning = 5,
            BeginSequence = 7,
            EndSequence = 10,
        };
        block.ReceiptTimes.Add(0x0000_1111);
        block.ReceiptTimes.Add(0x0000_2222);
        block.ReceiptTimes.Add(0x0000_3333);
        report.ReportBlocks.Add(block);

        var parsed = ParseSingle(report.ToByteArray());

        var roundTripped = parsed.ReportBlocks.Should().ContainSingle().Which
            .Should().BeOfType<RtcpPacketReceiptTimesReportBlock>().Subject;
        roundTripped.SourceSsrc.Should().Be(0xDDDD_0004);
        roundTripped.Thinning.Should().Be(5);
        roundTripped.BeginSequence.Should().Be(7);
        roundTripped.EndSequence.Should().Be(10);
        roundTripped.ReceiptTimes.Should().Equal(0x0000_1111u, 0x0000_2222u, 0x0000_3333u);
    }

    [Fact]
    public void Receiver_reference_time_block_round_trips()
    {
        var report = new RtcpExtendedReport { SenderSsrc = 0xAAAA_0001 };
        report.ReportBlocks.Add(new RtcpReceiverReferenceTimeReportBlock { NtpTimestamp = 0xE5F1_2345_6789_ABCD });

        var parsed = ParseSingle(report.ToByteArray());

        var roundTripped = parsed.ReportBlocks.Should().ContainSingle().Which
            .Should().BeOfType<RtcpReceiverReferenceTimeReportBlock>().Subject;
        roundTripped.NtpTimestamp.Should().Be(0xE5F1_2345_6789_ABCD);
    }

    [Fact]
    public void Dlrr_block_round_trips_multiple_sub_blocks()
    {
        var report = new RtcpExtendedReport { SenderSsrc = 0xAAAA_0001 };
        var block = new RtcpDelaySinceLastReceiverReportBlock();
        block.SubBlocks.Add(new RtcpDlrrSubBlock(0x1111_1111, 0xAABB_CCDD, 65536));
        block.SubBlocks.Add(new RtcpDlrrSubBlock(0x2222_2222, 0x1234_5678, 32768));
        report.ReportBlocks.Add(block);

        var parsed = ParseSingle(report.ToByteArray());

        var roundTripped = parsed.ReportBlocks.Should().ContainSingle().Which
            .Should().BeOfType<RtcpDelaySinceLastReceiverReportBlock>().Subject;
        roundTripped.SubBlocks.Should().Equal(
            new RtcpDlrrSubBlock(0x1111_1111, 0xAABB_CCDD, 65536),
            new RtcpDlrrSubBlock(0x2222_2222, 0x1234_5678, 32768));
    }

    [Fact]
    public void Statistics_summary_block_round_trips_with_all_flags_set()
    {
        var report = new RtcpExtendedReport { SenderSsrc = 0xAAAA_0001 };
        var block = new RtcpStatisticsSummaryReportBlock
        {
            SourceSsrc = 0xEEEE_0006,
            BeginSequence = 1000,
            EndSequence = 2000,
            HasLossReport = true,
            HasDuplicateReport = true,
            HasJitterReport = true,
            TtlOrHopLimit = RtcpTtlOrHopLimit.Ipv6HopLimit,
            LostPackets = 12,
            DuplicatePackets = 3,
            MinJitter = 4,
            MaxJitter = 400,
            MeanJitter = 40,
            DevJitter = 7,
            MinTtlOrHopLimit = 55,
            MaxTtlOrHopLimit = 64,
            MeanTtlOrHopLimit = 60,
            DevTtlOrHopLimit = 2,
        };
        report.ReportBlocks.Add(block);

        var bytes = report.ToByteArray();
        bytes.Length.Should().Be(4 + 4 + 40); // fixed 40-byte block (RFC 3611 §4.6)
        var parsed = ParseSingle(bytes);

        var roundTripped = parsed.ReportBlocks.Should().ContainSingle().Which
            .Should().BeOfType<RtcpStatisticsSummaryReportBlock>().Subject;
        roundTripped.SourceSsrc.Should().Be(0xEEEE_0006);
        roundTripped.BeginSequence.Should().Be(1000);
        roundTripped.EndSequence.Should().Be(2000);
        roundTripped.HasLossReport.Should().BeTrue();
        roundTripped.HasDuplicateReport.Should().BeTrue();
        roundTripped.HasJitterReport.Should().BeTrue();
        roundTripped.TtlOrHopLimit.Should().Be(RtcpTtlOrHopLimit.Ipv6HopLimit);
        roundTripped.LostPackets.Should().Be(12);
        roundTripped.DuplicatePackets.Should().Be(3);
        roundTripped.MinJitter.Should().Be(4);
        roundTripped.MaxJitter.Should().Be(400);
        roundTripped.MeanJitter.Should().Be(40);
        roundTripped.DevJitter.Should().Be(7);
        roundTripped.MinTtlOrHopLimit.Should().Be(55);
        roundTripped.MaxTtlOrHopLimit.Should().Be(64);
        roundTripped.MeanTtlOrHopLimit.Should().Be(60);
        roundTripped.DevTtlOrHopLimit.Should().Be(2);
    }

    [Fact]
    public void Multiple_blocks_in_one_report_round_trip_in_order()
    {
        var report = new RtcpExtendedReport { SenderSsrc = 0xAAAA_0001 };
        report.ReportBlocks.Add(new RtcpReceiverReferenceTimeReportBlock { NtpTimestamp = 0x1111_2222_3333_4444 });
        var dlrr = new RtcpDelaySinceLastReceiverReportBlock();
        dlrr.SubBlocks.Add(new RtcpDlrrSubBlock(0x5555_5555, 0x6666_6666, 0x7777_7777));
        report.ReportBlocks.Add(dlrr);

        var original = report.ToByteArray();
        var parsed = ParseSingle(original);

        parsed.ReportBlocks.Should().HaveCount(2);
        parsed.ReportBlocks[0].Should().BeOfType<RtcpReceiverReferenceTimeReportBlock>();
        parsed.ReportBlocks[1].Should().BeOfType<RtcpDelaySinceLastReceiverReportBlock>();
        parsed.ToByteArray().Should().Equal(original);
    }

    [Fact]
    public void An_unknown_block_type_is_preserved_and_re_serialized()
    {
        // Build an XR with a Receiver Reference Time block followed by an unknown BT=100 block.
        var known = new RtcpReceiverReferenceTimeReportBlock { NtpTimestamp = 0x0102_0304_0506_0708 };
        byte[] unknownBlock = [100, 0x2A, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF]; // BT=100, len=1 word => 8 bytes total

        var body = new byte[8 + known.Length + unknownBlock.Length];
        // common header + SSRC written by writing a report with only the known block, then splice.
        var scaffold = new RtcpExtendedReport { SenderSsrc = 0x1234_5678 };
        scaffold.ReportBlocks.Add(known);
        var scaffoldBytes = scaffold.ToByteArray();
        scaffoldBytes.CopyTo(body, 0);
        unknownBlock.CopyTo(body, scaffoldBytes.Length);
        // Patch the common-header length to cover the appended block.
        var totalWords = (body.Length / 4) - 1;
        body[2] = (byte)(totalWords >> 8);
        body[3] = (byte)totalWords;

        var parsed = ParseSingle(body);

        parsed.ReportBlocks.Should().HaveCount(2);
        parsed.ReportBlocks[0].Should().BeOfType<RtcpReceiverReferenceTimeReportBlock>();
        var unknown = parsed.ReportBlocks[1].Should().BeOfType<RtcpUnknownExtendedReportBlock>().Subject;
        unknown.BlockType.Should().Be(100);
        unknown.TypeSpecific.Should().Be(0x2A);
        unknown.Body.Should().Equal(0xDE, 0xAD, 0xBE, 0xEF);

        parsed.ToByteArray().Should().Equal(body);
    }

    [Fact]
    public void Extended_report_parses_within_a_compound_packet_alongside_sr_and_rr()
    {
        var sr = new RtcpSenderReport { SenderSsrc = 0x0000_0001 };
        var rr = new RtcpReceiverReport { SenderSsrc = 0x0000_0002 };
        var xr = new RtcpExtendedReport { SenderSsrc = 0x0000_0003 };
        xr.ReportBlocks.Add(new RtcpReceiverReferenceTimeReportBlock { NtpTimestamp = 0xCAFE_BABE_DEAD_BEEF });
        var dlrr = new RtcpDelaySinceLastReceiverReportBlock();
        dlrr.SubBlocks.Add(new RtcpDlrrSubBlock(0x0000_0002, 0x1111_2222, 4242));
        xr.ReportBlocks.Add(dlrr);

        var buffer = new byte[sr.Length + rr.Length + xr.Length];
        var offset = sr.WriteTo(buffer);
        offset += rr.WriteTo(buffer.AsSpan(offset));
        xr.WriteTo(buffer.AsSpan(offset));

        var packets = RtcpPacket.ParseCompound(buffer);

        packets.Should().HaveCount(3);
        packets[0].Should().BeOfType<RtcpSenderReport>();
        packets[1].Should().BeOfType<RtcpReceiverReport>();
        var parsedXr = packets[2].Should().BeOfType<RtcpExtendedReport>().Subject;
        parsedXr.SenderSsrc.Should().Be(0x0000_0003u);
        parsedXr.ReportBlocks.Should().HaveCount(2);

        var rebuilt = new byte[buffer.Length];
        RtcpPacket.WriteCompound(packets, rebuilt).Should().Be(buffer.Length);
        rebuilt.Should().Equal(buffer);
    }

    [Fact]
    public void An_extended_report_with_no_blocks_round_trips()
    {
        var report = new RtcpExtendedReport { SenderSsrc = 0x9999_9999 };

        var bytes = report.ToByteArray();

        bytes.Length.Should().Be(8);
        var parsed = ParseSingle(bytes);
        parsed.SenderSsrc.Should().Be(0x9999_9999u);
        parsed.ReportBlocks.Should().BeEmpty();
    }
}
