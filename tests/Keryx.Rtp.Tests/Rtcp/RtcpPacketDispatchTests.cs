using FluentAssertions;
using Keryx.Rtp.Rtcp;
using Xunit;

namespace Keryx.Rtp.Tests.Rtcp;

/// <summary>
/// Verifies that the generic entry point dispatches on packet type and, for RFC 4585 feedback,
/// on the feedback message type.
/// </summary>
public class RtcpPacketDispatchTests
{
    public static TheoryData<RtcpPacket, Type> Packets()
    {
        var sr = new RtcpSenderReport { SenderSsrc = 1, NtpTimestamp = 0x1122334455667788, RtpTimestamp = 9 };
        sr.ReportBlocks.Add(new RtcpReportBlock(2, 1, -1, 3, 4, 5, 6));

        var twcc = new RtcpTransportCcFeedback { SenderSsrc = 1, MediaSsrc = 2 };
        twcc.AddPacket(1, 64_000);

        return new TheoryData<RtcpPacket, Type>
        {
            { sr, typeof(RtcpSenderReport) },
            { new RtcpReceiverReport { SenderSsrc = 1 }, typeof(RtcpReceiverReport) },
            { RtcpSourceDescription.CreateCname(1, "keryx"), typeof(RtcpSourceDescription) },
            { new RtcpGoodbye(1, "bye"), typeof(RtcpGoodbye) },
            { new RtcpPictureLossIndication(1, 2), typeof(RtcpPictureLossIndication) },
            { new RtcpFullIntraRequest(1, 0, 2, 3), typeof(RtcpFullIntraRequest) },
            { new RtcpGenericNack(1, 2, [10, 12]), typeof(RtcpGenericNack) },
            { new RtcpReceiverEstimatedMaxBitrate(1, 2_000_000, 3), typeof(RtcpReceiverEstimatedMaxBitrate) },
            { twcc, typeof(RtcpTransportCcFeedback) },
        };
    }

    [Theory]
    [MemberData(nameof(Packets))]
    public void Dispatches_each_packet_type_and_round_trips_its_bytes(RtcpPacket packet, Type expected)
    {
        var bytes = packet.ToByteArray();
        (bytes.Length % 4).Should().Be(0);
        bytes.Length.Should().Be(packet.Length);

        RtcpPacket.TryParse(bytes, out var parsed).Should().BeTrue();
        parsed.Should().BeOfType(expected);
        parsed!.ToByteArray().Should().Equal(bytes);
    }

    [Fact]
    public void Remb_bitrate_survives_the_exponent_mantissa_encoding()
    {
        // draft-alvestrand-rmcat-remb-03 §2.2: values above 2^18 - 1 lose their low bits to the
        // 6-bit exponent, so the decoded estimate is the largest representable value at or below it.
        // 2 000 000 = 250 000 << 3, so it survives exactly.
        var exact = new RtcpReceiverEstimatedMaxBitrate(1, 2_000_000, 3);
        RtcpReceiverEstimatedMaxBitrate.TryParse(exact.ToByteArray(), out var parsed).Should().BeTrue();
        parsed!.BitrateBitsPerSecond.Should().Be(2_000_000);
        parsed.Ssrcs.Should().Equal(3u);

        // 1 000 001 does not: the smallest usable exponent is 2, so the low bits are dropped.
        var lossy = new RtcpReceiverEstimatedMaxBitrate(1, 1_000_001, 3);
        RtcpReceiverEstimatedMaxBitrate.TryParse(lossy.ToByteArray(), out var rounded).Should().BeTrue();
        rounded!.BitrateBitsPerSecond.Should().Be(1_000_000);
    }

    [Fact]
    public void Rejects_a_packet_whose_length_field_exceeds_the_buffer()
    {
        byte[] bytes = [0x80, 201, 0x00, 0x09, 0, 0, 0, 1];
        RtcpPacket.TryParse(bytes, out _).Should().BeFalse();
    }

    [Fact]
    public void Rejects_a_packet_with_the_wrong_version()
    {
        byte[] bytes = [0x00, 201, 0x00, 0x01, 0, 0, 0, 1];
        RtcpPacket.TryParse(bytes, out _).Should().BeFalse();
    }
}
