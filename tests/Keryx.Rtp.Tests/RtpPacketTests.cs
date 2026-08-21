using FluentAssertions;
using Keryx.Rtp;
using Xunit;

namespace Keryx.Rtp.Tests;

/// <summary>Coverage for whole-packet parsing, including RFC 3550 §5.1 padding.</summary>
public class RtpPacketTests
{
    private static byte[] BuildPacket(bool padding, byte[] payloadAndPadding)
    {
        var bytes = new byte[12 + payloadAndPadding.Length];
        bytes[0] = (byte)(0x80 | (padding ? 0x20 : 0x00));
        bytes[1] = 96;
        bytes[3] = 1;
        payloadAndPadding.CopyTo(bytes, 12);
        return bytes;
    }

    [Fact]
    public void Exposes_the_payload_after_the_header()
    {
        var packetBytes = BuildPacket(false, [1, 2, 3, 4]);
        RtpPacket.TryParse(packetBytes, out var packet).Should().BeTrue();
        packet.Payload.ToArray().Should().Equal(1, 2, 3, 4);
        packet.PaddingLength.Should().Be(0);
        packet.Header.SequenceNumber.Should().Be(1);
    }

    [Fact]
    public void Strips_padding_counted_by_the_last_octet()
    {
        // RFC 3550 §5.1: "The last octet of the padding contains a count of how many padding octets
        // should be ignored, including itself."
        var packetBytes = BuildPacket(true, [1, 2, 0x00, 0x00, 0x03]);
        RtpPacket.TryParse(packetBytes, out var packet).Should().BeTrue();
        packet.PaddingLength.Should().Be(3);
        packet.Payload.ToArray().Should().Equal(1, 2);
    }

    [Fact]
    public void Rejects_a_padding_count_of_zero()
    {
        // The count includes itself, so zero is impossible.
        var packetBytes = BuildPacket(true, [1, 2, 3, 0x00]);
        RtpPacket.TryParse(packetBytes, out _).Should().BeFalse();
    }

    [Fact]
    public void Rejects_a_padding_count_longer_than_the_payload()
    {
        var packetBytes = BuildPacket(true, [1, 2, 0x09]);
        RtpPacket.TryParse(packetBytes, out _).Should().BeFalse();
    }

    [Fact]
    public void Rejects_the_padding_bit_with_no_payload_at_all()
    {
        var packetBytes = BuildPacket(true, []);
        RtpPacket.TryParse(packetBytes, out _).Should().BeFalse();
    }

    [Fact]
    public void Accepts_a_packet_with_an_empty_payload()
    {
        var packetBytes = BuildPacket(false, []);
        RtpPacket.TryParse(packetBytes, out var packet).Should().BeTrue();
        packet.Payload.Length.Should().Be(0);
    }

    [Fact]
    public void Rejects_a_malformed_header()
    {
        RtpPacket.TryParse(new byte[] { 0x00, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, out _).Should().BeFalse();
    }
}
