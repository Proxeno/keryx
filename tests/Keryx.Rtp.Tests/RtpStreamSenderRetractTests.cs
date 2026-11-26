using FluentAssertions;
using Keryx.Rtp;
using Xunit;

namespace Keryx.Rtp.Tests;

/// <summary>
/// Coverage for <see cref="RtpStreamSender.RetractUnsent"/>, the sequence/counter rewind a barge-in cut
/// applies to packets that were written but discarded before SRTP protected them.
/// </summary>
public class RtpStreamSenderRetractTests
{
    [Fact]
    public void Rewinds_the_sequence_number_and_the_packet_and_octet_counts()
    {
        var sender = new RtpStreamSender(1, 111, 48_000, initialSequenceNumber: 100, initialTimestamp: 0);
        Span<byte> buffer = stackalloc byte[64];

        for (var i = 0; i < 5; i++)
        {
            sender.WritePacket(new byte[10], marker: false, buffer);
        }

        sender.NextSequenceNumber.Should().Be(105);
        sender.PacketCount.Should().Be(5);
        sender.OctetCount.Should().Be(50);

        sender.RetractUnsent(103, packets: 2, payloadOctets: 20);

        sender.NextSequenceNumber.Should().Be(103);
        sender.PacketCount.Should().Be(3);
        sender.OctetCount.Should().Be(30);

        var length = sender.WritePacket(new byte[10], marker: false, buffer);
        RtpPacket.TryParse(buffer[..length], out var packet).Should().BeTrue();
        packet.Header.SequenceNumber.Should().Be(103);
    }

    [Fact]
    public void Rewinds_across_the_sequence_number_wrap()
    {
        var sender = new RtpStreamSender(1, 111, 48_000, initialSequenceNumber: 65534, initialTimestamp: 0);
        Span<byte> buffer = stackalloc byte[64];

        for (var i = 0; i < 3; i++)
        {
            sender.WritePacket(new byte[10], marker: false, buffer);
        }

        // 65534, 65535, 0 -> the newest unsent packet is 0, so retracting one rewinds to 0.
        sender.NextSequenceNumber.Should().Be(1);
        sender.RetractUnsent(0, packets: 1, payloadOctets: 10);

        sender.NextSequenceNumber.Should().Be(0);
        sender.PacketCount.Should().Be(2);
        sender.OctetCount.Should().Be(20);

        var length = sender.WritePacket(new byte[10], marker: false, buffer);
        RtpPacket.TryParse(buffer[..length], out var packet).Should().BeTrue();
        packet.Header.SequenceNumber.Should().Be(0);

        // A second rewind across the wrap: keep 65534, retract 65535 and 0.
        sender.RetractUnsent(65535, packets: 2, payloadOctets: 20);
        sender.NextSequenceNumber.Should().Be(65535);
    }
}
