using FluentAssertions;
using Keryx.Rtp;
using Keryx.Rtp.Rtcp;
using Xunit;

namespace Keryx.Rtp.Tests;

/// <summary>Coverage for the per-stream sender state machine of RFC 3550 §5.1 and §6.4.1.</summary>
public class RtpStreamSenderTests
{
    [Fact]
    public void Writes_a_packet_that_parses_back_to_the_configured_stream_state()
    {
        var sender = new RtpStreamSender(0xDEADBEEF, 96, 90_000, initialSequenceNumber: 1000, initialTimestamp: 5000);
        Span<byte> buffer = stackalloc byte[256];

        var length = sender.WritePacket([0xAA, 0xBB, 0xCC], marker: true, buffer);

        length.Should().Be(15);
        RtpPacket.TryParse(buffer[..length], out var packet).Should().BeTrue();
        packet.Header.Ssrc.Should().Be(0xDEADBEEF);
        packet.Header.PayloadType.Should().Be(96);
        packet.Header.SequenceNumber.Should().Be(1000);
        packet.Header.Timestamp.Should().Be(5000u);
        packet.Header.Marker.Should().BeTrue();
        packet.Payload.ToArray().Should().Equal(0xAA, 0xBB, 0xCC);
    }

    [Fact]
    public void Increments_the_sequence_number_per_packet_and_wraps_at_sixty_five_thousand_five_hundred_and_thirty_five()
    {
        // RFC 3550 §5.1: "The sequence number increments by one for each RTP data packet sent."
        var sender = new RtpStreamSender(1, 96, 90_000, initialSequenceNumber: 65534);
        Span<byte> buffer = stackalloc byte[64];

        sender.WritePacket([1], false, buffer);
        sender.LastSequenceNumber.Should().Be(65534);
        sender.WritePacket([1], false, buffer);
        sender.LastSequenceNumber.Should().Be(65535);
        sender.WritePacket([1], false, buffer);
        sender.LastSequenceNumber.Should().Be(0);
        sender.NextSequenceNumber.Should().Be(1);
    }

    [Fact]
    public void Counts_packets_and_payload_octets_for_the_sender_report()
    {
        // RFC 3550 §6.4.1: the octet count covers payload octets only, excluding header and padding.
        var sender = new RtpStreamSender(7, 96, 90_000, initialSequenceNumber: 0, initialTimestamp: 0);
        Span<byte> buffer = stackalloc byte[256];

        sender.WritePacket(new byte[100], false, buffer);
        sender.WritePacket(new byte[50], true, buffer);

        sender.PacketCount.Should().Be(2);
        sender.OctetCount.Should().Be(150);

        var report = sender.CreateSenderReport(DateTimeOffset.UnixEpoch);
        report.SenderSsrc.Should().Be(7);
        report.PacketCount.Should().Be(2);
        report.OctetCount.Should().Be(150);
        report.NtpTimestamp.Should().Be((ulong)NtpTime.UnixEpochOffsetSeconds << 32);
    }

    [Fact]
    public void Advances_the_timestamp_by_ticks_and_by_duration()
    {
        var sender = new RtpStreamSender(1, 111, 48_000, initialTimestamp: 0);
        sender.AdvanceTimestamp(960);
        sender.Timestamp.Should().Be(960u);
        sender.AdvanceTimestampByDuration(TimeSpan.FromMilliseconds(20));
        sender.Timestamp.Should().Be(1920u);
    }

    [Fact]
    public void Wraps_the_timestamp_at_two_to_the_thirty_second()
    {
        var sender = new RtpStreamSender(1, 96, 90_000, initialTimestamp: uint.MaxValue - 1);
        sender.AdvanceTimestamp(3);
        sender.Timestamp.Should().Be(1u);
    }

    [Fact]
    public void Writes_a_one_byte_header_extension_when_asked()
    {
        var sender = new RtpStreamSender(1, 96, 90_000, initialSequenceNumber: 0, initialTimestamp: 0);
        Span<byte> scratch = stackalloc byte[16];
        var extensionWriter = new RtpOneByteExtensionWriter(scratch);
        extensionWriter.TryAppend(3, [0x00, 0x2A]).Should().BeTrue();
        var extensionLength = extensionWriter.Finish();

        Span<byte> buffer = stackalloc byte[128];
        var length = sender.WritePacket(
            [1, 2, 3],
            marker: false,
            timestamp: 0,
            RtpHeaderExtension.OneByteProfile,
            scratch[..extensionLength],
            buffer);

        RtpPacket.TryParse(buffer[..length], out var packet).Should().BeTrue();
        packet.Header.HasExtension.Should().BeTrue();
        packet.Header.TryGetExtension(3, out var value).Should().BeTrue();
        value.ToArray().Should().Equal(0x00, 0x2A);
        packet.Payload.ToArray().Should().Equal(1, 2, 3);
    }

    [Fact]
    public void LastSequenceNumber_throws_before_the_first_packet()
    {
        var sender = new RtpStreamSender(1, 96, 90_000);
        var act = () => sender.LastSequenceNumber;
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void Uses_a_random_initial_sequence_number_and_timestamp()
    {
        // RFC 3550 §5.1: both SHOULD start at a random value to frustrate known-plaintext attacks.
        var senders = new RtpStreamSender[16];
        for (var i = 0; i < senders.Length; i++)
        {
            senders[i] = new RtpStreamSender(1, 96, 90_000);
        }

        senders.Select(s => s.NextSequenceNumber).Distinct().Should().HaveCountGreaterThan(1);
        senders.Select(s => s.Timestamp).Distinct().Should().HaveCountGreaterThan(1);
    }
}
