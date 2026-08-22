using FluentAssertions;
using Keryx.Core;
using Xunit;

namespace Keryx.Rtp.Tests;

/// <summary>
/// Coverage for the transport-wide congestion-control header extension
/// (<c>draft-holmer-rmcat-transport-wide-cc-extensions-01</c>) one-byte-header encoding.
/// </summary>
public class TransportCcExtensionTests
{
    [Fact]
    public void The_body_is_the_element_header_the_two_octet_value_and_one_pad_byte()
    {
        // RFC 8285 §4.2: header octet is ID (4 bits) | len-1 (4 bits); the value is two octets, padded
        // up to the four-byte boundary RFC 3550 §5.3.1 requires.
        Span<byte> body = stackalloc byte[TransportCcExtension.OneByteBodyLength];

        var written = TransportCcExtension.WriteOneByteBody(body, id: 3, sequenceNumber: 0x1234);

        written.Should().Be(4);
        body[0].Should().Be(0x31); // id 3, len-1 = 1
        body[1].Should().Be(0x12);
        body[2].Should().Be(0x34);
        body[3].Should().Be(0x00); // padding
    }

    [Theory]
    [InlineData(0)]
    [InlineData(15)]
    public void An_identifier_outside_the_one_byte_range_is_rejected(int id)
    {
        var act = () =>
        {
            Span<byte> body = stackalloc byte[TransportCcExtension.OneByteBodyLength];
            TransportCcExtension.WriteOneByteBody(body, (byte)id, 1);
        };

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void A_body_that_does_not_fit_its_destination_throws()
    {
        var act = () =>
        {
            Span<byte> body = stackalloc byte[3];
            TransportCcExtension.WriteOneByteBody(body, id: 3, sequenceNumber: 1);
        };

        act.Should().Throw<ByteBufferException>();
    }

    [Fact]
    public void A_stamped_packet_round_trips_through_the_rtp_header()
    {
        // Stamp the extension via the sender, serialize, reparse, and read the value back.
        var sender = new RtpStreamSender(0xAABB_CCDD, payloadType: 96, clockRate: 90_000, initialSequenceNumber: 1);
        Span<byte> body = stackalloc byte[TransportCcExtension.OneByteBodyLength];
        TransportCcExtension.WriteOneByteBody(body, id: 5, sequenceNumber: 0xBEEF);

        var buffer = new byte[128];
        var length = sender.WritePacket(
            [1, 2, 3, 4],
            marker: false,
            timestamp: 100,
            RtpHeaderExtension.OneByteProfile,
            body,
            buffer);

        RtpHeader.TryParse(buffer.AsSpan(0, length), out var header).Should().BeTrue();
        header.HasExtension.Should().BeTrue();
        header.ExtensionProfile.Should().Be(RtpHeaderExtension.OneByteProfile);

        TransportCcExtension.TryRead(header, id: 5, out var sequenceNumber).Should().BeTrue();
        sequenceNumber.Should().Be(0xBEEF);
    }

    [Fact]
    public void Reading_returns_false_when_the_element_is_absent()
    {
        var sender = new RtpStreamSender(1, payloadType: 96, clockRate: 90_000, initialSequenceNumber: 1);
        var buffer = new byte[64];
        var length = sender.WritePacket([9, 9], marker: false, buffer);

        RtpHeader.TryParse(buffer.AsSpan(0, length), out var header).Should().BeTrue();
        TransportCcExtension.TryRead(header, id: 3, out var sequenceNumber).Should().BeFalse();
        sequenceNumber.Should().Be(0);
    }

    [Fact]
    public void Reading_returns_false_for_an_element_that_is_not_two_octets()
    {
        // A one-octet element under the queried id must not be misread as a sequence number.
        Span<byte> destination = stackalloc byte[64];
        var writer = new RtpOneByteExtensionWriter(destination);
        writer.TryAppend(3, [0x77]).Should().BeTrue();
        var bodyLength = writer.Finish();

        var sender = new RtpStreamSender(1, payloadType: 96, clockRate: 90_000, initialSequenceNumber: 1);
        var buffer = new byte[128];
        var length = sender.WritePacket(
            [1, 2],
            marker: false,
            timestamp: 0,
            RtpHeaderExtension.OneByteProfile,
            destination[..bodyLength],
            buffer);

        RtpHeader.TryParse(buffer.AsSpan(0, length), out var header).Should().BeTrue();
        TransportCcExtension.TryRead(header, id: 3, out _).Should().BeFalse();
    }
}
