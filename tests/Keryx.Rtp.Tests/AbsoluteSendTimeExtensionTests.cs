using FluentAssertions;
using Keryx.Core;
using Xunit;

namespace Keryx.Rtp.Tests;

/// <summary>
/// Coverage for the absolute send time header extension
/// (<c>http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time</c>): its 24-bit 6.18 fixed-point
/// one-byte-header encoding, its microsecond conversions, and the wrap-aware unwrapper.
/// </summary>
public class AbsoluteSendTimeExtensionTests
{
    [Fact]
    public void The_body_is_the_element_header_and_the_three_timestamp_octets()
    {
        // RFC 8285 §4.2: header octet is ID (4 bits) | len-1 (4 bits); the value is three octets, which
        // together with the header octet already fill the four-byte boundary — no pad byte.
        Span<byte> body = stackalloc byte[AbsoluteSendTimeExtension.OneByteBodyLength];

        var written = AbsoluteSendTimeExtension.WriteOneByteBody(body, id: 2, timestamp: 0xAB_CDEF);

        written.Should().Be(4);
        body[0].Should().Be(0x22); // id 2, len-1 = 2
        body[1].Should().Be(0xAB);
        body[2].Should().Be(0xCD);
        body[3].Should().Be(0xEF);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(15)]
    public void An_identifier_outside_the_one_byte_range_is_rejected(int id)
    {
        var act = () =>
        {
            Span<byte> body = stackalloc byte[AbsoluteSendTimeExtension.OneByteBodyLength];
            AbsoluteSendTimeExtension.WriteOneByteBody(body, (byte)id, 1);
        };

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void A_body_that_does_not_fit_its_destination_throws()
    {
        var act = () =>
        {
            Span<byte> body = stackalloc byte[3];
            AbsoluteSendTimeExtension.WriteOneByteBody(body, id: 2, timestamp: 1);
        };

        act.Should().Throw<ByteBufferException>();
    }

    [Fact]
    public void Microsecond_round_trip_is_within_one_fixed_point_tick()
    {
        // One 6.18 tick is ~3.8 us; conversion loss must stay under a whole tick.
        for (long micros = 0; micros < AbsoluteSendTimeExtension.WrapPeriodMicroseconds; micros += 123_457)
        {
            var encoded = AbsoluteSendTimeExtension.FromMicroseconds(micros);
            var decoded = AbsoluteSendTimeExtension.ToMicroseconds(encoded);
            Math.Abs(decoded - micros).Should().BeLessThan(5);
        }
    }

    [Fact]
    public void Encoding_wraps_every_sixty_four_seconds()
    {
        // The field spans exactly 64 s, so an instant and that instant plus 64 s encode identically.
        var atZero = AbsoluteSendTimeExtension.FromMicroseconds(1_000_000);
        var atWrap = AbsoluteSendTimeExtension.FromMicroseconds(1_000_000 + AbsoluteSendTimeExtension.WrapPeriodMicroseconds);
        atWrap.Should().Be(atZero);
    }

    [Fact]
    public void A_stamped_packet_round_trips_through_the_rtp_header()
    {
        var sender = new RtpStreamSender(0xAABB_CCDD, payloadType: 96, clockRate: 90_000, initialSequenceNumber: 1);
        Span<byte> body = stackalloc byte[AbsoluteSendTimeExtension.OneByteBodyLength];
        AbsoluteSendTimeExtension.WriteOneByteBody(body, id: 2, timestamp: 0x12_3456);

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

        AbsoluteSendTimeExtension.TryRead(header, id: 2, out var timestamp).Should().BeTrue();
        timestamp.Should().Be(0x12_3456u);
    }

    [Fact]
    public void Reading_returns_false_for_an_element_that_is_not_three_octets()
    {
        Span<byte> destination = stackalloc byte[64];
        var writer = new RtpOneByteExtensionWriter(destination);
        writer.TryAppend(2, [0x77, 0x88]).Should().BeTrue(); // two octets, not three
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
        AbsoluteSendTimeExtension.TryRead(header, id: 2, out _).Should().BeFalse();
    }

    [Fact]
    public void The_unwrapper_spans_the_sixty_four_second_field_boundary()
    {
        var unwrapper = new AbsoluteSendTimeUnwrapper();

        // Just before the wrap: value near the top of the 24-bit field.
        var justBefore = AbsoluteSendTimeExtension.FromMicroseconds(AbsoluteSendTimeExtension.WrapPeriodMicroseconds - 1_000_000);
        var justAfter = AbsoluteSendTimeExtension.FromMicroseconds(AbsoluteSendTimeExtension.WrapPeriodMicroseconds + 1_000_000);

        var before = unwrapper.Unwrap(justBefore);
        var after = unwrapper.Unwrap(justAfter);

        // The two instants are 2 s apart across the wrap; the unwrapped timeline must reflect that rather
        // than a ~62 s backward jump.
        (after - before).Should().BeInRange(1_900_000, 2_100_000);
    }
}
