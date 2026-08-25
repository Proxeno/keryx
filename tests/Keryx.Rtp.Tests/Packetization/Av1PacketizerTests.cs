using FluentAssertions;
using Keryx.Rtp.Packetization;
using Xunit;

namespace Keryx.Rtp.Tests.Packetization;

/// <summary>
/// Golden-vector coverage for the "RTP Payload Format For AV1" packetizer and its depacketizer.
/// </summary>
public class Av1PacketizerTests
{
    private const int MaxPayloadSize = 1200;

    /// <summary>Builds one low-overhead-format OBU (obu_has_size_field = 1) with a deterministic payload.</summary>
    private static byte[] Obu(byte obuType, int payloadLength, byte seed = 1)
    {
        var payload = new byte[payloadLength];
        for (var i = 0; i < payloadLength; i++)
        {
            payload[i] = (byte)(((i * 31) + seed) % 251);
        }

        var header = (byte)((obuType << 3) | 0x02); // obu_has_size_field = 1
        var size = new byte[Leb128SizeOf(payloadLength)];
        WriteLeb128(size, payloadLength);
        return [header, .. size, .. payload];
    }

    private static int Leb128SizeOf(int value)
    {
        var n = 1;
        while (value >= 0x80)
        {
            value >>= 7;
            n++;
        }

        return n;
    }

    private static void WriteLeb128(Span<byte> destination, int value)
    {
        var index = 0;
        do
        {
            var octet = (byte)(value & 0x7F);
            value >>= 7;
            if (value != 0)
            {
                octet |= 0x80;
            }

            destination[index++] = octet;
        }
        while (value != 0);
    }

    private static byte[] Concat(params byte[][] obus)
    {
        var total = obus.Sum(o => o.Length);
        var result = new byte[total];
        var offset = 0;
        foreach (var obu in obus)
        {
            obu.CopyTo(result, offset);
            offset += obu.Length;
        }

        return result;
    }

    /// <summary>A key-frame temporal unit: temporal delimiter, sequence header, then a frame OBU.</summary>
    private static byte[] KeyFrameTemporalUnit(int framePayloadLength) => Concat(
        Obu(Av1ObuType.TemporalDelimiter, 0),
        Obu(Av1ObuType.SequenceHeader, 12, seed: 7),
        Obu(Av1ObuType.Frame, framePayloadLength, seed: 3));

    /// <summary>An inter-frame temporal unit: temporal delimiter then a frame OBU (no sequence header).</summary>
    private static byte[] InterFrameTemporalUnit(int framePayloadLength) => Concat(
        Obu(Av1ObuType.TemporalDelimiter, 0),
        Obu(Av1ObuType.Frame, framePayloadLength, seed: 9));

    private static IReadOnlyList<RtpPayload> Packetize(byte[] frame, int maxPayloadSize = MaxPayloadSize)
    {
        var writer = new CollectingRtpPayloadWriter();
        var packetizer = new Av1Packetizer();
        var count = packetizer.Packetize(frame, 0, maxPayloadSize, writer);
        count.Should().Be(writer.Payloads.Count);
        return writer.Payloads;
    }

    private static byte[] RoundTrip(byte[] frame, int maxPayloadSize = MaxPayloadSize)
    {
        var payloads = Packetize(frame, maxPayloadSize);
        var depacketizer = new Av1Depacketizer();
        byte[]? reconstructed = null;
        foreach (var payload in payloads)
        {
            if (depacketizer.TryAddPayload(payload.Data, payload.Marker, out var result))
            {
                reconstructed = result.ToArray();
            }
        }

        reconstructed.Should().NotBeNull();
        return reconstructed!;
    }

    [Fact]
    public void Clock_rate_is_ninety_kilohertz()
    {
        new Av1Packetizer().ClockRate.Should().Be(90_000);
        new Av1Packetizer().GetTimestampIncrement(KeyFrameTemporalUnit(10)).Should().Be(0);
    }

    [Fact]
    public void An_empty_frame_produces_no_packets()
    {
        Packetize([]).Should().BeEmpty();
    }

    [Fact]
    public void A_small_key_frame_is_one_packet_with_the_new_sequence_bit_set()
    {
        var payloads = Packetize(KeyFrameTemporalUnit(20));
        payloads.Should().ContainSingle();

        var header = payloads[0].Data[0];
        (header & 0x80).Should().Be(0); // Z=0
        (header & 0x40).Should().Be(0); // Y=0
        ((header >> 4) & 0x03).Should().Be(0); // W=0 (every element length-prefixed)
        (header & 0x08).Should().NotBe(0); // N=1 (temporal unit opens a coded video sequence)
        payloads[0].Marker.Should().BeTrue();
    }

    [Fact]
    public void An_inter_frame_leaves_the_new_sequence_bit_clear()
    {
        var payloads = Packetize(InterFrameTemporalUnit(20));
        (payloads[0].Data[0] & 0x08).Should().Be(0); // N=0
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(7)]
    [InlineData(200)]
    [InlineData(1100)]
    [InlineData(1150)]
    [InlineData(5000)]
    [InlineData(40000)]
    public void Depacketizer_reconstructs_a_key_frame_byte_for_byte(int framePayloadLength)
    {
        var frame = KeyFrameTemporalUnit(framePayloadLength);
        RoundTrip(frame).Should().Equal(frame);
    }

    [Theory]
    [InlineData(50)]
    [InlineData(5000)]
    public void Depacketizer_reconstructs_an_inter_frame_byte_for_byte(int framePayloadLength)
    {
        var frame = InterFrameTemporalUnit(framePayloadLength);
        RoundTrip(frame).Should().Equal(frame);
    }

    [Fact]
    public void A_multi_obu_temporal_unit_aggregates_into_one_packet_and_round_trips()
    {
        // Four OBUs comfortably under the MTU: they aggregate into a single packet, each with its own
        // LEB128 length, and reassemble byte for byte.
        var frame = Concat(
            Obu(Av1ObuType.TemporalDelimiter, 0),
            Obu(Av1ObuType.SequenceHeader, 10, seed: 2),
            Obu(Av1ObuType.FrameHeader, 40, seed: 4),
            Obu(Av1ObuType.TileGroup, 300, seed: 6));

        var payloads = Packetize(frame);
        payloads.Should().ContainSingle();
        RoundTrip(frame).Should().Equal(frame);
    }

    [Fact]
    public void A_large_obu_fragments_across_packets_with_continuation_bits()
    {
        // One big frame OBU forces fragmentation. The first packet must not claim to continue a previous
        // fragment (Z=0) and must claim to continue into the next (Y=1); the last must be the mirror.
        var frame = InterFrameTemporalUnit(5000);
        var payloads = Packetize(frame, maxPayloadSize: 400);
        payloads.Count.Should().BeGreaterThan(1);

        (payloads[0].Data[0] & 0x80).Should().Be(0); // first packet: Z=0
        payloads[^1].Marker.Should().BeTrue();
        (payloads[^1].Data[0] & 0x40).Should().Be(0); // last packet: Y=0

        // Every interior packet both continues a fragment and continues into the next.
        for (var i = 1; i < payloads.Count - 1; i++)
        {
            (payloads[i].Data[0] & 0x80).Should().NotBe(0); // Z=1
            (payloads[i].Data[0] & 0x40).Should().NotBe(0); // Y=1
        }

        RoundTrip(frame, maxPayloadSize: 400).Should().Equal(frame);
    }

    [Fact]
    public void Depacketizer_handles_consecutive_temporal_units()
    {
        var first = KeyFrameTemporalUnit(3000);
        var second = InterFrameTemporalUnit(600);
        var depacketizer = new Av1Depacketizer();
        var packetizer = new Av1Packetizer();

        foreach (var frame in new[] { first, second })
        {
            var writer = new CollectingRtpPayloadWriter();
            packetizer.Packetize(frame, 0, MaxPayloadSize, writer);

            byte[]? reconstructed = null;
            foreach (var payload in writer.Payloads)
            {
                if (depacketizer.TryAddPayload(payload.Data, payload.Marker, out var result))
                {
                    reconstructed = result.ToArray();
                }
            }

            reconstructed.Should().Equal(frame);
            depacketizer.BeginNextFrame();
        }
    }

    [Fact]
    public void Depacketizer_detects_a_key_frame_from_the_sequence_header()
    {
        var depacketizer = new Av1Depacketizer();
        foreach (var payload in Packetize(KeyFrameTemporalUnit(80)))
        {
            depacketizer.TryAddPayload(payload.Data, payload.Marker, out _);
        }

        depacketizer.IsKeyFrame.Should().BeTrue();
    }

    [Fact]
    public void Depacketizer_reports_no_key_frame_without_a_sequence_header()
    {
        var depacketizer = new Av1Depacketizer();
        foreach (var payload in Packetize(InterFrameTemporalUnit(80)))
        {
            depacketizer.TryAddPayload(payload.Data, payload.Marker, out _);
        }

        depacketizer.IsKeyFrame.Should().BeFalse();
    }

    [Fact]
    public void Depacketizer_reads_the_explicit_w_greater_than_zero_element_layout()
    {
        // Hand-built single packet, W=2: one length-prefixed OBU element then one unprefixed element that
        // runs to the end of the payload. The depacketizer must restore each OBU's size field.
        // Element A: header 0x0A (temporal delimiter, size bit set is irrelevant on the wire form; here
        // we carry the size-stripped form header=type<<3), zero payload. Element B: frame OBU header +
        // 3 payload bytes.
        var elementA = new byte[] { (byte)(Av1ObuType.TemporalDelimiter << 3) };
        var elementB = new byte[] { (byte)(Av1ObuType.Frame << 3), 0xAA, 0xBB, 0xCC };
        byte header = 0x20; // Z=0, Y=0, W=2, N=0
        byte[] payload = [header, (byte)elementA.Length, .. elementA, .. elementB];

        var depacketizer = new Av1Depacketizer();
        depacketizer.TryAddPayload(payload, marker: true, out var frame).Should().BeTrue();

        // Reconstructed: TD OBU (header|size, leb128(0)) then frame OBU (header|size, leb128(3), payload).
        var expected = Concat(
            new byte[] { (byte)((Av1ObuType.TemporalDelimiter << 3) | 0x02), 0x00 },
            new byte[] { (byte)((Av1ObuType.Frame << 3) | 0x02), 0x03, 0xAA, 0xBB, 0xCC });
        frame.ToArray().Should().Equal(expected);
    }

    [Fact]
    public void Depacketizer_rejects_an_empty_payload()
    {
        new Av1Depacketizer().TryAddPayload([], marker: true, out _).Should().BeFalse();
    }

    [Fact]
    public void Depacketizer_rejects_a_truncated_obu_element_length()
    {
        // W=0 so a length field is expected, but the LEB128 never terminates.
        new Av1Depacketizer().TryAddPayload([0x00, 0x80], marker: true, out _).Should().BeFalse();
    }

    [Fact]
    public void Depacketizer_rejects_an_element_running_past_the_payload()
    {
        // W=0, declared element length 10 but only two bytes follow.
        new Av1Depacketizer().TryAddPayload([0x00, 0x0A, 0x01, 0x02], marker: true, out _).Should().BeFalse();
    }

    [Fact]
    public void Depacketizer_rejects_a_max_frame_size_smaller_than_the_initial_capacity()
    {
        var act = () => new Av1Depacketizer(initialCapacity: 1024, maxFrameSize: 512);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void Depacketizer_bounds_accumulation_when_the_marker_bit_is_withheld_and_recovers_after_the_cap()
    {
        const int cap = 4096;
        var depacketizer = new Av1Depacketizer(initialCapacity: 256, maxFrameSize: cap);

        // A fragmented OBU element that never terminates: first packet Z=0/Y=1, then continuations
        // Z=1/Y=1, each carrying a 200-byte chunk with a LEB128 length prefix, no marker.
        byte[] chunk = new byte[200];
        byte[] firstPacket = [0x40, 0xC8, 0x01, .. chunk]; // Z=0,Y=1; leb128(200)=0xC8 0x01
        byte[] contPacket = [0xC0, 0xC8, 0x01, .. chunk]; // Z=1,Y=1

        depacketizer.TryAddPayload(firstPacket, marker: false, out _).Should().BeFalse();
        depacketizer.Frame.Length.Should().BeLessThanOrEqualTo(cap);

        for (var i = 0; i < 60; i++)
        {
            depacketizer.TryAddPayload(contPacket, marker: false, out _).Should().BeFalse();
            depacketizer.Frame.Length.Should().BeLessThanOrEqualTo(cap);
        }

        // A fresh, self-contained temporal unit still round-trips after the overflow reset.
        var frame = KeyFrameTemporalUnit(40);
        byte[]? reconstructed = null;
        foreach (var payload in Packetize(frame))
        {
            if (depacketizer.TryAddPayload(payload.Data, payload.Marker, out var result))
            {
                reconstructed = result.ToArray();
            }
        }

        reconstructed.Should().Equal(frame);
    }
}
