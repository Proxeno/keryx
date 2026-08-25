using FluentAssertions;
using Keryx.Rtp.Packetization;
using Xunit;

namespace Keryx.Rtp.Tests.Packetization;

/// <summary>
/// Golden-vector coverage for the RFC 7741 VP8 packetizer and its depacketizer.
/// </summary>
public class Vp8PacketizerTests
{
    private const int MaxPayloadSize = 1200;

    private static byte[] SyntheticFrame(bool keyFrame, int length)
    {
        var frame = new byte[length];

        // RFC 6386 §9.1 uncompressed data chunk: bit 0 of byte 0 is the (inverted) key-frame flag.
        // Fill the rest of the "header" and body with a deterministic, non-trivial pattern.
        frame[0] = (byte)((keyFrame ? 0x00 : 0x01) | 0x02); // key/inter bit + arbitrary version bits
        for (var i = 1; i < length; i++)
        {
            frame[i] = (byte)(i * 11 % 253);
        }

        return frame;
    }

    private static IReadOnlyList<RtpPayload> Packetize(
        byte[] frame,
        int maxPayloadSize = MaxPayloadSize,
        bool includePictureId = true)
    {
        var writer = new CollectingRtpPayloadWriter();
        var packetizer = new Vp8Packetizer(includePictureId);
        // VP8 ignores the RTP timestamp; its marker is keyed off end-of-frame.
        var count = packetizer.Packetize(frame, 0, maxPayloadSize, writer);
        count.Should().Be(writer.Payloads.Count);
        return writer.Payloads;
    }

    [Fact]
    public void Clock_rate_is_ninety_kilohertz()
    {
        new Vp8Packetizer().ClockRate.Should().Be(90_000);
        new Vp8Packetizer().GetTimestampIncrement(SyntheticFrame(keyFrame: true, 10)).Should().Be(0);
    }

    [Fact]
    public void An_empty_frame_produces_no_packets()
    {
        Packetize([]).Should().BeEmpty();
    }

    [Fact]
    public void A_small_frame_becomes_a_single_packet_with_the_mandatory_descriptor()
    {
        var frame = SyntheticFrame(keyFrame: true, 20);
        var payloads = Packetize(frame, includePictureId: false);

        payloads.Should().ContainSingle();
        var data = payloads[0].Data;
        data[0].Should().Be(0x10); // X=0, N=0, S=1, PID=0
        data[1..].Should().Equal(frame);
        payloads[0].Marker.Should().BeTrue();
    }

    [Fact]
    public void The_extended_descriptor_carries_a_fifteen_bit_picture_id_with_the_m_bit_set()
    {
        var frame = SyntheticFrame(keyFrame: true, 20);
        var payloads = Packetize(frame);

        payloads.Should().ContainSingle();
        var data = payloads[0].Data;
        data[0].Should().Be(0x90);       // X=1, S=1, PID=0
        data[1].Should().Be(0x80);       // I=1, L=0, T=0, K=0
        (data[2] & 0x80).Should().NotBe(0); // M=1
        var pictureId = ((data[2] & 0x7F) << 8) | data[3];
        pictureId.Should().Be(0); // first frame from a fresh packetizer
        data[4..].Should().Equal(frame);
    }

    [Fact]
    public void The_picture_id_increments_once_per_frame_and_wraps_at_fifteen_bits()
    {
        var writer = new CollectingRtpPayloadWriter();
        var packetizer = new Vp8Packetizer();
        var frame = SyntheticFrame(keyFrame: true, 5);

        int ReadPictureId()
        {
            var data = writer.Payloads[^1].Data;
            return ((data[2] & 0x7F) << 8) | data[3];
        }

        packetizer.Packetize(frame, 0, MaxPayloadSize, writer);
        ReadPictureId().Should().Be(0);

        packetizer.Packetize(frame, 0, MaxPayloadSize, writer);
        ReadPictureId().Should().Be(1);

        // Drive the counter up to the 15-bit boundary and confirm it wraps back to zero.
        for (var i = 0; i < Vp8Packetizer.PictureIdModulus - 2; i++)
        {
            packetizer.Packetize(frame, 0, MaxPayloadSize, writer);
        }

        ReadPictureId().Should().Be(Vp8Packetizer.PictureIdModulus - 1);
        packetizer.Packetize(frame, 0, MaxPayloadSize, writer);
        ReadPictureId().Should().Be(0);
    }

    [Fact]
    public void A_large_frame_is_fragmented_with_s_set_only_on_the_first_packet()
    {
        var frame = SyntheticFrame(keyFrame: true, 5000);
        var payloads = Packetize(frame, includePictureId: false);

        var perFragment = MaxPayloadSize - 1; // one mandatory descriptor byte
        var expected = (frame.Length + perFragment - 1) / perFragment;
        payloads.Should().HaveCount(expected).And.HaveCount(5);

        for (var i = 0; i < payloads.Count; i++)
        {
            var s = (payloads[i].Data[0] & 0x10) != 0;
            s.Should().Be(i == 0);
            payloads[i].Marker.Should().Be(i == payloads.Count - 1);
        }
    }

    [Fact]
    public void Marker_is_set_only_on_the_last_packet_of_the_frame()
    {
        var frame = SyntheticFrame(keyFrame: true, 5000);
        var payloads = Packetize(frame);

        payloads.Take(payloads.Count - 1).Should().OnlyContain(p => !p.Marker);
        payloads[^1].Marker.Should().BeTrue();
    }

    [Fact]
    public void Packetizer_rejects_a_max_payload_size_too_small_for_the_descriptor()
    {
        var packetizer = new Vp8Packetizer(includePictureId: false);
        var writer = new CollectingRtpPayloadWriter();
        var act = () => packetizer.Packetize(SyntheticFrame(true, 10), 0, 1, writer);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(1195)]
    [InlineData(1196)]
    [InlineData(1197)]
    [InlineData(5000)]
    [InlineData(20000)]
    public void Depacketizer_reconstructs_the_frame_byte_for_byte(int frameLength)
    {
        var frame = SyntheticFrame(keyFrame: true, frameLength);
        var payloads = Packetize(frame);
        var depacketizer = new Vp8Depacketizer();

        byte[]? reconstructed = null;
        for (var i = 0; i < payloads.Count; i++)
        {
            if (depacketizer.TryAddPayload(payloads[i].Data, payloads[i].Marker, out var result))
            {
                reconstructed = result.ToArray();
            }
        }

        reconstructed.Should().NotBeNull();
        reconstructed.Should().Equal(frame);
    }

    [Fact]
    public void Multi_packet_frame_reassembles_across_fragments()
    {
        // A frame that spans several partitions'-worth of fragments (from the packetizer's point of
        // view, several RTP packets of the single logical partition) must reassemble byte for byte,
        // exactly like the fragmented case above but asserted explicitly against packet count.
        var frame = SyntheticFrame(keyFrame: false, 3600);
        var payloads = Packetize(frame, maxPayloadSize: 1000);
        payloads.Count.Should().BeGreaterThan(1);

        var depacketizer = new Vp8Depacketizer();
        byte[]? reconstructed = null;
        foreach (var payload in payloads)
        {
            if (depacketizer.TryAddPayload(payload.Data, payload.Marker, out var result))
            {
                reconstructed = result.ToArray();
            }
        }

        reconstructed.Should().Equal(frame);
    }

    [Fact]
    public void Depacketizer_handles_consecutive_frames()
    {
        var first = SyntheticFrame(keyFrame: true, 3000);
        var second = SyntheticFrame(keyFrame: false, 900);
        var depacketizer = new Vp8Depacketizer();

        foreach (var frame in new[] { first, second })
        {
            byte[]? reconstructed = null;
            foreach (var payload in Packetize(frame))
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
    public void Depacketizer_detects_a_key_frame_from_s_pid_and_the_payload_header_bit()
    {
        var keyFrame = SyntheticFrame(keyFrame: true, 50);
        var depacketizer = new Vp8Depacketizer();
        foreach (var payload in Packetize(keyFrame))
        {
            depacketizer.TryAddPayload(payload.Data, payload.Marker, out _);
        }

        depacketizer.IsKeyFrame.Should().BeTrue();
    }

    [Fact]
    public void Depacketizer_detects_a_non_key_frame_from_the_payload_header_bit()
    {
        var interFrame = SyntheticFrame(keyFrame: false, 50);
        var depacketizer = new Vp8Depacketizer();
        foreach (var payload in Packetize(interFrame))
        {
            depacketizer.TryAddPayload(payload.Data, payload.Marker, out _);
        }

        depacketizer.IsKeyFrame.Should().BeFalse();
    }

    [Fact]
    public void Depacketizer_parses_the_seven_bit_picture_id_form_without_the_m_bit()
    {
        // Hand-built payload: X=1, S=1, PID=0; extension byte I=1 only; picture ID byte with M=0 and a
        // 7-bit value, followed by two bytes of frame data.
        var depacketizer = new Vp8Depacketizer();
        byte[] payload = [0x90, 0x80, 0x2A, 0xAA, 0xBB]; // M=0, id=0x2A
        depacketizer.TryAddPayload(payload, marker: true, out var frame).Should().BeTrue();
        frame.ToArray().Should().Equal(0xAA, 0xBB);
    }

    [Fact]
    public void Depacketizer_parses_the_fifteen_bit_picture_id_form_with_the_m_bit()
    {
        var depacketizer = new Vp8Depacketizer();
        byte[] payload = [0x90, 0x80, 0xFF, 0x7F, 0xAA, 0xBB]; // M=1, id=0x7F7F
        depacketizer.TryAddPayload(payload, marker: true, out var frame).Should().BeTrue();
        frame.ToArray().Should().Equal(0xAA, 0xBB);
    }

    [Fact]
    public void Depacketizer_skips_tl0picidx_and_tid_keyidx_extension_bytes()
    {
        // X=1, S=1, PID=0; extension byte with I=0, L=1, T=1, K=0 (TID/KEYIDX byte still present
        // because T is set); one TL0PICIDX byte, one TID/KEYIDX byte, then two bytes of frame data.
        var depacketizer = new Vp8Depacketizer();
        byte[] payload = [0x90, 0x60, 0x07, 0x00, 0xAA, 0xBB];
        depacketizer.TryAddPayload(payload, marker: true, out var frame).Should().BeTrue();
        frame.ToArray().Should().Equal(0xAA, 0xBB);
    }

    [Fact]
    public void Depacketizer_rejects_an_empty_payload()
    {
        var depacketizer = new Vp8Depacketizer();
        depacketizer.TryAddPayload([], marker: true, out _).Should().BeFalse();
    }

    [Fact]
    public void Depacketizer_rejects_a_truncated_extended_control_bits_octet()
    {
        var depacketizer = new Vp8Depacketizer();
        depacketizer.TryAddPayload([0x80], marker: true, out _).Should().BeFalse(); // X=1, nothing follows
    }

    [Fact]
    public void Depacketizer_rejects_a_continuation_payload_with_no_preceding_start()
    {
        var depacketizer = new Vp8Depacketizer();
        depacketizer.TryAddPayload([0x00, 0xAA, 0xBB], marker: false, out _).Should().BeFalse(); // S=0
    }

    [Fact]
    public void Depacketizer_rejects_a_start_payload_with_no_data()
    {
        var depacketizer = new Vp8Depacketizer();
        depacketizer.TryAddPayload([0x10], marker: true, out _).Should().BeFalse(); // S=1, no body
    }

    [Fact]
    public void Depacketizer_rejects_a_max_frame_size_smaller_than_the_initial_capacity()
    {
        var act = () => new Vp8Depacketizer(initialCapacity: 1024, maxFrameSize: 512);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void Depacketizer_bounds_accumulation_when_the_marker_bit_is_withheld_and_recovers_after_the_cap()
    {
        // Each continuation payload contributes 32 bytes; a 216-byte cap holds a start payload (32
        // bytes) plus five continuations before the sixth overflows and resets the accumulator. 35
        // iterations after an initial start payload exercise several such cycles without ever growing
        // past the cap.
        const int cap = 216;
        var depacketizer = new Vp8Depacketizer(initialCapacity: 32, maxFrameSize: cap);

        // Build a start payload (S=1) with a 32-byte body, and continuation payloads (S=0) with 32-byte
        // bodies, all withholding the marker bit so the frame never completes.
        byte[] startPayload = [0x10, .. SyntheticFrame(true, 32)];
        byte[] continuationPayload = [0x00, .. SyntheticFrame(true, 32)];

        depacketizer.TryAddPayload(startPayload, marker: false, out _).Should().BeFalse();
        depacketizer.Frame.Length.Should().BeLessThanOrEqualTo(cap);

        for (var i = 0; i < 35; i++)
        {
            depacketizer.TryAddPayload(continuationPayload, marker: false, out _).Should().BeFalse();
            depacketizer.Frame.Length.Should().BeLessThanOrEqualTo(cap);
        }

        // A fresh frame after a reset still depacketizes normally.
        byte[] freshStart = [0x10, .. SyntheticFrame(true, 16)];
        depacketizer.TryAddPayload(freshStart, marker: true, out var frame).Should().BeTrue();
        frame.ToArray().Should().Equal(SyntheticFrame(true, 16));
    }

    [Fact]
    public void Depacketizer_rejects_an_absurdly_large_declared_frame_without_overflowing()
    {
        var depacketizer = new Vp8Depacketizer(initialCapacity: 1024, maxFrameSize: 1024 * 1024);
        var hugeBody = SyntheticFrame(true, 20 * 1024 * 1024); // far beyond the 1 MiB cap
        byte[] hugePayload = [0x10, .. hugeBody];

        depacketizer.TryAddPayload(hugePayload, marker: true, out var frame).Should().BeFalse();
        frame.Length.Should().Be(0);
        depacketizer.Frame.Length.Should().Be(0);
    }

    [Fact]
    public void Depacketizer_reassembles_correctly_with_a_configured_frame_size_cap()
    {
        var frame = SyntheticFrame(keyFrame: true, 5000);
        var payloads = Packetize(frame);
        var depacketizer = new Vp8Depacketizer(maxFrameSize: 1024 * 1024);

        byte[]? reconstructed = null;
        foreach (var payload in payloads)
        {
            if (depacketizer.TryAddPayload(payload.Data, payload.Marker, out var result))
            {
                reconstructed = result.ToArray();
            }
        }

        reconstructed.Should().Equal(frame);
    }
}
