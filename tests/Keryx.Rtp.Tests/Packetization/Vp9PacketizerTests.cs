using FluentAssertions;
using Keryx.Rtp.Packetization;
using Xunit;

namespace Keryx.Rtp.Tests.Packetization;

/// <summary>
/// Golden-vector coverage for the draft-ietf-payload-vp9 VP9 packetizer and its depacketizer.
/// </summary>
public class Vp9PacketizerTests
{
    private const int MaxPayloadSize = 1200;

    /// <summary>
    /// A synthetic VP9 frame whose uncompressed header classifies as a key frame or an inter frame,
    /// followed by a deterministic body. Profile 0: frame_marker(2)=10, profile bits 00,
    /// show_existing_frame=0, then frame_type (0=key, 1=inter).
    /// </summary>
    private static byte[] SyntheticFrame(bool keyFrame, int length)
    {
        var frame = new byte[length];

        // Bits (MSB first): 10 (marker) 0 0 (profile low/high) 0 (show_existing) T (frame_type) ...
        // key frame  (T=0): 0b1000_00xx = 0x80; inter (T=1): 0b1000_01xx = 0x84.
        frame[0] = keyFrame ? (byte)0x80 : (byte)0x84;
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
        var packetizer = new Vp9Packetizer(includePictureId);
        var count = packetizer.Packetize(frame, 0, maxPayloadSize, writer);
        count.Should().Be(writer.Payloads.Count);
        return writer.Payloads;
    }

    [Fact]
    public void Clock_rate_is_ninety_kilohertz()
    {
        new Vp9Packetizer().ClockRate.Should().Be(90_000);
        new Vp9Packetizer().GetTimestampIncrement(SyntheticFrame(keyFrame: true, 10)).Should().Be(0);
    }

    [Fact]
    public void An_empty_frame_produces_no_packets()
    {
        Packetize([]).Should().BeEmpty();
    }

    [Fact]
    public void A_small_key_frame_becomes_a_single_packet_with_the_mandatory_descriptor()
    {
        var frame = SyntheticFrame(keyFrame: true, 20);
        var payloads = Packetize(frame, includePictureId: false);

        payloads.Should().ContainSingle();
        var data = payloads[0].Data;
        // I=0, P=0 (key frame), L=0, F=0, B=1, E=1, V=0, Z=0 => 0b0000_1100 = 0x0C.
        data[0].Should().Be(0x0C);
        data[1..].Should().Equal(frame);
        payloads[0].Marker.Should().BeTrue();
    }

    [Fact]
    public void An_inter_frame_sets_the_p_bit()
    {
        var frame = SyntheticFrame(keyFrame: false, 20);
        var payloads = Packetize(frame, includePictureId: false);

        // I=0, P=1, B=1, E=1 => 0b0100_1100 = 0x4C.
        payloads[0].Data[0].Should().Be(0x4C);
    }

    [Fact]
    public void The_extended_descriptor_carries_a_fifteen_bit_picture_id_with_the_m_bit_set()
    {
        var frame = SyntheticFrame(keyFrame: true, 20);
        var payloads = Packetize(frame);

        payloads.Should().ContainSingle();
        var data = payloads[0].Data;
        // I=1, P=0, B=1, E=1 => 0b1000_1100 = 0x8C.
        data[0].Should().Be(0x8C);
        (data[1] & 0x80).Should().NotBe(0); // M=1
        var pictureId = ((data[1] & 0x7F) << 8) | data[2];
        pictureId.Should().Be(0); // first frame from a fresh packetizer
        data[3..].Should().Equal(frame);
    }

    [Fact]
    public void The_picture_id_increments_once_per_frame_and_wraps_at_fifteen_bits()
    {
        var writer = new CollectingRtpPayloadWriter();
        var packetizer = new Vp9Packetizer();
        var frame = SyntheticFrame(keyFrame: true, 5);

        int ReadPictureId()
        {
            var data = writer.Payloads[^1].Data;
            return ((data[1] & 0x7F) << 8) | data[2];
        }

        packetizer.Packetize(frame, 0, MaxPayloadSize, writer);
        ReadPictureId().Should().Be(0);

        packetizer.Packetize(frame, 0, MaxPayloadSize, writer);
        ReadPictureId().Should().Be(1);

        for (var i = 0; i < Vp9Packetizer.PictureIdModulus - 2; i++)
        {
            packetizer.Packetize(frame, 0, MaxPayloadSize, writer);
        }

        ReadPictureId().Should().Be(Vp9Packetizer.PictureIdModulus - 1);
        packetizer.Packetize(frame, 0, MaxPayloadSize, writer);
        ReadPictureId().Should().Be(0);
    }

    [Fact]
    public void A_large_frame_is_fragmented_with_b_on_first_and_e_on_last()
    {
        var frame = SyntheticFrame(keyFrame: true, 5000);
        var payloads = Packetize(frame, includePictureId: false);

        var perFragment = MaxPayloadSize - 1; // one mandatory descriptor byte
        var expected = (frame.Length + perFragment - 1) / perFragment;
        payloads.Should().HaveCount(expected).And.HaveCount(5);

        for (var i = 0; i < payloads.Count; i++)
        {
            var b = (payloads[i].Data[0] & 0x08) != 0;
            var e = (payloads[i].Data[0] & 0x04) != 0;
            b.Should().Be(i == 0);
            e.Should().Be(i == payloads.Count - 1);
            payloads[i].Marker.Should().Be(i == payloads.Count - 1);
        }
    }

    [Fact]
    public void Packetizer_rejects_a_max_payload_size_too_small_for_the_descriptor()
    {
        var packetizer = new Vp9Packetizer(includePictureId: false);
        var writer = new CollectingRtpPayloadWriter();
        var act = () => packetizer.Packetize(SyntheticFrame(true, 10), 0, 1, writer);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(1196)]
    [InlineData(1197)]
    [InlineData(1198)]
    [InlineData(5000)]
    [InlineData(20000)]
    public void Depacketizer_reconstructs_the_frame_byte_for_byte(int frameLength)
    {
        var frame = SyntheticFrame(keyFrame: true, frameLength);
        var payloads = Packetize(frame);
        var depacketizer = new Vp9Depacketizer();

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
    public void Multi_packet_frame_reassembles_across_fragments()
    {
        var frame = SyntheticFrame(keyFrame: false, 3600);
        var payloads = Packetize(frame, maxPayloadSize: 1000);
        payloads.Count.Should().BeGreaterThan(1);

        var depacketizer = new Vp9Depacketizer();
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
        var depacketizer = new Vp9Depacketizer();

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
    public void Depacketizer_detects_a_key_frame_from_the_p_bit()
    {
        var depacketizer = new Vp9Depacketizer();
        foreach (var payload in Packetize(SyntheticFrame(keyFrame: true, 50)))
        {
            depacketizer.TryAddPayload(payload.Data, payload.Marker, out _);
        }

        depacketizer.IsKeyFrame.Should().BeTrue();
    }

    [Fact]
    public void Depacketizer_detects_an_inter_frame_from_the_p_bit()
    {
        var depacketizer = new Vp9Depacketizer();
        foreach (var payload in Packetize(SyntheticFrame(keyFrame: false, 50)))
        {
            depacketizer.TryAddPayload(payload.Data, payload.Marker, out _);
        }

        depacketizer.IsKeyFrame.Should().BeFalse();
    }

    [Fact]
    public void Depacketizer_parses_the_seven_bit_picture_id_form()
    {
        // I=1, B=1, E=1 (0x8C); picture ID byte with M=0 and a 7-bit value; then two bytes of data.
        var depacketizer = new Vp9Depacketizer();
        byte[] payload = [0x8C, 0x2A, 0xAA, 0xBB];
        depacketizer.TryAddPayload(payload, marker: true, out var frame).Should().BeTrue();
        frame.ToArray().Should().Equal(0xAA, 0xBB);
    }

    [Fact]
    public void Depacketizer_parses_the_fifteen_bit_picture_id_form()
    {
        var depacketizer = new Vp9Depacketizer();
        byte[] payload = [0x8C, 0xFF, 0x7F, 0xAA, 0xBB]; // M=1, id=0x7F7F
        depacketizer.TryAddPayload(payload, marker: true, out var frame).Should().BeTrue();
        frame.ToArray().Should().Equal(0xAA, 0xBB);
    }

    [Fact]
    public void Depacketizer_skips_non_flexible_layer_indices()
    {
        // I=0, P=1, L=1, F=0, B=1, E=1 => 0b0110_1100 = 0x6C. Then TID/SID octet and TL0PICIDX octet,
        // followed by two bytes of frame data.
        var depacketizer = new Vp9Depacketizer();
        byte[] payload = [0x6C, 0x00, 0x11, 0xAA, 0xBB];
        depacketizer.TryAddPayload(payload, marker: true, out var frame).Should().BeTrue();
        frame.ToArray().Should().Equal(0xAA, 0xBB);
    }

    [Fact]
    public void Depacketizer_skips_flexible_mode_reference_indices()
    {
        // I=0, P=1, L=1, F=1, B=1, E=1 => 0b0111_1100 = 0x7C. Layer indices in flexible mode is one
        // octet (no TL0PICIDX); then two P_DIFF octets (first has N=1, second N=0), then frame data.
        var depacketizer = new Vp9Depacketizer();
        byte[] payload = [0x7C, 0x00, 0x03, 0x04, 0xAA, 0xBB];
        depacketizer.TryAddPayload(payload, marker: true, out var frame).Should().BeTrue();
        frame.ToArray().Should().Equal(0xAA, 0xBB);
    }

    [Fact]
    public void Depacketizer_skips_the_scalability_structure()
    {
        // I=0, P=0, B=1, E=1, V=1 => 0b0000_1110 = 0x0E. SS header N_S=0 (1 layer), Y=1, G=0 => bits
        // 000 1 0 000 = 0x10; then width(2)+height(2); then two bytes of frame data.
        var depacketizer = new Vp9Depacketizer();
        byte[] payload = [0x0E, 0x10, 0x05, 0x00, 0x02, 0xD0, 0xAA, 0xBB];
        depacketizer.TryAddPayload(payload, marker: true, out var frame).Should().BeTrue();
        frame.ToArray().Should().Equal(0xAA, 0xBB);
    }

    [Fact]
    public void Depacketizer_rejects_an_empty_payload()
    {
        new Vp9Depacketizer().TryAddPayload([], marker: true, out _).Should().BeFalse();
    }

    [Fact]
    public void Depacketizer_rejects_a_truncated_picture_id()
    {
        // I=1, B=1 but nothing follows the mandatory descriptor.
        new Vp9Depacketizer().TryAddPayload([0x88], marker: true, out _).Should().BeFalse();
    }

    [Fact]
    public void Depacketizer_rejects_a_continuation_payload_with_no_preceding_start()
    {
        // B=0, no picture ID; a lone continuation with no start frame.
        new Vp9Depacketizer().TryAddPayload([0x00, 0xAA, 0xBB], marker: false, out _).Should().BeFalse();
    }

    [Fact]
    public void Depacketizer_rejects_a_start_payload_with_no_data()
    {
        // I=0, B=1, E=1 but no body byte.
        new Vp9Depacketizer().TryAddPayload([0x0C], marker: true, out _).Should().BeFalse();
    }

    [Fact]
    public void Depacketizer_rejects_a_max_frame_size_smaller_than_the_initial_capacity()
    {
        var act = () => new Vp9Depacketizer(initialCapacity: 1024, maxFrameSize: 512);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void Depacketizer_bounds_accumulation_when_the_marker_bit_is_withheld_and_recovers_after_the_cap()
    {
        const int cap = 216;
        var depacketizer = new Vp9Depacketizer(initialCapacity: 32, maxFrameSize: cap);

        // Start payload (I=0, B=1 => 0x08) with a 32-byte body, continuations (B=0 => 0x00) with 32-byte
        // bodies, all withholding the marker so the frame never completes.
        byte[] startPayload = [0x08, .. new byte[32]];
        byte[] continuationPayload = [0x00, .. new byte[32]];

        depacketizer.TryAddPayload(startPayload, marker: false, out _).Should().BeFalse();
        depacketizer.Frame.Length.Should().BeLessThanOrEqualTo(cap);

        for (var i = 0; i < 35; i++)
        {
            depacketizer.TryAddPayload(continuationPayload, marker: false, out _).Should().BeFalse();
            depacketizer.Frame.Length.Should().BeLessThanOrEqualTo(cap);
        }

        byte[] freshStart = [0x0C, .. SyntheticFrame(true, 16)[..16]];
        depacketizer.TryAddPayload(freshStart, marker: true, out var frame).Should().BeTrue();
        frame.Length.Should().Be(16);
    }

    [Fact]
    public void Depacketizer_rejects_an_absurdly_large_declared_frame_without_overflowing()
    {
        var depacketizer = new Vp9Depacketizer(initialCapacity: 1024, maxFrameSize: 1024 * 1024);
        var hugeBody = SyntheticFrame(true, 20 * 1024 * 1024); // far beyond the 1 MiB cap
        byte[] hugePayload = [0x0C, .. hugeBody];

        depacketizer.TryAddPayload(hugePayload, marker: true, out var frame).Should().BeFalse();
        frame.Length.Should().Be(0);
        depacketizer.Frame.Length.Should().Be(0);
    }
}
