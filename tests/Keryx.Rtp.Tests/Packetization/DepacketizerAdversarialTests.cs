using FluentAssertions;
using Keryx.Rtp.Packetization;
using Xunit;

namespace Keryx.Rtp.Tests.Packetization;

/// <summary>
/// Adversarial coverage for the VP8/VP9/AV1 depacketizers, which parse attacker-controlled RTP payload
/// bytes from a peer. A malformed payload must be rejected cleanly (return <see langword="false"/>, never
/// throw), a crafted descriptor or LEB128 length must never read or write out of bounds, and a
/// withheld-marker flood or an absurd declared size must never grow the reassembly buffer past the cap.
/// The cases are deterministic; the fuzz sweeps use a fixed seed.
/// </summary>
public class DepacketizerAdversarialTests
{
    private const int SmallCapacity = 4096;
    private const int SmallMaxFrame = 8192;

    // ------------------------------------------------------------------ AV1 / LEB128

    /// <summary>
    /// Builds an AV1 aggregation packet with W = 0 (every OBU element LEB128-length-prefixed) carrying a
    /// single OBU whose raw bytes are <paramref name="obu"/>.
    /// </summary>
    private static byte[] Av1SingleObuPacket(byte[] obu)
    {
        var length = new byte[Leb128Bytes(obu.Length)];
        WriteLeb128(length, (uint)obu.Length);
        return [0x00, .. length, .. obu];
    }

    private static byte[] Av1Obu(int payloadLength)
    {
        // OBU_FRAME (type 6) header, no extension, no size field; the depacketizer restores the size.
        var payload = new byte[payloadLength];
        for (var i = 0; i < payloadLength; i++)
        {
            payload[i] = (byte)((i * 37) & 0xFF);
        }

        return [0x30, .. payload];
    }

    [Fact]
    public void Av1_leb128_length_that_overruns_the_payload_is_rejected_without_throwing()
    {
        var depacketizer = new Av1Depacketizer();

        // W = 0, then a 5-octet LEB128 declaring ~2 GiB while only two body bytes follow.
        byte[] payload = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0xAA, 0xBB];

        var added = false;
        var act = () => added = depacketizer.TryAddPayload(payload, marker: true, out _);

        act.Should().NotThrow();
        added.Should().BeFalse();
        depacketizer.Frame.Length.Should().Be(0);
    }

    [Fact]
    public void Av1_truncated_leb128_length_is_rejected_without_throwing()
    {
        var depacketizer = new Av1Depacketizer();

        // Every octet has the continuation bit set, so the length never terminates before the payload ends.
        byte[] payload = [0x00, 0xFF, 0xFF, 0xFF];

        var act = () => depacketizer.TryAddPayload(payload, marker: true, out _);

        act.Should().NotThrow();
        depacketizer.TryAddPayload(payload, marker: true, out _).Should().BeFalse();
    }

    [Fact]
    public void Av1_non_canonical_leb128_that_overflows_uint_is_rejected_without_throwing()
    {
        var depacketizer = new Av1Depacketizer();

        // Six octets with the fifth carrying bits above the 32-bit range; Leb128.TryRead must refuse it.
        byte[] payload = [0x00, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01, 0x02];

        var act = () => depacketizer.TryAddPayload(payload, marker: true, out _);

        act.Should().NotThrow();
        depacketizer.TryAddPayload(payload, marker: true, out _).Should().BeFalse();
    }

    [Fact]
    public void Av1_zero_length_obu_element_is_rejected_without_throwing()
    {
        var depacketizer = new Av1Depacketizer();

        // W = 0 then a LEB128 length of zero, which the depacketizer forbids.
        byte[] payload = [0x00, 0x00];

        depacketizer.TryAddPayload(payload, marker: true, out _).Should().BeFalse();
    }

    [Fact]
    public void Av1_withheld_marker_flood_keeps_the_reassembly_buffer_within_the_cap()
    {
        var depacketizer = new Av1Depacketizer(initialCapacity: SmallCapacity, maxFrameSize: SmallMaxFrame);
        var packet = Av1SingleObuPacket(Av1Obu(1000));

        for (var i = 0; i < 500; i++)
        {
            var completed = false;
            var act = () => completed = depacketizer.TryAddPayload(packet, marker: false, out _);

            act.Should().NotThrow();
            completed.Should().BeFalse("no marker was set");
            depacketizer.Frame.Length.Should().BeLessThanOrEqualTo(SmallMaxFrame);
        }
    }

    [Fact]
    public void Av1_explicit_obu_count_beyond_the_body_does_not_overrun()
    {
        var depacketizer = new Av1Depacketizer();

        // W = 3 (three OBUs promised) but only a couple of body bytes present.
        byte[] payload = [0x30, 0x01, 0xAA];

        var act = () => depacketizer.TryAddPayload(payload, marker: true, out _);
        act.Should().NotThrow();
    }

    // ------------------------------------------------------------------ VP9 descriptor

    [Theory]
    [InlineData(new byte[] { 0x88 })] // I|B set, picture ID missing
    [InlineData(new byte[] { 0x88, 0x80 })] // I|B, M-bit picture ID needs two octets, only one present
    [InlineData(new byte[] { 0x28 })] // L|B set, layer indices (2 octets, non-flexible) missing
    [InlineData(new byte[] { 0x0A })] // V|B set, scalability structure header missing
    [InlineData(new byte[] { 0x0A, 0xF0 })] // V|B, N_S=7 + Y: 32 resolution bytes promised, none present
    [InlineData(new byte[] { 0x0A, 0x08, 0x01 })] // V|B, G set, one picture group whose refs run past
    public void Vp9_malformed_descriptor_is_rejected_without_throwing(byte[] payload)
    {
        var depacketizer = new Vp9Depacketizer();

        var added = false;
        var act = () => added = depacketizer.TryAddPayload(payload, marker: true, out _);

        act.Should().NotThrow();
        added.Should().BeFalse();
    }

    [Fact]
    public void Vp9_withheld_marker_flood_keeps_the_reassembly_buffer_within_the_cap()
    {
        var depacketizer = new Vp9Depacketizer(initialCapacity: SmallCapacity, maxFrameSize: SmallMaxFrame);

        // A start packet (B bit) then a long run of continuation packets, none carrying the marker.
        byte[] start = [0x08, .. Payload(1000, 1)];
        depacketizer.TryAddPayload(start, marker: false, out _).Should().BeFalse();

        byte[] continuation = [0x00, .. Payload(1000, 2)];
        for (var i = 0; i < 500; i++)
        {
            var act = () => depacketizer.TryAddPayload(continuation, marker: false, out _);
            act.Should().NotThrow();
            depacketizer.Frame.Length.Should().BeLessThanOrEqualTo(SmallMaxFrame);
        }
    }

    // ------------------------------------------------------------------ VP8 descriptor

    [Theory]
    [InlineData(new byte[] { 0x80 })] // X set, extension control octet missing
    [InlineData(new byte[] { 0x80, 0x80 })] // X + I, picture ID missing
    [InlineData(new byte[] { 0x80, 0x80, 0x80 })] // X + I, M-bit picture ID needs two octets, one present
    [InlineData(new byte[] { 0x80, 0x40 })] // X + L, TL0PICIDX missing
    [InlineData(new byte[] { 0x80, 0x20 })] // X + T, TID/KEYIDX octet missing
    public void Vp8_malformed_descriptor_is_rejected_without_throwing(byte[] payload)
    {
        var depacketizer = new Vp8Depacketizer();

        var added = false;
        var act = () => added = depacketizer.TryAddPayload(payload, marker: true, out _);

        act.Should().NotThrow();
        added.Should().BeFalse();
    }

    [Fact]
    public void Vp8_withheld_marker_flood_keeps_the_reassembly_buffer_within_the_cap()
    {
        var depacketizer = new Vp8Depacketizer(initialCapacity: SmallCapacity, maxFrameSize: SmallMaxFrame);

        byte[] start = [0x10, .. Payload(1000, 1)]; // S bit set
        depacketizer.TryAddPayload(start, marker: false, out _).Should().BeFalse();

        byte[] continuation = [0x00, .. Payload(1000, 2)];
        for (var i = 0; i < 500; i++)
        {
            var act = () => depacketizer.TryAddPayload(continuation, marker: false, out _);
            act.Should().NotThrow();
            depacketizer.Frame.Length.Should().BeLessThanOrEqualTo(SmallMaxFrame);
        }
    }

    // ------------------------------------------------------------------ random fuzz

    [Fact]
    public void Depacketizers_never_throw_and_stay_bounded_on_random_payloads()
    {
        var random = new Random(0xC0FFEE);
        var av1 = new Av1Depacketizer(initialCapacity: SmallCapacity, maxFrameSize: SmallMaxFrame);
        var vp9 = new Vp9Depacketizer(initialCapacity: SmallCapacity, maxFrameSize: SmallMaxFrame);
        var vp8 = new Vp8Depacketizer(initialCapacity: SmallCapacity, maxFrameSize: SmallMaxFrame);

        for (var i = 0; i < 20_000; i++)
        {
            var payload = new byte[random.Next(0, 48)];
            random.NextBytes(payload);
            var marker = (random.Next() & 1) == 0;

            var av1Act = () => av1.TryAddPayload(payload, marker, out _);
            var vp9Act = () => vp9.TryAddPayload(payload, marker, out _);
            var vp8Act = () => vp8.TryAddPayload(payload, marker, out _);

            av1Act.Should().NotThrow();
            vp9Act.Should().NotThrow();
            vp8Act.Should().NotThrow();

            av1.Frame.Length.Should().BeLessThanOrEqualTo(SmallMaxFrame);
            vp9.Frame.Length.Should().BeLessThanOrEqualTo(SmallMaxFrame);
            vp8.Frame.Length.Should().BeLessThanOrEqualTo(SmallMaxFrame);
        }
    }

    // ------------------------------------------------------------------ helpers

    private static byte[] Payload(int length, byte seed)
    {
        var payload = new byte[length];
        for (var i = 0; i < length; i++)
        {
            payload[i] = (byte)(((i * 17) + seed) & 0xFF);
        }

        return payload;
    }

    private static int Leb128Bytes(int value)
    {
        var n = 1;
        while (value >= 0x80)
        {
            value >>= 7;
            n++;
        }

        return n;
    }

    private static void WriteLeb128(Span<byte> destination, uint value)
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
}
