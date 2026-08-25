using System.Buffers.Binary;
using FluentAssertions;
using Keryx.Rtp.Fec;
using Xunit;

namespace Keryx.Rtp.Tests.Fec;

/// <summary>
/// Adversarial coverage for the RFC 2198 RED, RFC 5109 ULPFEC and RFC 8627 FlexFEC parsers and recovery
/// paths, all of which consume attacker-controlled bytes. A malformed header must be rejected cleanly, a
/// declared length must never drive an out-of-bounds read or an oversized recovered packet, and a flood
/// of unrecoverable repair packets must stay bounded. The crafted cases are deterministic; the fuzz sweep
/// uses a fixed seed.
/// </summary>
public class FecParserAdversarialTests
{
    private const uint MediaSsrc = 0xAABB_CCDD;

    // ------------------------------------------------------------------ RED

    [Theory]
    [InlineData(new byte[] { 0x80, 0x00, 0x00 })] // F set but the four-octet redundant header is truncated
    [InlineData(new byte[] { 0x80, 0x00, 0x00, 0x08, 0x60 })] // redundant length (8) runs past the payload
    [InlineData(new byte[0])] // empty
    [InlineData(new byte[] { 0x80, 0x00, 0x00, 0x04 })] // header run never reaches a primary block
    public void Red_malformed_payload_is_rejected_without_throwing(byte[] payload)
    {
        var read = true;
        var act = () => read = RedPacket.TryReadPrimary(payload, out _, out _);

        act.Should().NotThrow();
        read.Should().BeFalse();
    }

    [Fact]
    public void Red_primary_only_block_reads_back_its_body()
    {
        // A single primary header (F = 0) naming PT 96, then a two-byte body.
        byte[] payload = [0x60, 0x01, 0x02];

        RedPacket.TryReadPrimary(payload, out var pt, out var data).Should().BeTrue();
        pt.Should().Be(96);
        data.ToArray().Should().Equal(0x01, 0x02);
    }

    // ------------------------------------------------------------------ ULPFEC

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(13)] // one octet short of the fixed header
    public void Ulpfec_payload_shorter_than_the_header_is_rejected(int length)
    {
        var payload = new byte[length];

        UlpFecPacket.TryParse(payload, out _).Should().BeFalse();
    }

    [Fact]
    public void Ulpfec_protection_length_past_the_payload_is_rejected()
    {
        // 10-octet FEC header + 4-octet ULP header, protection length claims 200 bytes with none present.
        var payload = new byte[UlpFecPacket.HeaderLength];
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(10), 200); // protection length field

        UlpFecPacket.TryParse(payload, out _).Should().BeFalse();
    }

    // ------------------------------------------------------------------ FlexFEC parse

    [Fact]
    public void Flexfec_payload_shorter_than_the_minimum_header_is_rejected()
    {
        var payload = new byte[FlexFecPacket.MinHeaderLength - 1];

        FlexFecPacket.TryParse(payload, out _).Should().BeFalse();
    }

    [Fact]
    public void Flexfec_retransmission_or_fixed_block_variant_is_rejected()
    {
        var retransmission = MinimalFlexFec();
        retransmission[0] |= 0x80; // R
        FlexFecPacket.TryParse(retransmission, out _).Should().BeFalse();

        var fixedBlock = MinimalFlexFec();
        fixedBlock[0] |= 0x40; // F
        FlexFecPacket.TryParse(fixedBlock, out _).Should().BeFalse();
    }

    [Fact]
    public void Flexfec_ssrc_count_other_than_one_is_rejected()
    {
        var payload = MinimalFlexFec();
        payload[8] = 2; // SSRCCount
        FlexFecPacket.TryParse(payload, out _).Should().BeFalse();
    }

    [Fact]
    public void Flexfec_continuation_bit_with_a_truncated_mask_is_rejected()
    {
        // Mask block 1 sets the k continuation bit (0x8000) promising a wider mask, but the payload ends
        // right after the two-byte block, so the 46-bit form's extra octets are missing.
        var payload = new byte[FlexFecPacket.MinHeaderLength];
        payload[8] = 1; // SSRCCount
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(12), MediaSsrc);
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(FlexFecPacket.MaskOffset), 0x8000);

        FlexFecPacket.TryParse(payload, out _).Should().BeFalse();
    }

    // ------------------------------------------------------------------ FlexFEC oversized recovery

    [Fact]
    public void Flexfec_recovery_length_beyond_the_repair_payload_recovers_nothing()
    {
        var receiver = new FlexFecReceiver(MediaSsrc);
        const int fecPayloadLength = 8;

        // Length recovery declares one octet more than the repair payload actually protects; the recovered
        // post-header region cannot be that long, so recovery must decline rather than over-read/allocate.
        var payload = FlexFecOneBitRepair(fecPayloadLength, lengthRecovery: (ushort)(fecPayloadLength + 1));

        var recovered = false;
        var act = () => recovered = receiver.OnFecPacket(payload);

        act.Should().NotThrow();
        recovered.Should().BeFalse();
        receiver.GetStats().PacketsRecovered.Should().Be(0);
    }

    [Fact]
    public void Flexfec_recovery_length_equal_to_the_repair_payload_recovers_a_bounded_packet()
    {
        var receiver = new FlexFecReceiver(MediaSsrc);
        const int fecPayloadLength = 8;

        var payload = FlexFecOneBitRepair(fecPayloadLength, lengthRecovery: fecPayloadLength);

        receiver.OnFecPacket(payload).Should().BeTrue();
        receiver.GetStats().PacketsRecovered.Should().Be(1);

        // The recovered packet is the fixed RTP header plus exactly the protected post-header length.
        var destination = new byte[2048];
        receiver.TryDequeueRecovered(destination, out var length, out _).Should().BeTrue();
        length.Should().Be(FlexFecPacket.FixedRtpHeaderLength + fecPayloadLength);
    }

    // ------------------------------------------------------------------ random fuzz

    [Fact]
    public void Fec_parsers_and_receivers_never_throw_on_random_payloads()
    {
        var random = new Random(0xBADF00D);
        var ulp = new UlpFecReceiver(MediaSsrc);
        var flex = new FlexFecReceiver(MediaSsrc);

        for (var i = 0; i < 20_000; i++)
        {
            var payload = new byte[random.Next(0, 64)];
            random.NextBytes(payload);

            var redAct = () => RedPacket.TryReadPrimary(payload, out _, out _);
            var ulpParseAct = () => UlpFecPacket.TryParse(payload, out _);
            var flexParseAct = () => FlexFecPacket.TryParse(payload, out _);
            var ulpFecAct = () => ulp.OnFecPacket(payload);
            var flexFecAct = () => flex.OnFecPacket(payload);
            var ulpMediaAct = () => ulp.OnMediaPacket(payload);
            var flexMediaAct = () => flex.OnMediaPacket(payload);

            redAct.Should().NotThrow();
            ulpParseAct.Should().NotThrow();
            flexParseAct.Should().NotThrow();
            ulpFecAct.Should().NotThrow();
            flexFecAct.Should().NotThrow();
            ulpMediaAct.Should().NotThrow();
            flexMediaAct.Should().NotThrow();
        }

        // Draining after the sweep must also stay clean and never over-run the destination.
        var destination = new byte[2048];
        var drainUlp = () => ulp.TryDequeueRecovered(destination, out _, out _);
        var drainFlex = () => flex.TryDequeueRecovered(destination, out _, out _);
        drainUlp.Should().NotThrow();
        drainFlex.Should().NotThrow();
    }

    // ------------------------------------------------------------------ helpers

    /// <summary>A syntactically valid minimal FlexFEC header: SSRCCount = 1, matching SSRC, 15-bit mask.</summary>
    private static byte[] MinimalFlexFec()
    {
        var payload = new byte[FlexFecPacket.MinHeaderLength];
        payload[8] = 1; // SSRCCount
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(12), MediaSsrc);
        return payload;
    }

    /// <summary>
    /// A FlexFEC repair packet whose 15-bit mask protects exactly the packet at SN base (logical bit 0),
    /// so a receiver holding none of the group treats that one packet as the single loss and recovers it.
    /// </summary>
    private static byte[] FlexFecOneBitRepair(int fecPayloadLength, ushort lengthRecovery)
    {
        var payload = new byte[FlexFecPacket.MinHeaderLength + fecPayloadLength];
        payload[8] = 1; // SSRCCount
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(2), lengthRecovery);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(12), MediaSsrc);
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(FlexFecPacket.SequenceNumberBaseOffset), 5000);

        // Mask block 1: logical bit 0 is the most significant mask bit (1 << 14); continuation bit clear.
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(FlexFecPacket.MaskOffset), 1 << 14);

        for (var i = 0; i < fecPayloadLength; i++)
        {
            payload[FlexFecPacket.MinHeaderLength + i] = (byte)(0x40 + i);
        }

        return payload;
    }
}
