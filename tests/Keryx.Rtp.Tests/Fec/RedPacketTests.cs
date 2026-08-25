using FluentAssertions;
using Keryx.Core;
using Keryx.Rtp.Fec;
using Xunit;

namespace Keryx.Rtp.Tests.Fec;

/// <summary>Coverage for the RFC 2198 RED payload format used to wrap media and ULPFEC.</summary>
public class RedPacketTests
{
    [Fact]
    public void A_primary_only_payload_is_a_one_byte_header_then_the_body()
    {
        // RFC 2198 §3: the primary block header is a clear F bit and a seven-bit payload type.
        Span<byte> destination = stackalloc byte[16];

        var written = RedPacket.WritePrimaryOnly(96, [0xAA, 0xBB, 0xCC], destination);

        written.Should().Be(RedPacket.PrimaryHeaderLength + 3);
        destination[0].Should().Be(96); // F = 0, PT = 96
        destination[1..4].ToArray().Should().Equal(0xAA, 0xBB, 0xCC);
    }

    [Fact]
    public void A_primary_only_payload_round_trips_to_its_block()
    {
        var body = new byte[] { 1, 2, 3, 4, 5 };
        var destination = new byte[64];
        var written = RedPacket.WritePrimaryOnly(110, body, destination);

        RedPacket.TryReadPrimary(destination.AsSpan(0, written), out var primaryPt, out var primaryData)
            .Should().BeTrue();
        primaryPt.Should().Be(110);
        primaryData.ToArray().Should().Equal(body);
    }

    [Fact]
    public void A_redundant_block_precedes_the_primary_and_carries_its_length_and_offset()
    {
        // RFC 2198 §3: F = 1, then PT, a 14-bit timestamp offset and a 10-bit block length.
        var redundant = new byte[] { 0x10, 0x20 };
        var primary = new byte[] { 0x30, 0x40, 0x50 };
        var destination = new byte[64];

        var written = RedPacket.WriteWithSingleRedundancy(
            redundantPayloadType: 100,
            timestampOffset: 0x1234,
            redundantData: redundant,
            primaryPayloadType: 96,
            primaryData: primary,
            destination);

        written.Should().Be(
            RedPacket.RedundantHeaderLength + RedPacket.PrimaryHeaderLength + redundant.Length + primary.Length);

        // F | PT
        destination[0].Should().Be(0x80 | 100);
        // 14-bit offset 0x1234 then 10-bit length 2, packed big-endian across three octets.
        var packed = ((uint)destination[1] << 16) | ((uint)destination[2] << 8) | destination[3];
        (packed >> 10).Should().Be(0x1234u);
        (packed & 0x3FF).Should().Be(2u);
        destination[4].Should().Be(96); // primary header, F = 0

        var blocks = new List<(byte Pt, ushort Offset, byte[] Data, bool Primary)>();
        foreach (var block in RedPacket.GetBlocks(destination.AsSpan(0, written)))
        {
            blocks.Add((block.PayloadType, block.TimestampOffset, block.Data.ToArray(), block.IsPrimary));
        }

        blocks.Should().HaveCount(2);
        blocks[0].Should().BeEquivalentTo((Pt: (byte)100, Offset: (ushort)0x1234, Data: redundant, Primary: false));
        blocks[1].Should().BeEquivalentTo((Pt: (byte)96, Offset: (ushort)0, Data: primary, Primary: true));
    }

    [Fact]
    public void Reading_the_primary_skips_the_redundant_block()
    {
        var destination = new byte[64];
        var written = RedPacket.WriteWithSingleRedundancy(
            100, 90, [0xDE, 0xAD], 96, [0xBE, 0xEF, 0xF0, 0x0D], destination);

        RedPacket.TryReadPrimary(destination.AsSpan(0, written), out var pt, out var data).Should().BeTrue();
        pt.Should().Be(96);
        data.ToArray().Should().Equal(0xBE, 0xEF, 0xF0, 0x0D);
    }

    [Fact]
    public void An_empty_primary_body_is_well_formed()
    {
        var destination = new byte[8];
        var written = RedPacket.WritePrimaryOnly(96, [], destination);

        written.Should().Be(1);
        RedPacket.TryReadPrimary(destination.AsSpan(0, written), out var pt, out var data).Should().BeTrue();
        pt.Should().Be(96);
        data.Length.Should().Be(0);
    }

    [Fact]
    public void A_truncated_redundant_header_is_rejected()
    {
        // F bit set but only three octets present: the header runs past the end.
        var malformed = new byte[] { 0x80, 0x00, 0x00 };
        RedPacket.TryReadPrimary(malformed, out _, out _).Should().BeFalse();
    }

    [Fact]
    public void A_redundant_length_that_overruns_the_payload_is_rejected()
    {
        // One redundant header declaring a 300-byte block, but no body follows.
        var destination = new byte[RedPacket.RedundantHeaderLength + RedPacket.PrimaryHeaderLength];
        destination[0] = 0x80 | 100;
        var packed = (0u << 10) | 300u;
        destination[1] = (byte)(packed >> 16);
        destination[2] = (byte)(packed >> 8);
        destination[3] = (byte)packed;
        destination[4] = 96;

        RedPacket.TryReadPrimary(destination, out _, out _).Should().BeFalse();
    }

    [Fact]
    public void A_payload_type_above_seven_bits_throws()
    {
        var act = () => RedPacket.WritePrimaryOnly(128, [1], new byte[8]);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void Writing_a_primary_that_does_not_fit_throws()
    {
        var act = () => RedPacket.WritePrimaryOnly(96, new byte[10], new byte[4]);
        act.Should().Throw<ByteBufferException>();
    }
}
