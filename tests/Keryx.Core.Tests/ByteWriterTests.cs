using FluentAssertions;
using Xunit;

namespace Keryx.Core.Tests;

public class ByteWriterTests
{
    [Fact]
    public void WriteU8_WritesSingleByte()
    {
        var buffer = new byte[3];
        var writer = new ByteWriter(buffer);

        writer.WriteU8(0x00);
        writer.WriteU8(0x7F);
        writer.WriteU8(0xFF);

        buffer.Should().Equal(0x00, 0x7F, 0xFF);
        writer.Position.Should().Be(3);
    }

    [Theory]
    [InlineData((ushort)0, new byte[] { 0x00, 0x00 })]
    [InlineData((ushort)1, new byte[] { 0x00, 0x01 })]
    [InlineData((ushort)0x1234, new byte[] { 0x12, 0x34 })]
    [InlineData(ushort.MaxValue, new byte[] { 0xFF, 0xFF })]
    public void WriteU16_BigEndian(ushort value, byte[] expected)
    {
        var buffer = new byte[2];
        var writer = new ByteWriter(buffer);

        writer.WriteU16(value);

        buffer.Should().Equal(expected);
        writer.Position.Should().Be(2);
    }

    [Theory]
    [InlineData(0u, new byte[] { 0x00, 0x00, 0x00 })]
    [InlineData(1u, new byte[] { 0x00, 0x00, 0x01 })]
    [InlineData(0x123456u, new byte[] { 0x12, 0x34, 0x56 })]
    [InlineData(0xFFFFFFu, new byte[] { 0xFF, 0xFF, 0xFF })]
    public void WriteU24_BigEndian(uint value, byte[] expected)
    {
        var buffer = new byte[3];
        var writer = new ByteWriter(buffer);

        writer.WriteU24(value);

        buffer.Should().Equal(expected);
        writer.Position.Should().Be(3);
    }

    [Fact]
    public void WriteU24_TruncatesHighByte()
    {
        var buffer = new byte[3];
        var writer = new ByteWriter(buffer);

        // 0x01FFFFFF has bits above the low 24 that must be discarded.
        writer.WriteU24(0x01FFFFFFu);

        buffer.Should().Equal(0xFF, 0xFF, 0xFF);
    }

    [Theory]
    [InlineData(0u, new byte[] { 0x00, 0x00, 0x00, 0x00 })]
    [InlineData(1u, new byte[] { 0x00, 0x00, 0x00, 0x01 })]
    [InlineData(0x12345678u, new byte[] { 0x12, 0x34, 0x56, 0x78 })]
    [InlineData(uint.MaxValue, new byte[] { 0xFF, 0xFF, 0xFF, 0xFF })]
    public void WriteU32_BigEndian(uint value, byte[] expected)
    {
        var buffer = new byte[4];
        var writer = new ByteWriter(buffer);

        writer.WriteU32(value);

        buffer.Should().Equal(expected);
        writer.Position.Should().Be(4);
    }

    [Theory]
    [InlineData(0ul, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })]
    [InlineData(1ul, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 })]
    [InlineData(0x0123456789ABul, new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB })]
    [InlineData(0xFFFFFFFFFFFFul, new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF })]
    public void WriteU48_BigEndian(ulong value, byte[] expected)
    {
        var buffer = new byte[6];
        var writer = new ByteWriter(buffer);

        writer.WriteU48(value);

        buffer.Should().Equal(expected);
        writer.Position.Should().Be(6);
    }

    [Fact]
    public void WriteU48_TruncatesHighBits()
    {
        var buffer = new byte[6];
        var writer = new ByteWriter(buffer);

        writer.WriteU48(0xFFFF_FFFFFFFFFFFFul);

        buffer.Should().Equal(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
    }

    [Theory]
    [InlineData(0ul, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })]
    [InlineData(1ul, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 })]
    [InlineData(0x0123456789ABCDEFul, new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF })]
    public void WriteU64_BigEndian(ulong value, byte[] expected)
    {
        var buffer = new byte[8];
        var writer = new ByteWriter(buffer);

        writer.WriteU64(value);

        buffer.Should().Equal(expected);
        writer.Position.Should().Be(8);
    }

    [Fact]
    public void WriteU64_MaxValue()
    {
        var buffer = new byte[8];
        var writer = new ByteWriter(buffer);

        writer.WriteU64(ulong.MaxValue);

        buffer.Should().Equal(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
    }

    [Fact]
    public void WriteBytes_CopiesSourceIntoBuffer()
    {
        var buffer = new byte[5];
        var writer = new ByteWriter(buffer);

        writer.WriteBytes(new byte[] { 1, 2, 3 });

        buffer.Should().Equal(1, 2, 3, 0, 0);
        writer.Position.Should().Be(3);
    }

    [Fact]
    public void WriteBytes_Empty_DoesNotAdvance()
    {
        var buffer = new byte[3];
        var writer = new ByteWriter(buffer);

        writer.WriteBytes(ReadOnlySpan<byte>.Empty);

        writer.Position.Should().Be(0);
    }

    [Fact]
    public void WriteZero_WritesZeroBytesAndAdvances()
    {
        var buffer = new byte[] { 1, 2, 3, 4, 5 };
        var writer = new ByteWriter(buffer);

        writer.WriteZero(3);

        buffer.Should().Equal(0, 0, 0, 4, 5);
        writer.Position.Should().Be(3);
    }

    [Fact]
    public void WriteZero_NegativeCount_ThrowsArgumentOutOfRangeException()
    {
        static void Act()
        {
            var writer = new ByteWriter(new byte[4]);
            writer.WriteZero(-1);
        }

        ((Action)Act).Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void Written_ReturnsOnlyThePopulatedPrefix()
    {
        var buffer = new byte[8];
        var writer = new ByteWriter(buffer);

        writer.WriteU16(0x1234);
        writer.WriteU8(0xFF);

        writer.Written.ToArray().Should().Equal(0x12, 0x34, 0xFF);
    }

    [Fact]
    public void Written_IsEmpty_BeforeAnyWrites()
    {
        var writer = new ByteWriter(new byte[4]);

        writer.Written.Length.Should().Be(0);
    }

    [Fact]
    public void Position_StartsAtZero()
    {
        var writer = new ByteWriter(new byte[4]);

        writer.Position.Should().Be(0);
    }

    [Fact]
    public void Remaining_ReflectsAvailableSpace()
    {
        var writer = new ByteWriter(new byte[5]);

        writer.Remaining.Should().Be(5);
        writer.WriteU16(1);
        writer.Remaining.Should().Be(3);
    }

    [Fact]
    public void Reserve_ReturnsOffsetAndAdvancesPastZeroedRegion()
    {
        var buffer = new byte[] { 9, 9, 9, 9, 9 };
        var writer = new ByteWriter(buffer);

        var offset = writer.Reserve(2);

        offset.Should().Be(0);
        writer.Position.Should().Be(2);
        buffer.Should().Equal(0, 0, 9, 9, 9);
    }

    [Fact]
    public void Reserve_ThenPatch_BackpatchesLengthField()
    {
        var buffer = new byte[16];
        var writer = new ByteWriter(buffer);

        // Simulate: reserve a U16 length prefix, write a payload, then patch the length in.
        var lengthOffset = writer.Reserve(2);
        writer.WriteBytes(new byte[] { 0xAA, 0xBB, 0xCC });

        var patchWriter = new ByteWriter(writer.Patch(lengthOffset, 2));
        patchWriter.WriteU16(3);

        writer.Written.ToArray().Should().Equal(0x00, 0x03, 0xAA, 0xBB, 0xCC);
    }

    [Fact]
    public void Patch_DoesNotAdvancePosition()
    {
        var buffer = new byte[8];
        var writer = new ByteWriter(buffer);
        writer.WriteU32(0);

        writer.Patch(0, 4);

        writer.Position.Should().Be(4);
    }

    [Fact]
    public void Patch_AtExactWrittenBoundary_Succeeds()
    {
        var buffer = new byte[8];
        var writer = new ByteWriter(buffer);
        writer.WriteU32(0xAABBCCDD);

        var patch = writer.Patch(0, 4);

        patch.ToArray().Should().Equal(0xAA, 0xBB, 0xCC, 0xDD);
    }

    [Fact]
    public void Patch_NegativeOffset_Throws()
    {
        static void Act()
        {
            var buffer = new byte[8];
            var writer = new ByteWriter(buffer);
            writer.WriteU32(0);
            writer.Patch(-1, 2);
        }

        ((Action)Act).Should().Throw<ByteBufferException>();
    }

    [Fact]
    public void Patch_NegativeCount_Throws()
    {
        static void Act()
        {
            var buffer = new byte[8];
            var writer = new ByteWriter(buffer);
            writer.WriteU32(0);
            writer.Patch(0, -1);
        }

        ((Action)Act).Should().Throw<ByteBufferException>();
    }

    [Fact]
    public void Patch_WindowExtendingPastPosition_Throws()
    {
        static void Act()
        {
            var buffer = new byte[8];
            var writer = new ByteWriter(buffer);
            writer.WriteU32(0); // Position == 4.
            writer.Patch(2, 4); // [2, 6) extends past Position (4).
        }

        ((Action)Act).Should().Throw<ByteBufferException>();
    }

    [Fact]
    public void Patch_WindowStartingAtPosition_Throws()
    {
        static void Act()
        {
            var buffer = new byte[8];
            var writer = new ByteWriter(buffer);
            writer.WriteU32(0); // Position == 4.
            writer.Patch(4, 1); // Nothing has been written at/after Position yet.
        }

        ((Action)Act).Should().Throw<ByteBufferException>();
    }

    [Fact]
    public void Patch_ZeroLengthWindowAtPosition_Succeeds()
    {
        var buffer = new byte[8];
        var writer = new ByteWriter(buffer);
        writer.WriteU32(0);

        var patch = writer.Patch(4, 0);

        patch.Length.Should().Be(0);
    }

    [Fact]
    public void WriteU8_OnFullBuffer_Throws()
    {
        static void Act()
        {
            var writer = new ByteWriter(Array.Empty<byte>());
            writer.WriteU8(1);
        }

        ((Action)Act).Should().Throw<ByteBufferException>();
    }

    [Fact]
    public void WriteU16_WithOneByteRemaining_Throws()
    {
        static void Act()
        {
            var writer = new ByteWriter(new byte[1]);
            writer.WriteU16(1);
        }

        ((Action)Act).Should().Throw<ByteBufferException>();
    }

    [Fact]
    public void WriteU24_WithTwoBytesRemaining_Throws()
    {
        static void Act()
        {
            var writer = new ByteWriter(new byte[2]);
            writer.WriteU24(1);
        }

        ((Action)Act).Should().Throw<ByteBufferException>();
    }

    [Fact]
    public void WriteU32_WithThreeBytesRemaining_Throws()
    {
        static void Act()
        {
            var writer = new ByteWriter(new byte[3]);
            writer.WriteU32(1);
        }

        ((Action)Act).Should().Throw<ByteBufferException>();
    }

    [Fact]
    public void WriteU48_WithFiveBytesRemaining_Throws()
    {
        static void Act()
        {
            var writer = new ByteWriter(new byte[5]);
            writer.WriteU48(1);
        }

        ((Action)Act).Should().Throw<ByteBufferException>();
    }

    [Fact]
    public void WriteU64_WithSevenBytesRemaining_Throws()
    {
        static void Act()
        {
            var writer = new ByteWriter(new byte[7]);
            writer.WriteU64(1);
        }

        ((Action)Act).Should().Throw<ByteBufferException>();
    }

    [Fact]
    public void WriteBytes_ExceedingRemaining_Throws()
    {
        static void Act()
        {
            var writer = new ByteWriter(new byte[2]);
            writer.WriteBytes(new byte[] { 1, 2, 3 });
        }

        ((Action)Act).Should().Throw<ByteBufferException>();
    }

    [Fact]
    public void WriteZero_ExceedingRemaining_Throws()
    {
        static void Act()
        {
            var writer = new ByteWriter(new byte[2]);
            writer.WriteZero(3);
        }

        ((Action)Act).Should().Throw<ByteBufferException>();
    }

    [Fact]
    public void Reserve_ExceedingRemaining_Throws()
    {
        static void Act()
        {
            var writer = new ByteWriter(new byte[2]);
            writer.Reserve(3);
        }

        ((Action)Act).Should().Throw<ByteBufferException>();
    }

    [Fact]
    public void ByteBufferException_MessageIncludesRequestedAndRemainingCounts()
    {
        static void Act()
        {
            var writer = new ByteWriter(new byte[2]);
            writer.WriteU32(1);
        }

        ((Action)Act).Should().Throw<ByteBufferException>()
            .WithMessage("*4*")
            .WithMessage("*2*");
    }

    [Fact]
    public void SequentialWrites_ProduceExpectedByteLayout()
    {
        var buffer = new byte[24];
        var writer = new ByteWriter(buffer);

        writer.WriteU8(0xAA);
        writer.WriteU16(0x1122);
        writer.WriteU24(0x334455);
        writer.WriteU32(0x66778899);
        writer.WriteU48(0xA0A1A2A3A4A5);
        writer.WriteU64(0xB0B1B2B3B4B5B6B7);

        writer.Position.Should().Be(24);
        writer.Written.ToArray().Should().Equal(
            0xAA,
            0x11, 0x22,
            0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99,
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
            0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7);
    }
}
