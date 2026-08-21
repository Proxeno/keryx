using FluentAssertions;
using Xunit;

namespace Keryx.Core.Tests;

public class ByteReaderTests
{
    [Fact]
    public void ReadU8_ReturnsByteAndAdvances()
    {
        var reader = new ByteReader(new byte[] { 0x00, 0x7F, 0xFF });

        reader.ReadU8().Should().Be(0x00);
        reader.ReadU8().Should().Be(0x7F);
        reader.ReadU8().Should().Be(0xFF);
        reader.Position.Should().Be(3);
    }

    [Theory]
    [InlineData(new byte[] { 0x00, 0x00 }, (ushort)0)]
    [InlineData(new byte[] { 0x00, 0x01 }, (ushort)1)]
    [InlineData(new byte[] { 0x12, 0x34 }, (ushort)0x1234)]
    [InlineData(new byte[] { 0xFF, 0xFF }, ushort.MaxValue)]
    public void ReadU16_BigEndian(byte[] bytes, ushort expected)
    {
        var reader = new ByteReader(bytes);

        reader.ReadU16().Should().Be(expected);
        reader.Position.Should().Be(2);
    }

    [Theory]
    [InlineData(new byte[] { 0x00, 0x00, 0x00 }, 0u)]
    [InlineData(new byte[] { 0x00, 0x00, 0x01 }, 1u)]
    [InlineData(new byte[] { 0x12, 0x34, 0x56 }, 0x123456u)]
    [InlineData(new byte[] { 0xFF, 0xFF, 0xFF }, 0xFFFFFFu)]
    public void ReadU24_BigEndian(byte[] bytes, uint expected)
    {
        var reader = new ByteReader(bytes);

        reader.ReadU24().Should().Be(expected);
        reader.Position.Should().Be(3);
    }

    [Theory]
    [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x00 }, 0u)]
    [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x01 }, 1u)]
    [InlineData(new byte[] { 0x12, 0x34, 0x56, 0x78 }, 0x12345678u)]
    [InlineData(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF }, uint.MaxValue)]
    public void ReadU32_BigEndian(byte[] bytes, uint expected)
    {
        var reader = new ByteReader(bytes);

        reader.ReadU32().Should().Be(expected);
        reader.Position.Should().Be(4);
    }

    [Theory]
    [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 0ul)]
    [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }, 1ul)]
    [InlineData(new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB }, 0x0123456789ABul)]
    [InlineData(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, 0xFFFFFFFFFFFFul)]
    public void ReadU48_BigEndian(byte[] bytes, ulong expected)
    {
        var reader = new ByteReader(bytes);

        reader.ReadU48().Should().Be(expected);
        reader.Position.Should().Be(6);
    }

    [Theory]
    [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 0ul)]
    [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }, 1ul)]
    [InlineData(new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF }, 0x0123456789ABCDEFul)]
    [InlineData(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, ulong.MaxValue)]
    public void ReadU64_BigEndian(byte[] bytes, ulong expected)
    {
        var reader = new ByteReader(bytes);

        reader.ReadU64().Should().Be(expected);
        reader.Position.Should().Be(8);
    }

    [Fact]
    public void ReadBytes_ReturnsSliceAndAdvances()
    {
        var reader = new ByteReader(new byte[] { 1, 2, 3, 4, 5 });

        var slice = reader.ReadBytes(3);

        slice.ToArray().Should().Equal(1, 2, 3);
        reader.Position.Should().Be(3);
        reader.Remaining.Should().Be(2);
    }

    [Fact]
    public void ReadBytes_ZeroCount_ReturnsEmptyAndDoesNotAdvance()
    {
        var reader = new ByteReader(new byte[] { 1, 2, 3 });

        var slice = reader.ReadBytes(0);

        slice.Length.Should().Be(0);
        reader.Position.Should().Be(0);
    }

    [Fact]
    public void ReadBytes_NegativeCount_ThrowsArgumentOutOfRangeException()
    {
        static void Act()
        {
            var reader = new ByteReader(new byte[] { 1, 2, 3 });
            reader.ReadBytes(-1);
        }

        ((Action)Act).Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void Skip_AdvancesPositionWithoutReturningData()
    {
        var reader = new ByteReader(new byte[] { 1, 2, 3, 4, 5 });

        reader.Skip(2);

        reader.Position.Should().Be(2);
        reader.ReadU8().Should().Be(3);
    }

    [Fact]
    public void Skip_NegativeCount_ThrowsArgumentOutOfRangeException()
    {
        static void Act()
        {
            var reader = new ByteReader(new byte[] { 1, 2, 3 });
            reader.Skip(-1);
        }

        ((Action)Act).Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void Peek_ReturnsRemainderWithoutAdvancing()
    {
        var reader = new ByteReader(new byte[] { 1, 2, 3, 4, 5 });
        reader.Skip(2);

        var peeked = reader.Peek();

        peeked.ToArray().Should().Equal(3, 4, 5);
        reader.Position.Should().Be(2);
    }

    [Fact]
    public void Peek_AtEnd_ReturnsEmpty()
    {
        var reader = new ByteReader(new byte[] { 1, 2, 3 });
        reader.Skip(3);

        reader.Peek().Length.Should().Be(0);
    }

    [Fact]
    public void Position_StartsAtZero()
    {
        var reader = new ByteReader(new byte[] { 1, 2, 3 });

        reader.Position.Should().Be(0);
    }

    [Fact]
    public void Remaining_ReflectsUnconsumedBytes()
    {
        var reader = new ByteReader(new byte[] { 1, 2, 3, 4, 5 });

        reader.Remaining.Should().Be(5);
        reader.ReadU16();
        reader.Remaining.Should().Be(3);
    }

    [Fact]
    public void Length_ReflectsTotalBufferSize()
    {
        var reader = new ByteReader(new byte[] { 1, 2, 3, 4, 5 });

        reader.Length.Should().Be(5);
        reader.ReadU16();
        reader.Length.Should().Be(5);
    }

    [Fact]
    public void Remaining_IsZero_ForEmptyBuffer()
    {
        var reader = new ByteReader(ReadOnlySpan<byte>.Empty);

        reader.Remaining.Should().Be(0);
    }

    [Fact]
    public void ReadU8_OnEmptyBuffer_Throws()
    {
        static void Act()
        {
            var reader = new ByteReader(ReadOnlySpan<byte>.Empty);
            reader.ReadU8();
        }

        ((Action)Act).Should().Throw<ByteBufferException>();
    }

    [Fact]
    public void ReadU16_WithOneByteRemaining_Throws()
    {
        static void Act()
        {
            var reader = new ByteReader(new byte[] { 0x01 });
            reader.ReadU16();
        }

        ((Action)Act).Should().Throw<ByteBufferException>();
    }

    [Fact]
    public void ReadU24_WithTwoBytesRemaining_Throws()
    {
        static void Act()
        {
            var reader = new ByteReader(new byte[] { 0x01, 0x02 });
            reader.ReadU24();
        }

        ((Action)Act).Should().Throw<ByteBufferException>();
    }

    [Fact]
    public void ReadU32_WithThreeBytesRemaining_Throws()
    {
        static void Act()
        {
            var reader = new ByteReader(new byte[] { 0x01, 0x02, 0x03 });
            reader.ReadU32();
        }

        ((Action)Act).Should().Throw<ByteBufferException>();
    }

    [Fact]
    public void ReadU48_WithFiveBytesRemaining_Throws()
    {
        static void Act()
        {
            var reader = new ByteReader(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 });
            reader.ReadU48();
        }

        ((Action)Act).Should().Throw<ByteBufferException>();
    }

    [Fact]
    public void ReadU64_WithSevenBytesRemaining_Throws()
    {
        static void Act()
        {
            var reader = new ByteReader(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 });
            reader.ReadU64();
        }

        ((Action)Act).Should().Throw<ByteBufferException>();
    }

    [Fact]
    public void ReadBytes_RequestingMoreThanRemaining_Throws()
    {
        static void Act()
        {
            var reader = new ByteReader(new byte[] { 1, 2, 3 });
            reader.ReadBytes(4);
        }

        ((Action)Act).Should().Throw<ByteBufferException>();
    }

    [Fact]
    public void Skip_RequestingMoreThanRemaining_Throws()
    {
        static void Act()
        {
            var reader = new ByteReader(new byte[] { 1, 2, 3 });
            reader.Skip(4);
        }

        ((Action)Act).Should().Throw<ByteBufferException>();
    }

    [Fact]
    public void ByteBufferException_MessageIncludesRequestedAndRemainingCounts()
    {
        static void Act()
        {
            var reader = new ByteReader(new byte[] { 1, 2 });
            reader.ReadU32();
        }

        ((Action)Act).Should().Throw<ByteBufferException>()
            .WithMessage("*4*")
            .WithMessage("*2*");
    }

    [Fact]
    public void SequentialReads_AdvancePositionCorrectly()
    {
        // U8 + U16 + U24 + U32 + U48 + U64 = 1+2+3+4+6+8 = 24 bytes.
        var bytes = new byte[]
        {
            0xAA,
            0x11, 0x22,
            0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99,
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
            0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
        };
        var reader = new ByteReader(bytes);

        reader.ReadU8().Should().Be(0xAA);
        reader.ReadU16().Should().Be(0x1122);
        reader.ReadU24().Should().Be(0x334455u);
        reader.ReadU32().Should().Be(0x66778899u);
        reader.ReadU48().Should().Be(0xA0A1A2A3A4A5ul);
        reader.ReadU64().Should().Be(0xB0B1B2B3B4B5B6B7ul);
        reader.Position.Should().Be(24);
        reader.Remaining.Should().Be(0);
    }
}
