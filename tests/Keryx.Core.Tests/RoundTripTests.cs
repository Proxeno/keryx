using FluentAssertions;
using Xunit;

namespace Keryx.Core.Tests;

public class RoundTripTests
{
    [Fact]
    public void WriterThenReader_MixedSequence_RoundTripsIdentically()
    {
        var buffer = new byte[64];
        var writer = new ByteWriter(buffer);

        writer.WriteU8(0x42);
        writer.WriteU16(0xBEEF);
        writer.WriteU24(0x0102_03u);
        writer.WriteU32(0xDEADBEEF);
        writer.WriteU48(0x0102_0304_0506ul);
        writer.WriteU64(0xFEEDFACECAFEBEEFul);
        writer.WriteBytes(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 });
        writer.WriteZero(3);
        writer.WriteU8(byte.MaxValue);

        var writtenLength = writer.Position;

        var reader = new ByteReader(buffer.AsSpan(0, writtenLength));

        reader.ReadU8().Should().Be(0x42);
        reader.ReadU16().Should().Be(0xBEEF);
        reader.ReadU24().Should().Be(0x010203u);
        reader.ReadU32().Should().Be(0xDEADBEEF);
        reader.ReadU48().Should().Be(0x010203040506ul);
        reader.ReadU64().Should().Be(0xFEEDFACECAFEBEEFul);
        reader.ReadBytes(5).ToArray().Should().Equal(0x01, 0x02, 0x03, 0x04, 0x05);
        reader.ReadBytes(3).ToArray().Should().Equal(0x00, 0x00, 0x00);
        reader.ReadU8().Should().Be(byte.MaxValue);

        reader.Position.Should().Be(writtenLength);
        reader.Remaining.Should().Be(0);
    }

    [Fact]
    public void WriterThenReader_ReservePatchedLengthPrefix_ReadsBackCorrectly()
    {
        var buffer = new byte[16];
        var writer = new ByteWriter(buffer);

        var lengthOffset = writer.Reserve(2);
        var payload = new byte[] { 0x10, 0x20, 0x30, 0x40 };
        writer.WriteBytes(payload);

        var patch = new ByteWriter(writer.Patch(lengthOffset, 2));
        patch.WriteU16((ushort)payload.Length);

        var reader = new ByteReader(writer.Written);

        reader.ReadU16().Should().Be((ushort)payload.Length);
        reader.ReadBytes(payload.Length).ToArray().Should().Equal(payload);
        reader.Remaining.Should().Be(0);
    }

    [Fact]
    public void WriterThenReader_EmptyBuffer_RoundTrips()
    {
        var writer = new ByteWriter(Array.Empty<byte>());
        var reader = new ByteReader(writer.Written);

        reader.Length.Should().Be(0);
        reader.Remaining.Should().Be(0);
    }

    [Fact]
    public void WriterThenReader_ReadingBeyondWrittenPrefix_Throws()
    {
        var buffer = new byte[8];
        var writer = new ByteWriter(buffer);
        writer.WriteU16(0x1234);
        var written = writer.Written.ToArray();

        // Reader over only the written prefix (2 bytes) — asking for more must throw.
        void Act()
        {
            var reader = new ByteReader(written);
            reader.ReadU32();
        }

        ((Action)Act).Should().Throw<ByteBufferException>();
    }
}
