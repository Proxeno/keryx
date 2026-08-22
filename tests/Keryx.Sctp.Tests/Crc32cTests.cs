using FluentAssertions;
using Keryx.Sctp;
using Xunit;

namespace Keryx.Sctp.Tests;

/// <summary>
/// CRC-32C conformance. The check value for "123456789" is the standard Castagnoli check value
/// published with the polynomial (0x1EDC6F41 / reflected 0x82F63B78). The 32-byte vectors are the
/// iSCSI CRC examples of RFC 3720 Appendix B.4, which RFC 4960/9260 Appendix A adopt for SCTP.
/// RFC 3720 prints each digest in transmission order (least significant byte first), so its
/// "aa 36 91 8a" is the value 0x8A9136AA asserted here.
/// </summary>
public class Crc32cTests
{
    [Fact]
    public void CastagnoliCheckValue()
    {
        // "123456789" -> 0xE3069283 (the CRC-32C check value).
        var data = "123456789"u8.ToArray();
        Crc32c.Compute(data).Should().Be(0xE3069283);
    }

    [Fact]
    public void Rfc3720ThirtyTwoBytesOfZeroes()
    {
        // RFC 3720 B.4: 32 bytes of 0x00 -> "aa 36 91 8a" == 0x8A9136AA.
        Crc32c.Compute(new byte[32]).Should().Be(0x8A9136AA);
    }

    [Fact]
    public void Rfc3720ThirtyTwoBytesOfOnes()
    {
        // RFC 3720 B.4: 32 bytes of 0xFF -> "43 ab a8 62" == 0x62A8AB43.
        var data = new byte[32];
        Array.Fill(data, (byte)0xFF);
        Crc32c.Compute(data).Should().Be(0x62A8AB43);
    }

    [Fact]
    public void Rfc3720IncrementingBytes()
    {
        // RFC 3720 B.4: 0x00..0x1F -> "4e 79 dd 46" == 0x46DD794E.
        var data = new byte[32];
        for (var i = 0; i < data.Length; i++)
        {
            data[i] = (byte)i;
        }

        Crc32c.Compute(data).Should().Be(0x46DD794E);
    }

    [Fact]
    public void Rfc3720DecrementingBytes()
    {
        // RFC 3720 B.4: 0x1F..0x00 -> "5c db 3f 11" == 0x113FDB5C.
        var data = new byte[32];
        for (var i = 0; i < data.Length; i++)
        {
            data[i] = (byte)(31 - i);
        }

        Crc32c.Compute(data).Should().Be(0x113FDB5C);
    }

    [Fact]
    public void EmptyInputIsZero()
    {
        Crc32c.Compute(ReadOnlySpan<byte>.Empty).Should().Be(0u);
    }

    [Fact]
    public void IncrementalUpdateMatchesSinglePass()
    {
        var data = new byte[257];
        new Random(1234).NextBytes(data);

        var state = Crc32c.Update(Crc32c.Seed, data.AsSpan(0, 100));
        state = Crc32c.Update(state, data.AsSpan(100, 57));
        state = Crc32c.Update(state, data.AsSpan(157));

        Crc32c.Finish(state).Should().Be(Crc32c.Compute(data));
    }
}
