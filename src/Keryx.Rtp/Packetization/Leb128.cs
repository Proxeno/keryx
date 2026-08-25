namespace Keryx.Rtp.Packetization;

/// <summary>
/// The little-endian base-128 (LEB128) unsigned integer coding AV1 uses for OBU sizes and for the
/// OBU-element length fields in its RTP aggregation header (AV1 bitstream §4.10.5, RTP Payload Format
/// For AV1 §4).
/// </summary>
internal static class Leb128
{
    /// <summary>The largest number of octets AV1 permits a single LEB128 value to occupy.</summary>
    public const int MaxLength = 8;

    /// <summary>The number of octets <see cref="Write"/> would spend on <paramref name="value"/>.</summary>
    /// <param name="value">The value to measure.</param>
    /// <returns>The octet count, between 1 and <see cref="MaxLength"/>.</returns>
    public static int Size(uint value)
    {
        var size = 1;
        while (value >= 0x80)
        {
            value >>= 7;
            size++;
        }

        return size;
    }

    /// <summary>Writes <paramref name="value"/> as canonical LEB128 into <paramref name="destination"/>.</summary>
    /// <param name="destination">The buffer to write into; must hold <see cref="Size"/> octets.</param>
    /// <param name="value">The value to encode.</param>
    /// <returns>The number of octets written.</returns>
    public static int Write(Span<byte> destination, uint value)
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

        return index;
    }

    /// <summary>
    /// Reads a LEB128 value from the front of <paramref name="source"/>.
    /// </summary>
    /// <param name="source">The bytes to read from.</param>
    /// <param name="value">On success, the decoded value.</param>
    /// <param name="bytesRead">On success, the number of octets consumed.</param>
    /// <returns>
    /// <see langword="false"/> when the encoding is truncated, runs past
    /// <see cref="MaxLength"/> octets, or does not fit in a <see cref="uint"/>.
    /// </returns>
    public static bool TryRead(ReadOnlySpan<byte> source, out uint value, out int bytesRead)
    {
        value = 0;
        bytesRead = 0;

        for (var i = 0; i < MaxLength; i++)
        {
            if (i >= source.Length)
            {
                return false;
            }

            var octet = source[i];
            // AV1 §4.10.5 encodes at most 32 significant bits; reject anything that would overflow uint.
            if (i == 4 && (octet & 0xF0) != 0)
            {
                return false;
            }

            value |= (uint)(octet & 0x7F) << (i * 7);
            if ((octet & 0x80) == 0)
            {
                bytesRead = i + 1;
                return true;
            }
        }

        return false;
    }
}
