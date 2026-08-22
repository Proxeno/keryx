using Keryx.Core;

namespace Keryx.Rtp.Rtcp;

/// <summary>
/// The four-byte header common to every RTCP packet (RFC 3550 §6.1): version, padding flag, a
/// five-bit count whose meaning depends on the packet type, the packet type, and the length.
/// </summary>
public readonly struct RtcpPacketHeader
{
    /// <summary>Length of the common header in bytes.</summary>
    public const int Length = 4;

    /// <summary>The only RTCP version this stack accepts.</summary>
    public const byte SupportedVersion = 2;

    /// <summary>Creates a header.</summary>
    /// <param name="version">RTCP version.</param>
    /// <param name="hasPadding">The P bit.</param>
    /// <param name="count">Reception report count, source count, or feedback message type.</param>
    /// <param name="packetType">The packet type.</param>
    /// <param name="lengthInWords">Length in 32-bit words minus one, exactly as it appears on the wire.</param>
    public RtcpPacketHeader(byte version, bool hasPadding, byte count, RtcpPacketType packetType, ushort lengthInWords)
    {
        Version = version;
        HasPadding = hasPadding;
        Count = count;
        PacketType = packetType;
        LengthInWords = lengthInWords;
    }

    /// <summary>RTCP version; only <see cref="SupportedVersion"/> is accepted when parsing.</summary>
    public byte Version { get; }

    /// <summary>The P bit: the packet ends with padding octets counted by its last byte.</summary>
    public bool HasPadding { get; }

    /// <summary>
    /// The five-bit field after the P bit: reception report count (SR/RR), source count (SDES/BYE), or
    /// feedback message type (RFC 4585 packet types 205 and 206).
    /// </summary>
    public byte Count { get; }

    /// <summary>The RTCP packet type.</summary>
    public RtcpPacketType PacketType { get; }

    /// <summary>The on-the-wire length field: the packet size in 32-bit words, minus one.</summary>
    public ushort LengthInWords { get; }

    /// <summary>Total packet length in bytes, including this header.</summary>
    public int PacketLength => (LengthInWords + 1) * 4;

    /// <summary>Creates a header from a byte length, converting it to the on-the-wire word count.</summary>
    /// <param name="count">Reception report count, source count, or feedback message type.</param>
    /// <param name="packetType">The packet type.</param>
    /// <param name="packetLength">Total packet length in bytes; must be a positive multiple of four.</param>
    /// <returns>The header.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The length is not a positive multiple of four, or is too large.</exception>
    public static RtcpPacketHeader FromByteLength(byte count, RtcpPacketType packetType, int packetLength)
    {
        if (packetLength < Length || packetLength % 4 != 0 || packetLength > (ushort.MaxValue + 1) * 4)
        {
            throw new ArgumentOutOfRangeException(
                nameof(packetLength), packetLength, "An RTCP packet length must be a multiple of four bytes and fit the 16-bit word count.");
        }

        return new RtcpPacketHeader(SupportedVersion, false, count, packetType, (ushort)((packetLength / 4) - 1));
    }

    /// <summary>Parses the common header from the front of <paramref name="buffer"/>.</summary>
    /// <param name="buffer">Buffer positioned at an RTCP packet.</param>
    /// <param name="header">On success, the parsed header.</param>
    /// <returns><see langword="false"/> when fewer than four bytes are available or the version is not 2.</returns>
    public static bool TryParse(ReadOnlySpan<byte> buffer, out RtcpPacketHeader header)
    {
        header = default;
        if (buffer.Length < Length)
        {
            return false;
        }

        var first = buffer[0];
        var version = (byte)(first >> 6);
        if (version != SupportedVersion)
        {
            return false;
        }

        header = new RtcpPacketHeader(
            version,
            (first & 0x20) != 0,
            (byte)(first & 0x1F),
            (RtcpPacketType)buffer[1],
            (ushort)((buffer[2] << 8) | buffer[3]));
        return true;
    }

    /// <summary>Serializes the common header.</summary>
    /// <param name="destination">Buffer of at least <see cref="Length"/> bytes.</param>
    /// <returns>The number of bytes written, always <see cref="Length"/>.</returns>
    /// <exception cref="ByteBufferException">The destination is too small.</exception>
    public int WriteTo(Span<byte> destination)
    {
        var writer = new ByteWriter(destination);
        writer.WriteU8((byte)((Version << 6) | (HasPadding ? 0x20 : 0) | (Count & 0x1F)));
        writer.WriteU8((byte)PacketType);
        writer.WriteU16(LengthInWords);
        return writer.Position;
    }
}
