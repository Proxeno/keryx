using System.Buffers.Binary;
using Keryx.Core;
using Keryx.Stun;

namespace Keryx.Turn;

/// <summary>
/// The ChannelData message of RFC 8656 section 12.4: a four-byte header (a 16-bit channel number
/// and a 16-bit payload length) followed by the application data.
/// </summary>
/// <remarks>
/// <para>
/// ChannelData is what makes a channel binding worth having. A Send indication wrapping the same
/// payload costs a 20-byte STUN header plus a 12-byte XOR-PEER-ADDRESS plus a 4-byte DATA header -
/// 36 bytes, and a full STUN parse on every packet. ChannelData costs four bytes and a length
/// check.
/// </para>
/// <para>
/// ChannelData carries no magic cookie, so it is told apart from STUN by its first byte. RFC 8656
/// section 12 allocates channel numbers 0x4000-0x4FFF, which puts the first byte in 0x40-0x4F -
/// distinct from STUN (0x00-0x3F, since a STUN message type's two most significant bits are zero),
/// from DTLS records (0x14-0x3F) and from RTP/RTCP (0x80-0xBF), exactly as RFC 7983 requires.
/// </para>
/// </remarks>
public static class TurnChannelData
{
    /// <summary>Length of the ChannelData header in bytes.</summary>
    public const int HeaderLength = 4;

    /// <summary>
    /// True when <paramref name="datagram"/> is shaped like a ChannelData message: at least a
    /// header, a first byte in the 0x40-0x4F range RFC 8656 section 12 allocates, and a length
    /// field that fits in the datagram.
    /// </summary>
    /// <param name="datagram">The datagram to classify.</param>
    public static bool LooksLikeChannelData(ReadOnlySpan<byte> datagram)
    {
        if (datagram.Length < HeaderLength)
        {
            return false;
        }

        var channel = BinaryPrimitives.ReadUInt16BigEndian(datagram);
        if (!StunChannelNumberAttribute.IsValid(channel))
        {
            return false;
        }

        var length = BinaryPrimitives.ReadUInt16BigEndian(datagram[2..]);
        return HeaderLength + length <= datagram.Length;
    }

    /// <summary>
    /// Writes a ChannelData message into <paramref name="destination"/>.
    /// </summary>
    /// <remarks>
    /// No padding is added: RFC 8656 section 12.4 requires four-byte padding only over TCP and
    /// TLS-over-TCP, and Keryx allocations are UDP.
    /// </remarks>
    /// <param name="destination">The buffer to write into.</param>
    /// <param name="channelNumber">The bound channel number; must be in 0x4000-0x4FFF.</param>
    /// <param name="payload">The application data.</param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="ByteBufferException"><paramref name="destination"/> is too small.</exception>
    public static int Encode(Span<byte> destination, ushort channelNumber, ReadOnlySpan<byte> payload)
    {
        if (!StunChannelNumberAttribute.IsValid(channelNumber))
        {
            throw new ArgumentOutOfRangeException(
                nameof(channelNumber), channelNumber, "RFC 8656 section 12 only allows channel numbers 0x4000-0x4FFF.");
        }

        if (payload.Length > ushort.MaxValue)
        {
            throw new ArgumentException("A ChannelData payload may be at most 65535 bytes.", nameof(payload));
        }

        var writer = new ByteWriter(destination);
        writer.WriteU16(channelNumber);
        writer.WriteU16((ushort)payload.Length);
        writer.WriteBytes(payload);
        return writer.Position;
    }

    /// <summary>
    /// Reads a ChannelData message.
    /// </summary>
    /// <param name="datagram">The received bytes; trailing padding is ignored.</param>
    /// <param name="channelNumber">The channel number on success.</param>
    /// <param name="payload">The application data on success, as a slice of <paramref name="datagram"/>.</param>
    /// <returns>True when <paramref name="datagram"/> held a well-formed ChannelData message.</returns>
    public static bool TryDecode(ReadOnlySpan<byte> datagram, out ushort channelNumber, out ReadOnlySpan<byte> payload)
    {
        if (!LooksLikeChannelData(datagram))
        {
            channelNumber = 0;
            payload = default;
            return false;
        }

        channelNumber = BinaryPrimitives.ReadUInt16BigEndian(datagram);
        var length = BinaryPrimitives.ReadUInt16BigEndian(datagram[2..]);
        payload = datagram.Slice(HeaderLength, length);
        return true;
    }
}
