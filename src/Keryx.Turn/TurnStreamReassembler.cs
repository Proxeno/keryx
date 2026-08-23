using System.Buffers.Binary;
using Keryx.Stun;

namespace Keryx.Turn;

/// <summary>
/// Thrown when the bytes arriving on a TURN TCP/TLS connection cannot be parsed as a STUN or
/// ChannelData message - a framing desync that leaves the stream unusable.
/// </summary>
internal sealed class TurnStreamException(string message) : Exception(message);

/// <summary>
/// Reassembles whole STUN and ChannelData messages out of the byte stream a TURN TCP or TLS
/// connection delivers (RFC 5389 section 7.2.2, RFC 5766 section 2.1). TCP is a stream, not a
/// sequence of datagrams, so a single read can carry a fraction of a message, several messages, or
/// a message split across two reads; this buffers what has arrived and yields one message at a time
/// once its declared length is fully present.
/// </summary>
/// <remarks>
/// <para>
/// A STUN message is told from a ChannelData message by its first byte (RFC 7983): a STUN message
/// type has its two most significant bits zero (0x00-0x3F), while a ChannelData channel number is
/// 0x4000-0x4FFF (first byte 0x40-0x4F). A STUN message is 20 header bytes plus the length its
/// header declares - already a multiple of four because every STUN attribute is padded - and needs
/// no extra framing. A ChannelData message is a four-byte header plus its declared payload length,
/// then padded to a four-byte boundary over TCP (RFC 5766 section 11.5); the padding is not counted
/// in the length field, so the reader consumes the padded size but yields only the unpadded message.
/// </para>
/// <para>
/// This type is not thread-safe: a connection drives it from a single read loop.
/// </para>
/// </remarks>
internal sealed class TurnStreamReassembler
{
    private byte[] _buffer;
    private int _start;
    private int _end;

    public TurnStreamReassembler(int initialCapacity = 2048)
        => _buffer = new byte[Math.Max(initialCapacity, StunMessage.HeaderLength)];

    /// <summary>Appends freshly received bytes to the buffer.</summary>
    public void Append(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return;
        }

        // Reclaim the space already yielded before growing: a long-lived connection would otherwise
        // let the buffer creep upward forever.
        if (_start > 0)
        {
            var remaining = _end - _start;
            if (remaining > 0)
            {
                Array.Copy(_buffer, _start, _buffer, 0, remaining);
            }

            _start = 0;
            _end = remaining;
        }

        var required = _end + data.Length;
        if (required > _buffer.Length)
        {
            var grown = _buffer.Length * 2;
            while (grown < required)
            {
                grown *= 2;
            }

            Array.Resize(ref _buffer, grown);
        }

        data.CopyTo(_buffer.AsSpan(_end));
        _end += data.Length;
    }

    /// <summary>
    /// Yields the next complete message, if one has fully arrived. The returned span is a view into
    /// the internal buffer and is valid only until the next <see cref="Append"/> call.
    /// </summary>
    /// <param name="message">On success, the whole message with any TCP padding trimmed off.</param>
    /// <returns>True when a complete message was available and consumed.</returns>
    /// <exception cref="TurnStreamException">The stream is not framed STUN or ChannelData.</exception>
    public bool TryReadMessage(out ReadOnlySpan<byte> message)
    {
        var available = _buffer.AsSpan(_start, _end - _start);
        if (!TryMeasure(available, out var consumed, out var yield))
        {
            message = default;
            return false;
        }

        message = _buffer.AsSpan(_start, yield);
        _start += consumed;
        return true;
    }

    /// <summary>
    /// Measures the leading message in <paramref name="data"/>: how many bytes it occupies on the
    /// wire (<paramref name="consumed"/>, including ChannelData padding) and how many make up the
    /// message itself (<paramref name="yield"/>). Exposed for direct unit testing of the framing.
    /// </summary>
    /// <returns>False when not enough bytes have arrived yet to know or complete the message.</returns>
    /// <exception cref="TurnStreamException">The leading byte is neither STUN nor ChannelData.</exception>
    public static bool TryMeasure(ReadOnlySpan<byte> data, out int consumed, out int yield)
    {
        consumed = 0;
        yield = 0;
        if (data.Length < 1)
        {
            return false;
        }

        var lead = data[0];
        if ((lead & 0xC0) == 0)
        {
            // STUN: 20-byte header, then the length the header declares (already 4-byte aligned).
            if (data.Length < StunMessage.HeaderLength)
            {
                return false;
            }

            var body = BinaryPrimitives.ReadUInt16BigEndian(data[2..]);
            var total = StunMessage.HeaderLength + body;
            if (data.Length < total)
            {
                return false;
            }

            consumed = total;
            yield = total;
            return true;
        }

        if (lead is >= 0x40 and <= 0x4F)
        {
            // ChannelData: 4-byte header, its declared payload, then padding to a 4-byte boundary.
            if (data.Length < TurnChannelData.HeaderLength)
            {
                return false;
            }

            var payload = BinaryPrimitives.ReadUInt16BigEndian(data[2..]);
            var unpadded = TurnChannelData.HeaderLength + payload;
            var padded = (unpadded + 3) & ~3;
            if (data.Length < padded)
            {
                return false;
            }

            consumed = padded;
            yield = unpadded;
            return true;
        }

        throw new TurnStreamException(
            $"A TURN TCP stream carried a leading byte 0x{lead:X2}, which is neither a STUN message (0x00-0x3F) nor ChannelData (0x40-0x4F).");
    }
}
