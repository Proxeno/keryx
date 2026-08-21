namespace Keryx.Rtp.Rtcp;

/// <summary>One packet inside a compound RTCP buffer: its common header and the bytes it occupies.</summary>
public readonly ref struct RtcpPacketView
{
    /// <summary>Creates a view.</summary>
    /// <param name="header">The parsed common header.</param>
    /// <param name="packet">The whole packet, including the common header.</param>
    public RtcpPacketView(RtcpPacketHeader header, ReadOnlySpan<byte> packet)
    {
        Header = header;
        Packet = packet;
    }

    /// <summary>The common header (RFC 3550 §6.1).</summary>
    public RtcpPacketHeader Header { get; }

    /// <summary>The complete packet, header included.</summary>
    public ReadOnlySpan<byte> Packet { get; }

    /// <summary>The packet body: everything after the four-byte common header.</summary>
    public ReadOnlySpan<byte> Body => Packet[RtcpPacketHeader.Length..];
}

/// <summary>
/// Walks the individual packets of a compound RTCP buffer (RFC 3550 §6.1) using each packet's length
/// field, without allocating and without interpreting packet types.
/// </summary>
/// <remarks>
/// Unknown packet types are yielded like any other, so a caller can simply ignore the ones it does not
/// handle — the reader has already skipped over them correctly. Enumeration stops at the first packet
/// that is truncated, has the wrong version, or declares a length running past the end of the buffer;
/// <see cref="IsMalformed"/> then reports that the remainder was discarded.
/// </remarks>
public ref struct RtcpCompoundReader
{
    private readonly ReadOnlySpan<byte> _buffer;
    private int _position;
    private RtcpPacketView _current;
    private bool _malformed;

    /// <summary>Creates a reader over a decrypted compound RTCP buffer.</summary>
    /// <param name="compound">The compound packet.</param>
    public RtcpCompoundReader(ReadOnlySpan<byte> compound)
    {
        _buffer = compound;
        _position = 0;
        _current = default;
        _malformed = false;
    }

    /// <summary>The packet produced by the last successful <see cref="MoveNext"/>.</summary>
    public readonly RtcpPacketView Current => _current;

    /// <summary>
    /// True when enumeration stopped early because a sub-packet was truncated or declared an
    /// impossible length. Any packets already yielded remain valid.
    /// </summary>
    public readonly bool IsMalformed => _malformed;

    /// <summary>Number of bytes not yet consumed.</summary>
    public readonly int Remaining => _buffer.Length - _position;

    /// <summary>Returns this reader so it can be used directly in <see langword="foreach"/>.</summary>
    /// <returns>A copy of this reader.</returns>
    public readonly RtcpCompoundReader GetEnumerator() => this;

    /// <summary>Advances to the next packet in the compound buffer.</summary>
    /// <returns><see langword="false"/> at the end of the buffer or at the first malformed packet.</returns>
    public bool MoveNext()
    {
        if (_position >= _buffer.Length)
        {
            return false;
        }

        var remaining = _buffer[_position..];
        if (!RtcpPacketHeader.TryParse(remaining, out var header))
        {
            _malformed = true;
            _position = _buffer.Length;
            return false;
        }

        var length = header.PacketLength;
        if (length > remaining.Length)
        {
            _malformed = true;
            _position = _buffer.Length;
            return false;
        }

        _current = new RtcpPacketView(header, remaining[..length]);
        _position += length;
        return true;
    }
}
