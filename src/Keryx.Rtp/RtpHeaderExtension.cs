namespace Keryx.Rtp;

/// <summary>Well-known RTP header-extension profile identifiers (RFC 8285 §4).</summary>
public static class RtpHeaderExtension
{
    /// <summary>Profile <c>0xBEDE</c>: one-byte-header extension elements (RFC 8285 §4.2).</summary>
    public const ushort OneByteProfile = 0xBEDE;

    /// <summary>
    /// Profile <c>0x1000</c> (with the low four bits of the appbits nibble masked off): two-byte-header
    /// extension elements (RFC 8285 §4.3). Keryx recognises the value but does not yet parse this form.
    /// </summary>
    public const ushort TwoByteProfile = 0x1000;

    /// <summary>Element identifier reserved for padding in the one-byte form (RFC 8285 §4.2).</summary>
    public const byte PaddingId = 0;

    /// <summary>Element identifier reserved to signal "stop parsing" in the one-byte form (RFC 8285 §4.2).</summary>
    public const byte ReservedForFutureId = 15;

    /// <summary>Largest body length, in bytes, an RFC 8285 one-byte-header element can carry.</summary>
    public const int MaxOneByteElementLength = 16;
}

/// <summary>One RFC 8285 header-extension element: a small negotiated identifier and its body.</summary>
public readonly ref struct RtpExtensionElement
{
    /// <summary>Creates an element.</summary>
    /// <param name="id">Element identifier negotiated through <c>a=extmap</c>.</param>
    /// <param name="data">Element body; aliases the packet buffer.</param>
    public RtpExtensionElement(byte id, ReadOnlySpan<byte> data)
    {
        Id = id;
        Data = data;
    }

    /// <summary>The element identifier (1–14 for the one-byte form).</summary>
    public byte Id { get; }

    /// <summary>The element body, 1–16 bytes for the one-byte form.</summary>
    public ReadOnlySpan<byte> Data { get; }
}

/// <summary>
/// Allocation-free forward enumerator over RFC 8285 §4.2 one-byte-header extension elements.
/// </summary>
/// <remarks>
/// Padding elements (identifier 0) are skipped, and enumeration stops at identifier 15 or at any
/// element whose declared length runs past the end of the extension body, matching the "ignore the
/// remainder" robustness rule of RFC 8285 §4.2.
/// </remarks>
public ref struct RtpOneByteExtensionEnumerator
{
    private readonly ReadOnlySpan<byte> _data;
    private int _position;
    private RtpExtensionElement _current;

    /// <summary>Creates an enumerator over an extension body (excluding the profile/length prefix).</summary>
    /// <param name="extensionData">The header-extension body.</param>
    public RtpOneByteExtensionEnumerator(ReadOnlySpan<byte> extensionData)
    {
        _data = extensionData;
        _position = 0;
        _current = default;
    }

    /// <summary>The element produced by the last successful <see cref="MoveNext"/>.</summary>
    public readonly RtpExtensionElement Current => _current;

    /// <summary>Returns this enumerator so it can be used directly in <see langword="foreach"/>.</summary>
    /// <returns>A copy of this enumerator.</returns>
    public readonly RtpOneByteExtensionEnumerator GetEnumerator() => this;

    /// <summary>Advances to the next element.</summary>
    /// <returns><see langword="false"/> when the body is exhausted or a stop condition is reached.</returns>
    public bool MoveNext()
    {
        while (_position < _data.Length)
        {
            var header = _data[_position];
            if (header == 0)
            {
                _position++;
                continue;
            }

            var id = (byte)(header >> 4);
            if (id == RtpHeaderExtension.ReservedForFutureId)
            {
                _position = _data.Length;
                return false;
            }

            var length = (header & 0x0F) + 1;
            if (_position + 1 + length > _data.Length)
            {
                _position = _data.Length;
                return false;
            }

            _current = new RtpExtensionElement(id, _data.Slice(_position + 1, length));
            _position += 1 + length;
            return true;
        }

        return false;
    }
}

/// <summary>
/// Builds an RFC 8285 §4.2 one-byte-header extension body into a caller-supplied buffer.
/// </summary>
/// <remarks>
/// The writer emits only the extension body; the <c>0xBEDE</c> profile word and the word count are
/// written by <see cref="RtpHeader.WriteTo"/>. Call <see cref="Finish"/> to pad the body out to a
/// four-byte boundary before assigning <see cref="Written"/> to <see cref="RtpHeader.ExtensionData"/>.
/// </remarks>
public ref struct RtpOneByteExtensionWriter
{
    private readonly Span<byte> _buffer;
    private int _position;

    /// <summary>Creates a writer over <paramref name="destination"/>.</summary>
    /// <param name="destination">Scratch buffer that will hold the extension body.</param>
    public RtpOneByteExtensionWriter(Span<byte> destination)
    {
        _buffer = destination;
        _position = 0;
    }

    /// <summary>The extension body written so far.</summary>
    public readonly ReadOnlySpan<byte> Written => _buffer[.._position];

    /// <summary>Appends one extension element.</summary>
    /// <param name="id">Element identifier; must be 1–14.</param>
    /// <param name="data">Element body; must be 1–16 bytes.</param>
    /// <returns><see langword="false"/> when the destination buffer has no room left.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The identifier or body length is out of range.</exception>
    public bool TryAppend(byte id, ReadOnlySpan<byte> data)
    {
        if (id is < 1 or > 14)
        {
            throw new ArgumentOutOfRangeException(nameof(id), id, "One-byte-header element identifiers are 1–14.");
        }

        if (data.Length is < 1 or > RtpHeaderExtension.MaxOneByteElementLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(data), data.Length, "One-byte-header element bodies are 1–16 bytes.");
        }

        if (_buffer.Length - _position < 1 + data.Length)
        {
            return false;
        }

        _buffer[_position++] = (byte)((id << 4) | (data.Length - 1));
        data.CopyTo(_buffer[_position..]);
        _position += data.Length;
        return true;
    }

    /// <summary>
    /// Pads the body with zero bytes up to the next four-byte boundary, as required by RFC 3550 §5.3.1.
    /// </summary>
    /// <returns>The final body length in bytes, always a multiple of four.</returns>
    /// <exception cref="InvalidOperationException">The destination buffer cannot hold the padding.</exception>
    public int Finish()
    {
        var padding = (4 - (_position % 4)) % 4;
        if (padding == 0)
        {
            return _position;
        }

        if (_buffer.Length - _position < padding)
        {
            throw new InvalidOperationException("The extension buffer cannot hold the four-byte alignment padding.");
        }

        _buffer.Slice(_position, padding).Clear();
        _position += padding;
        return _position;
    }
}
