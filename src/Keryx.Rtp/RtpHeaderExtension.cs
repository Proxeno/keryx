namespace Keryx.Rtp;

/// <summary>Well-known RTP header-extension profile identifiers (RFC 8285 §4).</summary>
public static class RtpHeaderExtension
{
    /// <summary>Profile <c>0xBEDE</c>: one-byte-header extension elements (RFC 8285 §4.2).</summary>
    public const ushort OneByteProfile = 0xBEDE;

    /// <summary>
    /// Profile <c>0x1000</c>: two-byte-header extension elements (RFC 8285 §4.3). The low four bits are
    /// an "appbits" nibble the sender and receiver may negotiate freely, so a wire value must be matched
    /// with the low nibble masked off (see <see cref="IsTwoByteProfile"/>) rather than by exact equality.
    /// </summary>
    public const ushort TwoByteProfile = 0x1000;

    /// <summary>Mask isolating the fixed bits of <see cref="TwoByteProfile"/>, excluding the appbits nibble.</summary>
    private const ushort TwoByteProfileMask = 0xFFF0;

    /// <summary>Element identifier reserved for padding in both the one-byte and two-byte forms (RFC 8285 §4.2, §4.3).</summary>
    public const byte PaddingId = 0;

    /// <summary>Element identifier reserved to signal "stop parsing" in the one-byte form (RFC 8285 §4.2).</summary>
    public const byte ReservedForFutureId = 15;

    /// <summary>Largest body length, in bytes, an RFC 8285 one-byte-header element can carry.</summary>
    public const int MaxOneByteElementLength = 16;

    /// <summary>Largest body length, in bytes, an RFC 8285 two-byte-header element can carry.</summary>
    public const int MaxTwoByteElementLength = 255;

    /// <summary>Largest element identifier the one-byte form can carry (RFC 8285 §4.2 reserves 15).</summary>
    public const byte MaxOneByteElementId = 14;

    /// <summary>
    /// True when <paramref name="profile"/> is the RFC 8285 §4.3 two-byte-header profile, once the
    /// appbits nibble is masked off.
    /// </summary>
    /// <param name="profile">A wire-format <c>ExtensionProfile</c> value.</param>
    public static bool IsTwoByteProfile(ushort profile) => (profile & TwoByteProfileMask) == TwoByteProfile;

    /// <summary>
    /// True when an element with the given identifier and body length cannot be represented by the RFC
    /// 8285 §4.2 one-byte form and therefore requires the two-byte form (§4.3): the identifier exceeds
    /// <see cref="MaxOneByteElementId"/>, the body exceeds <see cref="MaxOneByteElementLength"/> bytes, or
    /// the body is empty (the one-byte length nibble encodes length-minus-one and so cannot express zero).
    /// </summary>
    /// <param name="id">The element identifier.</param>
    /// <param name="dataLength">The element body length in bytes.</param>
    public static bool RequiresTwoByteProfile(byte id, int dataLength) =>
        id > MaxOneByteElementId || dataLength is 0 or > MaxOneByteElementLength;
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
/// Allocation-free forward enumerator over RFC 8285 §4.3 two-byte-header extension elements.
/// </summary>
/// <remarks>
/// Each element is a one-byte identifier followed by a one-byte length (which may be zero), then that
/// many octets of body. Padding elements (identifier 0) are skipped. Unlike the one-byte form, no
/// identifier is reserved to signal "stop parsing" — the two-byte form allows the full 1–255 identifier
/// range. Enumeration still stops, per the "ignore the remainder" robustness rule of RFC 8285, at any
/// element whose declared length runs past the end of the extension body.
/// </remarks>
public ref struct RtpTwoByteExtensionEnumerator
{
    private readonly ReadOnlySpan<byte> _data;
    private int _position;
    private RtpExtensionElement _current;

    /// <summary>Creates an enumerator over an extension body (excluding the profile/length prefix).</summary>
    /// <param name="extensionData">The header-extension body.</param>
    public RtpTwoByteExtensionEnumerator(ReadOnlySpan<byte> extensionData)
    {
        _data = extensionData;
        _position = 0;
        _current = default;
    }

    /// <summary>The element produced by the last successful <see cref="MoveNext"/>.</summary>
    public readonly RtpExtensionElement Current => _current;

    /// <summary>Returns this enumerator so it can be used directly in <see langword="foreach"/>.</summary>
    /// <returns>A copy of this enumerator.</returns>
    public readonly RtpTwoByteExtensionEnumerator GetEnumerator() => this;

    /// <summary>Advances to the next element.</summary>
    /// <returns><see langword="false"/> when the body is exhausted or a stop condition is reached.</returns>
    public bool MoveNext()
    {
        while (_position < _data.Length)
        {
            var id = _data[_position];
            if (id == RtpHeaderExtension.PaddingId)
            {
                _position++;
                continue;
            }

            if (_position + 2 > _data.Length)
            {
                _position = _data.Length;
                return false;
            }

            var length = _data[_position + 1];
            if (_position + 2 + length > _data.Length)
            {
                _position = _data.Length;
                return false;
            }

            _current = new RtpExtensionElement(id, _data.Slice(_position + 2, length));
            _position += 2 + length;
            return true;
        }

        return false;
    }
}

/// <summary>
/// Allocation-free enumerator over an RTP header's extension elements, dispatching to the RFC 8285
/// one-byte or two-byte form according to the wire-format profile. This is the type
/// <see cref="RtpHeader.GetExtensionElements"/> returns; use <see cref="RtpOneByteExtensionEnumerator"/>
/// or <see cref="RtpTwoByteExtensionEnumerator"/> directly only when the profile is already known.
/// </summary>
public ref struct RtpExtensionElementEnumerator
{
    private readonly bool _isTwoByte;
    private RtpOneByteExtensionEnumerator _oneByte;
    private RtpTwoByteExtensionEnumerator _twoByte;

    /// <summary>Creates an enumerator over an extension body for the given wire-format profile.</summary>
    /// <param name="extensionData">The header-extension body.</param>
    /// <param name="isTwoByte">
    /// <see langword="true"/> to parse <paramref name="extensionData"/> as the two-byte form; otherwise
    /// the one-byte form.
    /// </param>
    public RtpExtensionElementEnumerator(ReadOnlySpan<byte> extensionData, bool isTwoByte)
    {
        _isTwoByte = isTwoByte;
        _oneByte = isTwoByte ? default : new RtpOneByteExtensionEnumerator(extensionData);
        _twoByte = isTwoByte ? new RtpTwoByteExtensionEnumerator(extensionData) : default;
    }

    /// <summary>The element produced by the last successful <see cref="MoveNext"/>.</summary>
    public readonly RtpExtensionElement Current => _isTwoByte ? _twoByte.Current : _oneByte.Current;

    /// <summary>Returns this enumerator so it can be used directly in <see langword="foreach"/>.</summary>
    /// <returns>A copy of this enumerator.</returns>
    public readonly RtpExtensionElementEnumerator GetEnumerator() => this;

    /// <summary>Advances to the next element.</summary>
    /// <returns><see langword="false"/> when the body is exhausted or a stop condition is reached.</returns>
    public bool MoveNext() => _isTwoByte ? _twoByte.MoveNext() : _oneByte.MoveNext();
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

/// <summary>
/// Builds an RFC 8285 §4.3 two-byte-header extension body into a caller-supplied buffer.
/// </summary>
/// <remarks>
/// The writer emits only the extension body; the <see cref="RtpHeaderExtension.TwoByteProfile"/> profile
/// word and the word count are written by <see cref="RtpHeader.WriteTo"/>. Call <see cref="Finish"/> to
/// pad the body out to a four-byte boundary before assigning <see cref="Written"/> to
/// <see cref="RtpHeader.ExtensionData"/>. Use <see cref="RtpHeaderExtension.RequiresTwoByteProfile"/> to
/// decide, for a given set of elements, whether this writer or <see cref="RtpOneByteExtensionWriter"/> is
/// needed: the one-byte form is preferred whenever every element fits it, since it is more compact.
/// </remarks>
public ref struct RtpTwoByteExtensionWriter
{
    private readonly Span<byte> _buffer;
    private int _position;

    /// <summary>Creates a writer over <paramref name="destination"/>.</summary>
    /// <param name="destination">Scratch buffer that will hold the extension body.</param>
    public RtpTwoByteExtensionWriter(Span<byte> destination)
    {
        _buffer = destination;
        _position = 0;
    }

    /// <summary>The extension body written so far.</summary>
    public readonly ReadOnlySpan<byte> Written => _buffer[.._position];

    /// <summary>Appends one extension element.</summary>
    /// <param name="id">Element identifier; must be 1–255.</param>
    /// <param name="data">Element body; must be 0–255 bytes.</param>
    /// <returns><see langword="false"/> when the destination buffer has no room left.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The identifier or body length is out of range.</exception>
    public bool TryAppend(byte id, ReadOnlySpan<byte> data)
    {
        if (id == RtpHeaderExtension.PaddingId)
        {
            throw new ArgumentOutOfRangeException(nameof(id), id, "Two-byte-header element identifiers are 1–255.");
        }

        if (data.Length > RtpHeaderExtension.MaxTwoByteElementLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(data), data.Length, "Two-byte-header element bodies are 0–255 bytes.");
        }

        if (_buffer.Length - _position < 2 + data.Length)
        {
            return false;
        }

        _buffer[_position++] = id;
        _buffer[_position++] = (byte)data.Length;
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
