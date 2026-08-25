using Keryx.Core;

namespace Keryx.Rtp.Packetization;

/// <summary>
/// Reassembles "RTP Payload Format For AV1" payloads back into a complete AV1 temporal unit.
/// </summary>
/// <remarks>
/// <para>
/// This is the inverse of <see cref="Av1Packetizer"/> and exists so loopback tests can assert that what
/// a remote decoder would reconstruct is byte-identical to what the encoder produced. It is also usable
/// as a receive-side depacketizer for well-ordered input.
/// </para>
/// <para>
/// The depacketizer assumes payloads arrive in order and without loss; a <see cref="JitterBuffer"/>
/// belongs in front of it. It parses the aggregation header's Z/Y/W/N bits, both the implicit
/// (<c>W = 0</c>, every element LEB128-length-prefixed) and explicit (<c>W = 1..3</c>, the last element
/// running to the end of the packet) element layouts, and reassembles OBU elements that a sender split
/// across packets. Each reassembled OBU is re-emitted with its <c>obu_has_size_field</c> set and a
/// canonical LEB128 size restored, so the reconstructed temporal unit is a valid low-overhead bitstream.
/// Malformed payloads are logged and dropped.
/// </para>
/// <para>
/// A temporal unit is delimited by the marker bit; call <see cref="BeginNextFrame"/> after consuming a
/// completed unit (the depacketizer also self-heals, discarding a completed unit the moment the next
/// payload arrives). <b>Thread safety: single-writer.</b>
/// </para>
/// </remarks>
public sealed class Av1Depacketizer
{
    /// <summary>
    /// Default upper bound on the size, in bytes, of a single temporal unit under reassembly. A remote
    /// peer that withholds the marker bit (or spoofs OBU-element sizes) would otherwise drive
    /// <see cref="EnsureCapacity"/> to double the reassembly buffer without limit. 8 MiB is far larger
    /// than any real AV1 temporal unit carried over RTP while still bounding memory.
    /// </summary>
    public const int DefaultMaxFrameSize = 8 * 1024 * 1024;

    // Aggregation header bit masks (RTP Payload Format For AV1 §4): Z|Y|W(2)|N|-|-|-.
    private const byte ContinuesPrevious = 0x80; // Z
    private const byte ContinuesNext = 0x40; // Y
    private const byte ObuCountShift = 4; // W occupies bits 4..5
    private const byte ObuCountMask = 0x03;

    private const byte ObuTypeMask = 0x78; // bits 3..6 of the OBU header
    private const byte ObuExtensionFlag = 0x04;
    private const byte ObuHasSizeField = 0x02;

    private readonly IKeryxLogger _logger;
    private readonly int _maxFrameSize;
    private byte[] _buffer;
    private int _length;
    private byte[] _partial;
    private int _partialLength;
    private bool _keyFrame;
    private bool _frameComplete;

    /// <summary>Creates a depacketizer.</summary>
    /// <param name="initialCapacity">Initial size of the reassembly buffer in bytes.</param>
    /// <param name="maxFrameSize">
    /// Upper bound on the size, in bytes, of a single temporal unit under reassembly. Once reached, the
    /// in-progress unit is discarded and further payloads for it are dropped rather than growing the
    /// buffer further; see <see cref="DefaultMaxFrameSize"/>.
    /// </param>
    /// <param name="logger">Optional logger; malformed payloads are reported at warning level.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="initialCapacity"/> is not positive, or <paramref name="maxFrameSize"/> is
    /// smaller than <paramref name="initialCapacity"/>.
    /// </exception>
    public Av1Depacketizer(
        int initialCapacity = 64 * 1024,
        int maxFrameSize = DefaultMaxFrameSize,
        IKeryxLogger? logger = null)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(initialCapacity);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxFrameSize, initialCapacity);
        _buffer = new byte[initialCapacity];
        _partial = new byte[Math.Min(initialCapacity, 64 * 1024)];
        _maxFrameSize = maxFrameSize;
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>The bytes accumulated for the temporal unit currently being reassembled.</summary>
    public ReadOnlySpan<byte> Frame => _buffer.AsSpan(0, _length);

    /// <summary>
    /// <see langword="true"/> when the temporal unit currently being (or most recently) reassembled
    /// carried a sequence-header OBU, which marks a key frame (RTP Payload Format For AV1 §5).
    /// </summary>
    public bool IsKeyFrame => _keyFrame;

    /// <summary>Discards any partially reassembled temporal unit.</summary>
    public void Reset()
    {
        _length = 0;
        _partialLength = 0;
        _keyFrame = false;
        _frameComplete = false;
    }

    /// <summary>
    /// Clears the reassembly buffer so the next <see cref="TryAddPayload"/> starts a new temporal unit.
    /// Call this after consuming the span returned by <see cref="TryAddPayload"/>.
    /// </summary>
    public void BeginNextFrame() => Reset();

    /// <summary>
    /// Adds one RTP payload to the temporal unit under reassembly.
    /// </summary>
    /// <param name="payload">The RTP payload, without the RTP header.</param>
    /// <param name="marker">The packet's marker bit; it terminates the temporal unit.</param>
    /// <param name="frame">
    /// When the return value is <see langword="true"/>, the complete temporal unit. The span is valid
    /// until the next call.
    /// </param>
    /// <returns><see langword="true"/> when <paramref name="marker"/> completed a temporal unit.</returns>
    public bool TryAddPayload(ReadOnlySpan<byte> payload, bool marker, out ReadOnlySpan<byte> frame)
    {
        frame = default;

        // Self-heal: a completed unit's bytes stay valid until the next payload arrives, at which point
        // a fresh unit begins even if the caller never called BeginNextFrame.
        if (_frameComplete)
        {
            Reset();
        }

        if (payload.Length < 1)
        {
            Warn("Dropping an empty AV1 RTP payload.");
            return false;
        }

        var header = payload[0];
        var continuesPrevious = (header & ContinuesPrevious) != 0;
        var continuesNext = (header & ContinuesNext) != 0;
        var obuCount = (header >> ObuCountShift) & ObuCountMask;

        var body = payload[1..];
        var position = 0;
        var indexInPacket = 0;

        while (position < body.Length)
        {
            if (!TryReadElement(body, obuCount, indexInPacket, ref position, out var element, out var lastInPacket))
            {
                _partialLength = 0;
                return false;
            }

            var firstInPacket = indexInPacket == 0;
            if (firstInPacket && continuesPrevious)
            {
                if (_partialLength == 0)
                {
                    Warn("Dropping an AV1 continuation payload with no pending OBU element.");
                    return false;
                }
            }
            else
            {
                // A fresh OBU element begins; drop any stale fragment a lost marker may have left.
                _partialLength = 0;
            }

            if (!AppendPartial(element))
            {
                DropFrameTooLarge();
                return false;
            }

            var elementContinues = lastInPacket && continuesNext;
            if (!elementContinues && !FinalizeElement())
            {
                return false;
            }

            indexInPacket++;
            if (obuCount != 0 && indexInPacket == obuCount)
            {
                break;
            }
        }

        if (!marker)
        {
            return false;
        }

        if (_partialLength != 0)
        {
            // The marker ended the unit while an OBU element was still open — malformed; drop the tail.
            Warn("Dropping a dangling AV1 OBU fragment left open by the marker packet.");
            _partialLength = 0;
        }

        _frameComplete = true;
        frame = _buffer.AsSpan(0, _length);
        return true;
    }

    /// <summary>
    /// Slices the next OBU element out of <paramref name="body"/>, honouring the <c>W = 0</c> (every
    /// element length-prefixed) and <c>W &gt; 0</c> (last element unprefixed) layouts.
    /// </summary>
    private bool TryReadElement(
        ReadOnlySpan<byte> body,
        int obuCount,
        int indexInPacket,
        ref int position,
        out ReadOnlySpan<byte> element,
        out bool lastInPacket)
    {
        element = default;
        lastInPacket = false;

        var unprefixed = obuCount != 0 && indexInPacket == obuCount - 1;
        if (unprefixed)
        {
            // The final element of a W>0 packet runs to the end of the payload.
            element = body[position..];
            position = body.Length;
            lastInPacket = true;
            return element.Length != 0;
        }

        if (!Leb128.TryRead(body[position..], out var length, out var lengthBytes))
        {
            Warn("Dropping an AV1 payload with a truncated OBU-element length.");
            return false;
        }

        position += lengthBytes;
        if (length == 0 || position + length > body.Length)
        {
            Warn("Dropping an AV1 payload whose OBU element runs past the payload.");
            return false;
        }

        element = body.Slice(position, (int)length);
        position += (int)length;
        lastInPacket = obuCount == 0 ? position == body.Length : false;
        return true;
    }

    private bool AppendPartial(ReadOnlySpan<byte> element)
    {
        var required = (long)_partialLength + element.Length;
        if (required > _maxFrameSize)
        {
            return false;
        }

        if (_partial.Length < required)
        {
            long capacity = _partial.Length;
            while (capacity < required)
            {
                capacity *= 2;
            }

            Array.Resize(ref _partial, (int)Math.Min(capacity, _maxFrameSize));
        }

        element.CopyTo(_partial.AsSpan(_partialLength));
        _partialLength += element.Length;
        return true;
    }

    /// <summary>
    /// Restores the accumulated OBU element's size field and appends the reconstructed OBU to the
    /// temporal unit under reassembly.
    /// </summary>
    private bool FinalizeElement()
    {
        var element = _partial.AsSpan(0, _partialLength);
        _partialLength = 0;

        if (element.Length < 1)
        {
            Warn("Dropping an empty AV1 OBU element.");
            return false;
        }

        var header = element[0];
        var headerLength = (header & ObuExtensionFlag) != 0 ? 2 : 1;
        if (element.Length < headerLength)
        {
            Warn("Dropping an AV1 OBU element with a truncated header.");
            return false;
        }

        var payloadLength = element.Length - headerLength;
        if (((header & ObuTypeMask) >> 3) == Av1ObuType.SequenceHeader)
        {
            _keyFrame = true;
        }

        var sizeLength = Leb128.Size((uint)payloadLength);
        var total = (long)headerLength + sizeLength + payloadLength;
        if (!EnsureCapacity(_length + total))
        {
            DropFrameTooLarge();
            return false;
        }

        _buffer[_length++] = (byte)(header | ObuHasSizeField);
        for (var i = 1; i < headerLength; i++)
        {
            _buffer[_length++] = element[i];
        }

        _length += Leb128.Write(_buffer.AsSpan(_length), (uint)payloadLength);
        element[headerLength..].CopyTo(_buffer.AsSpan(_length));
        _length += payloadLength;
        return true;
    }

    private bool EnsureCapacity(long required)
    {
        if (required > _maxFrameSize)
        {
            return false;
        }

        if (_buffer.Length >= required)
        {
            return true;
        }

        long capacity = _buffer.Length;
        while (capacity < required)
        {
            capacity *= 2;
        }

        capacity = Math.Min(capacity, _maxFrameSize);
        Array.Resize(ref _buffer, (int)capacity);
        return true;
    }

    private void DropFrameTooLarge()
    {
        Debug($"Dropping an in-progress AV1 temporal unit that exceeded the {_maxFrameSize}-byte cap.");
        _length = 0;
        _partialLength = 0;
        _keyFrame = false;
    }

    private void Warn(string message)
    {
        if (_logger.IsEnabled(KeryxLogLevel.Warning))
        {
            _logger.Log(KeryxLogLevel.Warning, message);
        }
    }

    private void Debug(string message)
    {
        if (_logger.IsEnabled(KeryxLogLevel.Debug))
        {
            _logger.Log(KeryxLogLevel.Debug, message);
        }
    }
}
