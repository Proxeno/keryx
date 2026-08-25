using Keryx.Core;

namespace Keryx.Rtp.Packetization;

/// <summary>
/// Reassembles RFC 7741 VP8 RTP payloads back into complete encoded frames.
/// </summary>
/// <remarks>
/// <para>
/// This is the inverse of <see cref="Vp8Packetizer"/> and exists so loopback tests can assert that
/// what a remote decoder would reconstruct is byte-identical to what the encoder produced. It is also
/// usable as a receive-side depacketizer for well-ordered input.
/// </para>
/// <para>
/// The depacketizer assumes payloads arrive in order and without loss; a <see cref="JitterBuffer"/>
/// belongs in front of it. It parses the full payload descriptor — including the optional extended
/// control bits octet, the 7-bit and 15-bit (M-bit) forms of the picture ID, TL0PICIDX and the shared
/// TID/KEYIDX octet — so it can skip whatever a remote encoder sends, even though
/// <see cref="Vp8Packetizer"/> only ever emits the 15-bit picture ID form itself. Malformed payloads
/// are logged and dropped.
/// </para>
/// <para><b>Thread safety: single-writer</b>, like the rest of the per-stream state in this layer.</para>
/// </remarks>
public sealed class Vp8Depacketizer
{
    /// <summary>
    /// Default upper bound on the size, in bytes, of a single frame under reassembly. A remote peer
    /// that withholds the marker bit (or spoofs fragment sizes) would otherwise drive
    /// <see cref="EnsureCapacity"/> to double the reassembly buffer without limit. 8 MiB is far larger
    /// than any real VP8 keyframe carried over RTP while still bounding memory.
    /// </summary>
    public const int DefaultMaxFrameSize = 8 * 1024 * 1024;

    private readonly IKeryxLogger _logger;
    private readonly int _maxFrameSize;
    private byte[] _buffer;
    private int _length;
    private bool _haveStart;
    private bool _keyFrame;

    /// <summary>Creates a depacketizer.</summary>
    /// <param name="initialCapacity">Initial size of the reassembly buffer in bytes.</param>
    /// <param name="maxFrameSize">
    /// Upper bound on the size, in bytes, of a single frame under reassembly. Once reached, the
    /// in-progress frame is discarded and further payloads for it are dropped rather than growing the
    /// buffer further; see <see cref="DefaultMaxFrameSize"/>.
    /// </param>
    /// <param name="logger">Optional logger; malformed payloads are reported at warning level.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="initialCapacity"/> is not positive, or <paramref name="maxFrameSize"/> is
    /// smaller than <paramref name="initialCapacity"/>.
    /// </exception>
    public Vp8Depacketizer(
        int initialCapacity = 64 * 1024,
        int maxFrameSize = DefaultMaxFrameSize,
        IKeryxLogger? logger = null)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(initialCapacity);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxFrameSize, initialCapacity);
        _buffer = new byte[initialCapacity];
        _maxFrameSize = maxFrameSize;
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>The bytes accumulated for the frame currently being reassembled.</summary>
    public ReadOnlySpan<byte> Frame => _buffer.AsSpan(0, _length);

    /// <summary>
    /// <see langword="true"/> when the frame currently being (or most recently) reassembled started
    /// with a VP8 key frame, determined from the payload header's key-frame bit on the packet that
    /// carried partition 0's start (RFC 6386 §9.1, RFC 7741 §4.3).
    /// </summary>
    public bool IsKeyFrame => _keyFrame;

    /// <summary>Discards any partially reassembled frame.</summary>
    public void Reset()
    {
        _length = 0;
        _haveStart = false;
        _keyFrame = false;
    }

    /// <summary>
    /// Adds one RTP payload to the frame under reassembly.
    /// </summary>
    /// <param name="payload">The RTP payload, without the RTP header.</param>
    /// <param name="marker">The packet's marker bit; it terminates the frame (RFC 7741 §4.2).</param>
    /// <param name="frame">
    /// When the return value is <see langword="true"/>, the complete VP8 frame. The span is valid
    /// until the next call.
    /// </param>
    /// <returns><see langword="true"/> when <paramref name="marker"/> completed a frame.</returns>
    public bool TryAddPayload(ReadOnlySpan<byte> payload, bool marker, out ReadOnlySpan<byte> frame)
    {
        frame = default;

        if (!TryParseDescriptor(payload, out var start, out var partitionIndex, out var body))
        {
            return false;
        }

        if (start)
        {
            if (body.IsEmpty)
            {
                Warn("Dropping a VP8 payload that starts a partition but carries no data.");
                return false;
            }

            // A start bit always begins a fresh frame in this packetizer's scheme (the whole frame is
            // partition 0; see Vp8Packetizer's remarks). Reset unconditionally rather than requiring the
            // caller to have called BeginNextFrame — that keeps reassembly self-healing after a lost
            // marker, the same failure mode the size cap below guards against.
            _length = 0;
            _keyFrame = partitionIndex == 0 && (body[0] & 0x01) == 0;
            _haveStart = true;

            if (!EnsureCapacity(body.Length))
            {
                DropFrameTooLarge();
                return false;
            }

            body.CopyTo(_buffer.AsSpan(_length));
            _length += body.Length;
        }
        else
        {
            if (!_haveStart)
            {
                Warn("Dropping a VP8 continuation payload with no preceding start payload.");
                return false;
            }

            if (!EnsureCapacity((long)_length + body.Length))
            {
                DropFrameTooLarge();
                return false;
            }

            body.CopyTo(_buffer.AsSpan(_length));
            _length += body.Length;
        }

        if (!marker)
        {
            return false;
        }

        frame = _buffer.AsSpan(0, _length);
        return true;
    }

    /// <summary>
    /// Clears the reassembly buffer so the next <see cref="TryAddPayload"/> starts a new frame. Call
    /// this after consuming the span returned by <see cref="TryAddPayload"/>.
    /// </summary>
    public void BeginNextFrame()
    {
        _length = 0;
        _haveStart = false;
        _keyFrame = false;
    }

    /// <summary>
    /// Parses the RFC 7741 §4.2 payload descriptor, returning the start bit, partition index and the
    /// remaining payload bytes past the descriptor.
    /// </summary>
    private bool TryParseDescriptor(
        ReadOnlySpan<byte> payload,
        out bool start,
        out int partitionIndex,
        out ReadOnlySpan<byte> body)
    {
        start = false;
        partitionIndex = 0;
        body = default;

        if (payload.Length < 1)
        {
            Warn("Dropping an empty VP8 RTP payload.");
            return false;
        }

        var descriptor0 = payload[0];
        var extended = (descriptor0 & 0x80) != 0;
        start = (descriptor0 & 0x10) != 0;
        partitionIndex = descriptor0 & 0x07;
        var offset = 1;

        if (extended)
        {
            if (offset >= payload.Length)
            {
                Warn("Dropping a VP8 payload with a truncated extended control bits octet.");
                return false;
            }

            var extensionByte = payload[offset++];
            var hasPictureId = (extensionByte & 0x80) != 0;
            var hasTl0PicIdx = (extensionByte & 0x40) != 0;
            var hasTidOrKeyIdx = (extensionByte & 0x30) != 0; // T or K

            if (hasPictureId)
            {
                if (offset >= payload.Length)
                {
                    Warn("Dropping a VP8 payload with a truncated picture ID.");
                    return false;
                }

                var extendedPictureId = (payload[offset] & 0x80) != 0;
                offset += extendedPictureId ? 2 : 1;
                if (offset > payload.Length)
                {
                    Warn("Dropping a VP8 payload whose 15-bit picture ID runs past the payload.");
                    return false;
                }
            }

            if (hasTl0PicIdx)
            {
                if (offset >= payload.Length)
                {
                    Warn("Dropping a VP8 payload with a truncated TL0PICIDX.");
                    return false;
                }

                offset += 1;
            }

            if (hasTidOrKeyIdx)
            {
                if (offset >= payload.Length)
                {
                    Warn("Dropping a VP8 payload with a truncated TID/KEYIDX octet.");
                    return false;
                }

                offset += 1;
            }
        }

        body = payload[offset..];
        return true;
    }

    /// <summary>
    /// Grows the reassembly buffer, doubling, until it holds at least <paramref name="required"/> bytes.
    /// </summary>
    /// <param name="required">
    /// The byte count as a <see cref="long"/> so a huge fragment size cannot itself overflow the
    /// arithmetic before the cap check below runs.
    /// </param>
    /// <returns>
    /// <see langword="false"/> without touching <see cref="_buffer"/> when <paramref name="required"/>
    /// exceeds <see cref="_maxFrameSize"/>; the caller is responsible for discarding the in-progress
    /// frame in that case.
    /// </returns>
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

        // required <= _maxFrameSize <= int.MaxValue here, so this fits in an int; the doubling below is
        // done in long arithmetic and clamped to the cap, so it can neither overflow nor grow past
        // _maxFrameSize regardless of the starting capacity.
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
        Debug($"Dropping an in-progress VP8 frame that exceeded the {_maxFrameSize}-byte cap.");
        Reset();
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
