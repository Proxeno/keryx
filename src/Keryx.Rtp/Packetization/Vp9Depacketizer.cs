using Keryx.Core;

namespace Keryx.Rtp.Packetization;

/// <summary>
/// Reassembles draft-ietf-payload-vp9 VP9 RTP payloads back into complete encoded frames.
/// </summary>
/// <remarks>
/// <para>
/// This is the inverse of <see cref="Vp9Packetizer"/> and exists so loopback tests can assert that what
/// a remote decoder would reconstruct is byte-identical to what the encoder produced. It is also usable
/// as a receive-side depacketizer for well-ordered input.
/// </para>
/// <para>
/// The depacketizer assumes payloads arrive in order and without loss; a <see cref="JitterBuffer"/>
/// belongs in front of it. It parses the full payload descriptor — the mandatory I|P|L|F|B|E|V|Z octet,
/// the 7-bit and 15-bit (M-bit) picture ID forms, the layer-indices block (TID/SID and, in non-flexible
/// mode, TL0PICIDX), the flexible-mode P_DIFF references, and the scalability structure (SS) — so it can
/// skip whatever a remote encoder sends, even though <see cref="Vp9Packetizer"/> itself only emits the
/// mandatory descriptor plus a 15-bit picture ID. Malformed payloads are logged and dropped.
/// </para>
/// <para><b>Thread safety: single-writer</b>, like the rest of the per-stream state in this layer.</para>
/// </remarks>
public sealed class Vp9Depacketizer
{
    /// <summary>
    /// Default upper bound on the size, in bytes, of a single frame under reassembly. A remote peer that
    /// withholds the E/marker bits (or spoofs fragment sizes) would otherwise drive
    /// <see cref="EnsureCapacity"/> to double the reassembly buffer without limit. 8 MiB is far larger
    /// than any real VP9 frame carried over RTP while still bounding memory.
    /// </summary>
    public const int DefaultMaxFrameSize = 8 * 1024 * 1024;

    // Descriptor byte 0 bit masks (draft-ietf-payload-vp9 §4.2): I|P|L|F|B|E|V|Z.
    private const byte PictureIdPresent = 0x80; // I
    private const byte InterPicturePredicted = 0x40; // P
    private const byte LayerIndicesPresent = 0x20; // L
    private const byte FlexibleMode = 0x10; // F
    private const byte StartOfFrame = 0x08; // B
    private const byte ScalabilityStructurePresent = 0x02; // V

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
    public Vp9Depacketizer(
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
    /// <see langword="true"/> when the frame currently being (or most recently) reassembled started with
    /// a VP9 key frame, determined from the descriptor's P (inter-picture predicted) bit on the packet
    /// that carried the start of the frame: P=0 marks a key frame (draft-ietf-payload-vp9 §4.2).
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
    /// <param name="marker">The packet's marker bit; it terminates the frame.</param>
    /// <param name="frame">
    /// When the return value is <see langword="true"/>, the complete VP9 frame. The span is valid until
    /// the next call.
    /// </param>
    /// <returns><see langword="true"/> when <paramref name="marker"/> completed a frame.</returns>
    public bool TryAddPayload(ReadOnlySpan<byte> payload, bool marker, out ReadOnlySpan<byte> frame)
    {
        frame = default;

        if (!TryParseDescriptor(payload, out var start, out var interPredicted, out var body))
        {
            return false;
        }

        if (start)
        {
            if (body.IsEmpty)
            {
                Warn("Dropping a VP9 payload that starts a frame but carries no data.");
                return false;
            }

            // A start bit always begins a fresh frame in this packetizer's scheme. Reset unconditionally
            // rather than requiring the caller to have called BeginNextFrame — that keeps reassembly
            // self-healing after a lost marker, the same failure mode the size cap below guards against.
            _length = 0;
            _keyFrame = !interPredicted;
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
                Warn("Dropping a VP9 continuation payload with no preceding start payload.");
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
    /// Parses the draft-ietf-payload-vp9 §4.2 payload descriptor, returning the B (start) bit, the P
    /// (inter-picture predicted) bit and the remaining payload bytes past the descriptor.
    /// </summary>
    private bool TryParseDescriptor(
        ReadOnlySpan<byte> payload,
        out bool start,
        out bool interPredicted,
        out ReadOnlySpan<byte> body)
    {
        start = false;
        interPredicted = false;
        body = default;

        if (payload.Length < 1)
        {
            Warn("Dropping an empty VP9 RTP payload.");
            return false;
        }

        var descriptor0 = payload[0];
        var hasPictureId = (descriptor0 & PictureIdPresent) != 0;
        interPredicted = (descriptor0 & InterPicturePredicted) != 0;
        var hasLayerIndices = (descriptor0 & LayerIndicesPresent) != 0;
        var flexible = (descriptor0 & FlexibleMode) != 0;
        start = (descriptor0 & StartOfFrame) != 0;
        var hasScalabilityStructure = (descriptor0 & ScalabilityStructurePresent) != 0;
        var offset = 1;

        if (hasPictureId && !SkipPictureId(payload, ref offset))
        {
            return false;
        }

        if (hasLayerIndices && !SkipLayerIndices(payload, flexible, ref offset))
        {
            return false;
        }

        if (flexible && interPredicted && !SkipFlexibleReferences(payload, ref offset))
        {
            return false;
        }

        if (hasScalabilityStructure && !SkipScalabilityStructure(payload, ref offset))
        {
            return false;
        }

        if (offset > payload.Length)
        {
            Warn("Dropping a VP9 payload whose descriptor runs past the payload.");
            return false;
        }

        body = payload[offset..];
        return true;
    }

    private bool SkipPictureId(ReadOnlySpan<byte> payload, ref int offset)
    {
        if (offset >= payload.Length)
        {
            Warn("Dropping a VP9 payload with a truncated picture ID.");
            return false;
        }

        // M bit set → 15-bit picture ID (2 bytes); clear → 7-bit picture ID (1 byte).
        var extended = (payload[offset] & 0x80) != 0;
        offset += extended ? 2 : 1;
        if (offset > payload.Length)
        {
            Warn("Dropping a VP9 payload whose 15-bit picture ID runs past the payload.");
            return false;
        }

        return true;
    }

    private bool SkipLayerIndices(ReadOnlySpan<byte> payload, bool flexible, ref int offset)
    {
        // The TID/U/SID/D octet is always present when L=1; the TL0PICIDX octet follows it only in
        // non-flexible mode (F=0).
        var needed = flexible ? 1 : 2;
        if (offset + needed > payload.Length)
        {
            Warn("Dropping a VP9 payload with truncated layer indices.");
            return false;
        }

        offset += needed;
        return true;
    }

    private bool SkipFlexibleReferences(ReadOnlySpan<byte> payload, ref int offset)
    {
        // In flexible mode a predicted frame carries up to three P_DIFF octets, each with its low bit (N)
        // set while another follows.
        for (var i = 0; i < 3; i++)
        {
            if (offset >= payload.Length)
            {
                Warn("Dropping a VP9 payload with a truncated flexible-mode reference index.");
                return false;
            }

            var more = (payload[offset] & 0x01) != 0;
            offset += 1;
            if (!more)
            {
                return true;
            }
        }

        return true;
    }

    private bool SkipScalabilityStructure(ReadOnlySpan<byte> payload, ref int offset)
    {
        if (offset >= payload.Length)
        {
            Warn("Dropping a VP9 payload with a truncated scalability structure.");
            return false;
        }

        var ssHeader = payload[offset++];
        var spatialLayers = ((ssHeader >> 5) & 0x07) + 1; // N_S + 1
        var resolutionPresent = (ssHeader & 0x10) != 0; // Y
        var pictureGroupPresent = (ssHeader & 0x08) != 0; // G

        if (resolutionPresent)
        {
            // Each spatial layer contributes a 16-bit width and a 16-bit height.
            var resolutionBytes = spatialLayers * 4;
            if (offset + resolutionBytes > payload.Length)
            {
                Warn("Dropping a VP9 payload whose scalability resolutions run past the payload.");
                return false;
            }

            offset += resolutionBytes;
        }

        if (!pictureGroupPresent)
        {
            return true;
        }

        if (offset >= payload.Length)
        {
            Warn("Dropping a VP9 payload with a truncated picture-group count.");
            return false;
        }

        var pictureGroups = payload[offset++]; // N_G
        for (var i = 0; i < pictureGroups; i++)
        {
            if (offset >= payload.Length)
            {
                Warn("Dropping a VP9 payload with a truncated picture-group description.");
                return false;
            }

            var referenceCount = (payload[offset] >> 2) & 0x03; // R
            offset += 1 + referenceCount; // the TID/U/R octet plus R P_DIFF octets
            if (offset > payload.Length)
            {
                Warn("Dropping a VP9 payload whose picture-group references run past the payload.");
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Grows the reassembly buffer, doubling, until it holds at least <paramref name="required"/> bytes.
    /// </summary>
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
        Debug($"Dropping an in-progress VP9 frame that exceeded the {_maxFrameSize}-byte cap.");
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
