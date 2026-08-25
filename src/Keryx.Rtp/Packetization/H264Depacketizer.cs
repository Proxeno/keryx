using Keryx.Core;

namespace Keryx.Rtp.Packetization;

/// <summary>
/// Reassembles RFC 6184 single NAL unit, STAP-A and FU-A payloads back into an Annex B access unit.
/// </summary>
/// <remarks>
/// <para>
/// This is the inverse of <see cref="H264Packetizer"/> and exists so loopback tests can assert that
/// what a remote decoder would reconstruct is byte-identical to what the encoder produced. It is also
/// usable as a receive-side depacketizer for well-ordered input.
/// </para>
/// <para>
/// The depacketizer assumes payloads arrive in order and without loss; a <see cref="JitterBuffer"/>
/// belongs in front of it. Malformed payloads are logged and dropped. STAP-B, MTAP16, MTAP24 and FU-B are not
/// supported: WebRTC endpoints negotiate packetization-mode=1, which uses only the three forms above.
/// </para>
/// <para><b>Thread safety: single-writer</b>, like the rest of the per-stream state in this layer.</para>
/// </remarks>
public sealed class H264Depacketizer
{
    /// <summary>
    /// Default upper bound on the size, in bytes, of a single access unit under reassembly. A remote
    /// peer that withholds the marker bit (or spoofs FU-A/STAP-A fragment sizes) would otherwise drive
    /// <see cref="EnsureCapacity"/> to double the reassembly buffer without limit. 8 MiB is far larger
    /// than any real H.264 keyframe carried over RTP while still bounding memory.
    /// </summary>
    public const int DefaultMaxAccessUnitSize = 8 * 1024 * 1024;

    private readonly IKeryxLogger _logger;
    private readonly int _maxAccessUnitSize;
    private byte[] _buffer;
    private int _length;
    private bool _inFragment;

    /// <summary>Creates a depacketizer.</summary>
    /// <param name="initialCapacity">Initial size of the reassembly buffer in bytes.</param>
    /// <param name="maxAccessUnitSize">
    /// Upper bound on the size, in bytes, of a single access unit under reassembly. Once reached, the
    /// in-progress access unit is discarded and further payloads for it are dropped rather than growing
    /// the buffer further; see <see cref="DefaultMaxAccessUnitSize"/>.
    /// </param>
    /// <param name="logger">Optional logger; malformed payloads are reported at warning level.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="initialCapacity"/> is not positive, or <paramref name="maxAccessUnitSize"/> is
    /// smaller than <paramref name="initialCapacity"/>.
    /// </exception>
    public H264Depacketizer(
        int initialCapacity = 64 * 1024,
        int maxAccessUnitSize = DefaultMaxAccessUnitSize,
        IKeryxLogger? logger = null)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(initialCapacity);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxAccessUnitSize, initialCapacity);
        _buffer = new byte[initialCapacity];
        _maxAccessUnitSize = maxAccessUnitSize;
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>The Annex B bytes accumulated for the access unit currently being reassembled.</summary>
    public ReadOnlySpan<byte> AccessUnit => _buffer.AsSpan(0, _length);

    /// <summary>Discards any partially reassembled access unit.</summary>
    public void Reset()
    {
        _length = 0;
        _inFragment = false;
    }

    /// <summary>
    /// Adds one RTP payload to the access unit under reassembly.
    /// </summary>
    /// <param name="payload">The RTP payload, without the RTP header.</param>
    /// <param name="marker">The packet's marker bit; it terminates the access unit (RFC 6184 §5.1).</param>
    /// <param name="accessUnit">
    /// When the return value is <see langword="true"/>, the complete access unit in Annex B form with
    /// four-byte start codes. The span is valid until the next call.
    /// </param>
    /// <returns><see langword="true"/> when <paramref name="marker"/> completed an access unit.</returns>
    public bool TryAddPayload(ReadOnlySpan<byte> payload, bool marker, out ReadOnlySpan<byte> accessUnit)
    {
        accessUnit = default;

        if (payload.Length < 1)
        {
            Warn("Dropping an empty H.264 RTP payload.");
            return false;
        }

        var type = (byte)(payload[0] & 0x1F);
        switch (type)
        {
            case H264NalUnitType.StapA:
                if (!AppendStapA(payload))
                {
                    return false;
                }

                break;

            case H264NalUnitType.FuA:
                if (!AppendFuA(payload))
                {
                    return false;
                }

                break;

            case 25:
            case 26:
            case 27:
            case 29:
                Warn($"Dropping unsupported H.264 aggregation/fragmentation type {type}.");
                return false;

            default:
                if (!AppendNal(payload))
                {
                    return false;
                }

                break;
        }

        if (!marker)
        {
            return false;
        }

        accessUnit = _buffer.AsSpan(0, _length);
        return true;
    }

    /// <summary>
    /// Clears the reassembly buffer so the next <see cref="TryAddPayload"/> starts a new access unit.
    /// Call this after consuming the span returned by <see cref="TryAddPayload"/>.
    /// </summary>
    public void BeginNextAccessUnit()
    {
        _length = 0;
        _inFragment = false;
    }

    private bool AppendStapA(ReadOnlySpan<byte> payload)
    {
        var offset = 1;
        while (offset < payload.Length)
        {
            if (offset + 2 > payload.Length)
            {
                Warn("Dropping a STAP-A payload whose NAL unit size field is truncated.");
                return false;
            }

            var size = (payload[offset] << 8) | payload[offset + 1];
            offset += 2;
            if (size == 0 || offset + size > payload.Length)
            {
                Warn("Dropping a STAP-A payload whose NAL unit size runs past the payload.");
                return false;
            }

            if (!AppendNal(payload.Slice(offset, size)))
            {
                return false;
            }

            offset += size;
        }

        return true;
    }

    private bool AppendFuA(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < H264Packetizer.FuAHeaderLength + 1)
        {
            Warn("Dropping a FU-A payload with no fragment body.");
            return false;
        }

        var indicator = payload[0];
        var fuHeader = payload[1];
        var start = (fuHeader & 0x80) != 0;
        var end = (fuHeader & 0x40) != 0;
        var body = payload[H264Packetizer.FuAHeaderLength..];

        if (start)
        {
            if (!EnsureCapacity((long)_length + 4 + 1 + body.Length))
            {
                DropAccessUnitTooLarge();
                return false;
            }

            var reconstructed = (byte)((indicator & 0xE0) | (fuHeader & 0x1F));
            AnnexB.FourByteStartCode.CopyTo(_buffer.AsSpan(_length));
            _length += 4;
            _buffer[_length++] = reconstructed;
            _inFragment = true;
        }
        else if (!_inFragment)
        {
            Warn("Dropping a FU-A continuation fragment with no preceding start fragment.");
            return false;
        }
        else if (!EnsureCapacity((long)_length + body.Length))
        {
            DropAccessUnitTooLarge();
            return false;
        }

        body.CopyTo(_buffer.AsSpan(_length));
        _length += body.Length;

        if (end)
        {
            _inFragment = false;
        }

        return true;
    }

    private bool AppendNal(ReadOnlySpan<byte> nal)
    {
        if (!EnsureCapacity((long)_length + 4 + nal.Length))
        {
            DropAccessUnitTooLarge();
            return false;
        }

        AnnexB.FourByteStartCode.CopyTo(_buffer.AsSpan(_length));
        _length += 4;
        nal.CopyTo(_buffer.AsSpan(_length));
        _length += nal.Length;
        return true;
    }

    /// <summary>
    /// Grows the reassembly buffer, doubling, until it holds at least <paramref name="required"/> bytes.
    /// </summary>
    /// <param name="required">
    /// The byte count as a <see cref="long"/> so a huge fragment/NAL size cannot itself overflow the
    /// arithmetic before the cap check below runs.
    /// </param>
    /// <returns>
    /// <see langword="false"/> without touching <see cref="_buffer"/> when <paramref name="required"/>
    /// exceeds <see cref="_maxAccessUnitSize"/>; the caller is responsible for discarding the
    /// in-progress access unit in that case.
    /// </returns>
    private bool EnsureCapacity(long required)
    {
        if (required > _maxAccessUnitSize)
        {
            return false;
        }

        if (_buffer.Length >= required)
        {
            return true;
        }

        // required <= _maxAccessUnitSize <= int.MaxValue here, so this fits in an int; the doubling
        // below is done in long arithmetic and clamped to the cap, so it can neither overflow nor
        // grow past _maxAccessUnitSize regardless of the starting capacity.
        long capacity = _buffer.Length;
        while (capacity < required)
        {
            capacity *= 2;
        }

        capacity = Math.Min(capacity, _maxAccessUnitSize);
        Array.Resize(ref _buffer, (int)capacity);
        return true;
    }

    private void DropAccessUnitTooLarge()
    {
        Debug($"Dropping an in-progress H.264 access unit that exceeded the {_maxAccessUnitSize}-byte cap.");
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
