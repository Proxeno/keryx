namespace Keryx.Rtp.Fec;

/// <summary>One decoded block of an RFC 2198 RED payload: its inner payload type, its body, and,
/// for a redundant block, the timestamp offset from the primary.</summary>
/// <remarks>The body aliases the RED payload the block was decoded from; it is valid only while that
/// buffer is.</remarks>
public readonly ref struct RedBlock
{
    /// <summary>Creates a decoded block view.</summary>
    /// <param name="payloadType">The block's inner RTP payload type.</param>
    /// <param name="timestampOffset">Primary timestamp minus this block's timestamp; zero for the primary block.</param>
    /// <param name="data">The block body.</param>
    /// <param name="isPrimary">Whether this is the primary (last) block.</param>
    public RedBlock(byte payloadType, ushort timestampOffset, ReadOnlySpan<byte> data, bool isPrimary)
    {
        PayloadType = payloadType;
        TimestampOffset = timestampOffset;
        Data = data;
        IsPrimary = isPrimary;
    }

    /// <summary>The block's inner RTP payload type (the F bit stripped).</summary>
    public byte PayloadType { get; }

    /// <summary>The primary packet's timestamp minus this block's timestamp; zero for the primary block.</summary>
    public ushort TimestampOffset { get; }

    /// <summary>The block body, aliasing the RED payload.</summary>
    public ReadOnlySpan<byte> Data { get; }

    /// <summary>True for the primary block, whose header carries a clear F bit and no length.</summary>
    public bool IsPrimary { get; }
}

/// <summary>Allocation-free forward enumerator over the blocks of an RFC 2198 RED payload.</summary>
/// <remarks>
/// The header run and the body run are decoded together: the enumerator scans the headers once at
/// construction to find where the bodies begin, then walks headers and bodies in lockstep. A payload
/// whose headers are truncated, or whose redundant lengths run past the end, yields no blocks and
/// leaves <see cref="IsComplete"/> false.
/// </remarks>
public ref struct RedBlockEnumerator
{
    private const byte FBit = 0x80;
    private const byte PayloadTypeMask = 0x7F;

    private readonly ReadOnlySpan<byte> _payload;
    private readonly int _dataStart;
    private readonly bool _valid;
    private int _headerPos;
    private int _dataPos;
    private bool _completedPrimary;
    private RedBlock _current;

    /// <summary>Creates an enumerator over a RED payload.</summary>
    /// <param name="payload">The RED payload, block headers included.</param>
    public RedBlockEnumerator(ReadOnlySpan<byte> payload)
    {
        _payload = payload;
        _headerPos = 0;
        _dataPos = 0;
        _completedPrimary = false;
        _current = default;
        _valid = TryScan(payload, out _dataStart);
        _dataPos = _dataStart;
    }

    /// <summary>The block produced by the last successful <see cref="MoveNext"/>.</summary>
    public readonly RedBlock Current => _current;

    /// <summary>
    /// True once every block, up to and including the primary, has been decoded without the payload
    /// proving malformed. False for a truncated or over-long payload.
    /// </summary>
    public readonly bool IsComplete => _valid && _completedPrimary;

    /// <summary>Returns this enumerator so it can be used directly in <see langword="foreach"/>.</summary>
    /// <returns>A copy of this enumerator.</returns>
    public readonly RedBlockEnumerator GetEnumerator() => this;

    /// <summary>Advances to the next block.</summary>
    /// <returns><see langword="false"/> once the primary block has been produced or the payload is malformed.</returns>
    public bool MoveNext()
    {
        if (!_valid || _completedPrimary || _headerPos >= _dataStart)
        {
            return false;
        }

        var header = _payload[_headerPos];
        if ((header & FBit) != 0)
        {
            var payloadType = (byte)(header & PayloadTypeMask);
            var packed = ((uint)_payload[_headerPos + 1] << 16)
                | ((uint)_payload[_headerPos + 2] << 8)
                | _payload[_headerPos + 3];
            var timestampOffset = (ushort)(packed >> 10);
            var length = (int)(packed & RedPacket.MaxRedundantBlockLength);

            _current = new RedBlock(payloadType, timestampOffset, _payload.Slice(_dataPos, length), isPrimary: false);
            _headerPos += RedPacket.RedundantHeaderLength;
            _dataPos += length;
            return true;
        }

        _current = new RedBlock((byte)(header & PayloadTypeMask), 0, _payload[_dataPos..], isPrimary: true);
        _headerPos += RedPacket.PrimaryHeaderLength;
        _completedPrimary = true;
        return true;
    }

    /// <summary>
    /// Scans the header run to validate it and to find <paramref name="dataStart"/>, the offset at which
    /// the block bodies begin, checking that every redundant length fits inside the payload.
    /// </summary>
    private static bool TryScan(ReadOnlySpan<byte> payload, out int dataStart)
    {
        dataStart = 0;
        var offset = 0;
        long redundantBytes = 0;

        while (true)
        {
            if (offset >= payload.Length)
            {
                // Ran out of octets before meeting the primary header.
                return false;
            }

            var header = payload[offset];
            if ((header & FBit) == 0)
            {
                offset += RedPacket.PrimaryHeaderLength;
                dataStart = offset;
                break;
            }

            if (offset + RedPacket.RedundantHeaderLength > payload.Length)
            {
                return false;
            }

            var length = ((payload[offset + 2] & 0x03) << 8) | payload[offset + 3];
            redundantBytes += length;
            offset += RedPacket.RedundantHeaderLength;
        }

        // The bodies of every redundant block must fit between the header run and the payload end; the
        // primary body takes whatever remains (it may legitimately be empty).
        return dataStart + redundantBytes <= payload.Length;
    }
}
