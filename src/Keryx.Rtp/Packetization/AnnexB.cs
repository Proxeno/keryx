namespace Keryx.Rtp.Packetization;

/// <summary>
/// Allocation-free forward enumerator over the NAL units of an Annex B byte stream (ITU-T H.264
/// Annex B), handling both three-byte <c>00 00 01</c> and four-byte <c>00 00 00 01</c> start codes.
/// </summary>
public ref struct AnnexBNalEnumerator
{
    private readonly ReadOnlySpan<byte> _data;
    private int _position;
    private ReadOnlySpan<byte> _current;

    /// <summary>Creates an enumerator over an Annex B byte stream.</summary>
    /// <param name="data">The byte stream, typically one access unit.</param>
    public AnnexBNalEnumerator(ReadOnlySpan<byte> data)
    {
        _data = data;
        _position = 0;
        _current = default;
    }

    /// <summary>The NAL unit produced by the last successful <see cref="MoveNext"/>, without its start code.</summary>
    public readonly ReadOnlySpan<byte> Current => _current;

    /// <summary>Returns this enumerator so it can be used directly in <see langword="foreach"/>.</summary>
    /// <returns>A copy of this enumerator.</returns>
    public readonly AnnexBNalEnumerator GetEnumerator() => this;

    /// <summary>Advances to the next non-empty NAL unit.</summary>
    /// <returns><see langword="false"/> when no further NAL unit is present.</returns>
    public bool MoveNext()
    {
        while (_position < _data.Length)
        {
            var startCodeLength = AnnexB.StartCodeLengthAt(_data, _position);
            if (startCodeLength == 0)
            {
                // Not positioned on a start code: skip ahead to the next one.
                var next = AnnexB.IndexOfStartCode(_data, _position);
                if (next < 0)
                {
                    _position = _data.Length;
                    return false;
                }

                _position = next;
                continue;
            }

            var payloadStart = _position + startCodeLength;
            var nextStart = AnnexB.IndexOfStartCode(_data, payloadStart);
            var payloadEnd = nextStart < 0 ? _data.Length : nextStart;
            _position = payloadEnd;

            if (payloadEnd > payloadStart)
            {
                _current = _data[payloadStart..payloadEnd];
                return true;
            }
        }

        return false;
    }
}

/// <summary>Utilities for the Annex B byte-stream format that H.264 and H.265 encoders emit.</summary>
public static class AnnexB
{
    /// <summary>The four-byte start code an Annex B stream normally uses to delimit NAL units.</summary>
    /// <returns>The bytes <c>00 00 00 01</c>.</returns>
    public static ReadOnlySpan<byte> FourByteStartCode => [0x00, 0x00, 0x00, 0x01];

    /// <summary>The three-byte start code prefix that both start-code forms end with.</summary>
    private static ReadOnlySpan<byte> ThreeByteStartCode => [0x00, 0x00, 0x01];

    /// <summary>Enumerates the NAL units of an Annex B byte stream without allocating.</summary>
    /// <param name="data">The byte stream.</param>
    /// <returns>An enumerator usable directly in <see langword="foreach"/>.</returns>
    public static AnnexBNalEnumerator EnumerateNalUnits(ReadOnlySpan<byte> data) => new(data);

    /// <summary>Counts the NAL units in an Annex B byte stream.</summary>
    /// <param name="data">The byte stream.</param>
    /// <returns>The number of non-empty NAL units.</returns>
    public static int CountNalUnits(ReadOnlySpan<byte> data)
    {
        var count = 0;
        var enumerator = new AnnexBNalEnumerator(data);
        while (enumerator.MoveNext())
        {
            count++;
        }

        return count;
    }

    /// <summary>
    /// Returns the length of the start code beginning at <paramref name="offset"/>, or zero when there
    /// is none there.
    /// </summary>
    /// <param name="data">The byte stream.</param>
    /// <param name="offset">Offset to test.</param>
    /// <returns>4, 3, or 0.</returns>
    public static int StartCodeLengthAt(ReadOnlySpan<byte> data, int offset)
    {
        if (offset + 4 <= data.Length
            && data[offset] == 0 && data[offset + 1] == 0 && data[offset + 2] == 0 && data[offset + 3] == 1)
        {
            return 4;
        }

        if (offset + 3 <= data.Length && data[offset] == 0 && data[offset + 1] == 0 && data[offset + 2] == 1)
        {
            return 3;
        }

        return 0;
    }

    /// <summary>
    /// Finds the next start code at or after <paramref name="offset"/>. A four-byte start code is
    /// reported at the position of its leading zero, so the NAL unit before it ends there.
    /// </summary>
    /// <param name="data">The byte stream.</param>
    /// <param name="offset">Where to begin searching.</param>
    /// <returns>The offset of the start code, or -1 when none remains.</returns>
    /// <remarks>
    /// The scan is delegated to <see cref="MemoryExtensions.IndexOf{T}(ReadOnlySpan{T}, ReadOnlySpan{T})"/>,
    /// which searches for the three-byte pattern with the runtime's vectorized substring search instead
    /// of one byte at a time. Slice payloads are kilobytes long, so this is the dominant cost of
    /// packetizing an access unit.
    /// </remarks>
    public static int IndexOfStartCode(ReadOnlySpan<byte> data, int offset)
    {
        var start = Math.Max(offset, 0);
        if (data.Length - start < 3)
        {
            return -1;
        }

        var found = data[start..].IndexOf(ThreeByteStartCode);
        if (found < 0)
        {
            return -1;
        }

        var index = start + found;
        return index > start && data[index - 1] == 0 ? index - 1 : index;
    }
}
