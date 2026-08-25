namespace Keryx.Rtp.Packetization;

/// <summary>AV1 OBU types relevant to RTP packetization (AV1 bitstream specification §6.2.2).</summary>
public static class Av1ObuType
{
    /// <summary>Sequence header OBU; its presence marks the start of a coded video sequence (a key frame).</summary>
    public const byte SequenceHeader = 1;

    /// <summary>Temporal delimiter OBU.</summary>
    public const byte TemporalDelimiter = 2;

    /// <summary>Frame header OBU.</summary>
    public const byte FrameHeader = 3;

    /// <summary>Tile group OBU.</summary>
    public const byte TileGroup = 4;

    /// <summary>Metadata OBU.</summary>
    public const byte Metadata = 5;

    /// <summary>Frame OBU (a frame header and its tile group combined).</summary>
    public const byte Frame = 6;
}

/// <summary>
/// "RTP Payload Format For AV1" packetizer: turns one AV1 temporal unit into RTP payloads carrying the
/// one-byte aggregation header and a sequence of OBU elements.
/// </summary>
/// <remarks>
/// <para>
/// The input is one temporal unit in AV1's low-overhead bitstream format: a run of OBUs each of which
/// carries <c>obu_has_size_field = 1</c> (the encoder output WebRTC feeds to RTP), except that a final
/// OBU may omit its size field and run to the end of the unit. Each OBU is re-emitted as an RTP OBU
/// element with its internal size field removed (RTP Payload Format For AV1 §5): the element's length
/// travels instead in a LEB128 length field in the aggregation, which is what
/// <see cref="Av1Depacketizer"/> reads to restore the size field on reassembly.
/// </para>
/// <para>
/// Every packet is emitted in the <c>W = 0</c> form, so each OBU element — whole or a fragment — is
/// preceded by its LEB128 length; an OBU element too large for one packet is split across packets with
/// the aggregation header's Z (continues a previous fragment) and Y (continues into the next packet)
/// bits. The N bit is set on the first packet of a temporal unit that opens a new coded video sequence,
/// which this packetizer detects from the presence of a sequence-header OBU. The marker bit is set on
/// the last packet of the temporal unit.
/// </para>
/// <para>
/// The packetizer parses the temporal unit into a reused scratch buffer of size-stripped OBU elements,
/// so after warm-up it allocates nothing on the packetizing path. <b>Thread safety: single-writer.</b>
/// </para>
/// </remarks>
public sealed class Av1Packetizer : IRtpPayloadizer
{
    /// <summary>The RTP clock rate AV1 uses in WebRTC deployments.</summary>
    public const uint Av1ClockRate = 90_000;

    /// <summary>Length, in bytes, of the mandatory aggregation header.</summary>
    public const int AggregationHeaderLength = 1;

    // Aggregation header bit masks (RTP Payload Format For AV1 §4): Z|Y|W(2)|N|-|-|-.
    private const byte ContinuesPrevious = 0x80; // Z
    private const byte ContinuesNext = 0x40; // Y
    private const byte NewCodedVideoSequence = 0x08; // N

    private const byte ObuTypeMask = 0x78; // bits 3..6 of the OBU header
    private const byte ObuExtensionFlag = 0x04;
    private const byte ObuHasSizeField = 0x02;

    private byte[] _scratch = [];
    private readonly List<(int Offset, int Length)> _elements = [];

    /// <inheritdoc />
    public uint ClockRate => Av1ClockRate;

    /// <summary>
    /// Always zero: AV1's RTP payload format does not encode frame duration, so the caller must supply
    /// capture timestamps.
    /// </summary>
    /// <param name="frame">The temporal unit; ignored.</param>
    /// <returns>Zero.</returns>
    public uint GetTimestampIncrement(ReadOnlySpan<byte> frame) => 0;

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException"><paramref name="writer"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="maxPayloadSize"/> leaves no room for the aggregation header plus a length-prefixed
    /// byte of payload.
    /// </exception>
    public int Packetize(ReadOnlySpan<byte> frame, uint rtpTimestamp, int maxPayloadSize, IRtpPayloadWriter writer)
    {
        // AV1's marker bit means end-of-temporal-unit, not talkspurt start, so the RTP timestamp plays no
        // part in it, exactly as for VP8, VP9 and H.264.
        _ = rtpTimestamp;
        ArgumentNullException.ThrowIfNull(writer);

        // The aggregation header, plus at least one LEB128 length octet and one payload octet.
        ArgumentOutOfRangeException.ThrowIfLessThan(maxPayloadSize, AggregationHeaderLength + 2);

        if (frame.IsEmpty || !TryParseTemporalUnit(frame, out var hasSequenceHeader))
        {
            return 0;
        }

        var elementIndex = 0;
        var offsetInElement = 0;
        var continuesFromPrevious = false;
        var firstPacket = true;
        var packets = 0;

        while (elementIndex < _elements.Count)
        {
            var buffer = writer.GetPayloadBuffer(maxPayloadSize);
            var position = AggregationHeaderLength;
            var startedContinuation = continuesFromPrevious;
            var lastElementContinues = false;

            while (elementIndex < _elements.Count)
            {
                var (elementOffset, elementLength) = _elements[elementIndex];
                var remaining = elementLength - offsetInElement;
                var spaceLeft = maxPayloadSize - position;
                var chunk = MaxChunk(spaceLeft, remaining);
                if (chunk == 0)
                {
                    break;
                }

                position += Leb128.Write(buffer[position..], (uint)chunk);
                _scratch.AsSpan(elementOffset + offsetInElement, chunk).CopyTo(buffer[position..]);
                position += chunk;
                offsetInElement += chunk;

                if (offsetInElement == elementLength)
                {
                    elementIndex++;
                    offsetInElement = 0;
                }
                else
                {
                    // The element did not finish: it continues into the next packet.
                    lastElementContinues = true;
                    break;
                }
            }

            byte header = 0;
            if (startedContinuation)
            {
                header |= ContinuesPrevious;
            }

            if (lastElementContinues)
            {
                header |= ContinuesNext;
            }

            if (firstPacket && hasSequenceHeader)
            {
                header |= NewCodedVideoSequence;
            }

            buffer[0] = header;

            var isLastPacket = elementIndex >= _elements.Count;
            writer.Commit(position, isLastPacket);
            continuesFromPrevious = lastElementContinues;
            firstPacket = false;
            packets++;
        }

        return packets;
    }

    /// <summary>
    /// The largest number of content bytes that fit in <paramref name="spaceLeft"/> once a LEB128 length
    /// prefix for that many bytes is accounted for, capped at <paramref name="remaining"/>.
    /// </summary>
    private static int MaxChunk(int spaceLeft, int remaining)
    {
        if (spaceLeft < 2 || remaining <= 0)
        {
            return 0;
        }

        for (var prefix = 1; prefix <= Leb128.MaxLength; prefix++)
        {
            var capacity = spaceLeft - prefix;
            if (capacity <= 0)
            {
                return 0;
            }

            var chunk = Math.Min(remaining, capacity);
            if (Leb128.Size((uint)chunk) <= prefix)
            {
                return chunk;
            }
        }

        return 0;
    }

    /// <summary>
    /// Parses <paramref name="frame"/> into size-stripped OBU elements in <see cref="_scratch"/>, filling
    /// <see cref="_elements"/> with their offsets and lengths.
    /// </summary>
    /// <param name="frame">The temporal unit.</param>
    /// <param name="hasSequenceHeader">On success, whether the unit carries a sequence-header OBU.</param>
    /// <returns><see langword="false"/> when the unit is malformed.</returns>
    private bool TryParseTemporalUnit(ReadOnlySpan<byte> frame, out bool hasSequenceHeader)
    {
        hasSequenceHeader = false;
        _elements.Clear();

        // Stripping size fields only ever shrinks the data, so the frame length is a safe scratch size.
        if (_scratch.Length < frame.Length)
        {
            _scratch = new byte[frame.Length];
        }

        var position = 0;
        var scratchPosition = 0;

        while (position < frame.Length)
        {
            var header = frame[position];
            var hasExtension = (header & ObuExtensionFlag) != 0;
            var hasSizeField = (header & ObuHasSizeField) != 0;
            var headerLength = hasExtension ? 2 : 1;
            if (position + headerLength > frame.Length)
            {
                return false;
            }

            int payloadOffset;
            int payloadLength;
            if (hasSizeField)
            {
                if (!Leb128.TryRead(frame[(position + headerLength)..], out var size, out var sizeLength))
                {
                    return false;
                }

                payloadOffset = position + headerLength + sizeLength;
                payloadLength = (int)size;
            }
            else
            {
                // Only the final OBU may omit its size field; it then runs to the end of the unit.
                payloadOffset = position + headerLength;
                payloadLength = frame.Length - payloadOffset;
            }

            if (payloadLength < 0 || payloadOffset + payloadLength > frame.Length)
            {
                return false;
            }

            if (((header & ObuTypeMask) >> 3) == Av1ObuType.SequenceHeader)
            {
                hasSequenceHeader = true;
            }

            // Emit the size-stripped element: the header with obu_has_size_field cleared, the optional
            // extension octet, then the OBU payload verbatim.
            var elementStart = scratchPosition;
            _scratch[scratchPosition++] = (byte)(header & ~ObuHasSizeField);
            if (hasExtension)
            {
                _scratch[scratchPosition++] = frame[position + 1];
            }

            frame.Slice(payloadOffset, payloadLength).CopyTo(_scratch.AsSpan(scratchPosition));
            scratchPosition += payloadLength;
            _elements.Add((elementStart, scratchPosition - elementStart));

            position = payloadOffset + payloadLength;
        }

        return _elements.Count > 0;
    }
}
