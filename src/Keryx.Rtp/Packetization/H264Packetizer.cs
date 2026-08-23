namespace Keryx.Rtp.Packetization;

/// <summary>H.264 NAL unit types relevant to RTP packetization (RFC 6184 §5.2, ITU-T H.264 Table 7-1).</summary>
public static class H264NalUnitType
{
    /// <summary>Coded slice of a non-IDR picture.</summary>
    public const byte NonIdrSlice = 1;

    /// <summary>Coded slice of an IDR picture.</summary>
    public const byte IdrSlice = 5;

    /// <summary>Supplemental enhancement information.</summary>
    public const byte Sei = 6;

    /// <summary>Sequence parameter set.</summary>
    public const byte SequenceParameterSet = 7;

    /// <summary>Picture parameter set.</summary>
    public const byte PictureParameterSet = 8;

    /// <summary>Access unit delimiter.</summary>
    public const byte AccessUnitDelimiter = 9;

    /// <summary>Single-time aggregation packet type A (RFC 6184 §5.7.1).</summary>
    public const byte StapA = 24;

    /// <summary>Fragmentation unit type A (RFC 6184 §5.8).</summary>
    public const byte FuA = 28;
}

/// <summary>
/// RFC 6184 packetization-mode=1 packetizer: turns an Annex B access unit into single NAL unit
/// packets, STAP-A aggregation packets and FU-A fragments.
/// </summary>
/// <remarks>
/// <para>
/// The input is an access unit as encoders emit it: one or more NAL units delimited by three- or
/// four-byte start codes. Start codes are stripped; NAL payload bytes are carried verbatim, since RTP
/// transports the emulation-prevention bytes exactly as the encoder produced them (RFC 6184 §5.1).
/// </para>
/// <para>
/// The packetizer holds no state, allocates nothing, and makes a single pass over the access unit: it
/// keeps one NAL unit of lookahead so it knows which packet is the last one and therefore carries the
/// marker bit (RFC 6184 §5.1: the marker bit is set on the last packet of an access unit).
/// </para>
/// </remarks>
public sealed class H264Packetizer : IRtpPayloadizer
{
    /// <summary>The RTP clock rate H.264 always uses (RFC 6184 §8.1).</summary>
    public const uint H264ClockRate = 90_000;

    /// <summary>Bytes a FU-A fragment spends on its two-byte header.</summary>
    public const int FuAHeaderLength = 2;

    /// <summary>Bytes a STAP-A spends on the aggregation header plus one NAL unit size field.</summary>
    public const int StapAPerNalOverhead = 2;

    /// <inheritdoc />
    public uint ClockRate => H264ClockRate;

    /// <summary>
    /// Always zero: H.264 does not encode frame duration in the bitstream, so the caller must supply
    /// capture timestamps.
    /// </summary>
    /// <param name="frame">The access unit; ignored.</param>
    /// <returns>Zero.</returns>
    public uint GetTimestampIncrement(ReadOnlySpan<byte> frame) => 0;

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException"><paramref name="writer"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxPayloadSize"/> leaves no room for a FU-A header.</exception>
    public int Packetize(ReadOnlySpan<byte> frame, uint rtpTimestamp, int maxPayloadSize, IRtpPayloadWriter writer)
    {
        // H.264's marker bit means end-of-access-unit, not talkspurt start, so the RTP timestamp plays
        // no part in it: rtpTimestamp is ignored here and the marker stays keyed off the last NAL unit.
        _ = rtpTimestamp;
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxPayloadSize, FuAHeaderLength + 1);

        var enumerator = AnnexB.EnumerateNalUnits(frame);
        if (!enumerator.MoveNext())
        {
            return 0;
        }

        var nal = enumerator.Current;
        var hasNal = true;
        var packets = 0;

        while (hasNal)
        {
            if (nal.Length > maxPayloadSize)
            {
                var fragmented = nal;
                Advance(ref enumerator, ref nal, ref hasNal);
                packets += WriteFragmentationUnits(fragmented, maxPayloadSize, writer, !hasNal);
                continue;
            }

            var buffer = writer.GetPayloadBuffer(maxPayloadSize);
            var offset = 1;
            var aggregated = 0;
            byte forbidden = 0;
            byte nri = 0;

            while (hasNal
                   && nal.Length <= ushort.MaxValue
                   && offset + StapAPerNalOverhead + nal.Length <= maxPayloadSize)
            {
                buffer[offset] = (byte)(nal.Length >> 8);
                buffer[offset + 1] = (byte)nal.Length;
                nal.CopyTo(buffer[(offset + 2)..]);
                offset += 2 + nal.Length;
                forbidden |= (byte)(nal[0] & 0x80);
                nri = Math.Max(nri, (byte)(nal[0] & 0x60));
                aggregated++;
                Advance(ref enumerator, ref nal, ref hasNal);
            }

            switch (aggregated)
            {
                case 0:
                    // The NAL fits a single NAL unit packet but not a STAP-A that also carries its size field.
                    var single = nal;
                    Advance(ref enumerator, ref nal, ref hasNal);
                    single.CopyTo(buffer);
                    writer.Commit(single.Length, !hasNal);
                    break;

                case 1:
                    // Aggregating one NAL unit costs three bytes and buys nothing: send it on its own
                    // (RFC 6184 §5.6 single NAL unit packet).
                    var length = offset - 3;
                    buffer.Slice(3, length).CopyTo(buffer);
                    writer.Commit(length, !hasNal);
                    break;

                default:
                    buffer[0] = (byte)(forbidden | nri | H264NalUnitType.StapA);
                    writer.Commit(offset, !hasNal);
                    break;
            }

            packets++;
        }

        return packets;
    }

    private static void Advance(ref AnnexBNalEnumerator enumerator, ref ReadOnlySpan<byte> nal, ref bool hasNal)
    {
        hasNal = enumerator.MoveNext();
        nal = hasNal ? enumerator.Current : default;
    }

    private static int WriteFragmentationUnits(
        ReadOnlySpan<byte> nal,
        int maxPayloadSize,
        IRtpPayloadWriter writer,
        bool lastNalOfAccessUnit)
    {
        var indicator = (byte)((nal[0] & 0xE0) | H264NalUnitType.FuA);
        var type = (byte)(nal[0] & 0x1F);
        var body = nal[1..];
        var maxFragment = maxPayloadSize - FuAHeaderLength;
        var position = 0;
        var packets = 0;

        while (position < body.Length)
        {
            var length = Math.Min(maxFragment, body.Length - position);
            var isFirst = position == 0;
            var isLast = position + length == body.Length;

            var buffer = writer.GetPayloadBuffer(length + FuAHeaderLength);
            buffer[0] = indicator;
            buffer[1] = (byte)((isFirst ? 0x80 : 0x00) | (isLast ? 0x40 : 0x00) | type);
            body.Slice(position, length).CopyTo(buffer[FuAHeaderLength..]);
            position += length;
            writer.Commit(length + FuAHeaderLength, isLast && lastNalOfAccessUnit);
            packets++;
        }

        return packets;
    }
}
