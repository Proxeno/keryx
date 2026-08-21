using Keryx.Core;

namespace Keryx.Rtp.Rtcp;

/// <summary>
/// A reception report block as carried by sender and receiver reports (RFC 3550 §6.4.1).
/// </summary>
public readonly struct RtcpReportBlock
{
    /// <summary>Length of a report block in bytes.</summary>
    public const int Length = 24;

    /// <summary>Creates a report block.</summary>
    /// <param name="sourceSsrc">SSRC of the source this block reports on.</param>
    /// <param name="fractionLost">Fraction of packets lost since the previous report, as an 8-bit fixed-point fraction.</param>
    /// <param name="cumulativePacketsLost">Signed 24-bit cumulative number of packets lost.</param>
    /// <param name="extendedHighestSequenceNumber">Extended highest sequence number received.</param>
    /// <param name="jitter">Interarrival jitter in timestamp units.</param>
    /// <param name="lastSenderReport">Middle 32 bits of the NTP timestamp of the last sender report received.</param>
    /// <param name="delaySinceLastSenderReport">Delay since that sender report, in units of 1/65536 second.</param>
    public RtcpReportBlock(
        uint sourceSsrc,
        byte fractionLost,
        int cumulativePacketsLost,
        uint extendedHighestSequenceNumber,
        uint jitter,
        uint lastSenderReport,
        uint delaySinceLastSenderReport)
    {
        SourceSsrc = sourceSsrc;
        FractionLost = fractionLost;
        CumulativePacketsLost = cumulativePacketsLost;
        ExtendedHighestSequenceNumber = extendedHighestSequenceNumber;
        Jitter = jitter;
        LastSenderReport = lastSenderReport;
        DelaySinceLastSenderReport = delaySinceLastSenderReport;
    }

    /// <summary>SSRC of the source this block reports on.</summary>
    public uint SourceSsrc { get; }

    /// <summary>
    /// Fraction of RTP packets lost since the previous report, expressed as the numerator of a
    /// fraction with denominator 256.
    /// </summary>
    public byte FractionLost { get; }

    /// <summary>
    /// Cumulative number of packets lost, a signed 24-bit quantity: duplicates can make it negative,
    /// and it saturates rather than wrapping (RFC 3550 §6.4.1).
    /// </summary>
    public int CumulativePacketsLost { get; }

    /// <summary>Extended highest sequence number received: the sequence-number cycle count in the high 16 bits.</summary>
    public uint ExtendedHighestSequenceNumber { get; }

    /// <summary>Estimated statistical variance of the RTP packet interarrival time, in timestamp units.</summary>
    public uint Jitter { get; }

    /// <summary>Middle 32 bits of the NTP timestamp of the most recent sender report from this source.</summary>
    public uint LastSenderReport { get; }

    /// <summary>Delay between receiving the last sender report and sending this block, in units of 1/65536 second.</summary>
    public uint DelaySinceLastSenderReport { get; }

    /// <summary>The sequence-number cycle count, i.e. the high 16 bits of <see cref="ExtendedHighestSequenceNumber"/>.</summary>
    public ushort SequenceNumberCycles => (ushort)(ExtendedHighestSequenceNumber >> 16);

    /// <summary>The highest sequence number received in the current cycle.</summary>
    public ushort HighestSequenceNumber => (ushort)ExtendedHighestSequenceNumber;

    /// <summary>Parses one report block from the front of <paramref name="buffer"/>.</summary>
    /// <param name="buffer">Buffer positioned at a report block.</param>
    /// <param name="block">On success, the parsed block.</param>
    /// <returns><see langword="false"/> when fewer than <see cref="Length"/> bytes are available.</returns>
    public static bool TryParse(ReadOnlySpan<byte> buffer, out RtcpReportBlock block)
    {
        block = default;
        if (buffer.Length < Length)
        {
            return false;
        }

        var reader = new ByteReader(buffer);
        var ssrc = reader.ReadU32();
        var fractionLost = reader.ReadU8();
        var cumulative = SignExtend24(reader.ReadU24());
        var extendedHighest = reader.ReadU32();
        var jitter = reader.ReadU32();
        var lsr = reader.ReadU32();
        var dlsr = reader.ReadU32();
        block = new RtcpReportBlock(ssrc, fractionLost, cumulative, extendedHighest, jitter, lsr, dlsr);
        return true;
    }

    /// <summary>Serializes the report block.</summary>
    /// <param name="destination">Buffer of at least <see cref="Length"/> bytes.</param>
    /// <returns>The number of bytes written, always <see cref="Length"/>.</returns>
    /// <exception cref="ByteBufferException">The destination is too small.</exception>
    public int WriteTo(Span<byte> destination)
    {
        var writer = new ByteWriter(destination);
        writer.WriteU32(SourceSsrc);
        writer.WriteU8(FractionLost);
        writer.WriteU24((uint)CumulativePacketsLost & 0x00FFFFFF);
        writer.WriteU32(ExtendedHighestSequenceNumber);
        writer.WriteU32(Jitter);
        writer.WriteU32(LastSenderReport);
        writer.WriteU32(DelaySinceLastSenderReport);
        return writer.Position;
    }

    private static int SignExtend24(uint value) =>
        (value & 0x00800000) != 0 ? (int)(value | 0xFF000000) : (int)value;
}
