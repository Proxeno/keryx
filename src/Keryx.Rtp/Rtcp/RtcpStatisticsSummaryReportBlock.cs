using Keryx.Core;

namespace Keryx.Rtp.Rtcp;

/// <summary>
/// Meaning of the two <c>ToH</c> bits in a statistics summary block (RFC 3611 §4.6): whether the
/// TTL/Hop-Limit fields carry an IPv4 TTL, an IPv6 Hop Limit, or nothing.
/// </summary>
public enum RtcpTtlOrHopLimit : byte
{
    /// <summary>No TTL or Hop Limit data is present; the four TTL/HL octets are undefined.</summary>
    None = 0,

    /// <summary>The TTL/HL octets carry IPv4 time-to-live values.</summary>
    Ipv4TimeToLive = 1,

    /// <summary>The TTL/HL octets carry IPv6 hop-limit values.</summary>
    Ipv6HopLimit = 2,

    /// <summary>Reserved.</summary>
    Reserved = 3,
}

/// <summary>
/// Statistics summary report block, RFC 3611 §4.6: aggregate loss, duplicate, jitter and TTL/Hop-Limit
/// statistics for one source over the sequence-number range <see cref="BeginSequence"/> (inclusive)
/// to <see cref="EndSequence"/> (exclusive). Presence flags mark which groups of fields are valid.
/// </summary>
public sealed class RtcpStatisticsSummaryReportBlock : RtcpExtendedReportBlock
{
    /// <summary>Content length in bytes: the fixed 36-octet body of RFC 3611 §4.6.</summary>
    private const int ContentLength = 36;

    /// <summary>SSRC of the source these statistics describe.</summary>
    public uint SourceSsrc { get; set; }

    /// <summary>First sequence number this block reports on (inclusive).</summary>
    public ushort BeginSequence { get; set; }

    /// <summary>Sequence number one past the last this block reports on (exclusive).</summary>
    public ushort EndSequence { get; set; }

    /// <summary>The <c>L</c> flag: <see cref="LostPackets"/> is valid.</summary>
    public bool HasLossReport { get; set; }

    /// <summary>The <c>D</c> flag: <see cref="DuplicatePackets"/> is valid.</summary>
    public bool HasDuplicateReport { get; set; }

    /// <summary>The <c>J</c> flag: the four jitter fields are valid.</summary>
    public bool HasJitterReport { get; set; }

    /// <summary>The <c>ToH</c> field: whether the TTL/Hop-Limit fields are valid and which they carry.</summary>
    public RtcpTtlOrHopLimit TtlOrHopLimit { get; set; }

    /// <summary>Number of lost packets in the range; valid only when <see cref="HasLossReport"/>.</summary>
    public uint LostPackets { get; set; }

    /// <summary>Number of duplicate packets in the range; valid only when <see cref="HasDuplicateReport"/>.</summary>
    public uint DuplicatePackets { get; set; }

    /// <summary>Minimum interarrival jitter in the range; valid only when <see cref="HasJitterReport"/>.</summary>
    public uint MinJitter { get; set; }

    /// <summary>Maximum interarrival jitter in the range; valid only when <see cref="HasJitterReport"/>.</summary>
    public uint MaxJitter { get; set; }

    /// <summary>Mean interarrival jitter in the range; valid only when <see cref="HasJitterReport"/>.</summary>
    public uint MeanJitter { get; set; }

    /// <summary>Standard deviation of interarrival jitter; valid only when <see cref="HasJitterReport"/>.</summary>
    public uint DevJitter { get; set; }

    /// <summary>Minimum TTL or Hop Limit; valid only when <see cref="TtlOrHopLimit"/> is not <see cref="RtcpTtlOrHopLimit.None"/>.</summary>
    public byte MinTtlOrHopLimit { get; set; }

    /// <summary>Maximum TTL or Hop Limit; valid only when <see cref="TtlOrHopLimit"/> is not <see cref="RtcpTtlOrHopLimit.None"/>.</summary>
    public byte MaxTtlOrHopLimit { get; set; }

    /// <summary>Mean TTL or Hop Limit; valid only when <see cref="TtlOrHopLimit"/> is not <see cref="RtcpTtlOrHopLimit.None"/>.</summary>
    public byte MeanTtlOrHopLimit { get; set; }

    /// <summary>Standard deviation of TTL or Hop Limit; valid only when <see cref="TtlOrHopLimit"/> is not <see cref="RtcpTtlOrHopLimit.None"/>.</summary>
    public byte DevTtlOrHopLimit { get; set; }

    /// <inheritdoc />
    public override byte BlockType => (byte)RtcpExtendedReportBlockType.StatisticsSummary;

    /// <inheritdoc />
    public override int Length => HeaderLength + ContentLength;

    /// <summary>Parses a statistics summary report block.</summary>
    /// <param name="block">The complete block, header included.</param>
    /// <param name="parsed">On success, the parsed block.</param>
    /// <returns><see langword="false"/> when the block is malformed or truncated.</returns>
    public static bool TryParse(ReadOnlySpan<byte> block, out RtcpStatisticsSummaryReportBlock? parsed)
    {
        parsed = null;
        if (!TryReadHeader(block, out var blockType, out var typeSpecific, out var body)
            || blockType != (byte)RtcpExtendedReportBlockType.StatisticsSummary
            || body.Length < ContentLength)
        {
            return false;
        }

        var reader = new ByteReader(body);
        parsed = new RtcpStatisticsSummaryReportBlock
        {
            HasLossReport = (typeSpecific & 0x80) != 0,
            HasDuplicateReport = (typeSpecific & 0x40) != 0,
            HasJitterReport = (typeSpecific & 0x20) != 0,
            TtlOrHopLimit = (RtcpTtlOrHopLimit)((typeSpecific >> 3) & 0x03),
            SourceSsrc = reader.ReadU32(),
            BeginSequence = reader.ReadU16(),
            EndSequence = reader.ReadU16(),
            LostPackets = reader.ReadU32(),
            DuplicatePackets = reader.ReadU32(),
            MinJitter = reader.ReadU32(),
            MaxJitter = reader.ReadU32(),
            MeanJitter = reader.ReadU32(),
            DevJitter = reader.ReadU32(),
            MinTtlOrHopLimit = reader.ReadU8(),
            MaxTtlOrHopLimit = reader.ReadU8(),
            MeanTtlOrHopLimit = reader.ReadU8(),
            DevTtlOrHopLimit = reader.ReadU8(),
        };
        return true;
    }

    /// <inheritdoc />
    public override int WriteTo(Span<byte> destination)
    {
        var typeSpecific = (byte)(
            (HasLossReport ? 0x80 : 0)
            | (HasDuplicateReport ? 0x40 : 0)
            | (HasJitterReport ? 0x20 : 0)
            | (((byte)TtlOrHopLimit & 0x03) << 3));

        var offset = WriteBlockHeader(destination, typeSpecific);
        var writer = new ByteWriter(destination[offset..]);
        writer.WriteU32(SourceSsrc);
        writer.WriteU16(BeginSequence);
        writer.WriteU16(EndSequence);
        writer.WriteU32(LostPackets);
        writer.WriteU32(DuplicatePackets);
        writer.WriteU32(MinJitter);
        writer.WriteU32(MaxJitter);
        writer.WriteU32(MeanJitter);
        writer.WriteU32(DevJitter);
        writer.WriteU8(MinTtlOrHopLimit);
        writer.WriteU8(MaxTtlOrHopLimit);
        writer.WriteU8(MeanTtlOrHopLimit);
        writer.WriteU8(DevTtlOrHopLimit);
        return offset + writer.Position;
    }
}
