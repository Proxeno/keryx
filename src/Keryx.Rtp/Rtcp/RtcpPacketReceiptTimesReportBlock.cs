using Keryx.Core;

namespace Keryx.Rtp.Rtcp;

/// <summary>
/// Packet receipt times report block, RFC 3611 §4.3: the RTP-timestamp-clock receipt time of each
/// packet across the sequence-number range <see cref="BeginSequence"/> (inclusive) to
/// <see cref="EndSequence"/> (exclusive).
/// </summary>
public sealed class RtcpPacketReceiptTimesReportBlock : RtcpExtendedReportBlock
{
    private readonly List<uint> _receiptTimes = [];

    /// <summary>SSRC of the source these receipt times describe.</summary>
    public uint SourceSsrc { get; set; }

    /// <summary>
    /// Thinning value (the low four bits of the type-specific field): only sequence numbers that are
    /// zero modulo 2^T are reported.
    /// </summary>
    public byte Thinning { get; set; }

    /// <summary>First sequence number this block reports on (inclusive).</summary>
    public ushort BeginSequence { get; set; }

    /// <summary>Sequence number one past the last this block reports on (exclusive).</summary>
    public ushort EndSequence { get; set; }

    /// <summary>Receipt time of each reported packet, in the units of the source's RTP timestamp clock.</summary>
    public IList<uint> ReceiptTimes => _receiptTimes;

    /// <inheritdoc />
    public override byte BlockType => (byte)RtcpExtendedReportBlockType.PacketReceiptTimes;

    /// <inheritdoc />
    public override int Length => HeaderLength + 8 + (_receiptTimes.Count * 4);

    /// <summary>Parses a packet receipt times report block.</summary>
    /// <param name="block">The complete block, header included.</param>
    /// <param name="parsed">On success, the parsed block.</param>
    /// <returns><see langword="false"/> when the block is malformed or truncated.</returns>
    public static bool TryParse(ReadOnlySpan<byte> block, out RtcpPacketReceiptTimesReportBlock? parsed)
    {
        parsed = null;
        if (!TryReadHeader(block, out var blockType, out var typeSpecific, out var body)
            || blockType != (byte)RtcpExtendedReportBlockType.PacketReceiptTimes)
        {
            return false;
        }

        try
        {
            var reader = new ByteReader(body);
            var candidate = new RtcpPacketReceiptTimesReportBlock
            {
                SourceSsrc = reader.ReadU32(),
                BeginSequence = reader.ReadU16(),
                EndSequence = reader.ReadU16(),
                Thinning = (byte)(typeSpecific & 0x0F),
            };

            while (reader.Remaining >= 4)
            {
                candidate._receiptTimes.Add(reader.ReadU32());
            }

            parsed = candidate;
            return true;
        }
        catch (ByteBufferException)
        {
            return false;
        }
    }

    /// <inheritdoc />
    public override int WriteTo(Span<byte> destination)
    {
        var offset = WriteBlockHeader(destination, (byte)(Thinning & 0x0F));
        var writer = new ByteWriter(destination[offset..]);
        writer.WriteU32(SourceSsrc);
        writer.WriteU16(BeginSequence);
        writer.WriteU16(EndSequence);
        foreach (var receiptTime in _receiptTimes)
        {
            writer.WriteU32(receiptTime);
        }

        return offset + writer.Position;
    }
}
