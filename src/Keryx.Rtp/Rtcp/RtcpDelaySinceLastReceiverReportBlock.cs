using Keryx.Core;

namespace Keryx.Rtp.Rtcp;

/// <summary>
/// One receiver's sub-block within a DLRR report block (RFC 3611 §4.5): the SSRC being reported on,
/// the middle 32 bits of the last receiver reference time received from it, and the delay since.
/// </summary>
/// <param name="Ssrc">SSRC of the receiver whose reference time is echoed.</param>
/// <param name="LastReceiverReport">
/// Middle 32 bits (the <c>LRR</c> field) of the NTP timestamp from that receiver's most recent
/// <see cref="RtcpReceiverReferenceTimeReportBlock"/>, or zero if none has been received.
/// </param>
/// <param name="DelaySinceLastReceiverReport">
/// Delay between receiving that reference time and sending this block, in units of 1/65536 second.
/// </param>
public readonly record struct RtcpDlrrSubBlock(
    uint Ssrc, uint LastReceiverReport, uint DelaySinceLastReceiverReport)
{
    /// <summary>Length of a DLRR sub-block in bytes.</summary>
    public const int Length = 12;
}

/// <summary>
/// Delay since the last receiver report (DLRR) block, RFC 3611 §4.5: the sender's reply to one or
/// more <see cref="RtcpReceiverReferenceTimeReportBlock"/>s, letting a non-sending receiver compute
/// round-trip time exactly as a sender does from an RR's LSR/DLSR fields.
/// </summary>
public sealed class RtcpDelaySinceLastReceiverReportBlock : RtcpExtendedReportBlock
{
    private readonly List<RtcpDlrrSubBlock> _subBlocks = [];

    /// <summary>One sub-block per receiver being replied to.</summary>
    public IList<RtcpDlrrSubBlock> SubBlocks => _subBlocks;

    /// <inheritdoc />
    public override byte BlockType => (byte)RtcpExtendedReportBlockType.DelaySinceLastReceiverReport;

    /// <inheritdoc />
    public override int Length => HeaderLength + (_subBlocks.Count * RtcpDlrrSubBlock.Length);

    /// <summary>Parses a DLRR report block.</summary>
    /// <param name="block">The complete block, header included.</param>
    /// <param name="parsed">On success, the parsed block.</param>
    /// <returns><see langword="false"/> when the block is malformed or truncated.</returns>
    public static bool TryParse(ReadOnlySpan<byte> block, out RtcpDelaySinceLastReceiverReportBlock? parsed)
    {
        parsed = null;
        if (!TryReadHeader(block, out var blockType, out _, out var body)
            || blockType != (byte)RtcpExtendedReportBlockType.DelaySinceLastReceiverReport)
        {
            return false;
        }

        try
        {
            var reader = new ByteReader(body);
            var candidate = new RtcpDelaySinceLastReceiverReportBlock();
            while (reader.Remaining >= RtcpDlrrSubBlock.Length)
            {
                candidate._subBlocks.Add(new RtcpDlrrSubBlock(reader.ReadU32(), reader.ReadU32(), reader.ReadU32()));
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
        var offset = WriteBlockHeader(destination, 0);
        var writer = new ByteWriter(destination[offset..]);
        foreach (var sub in _subBlocks)
        {
            writer.WriteU32(sub.Ssrc);
            writer.WriteU32(sub.LastReceiverReport);
            writer.WriteU32(sub.DelaySinceLastReceiverReport);
        }

        return offset + writer.Position;
    }
}
