namespace Keryx.Rtp.Rtcp;

/// <summary>Loss RLE report block, RFC 3611 §4.1: which packets in a sequence range were lost.</summary>
public sealed class RtcpLossRleReportBlock : RtcpRunLengthEncodedReportBlock
{
    /// <inheritdoc />
    public override byte BlockType => (byte)RtcpExtendedReportBlockType.LossRle;

    /// <summary>Parses a Loss RLE report block.</summary>
    /// <param name="block">The complete block, header included.</param>
    /// <param name="parsed">On success, the parsed block.</param>
    /// <returns><see langword="false"/> when the block is malformed or truncated.</returns>
    public static bool TryParse(ReadOnlySpan<byte> block, out RtcpLossRleReportBlock? parsed)
    {
        var candidate = new RtcpLossRleReportBlock();
        if (!candidate.TryLoad(block, RtcpExtendedReportBlockType.LossRle))
        {
            parsed = null;
            return false;
        }

        parsed = candidate;
        return true;
    }
}
