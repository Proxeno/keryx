namespace Keryx.Rtp.Rtcp;

/// <summary>Duplicate RLE report block, RFC 3611 §4.2: which packets in a sequence range were duplicated.</summary>
public sealed class RtcpDuplicateRleReportBlock : RtcpRunLengthEncodedReportBlock
{
    /// <inheritdoc />
    public override byte BlockType => (byte)RtcpExtendedReportBlockType.DuplicateRle;

    /// <summary>Parses a Duplicate RLE report block.</summary>
    /// <param name="block">The complete block, header included.</param>
    /// <param name="parsed">On success, the parsed block.</param>
    /// <returns><see langword="false"/> when the block is malformed or truncated.</returns>
    public static bool TryParse(ReadOnlySpan<byte> block, out RtcpDuplicateRleReportBlock? parsed)
    {
        var candidate = new RtcpDuplicateRleReportBlock();
        if (!candidate.TryLoad(block, RtcpExtendedReportBlockType.DuplicateRle))
        {
            parsed = null;
            return false;
        }

        parsed = candidate;
        return true;
    }
}
