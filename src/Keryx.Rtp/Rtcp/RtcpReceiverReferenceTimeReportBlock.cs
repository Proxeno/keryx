using Keryx.Core;

namespace Keryx.Rtp.Rtcp;

/// <summary>
/// Receiver reference time report block, RFC 3611 §4.4: a receiver's own 64-bit NTP-format wall-clock
/// timestamp. Paired with a <see cref="RtcpDelaySinceLastReceiverReportBlock"/> from the far end, it
/// lets a non-sending receiver measure round-trip time (RFC 3611 §4.5).
/// </summary>
public sealed class RtcpReceiverReferenceTimeReportBlock : RtcpExtendedReportBlock
{
    /// <summary>Content length in bytes: a single 64-bit NTP timestamp.</summary>
    private const int ContentLength = 8;

    /// <summary>The receiver's wall-clock time as a 64-bit NTP timestamp (see <see cref="NtpTime"/>).</summary>
    public ulong NtpTimestamp { get; set; }

    /// <inheritdoc />
    public override byte BlockType => (byte)RtcpExtendedReportBlockType.ReceiverReferenceTime;

    /// <inheritdoc />
    public override int Length => HeaderLength + ContentLength;

    /// <summary>Parses a receiver reference time report block.</summary>
    /// <param name="block">The complete block, header included.</param>
    /// <param name="parsed">On success, the parsed block.</param>
    /// <returns><see langword="false"/> when the block is malformed or truncated.</returns>
    public static bool TryParse(ReadOnlySpan<byte> block, out RtcpReceiverReferenceTimeReportBlock? parsed)
    {
        parsed = null;
        if (!TryReadHeader(block, out var blockType, out _, out var body)
            || blockType != (byte)RtcpExtendedReportBlockType.ReceiverReferenceTime
            || body.Length < ContentLength)
        {
            return false;
        }

        var reader = new ByteReader(body);
        parsed = new RtcpReceiverReferenceTimeReportBlock { NtpTimestamp = reader.ReadU64() };
        return true;
    }

    /// <inheritdoc />
    public override int WriteTo(Span<byte> destination)
    {
        var offset = WriteBlockHeader(destination, 0);
        var writer = new ByteWriter(destination[offset..]);
        writer.WriteU64(NtpTimestamp);
        return offset + writer.Position;
    }
}
