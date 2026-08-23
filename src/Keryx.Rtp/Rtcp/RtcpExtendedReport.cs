using Keryx.Core;

namespace Keryx.Rtp.Rtcp;

/// <summary>
/// Extended report, RFC 3611 §2: a sender or receiver SSRC followed by a sequence of typed report
/// blocks. Blocks Keryx does not model are preserved as
/// <see cref="RtcpUnknownExtendedReportBlock"/> so an XR round-trips without loss.
/// </summary>
public sealed class RtcpExtendedReport : RtcpPacket
{
    /// <summary>Length in bytes of the sender SSRC that follows the common header.</summary>
    public const int SenderInfoLength = 4;

    private readonly List<RtcpExtendedReportBlock> _reportBlocks = [];

    /// <summary>SSRC of the originator of this extended report.</summary>
    public uint SenderSsrc { get; set; }

    /// <summary>The report blocks carried by this extended report, in wire order.</summary>
    public IList<RtcpExtendedReportBlock> ReportBlocks => _reportBlocks;

    /// <inheritdoc />
    public override RtcpPacketType PacketType => RtcpPacketType.ExtendedReport;

    /// <inheritdoc />
    public override int Length
    {
        get
        {
            var length = RtcpPacketHeader.Length + SenderInfoLength;
            foreach (var block in _reportBlocks)
            {
                length += block.Length;
            }

            return length;
        }
    }

    /// <summary>Parses an extended report.</summary>
    /// <param name="buffer">The complete packet, common header included.</param>
    /// <param name="report">On success, the parsed report.</param>
    /// <returns><see langword="false"/> when the packet is truncated or a report block is malformed.</returns>
    public static bool TryParse(ReadOnlySpan<byte> buffer, out RtcpExtendedReport? report)
    {
        report = null;
        if (!RtcpPacketHeader.TryParse(buffer, out var header)
            || header.PacketType != RtcpPacketType.ExtendedReport
            || header.PacketLength > buffer.Length
            || header.PacketLength < RtcpPacketHeader.Length + SenderInfoLength)
        {
            return false;
        }

        try
        {
            var span = buffer[..header.PacketLength];
            var reader = new ByteReader(span);
            reader.Skip(RtcpPacketHeader.Length);
            var parsed = new RtcpExtendedReport { SenderSsrc = reader.ReadU32() };

            while (reader.Remaining > 0)
            {
                // A report block is at least its four-byte header; a trailing scrap smaller than that
                // is a malformed report, not a block to skip.
                if (reader.Remaining < RtcpExtendedReportBlock.HeaderLength)
                {
                    return false;
                }

                var blockSpan = reader.Peek();
                if (!RtcpExtendedReportBlock.TryParse(blockSpan, out var block) || block is null)
                {
                    return false;
                }

                parsed._reportBlocks.Add(block);
                reader.Skip(block.Length);
            }

            report = parsed;
            return true;
        }
        catch (ByteBufferException)
        {
            report = null;
            return false;
        }
    }

    /// <inheritdoc />
    public override int WriteTo(Span<byte> destination)
    {
        // The five-bit count field is reserved for XR (RFC 3611 §2) and must be sent as zero.
        var offset = WriteCommonHeader(destination, 0);
        var writer = new ByteWriter(destination[offset..]);
        writer.WriteU32(SenderSsrc);
        offset += writer.Position;

        foreach (var block in _reportBlocks)
        {
            offset += block.WriteTo(destination[offset..]);
        }

        return offset;
    }
}
