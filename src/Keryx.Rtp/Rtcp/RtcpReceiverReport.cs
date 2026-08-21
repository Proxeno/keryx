using Keryx.Core;

namespace Keryx.Rtp.Rtcp;

/// <summary>Receiver report, RFC 3550 §6.4.2.</summary>
public sealed class RtcpReceiverReport : RtcpPacket
{
    private readonly List<RtcpReportBlock> _reportBlocks = [];

    /// <summary>SSRC of the receiver originating this report.</summary>
    public uint SenderSsrc { get; set; }

    /// <summary>Reception report blocks; at most <see cref="RtcpSenderReport.MaxReportBlocks"/>.</summary>
    public IList<RtcpReportBlock> ReportBlocks => _reportBlocks;

    /// <inheritdoc />
    public override RtcpPacketType PacketType => RtcpPacketType.ReceiverReport;

    /// <inheritdoc />
    public override int Length =>
        RtcpPacketHeader.Length + 4 + (_reportBlocks.Count * RtcpReportBlock.Length);

    /// <summary>Parses a receiver report.</summary>
    /// <param name="buffer">The complete packet, common header included.</param>
    /// <param name="report">On success, the parsed report.</param>
    /// <returns><see langword="false"/> when the packet is truncated or its length disagrees with the report count.</returns>
    public static bool TryParse(ReadOnlySpan<byte> buffer, out RtcpReceiverReport? report)
    {
        report = null;
        if (!RtcpPacketHeader.TryParse(buffer, out var header)
            || header.PacketType != RtcpPacketType.ReceiverReport
            || header.PacketLength > buffer.Length)
        {
            return false;
        }

        var expected = RtcpPacketHeader.Length + 4 + (header.Count * RtcpReportBlock.Length);
        if (header.PacketLength < expected)
        {
            return false;
        }

        try
        {
            var reader = new ByteReader(buffer[..header.PacketLength]);
            reader.Skip(RtcpPacketHeader.Length);
            var parsed = new RtcpReceiverReport { SenderSsrc = reader.ReadU32() };

            for (var i = 0; i < header.Count; i++)
            {
                if (!RtcpReportBlock.TryParse(reader.ReadBytes(RtcpReportBlock.Length), out var block))
                {
                    return false;
                }

                parsed._reportBlocks.Add(block);
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
        if (_reportBlocks.Count > RtcpSenderReport.MaxReportBlocks)
        {
            throw new InvalidOperationException(
                $"A receiver report carries at most {RtcpSenderReport.MaxReportBlocks} report blocks.");
        }

        var offset = WriteCommonHeader(destination, (byte)_reportBlocks.Count);
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
