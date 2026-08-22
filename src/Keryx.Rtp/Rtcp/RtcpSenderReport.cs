using Keryx.Core;

namespace Keryx.Rtp.Rtcp;

/// <summary>Sender report, RFC 3550 §6.4.1.</summary>
public sealed class RtcpSenderReport : RtcpPacket
{
    /// <summary>
    /// Length in bytes of the sender SSRC plus the 20-octet sender information block of RFC 3550
    /// §6.4.1, i.e. everything between the common header and the first report block.
    /// </summary>
    public const int SenderInfoLength = 24;

    /// <summary>Maximum number of report blocks a single report can carry; the RC field is five bits wide.</summary>
    public const int MaxReportBlocks = 31;

    private readonly List<RtcpReportBlock> _reportBlocks = [];

    /// <summary>SSRC of the sender originating this report.</summary>
    public uint SenderSsrc { get; set; }

    /// <summary>Wall-clock time the report was sent, as a 64-bit NTP timestamp (see <see cref="NtpTime"/>).</summary>
    public ulong NtpTimestamp { get; set; }

    /// <summary>The RTP timestamp corresponding to <see cref="NtpTimestamp"/>.</summary>
    public uint RtpTimestamp { get; set; }

    /// <summary>Total number of RTP data packets sent by this source since transmission started.</summary>
    public uint PacketCount { get; set; }

    /// <summary>Total number of payload octets sent by this source since transmission started.</summary>
    public uint OctetCount { get; set; }

    /// <summary>Reception report blocks appended to this report; at most <see cref="MaxReportBlocks"/>.</summary>
    public IList<RtcpReportBlock> ReportBlocks => _reportBlocks;

    /// <inheritdoc />
    public override RtcpPacketType PacketType => RtcpPacketType.SenderReport;

    /// <inheritdoc />
    public override int Length =>
        RtcpPacketHeader.Length + SenderInfoLength + (_reportBlocks.Count * RtcpReportBlock.Length);

    /// <summary>Parses a sender report.</summary>
    /// <param name="buffer">The complete packet, common header included.</param>
    /// <param name="report">On success, the parsed report.</param>
    /// <returns><see langword="false"/> when the packet is truncated or its length disagrees with the report count.</returns>
    public static bool TryParse(ReadOnlySpan<byte> buffer, out RtcpSenderReport? report)
    {
        report = null;
        if (!RtcpPacketHeader.TryParse(buffer, out var header)
            || header.PacketType != RtcpPacketType.SenderReport
            || header.PacketLength > buffer.Length)
        {
            return false;
        }

        var expected = RtcpPacketHeader.Length + SenderInfoLength + (header.Count * RtcpReportBlock.Length);
        if (header.PacketLength < expected)
        {
            return false;
        }

        try
        {
            var reader = new ByteReader(buffer[..header.PacketLength]);
            reader.Skip(RtcpPacketHeader.Length);
            var parsed = new RtcpSenderReport
            {
                SenderSsrc = reader.ReadU32(),
                NtpTimestamp = reader.ReadU64(),
                RtpTimestamp = reader.ReadU32(),
                PacketCount = reader.ReadU32(),
                OctetCount = reader.ReadU32(),
            };

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
        if (_reportBlocks.Count > MaxReportBlocks)
        {
            throw new InvalidOperationException($"A sender report carries at most {MaxReportBlocks} report blocks.");
        }

        var offset = WriteCommonHeader(destination, (byte)_reportBlocks.Count);
        var writer = new ByteWriter(destination[offset..]);
        writer.WriteU32(SenderSsrc);
        writer.WriteU64(NtpTimestamp);
        writer.WriteU32(RtpTimestamp);
        writer.WriteU32(PacketCount);
        writer.WriteU32(OctetCount);
        offset += writer.Position;

        foreach (var block in _reportBlocks)
        {
            offset += block.WriteTo(destination[offset..]);
        }

        return offset;
    }
}
