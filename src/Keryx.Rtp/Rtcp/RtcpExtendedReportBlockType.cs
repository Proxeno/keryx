namespace Keryx.Rtp.Rtcp;

/// <summary>
/// Extended report block types (the BT field) carried inside an RTCP extended report,
/// registered by RFC 3611 §4 and its IANA table.
/// </summary>
public enum RtcpExtendedReportBlockType : byte
{
    /// <summary>Loss RLE report block, RFC 3611 §4.1.</summary>
    LossRle = 1,

    /// <summary>Duplicate RLE report block, RFC 3611 §4.2.</summary>
    DuplicateRle = 2,

    /// <summary>Packet receipt times report block, RFC 3611 §4.3.</summary>
    PacketReceiptTimes = 3,

    /// <summary>Receiver reference time report block, RFC 3611 §4.4.</summary>
    ReceiverReferenceTime = 4,

    /// <summary>Delay since the last receiver report (DLRR) block, RFC 3611 §4.5.</summary>
    DelaySinceLastReceiverReport = 5,

    /// <summary>Statistics summary report block, RFC 3611 §4.6.</summary>
    StatisticsSummary = 6,

    /// <summary>VoIP metrics report block, RFC 3611 §4.7.</summary>
    VoipMetrics = 7,
}
