namespace Keryx.Rtp.Rtcp;

/// <summary>RTCP packet types (RFC 3550 §12.1 and the feedback profiles that extend it).</summary>
public enum RtcpPacketType : byte
{
    /// <summary>Sender report, RFC 3550 §6.4.1.</summary>
    SenderReport = 200,

    /// <summary>Receiver report, RFC 3550 §6.4.2.</summary>
    ReceiverReport = 201,

    /// <summary>Source description, RFC 3550 §6.5.</summary>
    SourceDescription = 202,

    /// <summary>Goodbye, RFC 3550 §6.6.</summary>
    Goodbye = 203,

    /// <summary>Application-defined, RFC 3550 §6.7.</summary>
    ApplicationDefined = 204,

    /// <summary>Transport-layer feedback, RFC 4585 §6.2 (NACK, transport-wide congestion control).</summary>
    TransportLayerFeedback = 205,

    /// <summary>Payload-specific feedback, RFC 4585 §6.3 (PLI, FIR, REMB).</summary>
    PayloadSpecificFeedback = 206,

    /// <summary>Extended report, RFC 3611.</summary>
    ExtendedReport = 207,
}

/// <summary>
/// Feedback message types (the FMT field) for <see cref="RtcpPacketType.TransportLayerFeedback"/>.
/// </summary>
public enum RtcpTransportFeedbackType : byte
{
    /// <summary>Generic NACK, RFC 4585 §6.2.1.</summary>
    GenericNack = 1,

    /// <summary>Transport-wide congestion control feedback, <c>draft-holmer-rmcat-transport-wide-cc-extensions-01</c> §3.1.</summary>
    TransportCc = 15,
}

/// <summary>
/// Feedback message types (the FMT field) for <see cref="RtcpPacketType.PayloadSpecificFeedback"/>.
/// </summary>
public enum RtcpPayloadFeedbackType : byte
{
    /// <summary>Picture loss indication, RFC 4585 §6.3.1.</summary>
    PictureLossIndication = 1,

    /// <summary>Slice loss indication, RFC 4585 §6.3.2.</summary>
    SliceLossIndication = 2,

    /// <summary>Reference picture selection indication, RFC 4585 §6.3.3.</summary>
    ReferencePictureSelectionIndication = 3,

    /// <summary>Full intra request, RFC 5104 §4.3.1.</summary>
    FullIntraRequest = 4,

    /// <summary>Temporal-spatial trade-off request, RFC 5104 §4.3.2.</summary>
    TemporalSpatialTradeOffRequest = 5,

    /// <summary>Temporal-spatial trade-off notification, RFC 5104 §4.3.3.</summary>
    TemporalSpatialTradeOffNotification = 6,

    /// <summary>Video back channel message, RFC 5104 §4.3.4.</summary>
    VideoBackChannelMessage = 7,

    /// <summary>Application-layer feedback, RFC 4585 §6.4 — carries REMB.</summary>
    ApplicationLayerFeedback = 15,
}
