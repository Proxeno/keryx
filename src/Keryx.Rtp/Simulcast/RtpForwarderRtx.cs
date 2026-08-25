namespace Keryx.Rtp.Simulcast;

/// <summary>
/// Enables RFC 4588 retransmission on a <see cref="RtpForwarder"/>'s egress: the forwarder records
/// every packet it rewrites in a send history and answers a downstream subscriber's NACK for a
/// forwarded sequence number with an RTX packet on this repair stream's own SSRC and payload type.
/// </summary>
/// <remarks>
/// The forwarded stream is a full RTP stream the SFU owns (its <see cref="RtpForwarder.OutboundSsrc"/>
/// and rewritten sequence space), so its repair stream is a full stream in its own right too — the
/// second member of the subscriber's <c>a=ssrc-group:FID</c>, with its own <c>rtx</c> payload type and
/// sequence numbering. This mirrors <see cref="RtxRetransmitter"/>, which backs it.
/// </remarks>
/// <param name="Ssrc">The repair stream's SSRC. Must differ from <see cref="RtpForwarder.OutboundSsrc"/>.</param>
/// <param name="PayloadType">The negotiated <c>rtx</c> payload type stamped on retransmissions.</param>
/// <param name="MaxPacketSize">
/// Largest rewritten packet the send history must retain, header included. Sizes the history arena up
/// front; a rewritten packet larger than this is simply not retained and so cannot be repaired.
/// </param>
/// <param name="HistoryOptions">Retention limits for the send history; defaults are used when null.</param>
/// <param name="RetransmitOptions">Rate and bandwidth limits for retransmission; defaults are used when null.</param>
/// <param name="InitialSequenceNumber">Overrides the random initial RTX sequence number; for tests.</param>
/// <param name="TimeProvider">Clock used for retention and rate limiting; the system clock when null.</param>
public sealed record RtpForwarderRtx(
    uint Ssrc,
    byte PayloadType,
    int MaxPacketSize = 1500,
    RtpSendHistoryOptions? HistoryOptions = null,
    RtxRetransmitOptions? RetransmitOptions = null,
    ushort? InitialSequenceNumber = null,
    System.TimeProvider? TimeProvider = null);
