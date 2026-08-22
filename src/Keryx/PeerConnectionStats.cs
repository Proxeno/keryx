using Keryx.Dtls;
using Keryx.Ice;

namespace Keryx;

/// <summary>
/// What the peer most recently reported about one stream this endpoint sends, from an RTCP reception
/// report block (RFC 3550 §6.4.1).
/// </summary>
/// <remarks>
/// This is the link-quality signal a sender-side rate controller reads: <see cref="FractionLost"/> and
/// <see cref="RoundTripTime"/> move within one reporting interval, while
/// <see cref="CumulativePacketsLost"/> and <see cref="Jitter"/> describe the session so far.
/// </remarks>
public sealed record OutboundStreamQuality
{
    /// <summary>Creates a quality snapshot.</summary>
    /// <param name="ssrc">The reported stream's synchronisation source.</param>
    /// <param name="fractionLost">Fraction of packets lost since the previous report, 0 to 1.</param>
    /// <param name="cumulativePacketsLost">Signed cumulative packets lost since the session began.</param>
    /// <param name="extendedHighestSequenceNumber">Extended highest sequence number the peer received.</param>
    /// <param name="jitter">Interarrival jitter in the codec's timestamp units.</param>
    /// <param name="jitterInterval">The same jitter as a duration, when the clock rate is known.</param>
    /// <param name="roundTripTime">Round-trip time from LSR/DLSR, when the peer has heard a sender report.</param>
    /// <param name="reportedAt">The wall-clock instant the report arrived.</param>
    public OutboundStreamQuality(
        uint ssrc,
        double fractionLost,
        int cumulativePacketsLost,
        uint extendedHighestSequenceNumber,
        uint jitter,
        TimeSpan? jitterInterval,
        TimeSpan? roundTripTime,
        DateTimeOffset reportedAt)
    {
        Ssrc = ssrc;
        FractionLost = fractionLost;
        CumulativePacketsLost = cumulativePacketsLost;
        ExtendedHighestSequenceNumber = extendedHighestSequenceNumber;
        Jitter = jitter;
        JitterInterval = jitterInterval;
        RoundTripTime = roundTripTime;
        ReportedAt = reportedAt;
    }

    /// <summary>The synchronisation source the report block described.</summary>
    public uint Ssrc { get; }

    /// <summary>
    /// Packets lost since the previous report, as a fraction from 0 to 1. The wire field is an eighth
    /// of a fixed-point fraction with denominator 256; this is that value divided out.
    /// </summary>
    public double FractionLost { get; }

    /// <summary>
    /// Cumulative packets lost since the session began. Signed: duplicates can drive it negative.
    /// </summary>
    public int CumulativePacketsLost { get; }

    /// <summary>The extended highest sequence number the peer reports having received.</summary>
    public uint ExtendedHighestSequenceNumber { get; }

    /// <summary>Interarrival jitter in the stream's RTP timestamp units.</summary>
    public uint Jitter { get; }

    /// <summary>
    /// <see cref="Jitter"/> converted with the negotiated clock rate, or <see langword="null"/> when no
    /// clock rate is known for the stream.
    /// </summary>
    public TimeSpan? JitterInterval { get; }

    /// <summary>
    /// Round-trip time computed from the report's LSR and DLSR fields (RFC 3550 §6.4.1), or
    /// <see langword="null"/> until the peer has received a sender report from this endpoint.
    /// </summary>
    public TimeSpan? RoundTripTime { get; }

    /// <summary>The wall-clock instant the report carrying this block arrived.</summary>
    public DateTimeOffset ReportedAt { get; }
}

/// <summary>Counters for one RFC 4588 retransmission stream.</summary>
/// <param name="RtxSsrc">The repair stream's synchronisation source.</param>
/// <param name="RtxPayloadType">The negotiated <c>rtx</c> payload type.</param>
/// <param name="NacksReceived">Generic NACK packets received for this media stream.</param>
/// <param name="NackRequestedPackets">Sequence numbers those NACKs asked for, bitmasks expanded.</param>
/// <param name="PacketsRetransmitted">RTX packets sent.</param>
/// <param name="BytesRetransmitted">Bytes of RTX packets sent, RTP headers and OSN included.</param>
/// <param name="HistoryMisses">Requests for a packet that had already left the send history.</param>
/// <param name="Suppressed">Requests dropped by the resend rate limit or the bandwidth budget.</param>
public readonly record struct RetransmissionStats(
    uint RtxSsrc,
    byte RtxPayloadType,
    long NacksReceived,
    long NackRequestedPackets,
    long PacketsRetransmitted,
    long BytesRetransmitted,
    long HistoryMisses,
    long Suppressed);

/// <summary>Transmission counters for one outbound RTP stream.</summary>
/// <param name="Kind">Whether the track carries audio or video.</param>
/// <param name="Mid">The <c>a=mid</c> of the track's m-section.</param>
/// <param name="Ssrc">The stream's synchronisation source.</param>
/// <param name="PayloadType">The negotiated payload type in use.</param>
/// <param name="PacketsSent">RTP packets handed to SRTP and sent, retransmissions excluded.</param>
/// <param name="BytesSent">RTP payload octets sent, excluding headers and SRTP overhead.</param>
/// <param name="FramesSent">Encoded frames (video access units, audio packets) packetized.</param>
/// <param name="FramesDropped">Frames discarded because the connection was not yet <see cref="PeerConnectionState.Connected"/>.</param>
/// <param name="Quality">
/// What the peer last reported about this stream, or <see langword="null"/> before the first reception
/// report block naming it arrives.
/// </param>
/// <param name="Retransmission">
/// Retransmission counters, or <see langword="null"/> when RFC 4588 RTX was not negotiated for the
/// track.
/// </param>
public readonly record struct MediaTrackStats(
    MediaKind Kind,
    string Mid,
    uint Ssrc,
    byte PayloadType,
    long PacketsSent,
    long BytesSent,
    long FramesSent,
    long FramesDropped,
    OutboundStreamQuality? Quality = null,
    RetransmissionStats? Retransmission = null);

/// <summary>Counts of the typed RTCP feedback received from the peer.</summary>
/// <param name="PictureLossIndications">Picture Loss Indications received.</param>
/// <param name="FullIntraRequests">Full Intra Requests received.</param>
/// <param name="Nacks">Generic NACK packets received.</param>
/// <param name="TransportCcFeedbacks">Transport-wide congestion control feedback packets received.</param>
/// <param name="ReceiverReports">Receiver reports (and sender reports carrying report blocks) received.</param>
public readonly record struct FeedbackStats(
    long PictureLossIndications,
    long FullIntraRequests,
    long Nacks,
    long TransportCcFeedbacks,
    long ReceiverReports);

/// <summary>A small point-in-time snapshot of a <see cref="PeerConnection"/>.</summary>
/// <param name="State">The connection state.</param>
/// <param name="IceState">The ICE agent's state.</param>
/// <param name="DtlsState">The DTLS transport's state.</param>
/// <param name="Video">Counters for the outbound video track, when one exists.</param>
/// <param name="Audio">Counters for the outbound audio track, when one exists.</param>
/// <param name="Feedback">Counts of typed RTCP feedback received.</param>
/// <param name="RtpPacketsReceived">Inbound RTP packets that decrypted and parsed.</param>
/// <param name="RtcpPacketsReceived">Inbound SRTCP datagrams that decrypted.</param>
/// <param name="SrtpAuthenticationFailures">Inbound media datagrams SRTP rejected (bad tag or replay).</param>
/// <param name="MediaDroppedBeforeReady">Inbound media datagrams discarded because SRTP was not keyed yet.</param>
public readonly record struct PeerConnectionStats(
    PeerConnectionState State,
    IceAgentState IceState,
    DtlsTransportState DtlsState,
    MediaTrackStats? Video,
    MediaTrackStats? Audio,
    FeedbackStats Feedback,
    long RtpPacketsReceived,
    long RtcpPacketsReceived,
    long SrtpAuthenticationFailures,
    long MediaDroppedBeforeReady);
