using Keryx.Dtls;
using Keryx.Ice;

namespace Keryx;

/// <summary>Transmission counters for one outbound RTP stream.</summary>
/// <param name="Kind">Whether the track carries audio or video.</param>
/// <param name="Mid">The <c>a=mid</c> of the track's m-section.</param>
/// <param name="Ssrc">The stream's synchronisation source.</param>
/// <param name="PayloadType">The negotiated payload type in use.</param>
/// <param name="PacketsSent">RTP packets handed to SRTP and sent.</param>
/// <param name="BytesSent">RTP payload octets sent, excluding headers and SRTP overhead.</param>
/// <param name="FramesSent">Encoded frames (video access units, audio packets) packetized.</param>
/// <param name="FramesDropped">Frames discarded because the connection was not yet <see cref="PeerConnectionState.Connected"/>.</param>
public readonly record struct MediaTrackStats(
    MediaKind Kind,
    string Mid,
    uint Ssrc,
    byte PayloadType,
    long PacketsSent,
    long BytesSent,
    long FramesSent,
    long FramesDropped);

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
