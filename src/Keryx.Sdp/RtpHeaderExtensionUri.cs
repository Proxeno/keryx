namespace Keryx.Sdp;

/// <summary>
/// URIs for the RTP header extensions Keryx negotiates through <c>a=extmap</c> (RFC 8285 §5, RFC 8852).
/// </summary>
/// <remarks>
/// The RID and repaired-RID extensions carry the RTP-stream identifiers that make simulcast demux
/// possible: an ingest SFU keys each incoming packet to a simulcast layer by the RID string these
/// extensions carry, falling back to the MID extension when a RID is absent (RFC 8852 §3, §4).
/// </remarks>
public static class RtpHeaderExtensionUri
{
    /// <summary>Media identification (MID): <c>urn:ietf:params:rtp-hdrext:sdes:mid</c> (RFC 8852 §4).</summary>
    public const string Mid = "urn:ietf:params:rtp-hdrext:sdes:mid";

    /// <summary>RTP stream identifier (RID): <c>urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id</c> (RFC 8852 §3).</summary>
    public const string Rid = "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id";

    /// <summary>
    /// Repaired RTP stream identifier: <c>urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id</c>
    /// (RFC 8852 §3). Carried on RFC 4588 retransmission (RTX) packets to name the layer they repair.
    /// </summary>
    public const string RepairedRid = "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id";

    /// <summary>Absolute send time: <c>http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time</c>.</summary>
    public const string AbsoluteSendTime = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";

    /// <summary>
    /// Transport-wide congestion control sequence number:
    /// <c>http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01</c>.
    /// </summary>
    public const string TransportWideCc =
        "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
}
