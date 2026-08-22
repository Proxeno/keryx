namespace Keryx.Rtp.Simulcast;

/// <summary>The RTCP feedback a keyframe request is issued as, once a coalescer has resolved which
/// upstream SSRC to ask.</summary>
public enum KeyframeRequestKind
{
    /// <summary>Picture Loss Indication (RFC 4585): the common, low-overhead keyframe request.</summary>
    PictureLossIndication,

    /// <summary>
    /// Full Intra Request (RFC 5104): carries a per-source command sequence number and is used when the
    /// receiver needs an authoritative intra frame rather than a best-effort one.
    /// </summary>
    FullIntraRequest,
}
