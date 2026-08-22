namespace Keryx.Rtp.Simulcast;

/// <summary>
/// How a <see cref="RtpForwarder"/> rewrites RFC 8285 one-byte header extensions on egress: the
/// ingest-only RID and repaired-RID elements are stripped, and the MID element is rewritten to the
/// subscriber's negotiated MID (RFC 8843 BUNDLE). Element ids left at <c>0</c> are not touched.
/// </summary>
/// <param name="RidElementId">
/// The negotiated RID (<c>rtp-stream-id</c>) element id to strip from forwarded packets, or 0 to keep it.
/// </param>
/// <param name="RepairedRidElementId">
/// The negotiated repaired-RID element id to strip, or 0 to keep it.
/// </param>
/// <param name="MidElementId">
/// The negotiated MID element id to rewrite to <paramref name="OutboundMid"/>, or 0 to leave MID
/// elements untouched.
/// </param>
/// <param name="OutboundMid">
/// The subscriber-facing MID to stamp when <paramref name="MidElementId"/> is set. When the source
/// carried no MID element, one is added; when it carried one, its body is replaced. Ignored when null.
/// </param>
public sealed record RtpEgressExtensions(
    byte RidElementId = 0,
    byte RepairedRidElementId = 0,
    byte MidElementId = 0,
    string? OutboundMid = null)
{
    /// <summary>True when at least one element id is set, so egress rewriting has work to do.</summary>
    public bool RewritesAnything =>
        RidElementId is >= 1 and <= 14
        || RepairedRidElementId is >= 1 and <= 14
        || (MidElementId is >= 1 and <= 14);
}
