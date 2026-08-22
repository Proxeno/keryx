namespace Keryx.Rtp.CongestionControl;

/// <summary>
/// The delay-based overuse detector's verdict on the forward path
/// (draft-ietf-rmcat-gcc-02 §4): whether the estimated one-way queuing delay is growing, shrinking,
/// or steady.
/// </summary>
public enum BandwidthUsage
{
    /// <summary>Queuing delay is steady; the link is not congested.</summary>
    Normal,

    /// <summary>Queuing delay is falling; a queue built up earlier is draining.</summary>
    Underusing,

    /// <summary>Queuing delay is growing; the send rate is outrunning the link.</summary>
    Overusing,
}
