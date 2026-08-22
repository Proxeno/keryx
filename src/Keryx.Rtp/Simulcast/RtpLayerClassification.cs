namespace Keryx.Rtp.Simulcast;

/// <summary>
/// The result of mapping one received RTP packet to a simulcast layer: which layer it belongs to, the
/// SSRC it arrived on, and whether it is a repair (RTX) packet for that layer rather than media.
/// </summary>
/// <param name="LayerId">The simulcast layer the packet belongs to.</param>
/// <param name="Ssrc">The SSRC the packet arrived on.</param>
/// <param name="IsRepair">
/// True when the packet is an RFC 4588 retransmission for the layer, identified by the repaired-RID
/// extension or a learned repair SSRC. Media forwarding and repair forwarding are handled separately.
/// </param>
/// <param name="Source">How the layer was determined, for diagnostics and stats.</param>
public readonly record struct RtpLayerClassification(
    SimulcastLayerId LayerId,
    uint Ssrc,
    bool IsRepair,
    RtpLayerClassificationSource Source);

/// <summary>How a <see cref="RtpLayerClassification"/> resolved its layer.</summary>
public enum RtpLayerClassificationSource
{
    /// <summary>The RID header extension named the layer directly.</summary>
    RidExtension,

    /// <summary>The repaired-RID header extension named the layer (a repair packet).</summary>
    RepairedRidExtension,

    /// <summary>The SSRC was matched against a binding learned from an earlier RID-tagged packet.</summary>
    LearnedSsrc,
}
