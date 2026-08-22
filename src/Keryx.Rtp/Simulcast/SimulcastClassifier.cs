namespace Keryx.Rtp.Simulcast;

/// <summary>
/// Maps each incoming RTP packet of one simulcast m-section to its layer, keying on the RFC 8852 RID
/// header extension and falling back to the SSRC once a binding has been learned. This is the ingest
/// demux primitive: it turns one bundled RTP stream into per-layer streams. It does not choose,
/// forward or drop layers — that policy lives in the application.
/// </summary>
/// <remarks>
/// <para>
/// Browsers tag every simulcast packet with a RID for the first few seconds, then may stop once the
/// SFU is expected to have learned the SSRC↔RID binding (RFC 8852 §3). The classifier learns each
/// binding from the first RID-tagged packet and thereafter classifies untagged packets by SSRC, so a
/// layer keeps routing after its RID tagging ceases.
/// </para>
/// <para>
/// Repair (RTX) packets carry the repaired-RID extension and a distinct SSRC; they are classified to
/// the same layer with <see cref="RtpLayerClassification.IsRepair"/> set.
/// </para>
/// <para>Thread-safe: the receive path classifies while the application reads learned bindings.</para>
/// </remarks>
public sealed class SimulcastClassifier
{
    private readonly RtpStreamIdentifierExtensions _extensions;
    private readonly object _lock = new();
    private readonly Dictionary<uint, SimulcastLayerId> _mediaBySsrc = new();
    private readonly Dictionary<uint, SimulcastLayerId> _repairBySsrc = new();

    /// <summary>Creates a classifier for one m-section's negotiated header-extension identifiers.</summary>
    /// <param name="extensions">The negotiated MID/RID/repaired-RID element ids.</param>
    public SimulcastClassifier(RtpStreamIdentifierExtensions extensions)
    {
        _extensions = extensions;
    }

    /// <summary>The negotiated header-extension identifiers this classifier reads.</summary>
    public RtpStreamIdentifierExtensions Extensions => _extensions;

    /// <summary>
    /// Classifies one received RTP packet. Learns the SSRC↔layer binding when the packet is RID-tagged.
    /// Never throws.
    /// </summary>
    /// <param name="header">The parsed RTP header of the packet.</param>
    /// <param name="classification">On success, the layer the packet belongs to.</param>
    /// <returns>
    /// False when no RID extension is present and the SSRC has not yet been bound to a layer — the
    /// caller cannot yet route the packet and should drop it (or buffer briefly) until a RID arrives.
    /// </returns>
    public bool TryClassify(in RtpHeader header, out RtpLayerClassification classification)
    {
        // A repair packet is identified by the repaired-RID extension. Check it first: a repaired-RID
        // element unambiguously marks the packet as RTX, whereas a plain RID element marks media.
        if (RtpStreamIdentifier.TryGetRepairedRid(header, _extensions.RepairedRidId, out var repairLayer))
        {
            Bind(_repairBySsrc, header.Ssrc, repairLayer);
            classification = new RtpLayerClassification(
                repairLayer, header.Ssrc, IsRepair: true, RtpLayerClassificationSource.RepairedRidExtension);
            return true;
        }

        if (RtpStreamIdentifier.TryGetRid(header, _extensions.RidId, out var mediaLayer))
        {
            Bind(_mediaBySsrc, header.Ssrc, mediaLayer);
            classification = new RtpLayerClassification(
                mediaLayer, header.Ssrc, IsRepair: false, RtpLayerClassificationSource.RidExtension);
            return true;
        }

        lock (_lock)
        {
            if (_mediaBySsrc.TryGetValue(header.Ssrc, out var learnedMedia))
            {
                classification = new RtpLayerClassification(
                    learnedMedia, header.Ssrc, IsRepair: false, RtpLayerClassificationSource.LearnedSsrc);
                return true;
            }

            if (_repairBySsrc.TryGetValue(header.Ssrc, out var learnedRepair))
            {
                classification = new RtpLayerClassification(
                    learnedRepair, header.Ssrc, IsRepair: true, RtpLayerClassificationSource.LearnedSsrc);
                return true;
            }
        }

        classification = default;
        return false;
    }

    /// <summary>The media SSRC learned for a layer, or <see langword="null"/> when none has been seen.</summary>
    /// <param name="layerId">The layer to look up.</param>
    /// <returns>The media SSRC carrying the layer, or null.</returns>
    public uint? GetMediaSsrc(SimulcastLayerId layerId)
    {
        lock (_lock)
        {
            foreach (var pair in _mediaBySsrc)
            {
                if (pair.Value == layerId)
                {
                    return pair.Key;
                }
            }
        }

        return null;
    }

    /// <summary>Forgets every learned binding, for example after an ICE restart or track replacement.</summary>
    public void Reset()
    {
        lock (_lock)
        {
            _mediaBySsrc.Clear();
            _repairBySsrc.Clear();
        }
    }

    private void Bind(Dictionary<uint, SimulcastLayerId> table, uint ssrc, SimulcastLayerId layerId)
    {
        lock (_lock)
        {
            // A late RID change for an already-bound SSRC is an interop anomaly, not the common path;
            // overwrite so the newest signalled binding wins.
            table[ssrc] = layerId;
        }
    }
}
