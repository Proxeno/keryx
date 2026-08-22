using Keryx.Rtp;
using Keryx.Rtp.Simulcast;

namespace Keryx;

/// <summary>
/// Per-layer counters for one simulcast m-section's inbound stream: how many media and repair packets
/// have been classified to a layer, and the media SSRC learned for it. A snapshot; values do not
/// update after it is taken.
/// </summary>
/// <param name="Layer">The simulcast layer (RFC 8851 RID).</param>
/// <param name="MediaPackets">Media packets classified to the layer.</param>
/// <param name="RepairPackets">RFC 4588 repair (RTX) packets classified to the layer.</param>
/// <param name="MediaSsrc">The media SSRC learned for the layer, or 0 when none has been seen.</param>
public readonly record struct SimulcastLayerReceiveStats(
    SimulcastLayerId Layer,
    long MediaPackets,
    long RepairPackets,
    uint MediaSsrc);

/// <summary>
/// Drives one <see cref="SimulcastClassifier"/> for one simulcast m-section and accumulates per-layer
/// receive counts, so the peer connection can populate <see cref="RtpPacketInfo.Rid"/> and report
/// per-layer statistics without the classifier having to carry counters of its own.
/// </summary>
internal sealed class SimulcastReceiveTracker
{
    private sealed class LayerCounters
    {
        public long MediaPackets;
        public long RepairPackets;
        public uint MediaSsrc;
    }

    private readonly SimulcastClassifier _classifier;
    private readonly object _lock = new();
    private readonly Dictionary<SimulcastLayerId, LayerCounters> _byLayer = new();

    public SimulcastReceiveTracker(RtpStreamIdentifierExtensions extensions)
    {
        _classifier = new SimulcastClassifier(extensions);
    }

    /// <summary>The classifier this tracker drives, exposed so an app can learn upstream layer SSRCs.</summary>
    public SimulcastClassifier Classifier => _classifier;

    /// <summary>Classifies a packet and folds it into the per-layer counters. Never throws.</summary>
    /// <param name="header">The parsed inbound RTP header.</param>
    /// <param name="classification">On success, the layer the packet belongs to.</param>
    /// <returns>True when the packet was classified to a layer.</returns>
    public bool TryClassify(in RtpHeader header, out RtpLayerClassification classification)
    {
        if (!_classifier.TryClassify(header, out classification))
        {
            return false;
        }

        lock (_lock)
        {
            if (!_byLayer.TryGetValue(classification.LayerId, out var counters))
            {
                counters = new LayerCounters();
                _byLayer[classification.LayerId] = counters;
            }

            if (classification.IsRepair)
            {
                counters.RepairPackets++;
            }
            else
            {
                counters.MediaPackets++;
                counters.MediaSsrc = classification.Ssrc;
            }
        }

        return true;
    }

    /// <summary>Takes a point-in-time snapshot of the per-layer counters.</summary>
    /// <returns>One entry per layer seen so far.</returns>
    public IReadOnlyList<SimulcastLayerReceiveStats> Snapshot()
    {
        lock (_lock)
        {
            var result = new List<SimulcastLayerReceiveStats>(_byLayer.Count);
            foreach (var pair in _byLayer)
            {
                result.Add(new SimulcastLayerReceiveStats(
                    pair.Key, pair.Value.MediaPackets, pair.Value.RepairPackets, pair.Value.MediaSsrc));
            }

            return result;
        }
    }
}
