namespace Keryx.Rtp.Simulcast;

/// <summary>
/// Routes downstream keyframe requests (PLI/FIR) from subscribers back to the correct upstream
/// simulcast layer and coalesces them, so that many subscribers watching one layer produce at most
/// one upstream keyframe request per interval. This is a routing primitive: it resolves <em>which</em>
/// upstream SSRC to ask and <em>whether</em> asking now is allowed. It does not build or send RTCP —
/// the application issues the request through its peer connection (for example
/// <c>SendPictureLossIndication</c>) using the SSRC this type returns.
/// </summary>
/// <remarks>
/// A subscriber's decoder requests a keyframe against the SSRC it receives — the forwarder's outbound
/// SSRC — which bears no relation to the creator's upstream layer SSRC. The coalescer maps outbound
/// SSRC → layer → learned upstream SSRC. Coalescing keys on the upstream SSRC so that a request storm
/// from many subscribers on the same layer collapses to one upstream ask, protecting the creator's
/// encoder from a keyframe flood when a popular layer has a loss event or a wave of layer switches.
/// </remarks>
public sealed class KeyframeRequestCoalescer
{
    private readonly object _lock = new();
    private readonly Dictionary<uint, SimulcastLayerId> _layerByOutput = new();
    private readonly Dictionary<SimulcastLayerId, uint> _upstreamByLayer = new();
    private readonly Dictionary<uint, DateTimeOffset> _lastRequestByUpstream = new();

    /// <summary>Creates a coalescer with the given minimum interval between upstream requests per layer.</summary>
    /// <param name="minimumInterval">
    /// The shortest time allowed between two upstream keyframe requests for the same layer. A common
    /// choice is a few hundred milliseconds.
    /// </param>
    public KeyframeRequestCoalescer(TimeSpan minimumInterval)
    {
        MinimumInterval = minimumInterval;
    }

    /// <summary>The minimum interval between upstream keyframe requests for one layer.</summary>
    public TimeSpan MinimumInterval { get; }

    /// <summary>Binds one subscriber's outbound SSRC to the layer it currently receives.</summary>
    /// <param name="subscriberOutboundSsrc">The forwarder's outbound SSRC for this subscriber.</param>
    /// <param name="layerId">The layer the subscriber is currently being sent.</param>
    public void BindOutput(uint subscriberOutboundSsrc, SimulcastLayerId layerId)
    {
        lock (_lock)
        {
            _layerByOutput[subscriberOutboundSsrc] = layerId;
        }
    }

    /// <summary>Records the learned upstream media SSRC carrying one layer (from the classifier).</summary>
    /// <param name="layerId">The layer.</param>
    /// <param name="upstreamSsrc">The creator's media SSRC for that layer.</param>
    public void SetLayerUpstreamSsrc(SimulcastLayerId layerId, uint upstreamSsrc)
    {
        lock (_lock)
        {
            _upstreamByLayer[layerId] = upstreamSsrc;
        }
    }

    /// <summary>
    /// Resolves a subscriber keyframe request to the upstream SSRC to ask, and decides whether asking
    /// now is permitted under the coalescing interval. Never throws.
    /// </summary>
    /// <param name="subscriberOutboundSsrc">The SSRC the subscriber's PLI/FIR named.</param>
    /// <param name="now">The current time (injected so callers can test deterministically).</param>
    /// <param name="upstreamSsrc">On success, the upstream layer SSRC to send the request to.</param>
    /// <returns>
    /// True when the caller should send an upstream keyframe request now. False when the outbound SSRC
    /// or its layer is unknown, or when an equivalent request was sent within
    /// <see cref="MinimumInterval"/> and this one is coalesced away.
    /// </returns>
    public bool TryResolveUpstream(uint subscriberOutboundSsrc, DateTimeOffset now, out uint upstreamSsrc)
    {
        upstreamSsrc = 0;
        lock (_lock)
        {
            if (!_layerByOutput.TryGetValue(subscriberOutboundSsrc, out var layer)
                || !_upstreamByLayer.TryGetValue(layer, out var ssrc))
            {
                return false;
            }

            if (_lastRequestByUpstream.TryGetValue(ssrc, out var last) && now - last < MinimumInterval)
            {
                // TODO(EWI-1250 keyframe PR): track that a request was suppressed so a single upstream
                // ask can be issued the instant the interval elapses, rather than waiting for the next
                // subscriber to ask. The current policy simply drops coalesced requests.
                return false;
            }

            _lastRequestByUpstream[ssrc] = now;
            upstreamSsrc = ssrc;
            return true;
        }
    }

    /// <summary>Forgets learned upstream SSRCs and request timestamps; output bindings are kept.</summary>
    public void ResetUpstream()
    {
        lock (_lock)
        {
            _upstreamByLayer.Clear();
            _lastRequestByUpstream.Clear();
        }
    }
}
