namespace Keryx.Rtp.Simulcast;

/// <summary>The outcome of offering one packet to a <see cref="RtpForwarder"/>.</summary>
public enum RtpForwardResult
{
    /// <summary>The packet was rewritten into <c>destination</c> and should be sent to the subscriber.</summary>
    Forwarded,

    /// <summary>
    /// The packet belongs to a layer this forwarder is not currently sending, so it was dropped. This
    /// is the normal case for every layer except the selected one.
    /// </summary>
    Dropped,

    /// <summary>The destination buffer was too small; nothing was written.</summary>
    BufferTooSmall,
}

/// <summary>
/// Rewrites the RTP stream of one selected simulcast layer into a single continuous outbound stream
/// for one subscriber: a stable SSRC, gap-preserving contiguous sequence numbers, and a monotonic
/// timestamp timeline that survives layer switches. This is a transport primitive — it rewrites the
/// layer the application selects and nothing more. It does not estimate bandwidth, decide which layer
/// to send, or detect keyframes; the application drives <see cref="SelectLayer"/> and tells the
/// forwarder where a switch may safely land.
/// </summary>
/// <remarks>
/// <para>
/// A simulcast switch must land on a decodable boundary (a keyframe of the target layer), which only
/// a codec-aware caller can identify. The forwarder therefore holds a <em>desired</em> layer set by
/// <see cref="SelectLayer"/> and an <em>active</em> layer it is actually forwarding; it promotes
/// desired to active only when the caller offers a packet with <c>canStartLayer</c> set. Until then it
/// keeps forwarding the active layer so the subscriber's picture never freezes.
/// </para>
/// <para>Not thread-safe: one forwarder serves one subscriber output and is driven from one send path.</para>
/// </remarks>
public sealed class RtpForwarder
{
    private readonly uint _outboundSsrc;
    private readonly byte? _outboundPayloadType;

    private SimulcastLayerId _desiredLayer;
    private SimulcastLayerId _activeLayer;
    private bool _hasActiveLayer;

    private bool _started;
    private ushort _highestOutSeq;
    private int _seqOffset;
    private uint _tsOffset;
    private bool _segmentInitialized;

    /// <summary>Creates a forwarder that emits one subscriber's outbound stream.</summary>
    /// <param name="outboundSsrc">The stable SSRC every forwarded packet is rewritten to carry.</param>
    /// <param name="outboundPayloadType">
    /// The payload type to stamp on egress, or <see langword="null"/> to keep each packet's own type.
    /// </param>
    public RtpForwarder(uint outboundSsrc, byte? outboundPayloadType = null)
    {
        _outboundSsrc = outboundSsrc;
        _outboundPayloadType = outboundPayloadType;
    }

    /// <summary>The SSRC every forwarded packet carries.</summary>
    public uint OutboundSsrc => _outboundSsrc;

    /// <summary>The layer the application has asked to send. Default until <see cref="SelectLayer"/> is called.</summary>
    public SimulcastLayerId DesiredLayer => _desiredLayer;

    /// <summary>The layer currently being forwarded, or default before the first switch lands.</summary>
    public SimulcastLayerId ActiveLayer => _activeLayer;

    /// <summary>
    /// True when a layer switch is pending: the desired layer differs from the active layer and the
    /// forwarder is waiting for a packet it may switch on. The application should request a keyframe on
    /// the desired layer's upstream SSRC while this is set.
    /// </summary>
    public bool IsSwitchPending => _desiredLayer != _activeLayer;

    /// <summary>
    /// Selects the layer to forward. The change is not applied until a subsequent
    /// <see cref="TryForward"/> offers a packet of that layer with <c>canStartLayer</c> set, so egress
    /// stays decodable across the switch. Selection policy (which layer, based on the subscriber's
    /// bandwidth estimate) belongs to the application.
    /// </summary>
    /// <param name="layerId">The layer to switch to.</param>
    public void SelectLayer(SimulcastLayerId layerId) => _desiredLayer = layerId;

    /// <summary>
    /// Offers one classified media packet to the forwarder, rewriting it for the subscriber when it
    /// belongs to the active (or newly promoted) layer. Never throws.
    /// </summary>
    /// <param name="classification">The packet's layer, from <see cref="SimulcastClassifier"/>.</param>
    /// <param name="header">The parsed inbound RTP header.</param>
    /// <param name="payload">The inbound RTP payload.</param>
    /// <param name="canStartLayer">
    /// True when this packet begins an independently decodable unit (a keyframe) of its layer, so a
    /// pending switch to that layer may land here. Supplied by the caller's codec-aware depacketizer.
    /// </param>
    /// <param name="destination">Receives the rewritten packet.</param>
    /// <param name="bytesWritten">On <see cref="RtpForwardResult.Forwarded"/>, the packet length.</param>
    /// <returns>Whether the packet was forwarded, dropped, or could not fit.</returns>
    public RtpForwardResult TryForward(
        in RtpLayerClassification classification,
        in RtpHeader header,
        ReadOnlySpan<byte> payload,
        bool canStartLayer,
        Span<byte> destination,
        out int bytesWritten)
    {
        bytesWritten = 0;

        // Repair packets are handled by a separate repair path, not the media forwarder.
        if (classification.IsRepair)
        {
            return RtpForwardResult.Dropped;
        }

        var isDesired = _desiredLayer == classification.LayerId;
        var isActive = _hasActiveLayer && _activeLayer == classification.LayerId;

        if (IsSwitchPending && isDesired && canStartLayer)
        {
            // Promote the desired layer to active on this keyframe boundary and re-base the sequence
            // and timestamp offsets so egress stays contiguous and monotonic.
            _activeLayer = classification.LayerId;
            _hasActiveLayer = true;
            _segmentInitialized = false;
            isActive = true;
        }

        if (!isActive)
        {
            return RtpForwardResult.Dropped;
        }

        if (!_segmentInitialized)
        {
            InitializeSegment(header);
        }

        var outSeq = unchecked((ushort)(header.SequenceNumber + _seqOffset));
        var outTs = unchecked(header.Timestamp + _tsOffset);

        var rewritten = header;
        rewritten.Ssrc = _outboundSsrc;
        rewritten.SequenceNumber = outSeq;
        rewritten.Timestamp = outTs;
        if (_outboundPayloadType is { } pt)
        {
            rewritten.PayloadType = pt;
        }

        // TODO(EWI-1250 forwarding PR): strip the RID/repaired-RID header extensions on egress and, for
        // BUNDLE, rewrite the MID extension to the subscriber's negotiated MID. For now the header is
        // re-emitted as received apart from the three rewritten identifiers.
        var headerLength = rewritten.HeaderLength;
        if (destination.Length < headerLength + payload.Length)
        {
            return RtpForwardResult.BufferTooSmall;
        }

        if (!rewritten.TryWriteTo(destination, out var written))
        {
            return RtpForwardResult.BufferTooSmall;
        }

        payload.CopyTo(destination[written..]);
        bytesWritten = written + payload.Length;

        if (!_started || IsNewer(outSeq, _highestOutSeq))
        {
            _highestOutSeq = outSeq;
            _started = true;
        }

        return RtpForwardResult.Forwarded;
    }

    private void InitializeSegment(in RtpHeader header)
    {
        if (!_started)
        {
            // First packet ever: keep the inbound numbering so downstream sequencing starts naturally.
            _seqOffset = 0;
            _tsOffset = 0;
        }
        else
        {
            // A switch mid-stream: continue one past the highest sequence number already emitted.
            _seqOffset = unchecked((ushort)(_highestOutSeq + 1) - header.SequenceNumber);

            // TODO(EWI-1250 forwarding PR): align the timestamp across layers. Simulcast encodings of
            // one source share a capture clock but carry independent random RTP offsets, so a correct
            // switch computes _tsOffset from the wall-clock/RTCP-SR mapping of both layers. The baseline
            // leaves _tsOffset unchanged, which is adequate for a proof of concept but not for
            // lip-sync-accurate switching.
        }

        _segmentInitialized = true;
    }

    private static bool IsNewer(ushort candidate, ushort reference) =>
        unchecked((ushort)(candidate - reference)) < 0x8000 && candidate != reference;
}
