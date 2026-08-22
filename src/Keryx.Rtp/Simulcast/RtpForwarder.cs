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
    private readonly uint _clockRate;
    private readonly RtpEgressExtensions? _egress;
    private readonly byte[]? _outboundMid;
    private readonly byte[]? _extScratch;

    private readonly object _srLock = new();
    private readonly Dictionary<SimulcastLayerId, SenderReportMapping> _senderReports = new();

    private SimulcastLayerId _desiredLayer;
    private SimulcastLayerId _activeLayer;
    private bool _hasActiveLayer;

    private bool _started;
    private ushort _highestOutSeq;
    private int _seqOffset;
    private uint _tsOffset;
    private bool _segmentInitialized;
    private uint _lastInTs;
    private uint _lastOutTs;

    /// <summary>One layer's RTCP sender-report correspondence between NTP wall-clock and RTP timestamp.</summary>
    private readonly record struct SenderReportMapping(ulong NtpTimestamp, uint RtpTimestamp);

    /// <summary>Creates a forwarder that emits one subscriber's outbound stream.</summary>
    /// <param name="outboundSsrc">The stable SSRC every forwarded packet is rewritten to carry.</param>
    /// <param name="outboundPayloadType">
    /// The payload type to stamp on egress, or <see langword="null"/> to keep each packet's own type.
    /// </param>
    /// <param name="clockRate">
    /// The RTP timestamp clock rate (90000 for video), used to convert the RTCP sender-report
    /// wall-clock mapping to RTP ticks when aligning timestamps across a layer switch.
    /// </param>
    /// <param name="egressExtensions">
    /// How to rewrite RFC 8285 header extensions on egress — strip the ingest RID/repaired-RID
    /// elements and rewrite MID to the subscriber's value. <see langword="null"/> re-emits the header
    /// extensions as received.
    /// </param>
    public RtpForwarder(
        uint outboundSsrc,
        byte? outboundPayloadType = null,
        uint clockRate = 90000,
        RtpEgressExtensions? egressExtensions = null)
    {
        _outboundSsrc = outboundSsrc;
        _outboundPayloadType = outboundPayloadType;
        _clockRate = clockRate == 0 ? 90000 : clockRate;
        if (egressExtensions is { RewritesAnything: true })
        {
            _egress = egressExtensions;
            _outboundMid = egressExtensions.OutboundMid is { Length: > 0 } mid
                ? System.Text.Encoding.ASCII.GetBytes(mid)
                : null;

            // One RTP header extension block is bounded by the 16-bit word-count field; a subscriber's
            // rewritten block is smaller than the ingest one, so a modest scratch buffer suffices.
            _extScratch = new byte[512];
        }
    }

    /// <summary>
    /// Records the RTCP sender-report NTP↔RTP correspondence for one layer, so a later switch to or
    /// from that layer can align the outbound timestamp to real time. Safe to call from the RTCP
    /// receive path while forwarding proceeds on the send path. Never throws.
    /// </summary>
    /// <param name="layerId">The layer the sender report describes.</param>
    /// <param name="ntpTimestamp">The 64-bit NTP wall-clock from the sender report.</param>
    /// <param name="rtpTimestamp">The RTP timestamp corresponding to <paramref name="ntpTimestamp"/>.</param>
    public void RecordSenderReport(SimulcastLayerId layerId, ulong ntpTimestamp, uint rtpTimestamp)
    {
        lock (_srLock)
        {
            _senderReports[layerId] = new SenderReportMapping(ntpTimestamp, rtpTimestamp);
        }
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

        var previousLayer = _activeLayer;
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
            InitializeSegment(header, previousLayer, classification.LayerId);
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

        // Strip the ingest-only RID/repaired-RID extensions and rewrite MID to the subscriber's value.
        if (_egress is not null)
        {
            RewriteEgressExtensions(ref rewritten, in header);
        }

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
        }

        _started = true;
        _lastInTs = header.Timestamp;
        _lastOutTs = outTs;

        return RtpForwardResult.Forwarded;
    }

    private void InitializeSegment(in RtpHeader header, SimulcastLayerId previousLayer, SimulcastLayerId newLayer)
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

            // Align the timestamp across layers. Simulcast encodings of one source share a capture
            // clock but carry independent random RTP offsets, so the outbound timestamp for the switch
            // packet is placed on a timeline that advances from the last emitted packet by the real
            // (wall-clock) time between the two, read from each layer's RTCP sender report. Without a
            // sender report for either layer, fall back to a single-tick advance so egress stays
            // strictly monotonic even if not lip-sync accurate.
            var desiredOutTs = ComputeSwitchTimestamp(header.Timestamp, previousLayer, newLayer);
            _tsOffset = unchecked(desiredOutTs - header.Timestamp);
        }

        _segmentInitialized = true;
    }

    private uint ComputeSwitchTimestamp(uint newInTs, SimulcastLayerId previousLayer, SimulcastLayerId newLayer)
    {
        if (TryGetSenderReport(previousLayer, out var previous) && TryGetSenderReport(newLayer, out var next))
        {
            var previousWall = WallClockSeconds(previous, _lastInTs);
            var newWall = WallClockSeconds(next, newInTs);
            var deltaTicks = (long)Math.Round((newWall - previousWall) * _clockRate);
            if (deltaTicks < 1)
            {
                // The new layer's wall-clock is at or behind the last emitted packet's; still advance so
                // the outbound timeline never stalls or runs backwards.
                deltaTicks = 1;
            }

            return unchecked(_lastOutTs + (uint)deltaTicks);
        }

        return unchecked(_lastOutTs + 1);
    }

    private bool TryGetSenderReport(SimulcastLayerId layerId, out SenderReportMapping mapping)
    {
        lock (_srLock)
        {
            return _senderReports.TryGetValue(layerId, out mapping);
        }
    }

    private double WallClockSeconds(SenderReportMapping mapping, uint rtpTimestamp)
    {
        // The RTP delta from the sender-report reference wraps at 32 bits; a signed reading spans a
        // window of roughly ±6.6 hours at 90 kHz around the report, far wider than any switch gap.
        var rtpDelta = unchecked((int)(rtpTimestamp - mapping.RtpTimestamp));
        return NtpToSeconds(mapping.NtpTimestamp) + (rtpDelta / (double)_clockRate);
    }

    private static double NtpToSeconds(ulong ntpTimestamp) =>
        (ntpTimestamp >> 32) + ((ntpTimestamp & 0xFFFFFFFF) / 4294967296.0);

    private void RewriteEgressExtensions(ref RtpHeader rewritten, in RtpHeader source)
    {
        var egress = _egress!;
        var writer = new RtpOneByteExtensionWriter(_extScratch);
        var midWritten = false;

        if (source.HasExtension && source.ExtensionProfile == RtpHeaderExtension.OneByteProfile)
        {
            foreach (var element in source.GetExtensionElements())
            {
                if (egress.RidElementId is >= 1 and <= 14 && element.Id == egress.RidElementId)
                {
                    continue;
                }

                if (egress.RepairedRidElementId is >= 1 and <= 14 && element.Id == egress.RepairedRidElementId)
                {
                    continue;
                }

                if (egress.MidElementId is >= 1 and <= 14 && element.Id == egress.MidElementId)
                {
                    // Replace the ingest MID with the subscriber's; drop it when no outbound MID is set.
                    if (_outboundMid is not null)
                    {
                        writer.TryAppend(egress.MidElementId, _outboundMid);
                        midWritten = true;
                    }

                    continue;
                }

                writer.TryAppend(element.Id, element.Data);
            }
        }

        // Add the subscriber MID when the source carried none but one must be present (RFC 8843).
        if (!midWritten && egress.MidElementId is >= 1 and <= 14 && _outboundMid is not null)
        {
            writer.TryAppend(egress.MidElementId, _outboundMid);
        }

        var length = writer.Finish();
        if (length == 0)
        {
            rewritten.HasExtension = false;
            rewritten.ExtensionData = default;
        }
        else
        {
            rewritten.HasExtension = true;
            rewritten.ExtensionProfile = RtpHeaderExtension.OneByteProfile;
            rewritten.ExtensionData = _extScratch.AsSpan(0, length);
        }
    }

    private static bool IsNewer(ushort candidate, ushort reference) =>
        unchecked((ushort)(candidate - reference)) < 0x8000 && candidate != reference;
}
