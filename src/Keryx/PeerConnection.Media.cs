using System.Security.Cryptography;
using Keryx.Core;
using Keryx.Dtls;
using Keryx.Ice;
using Keryx.Rtp;
using Keryx.Rtp.CongestionControl;
using Keryx.Rtp.Packetization;
using Keryx.Rtp.Rtcp;
using Keryx.Rtp.Simulcast;
using Keryx.Sctp;
using Keryx.Srtp;
using DtlsSrtpProfile = Keryx.Dtls.SrtpProtectionProfile;
using SrtpProfile = Keryx.Srtp.SrtpProtectionProfile;

namespace Keryx;

/// <content>
/// The transport half of <see cref="PeerConnection"/>: the RFC 7983 demultiplexer over the ICE
/// transport, the ICE&#8594;DTLS&#8594;SRTP&#8594;SCTP connection driver, the media send path, and the
/// RTCP reporting loop with its typed feedback dispatch.
/// </content>
public sealed partial class PeerConnection
{
    private const byte DtlsFirstByteMin = 20;
    private const byte DtlsFirstByteMax = 63;
    private const byte MediaFirstByteMin = 128;
    private const byte MediaFirstByteMax = 191;

    private readonly object _sendLock = new();
    private readonly byte[] _rxPlain = new byte[2048];

    // Scratch buffer the reconstructed media packet is written into when an inbound RFC 4588 RTX packet
    // is decapsulated. Distinct from _rxPlain (which still holds the RTX packet being read) so the two
    // never overlap, and touched only from the single ICE receive loop that drives HandleRtp.
    private readonly byte[] _rtxRecovered = new byte[2048];
    private readonly byte[] _rtcpTx = new byte[1500];

    /// <summary>The <c>a=extmap</c> id offered for the transport-wide congestion-control extension.</summary>
    private const int TransportCcExtensionId = 3;

    /// <summary>The <c>a=extmap</c> id offered for the absolute send time extension.</summary>
    private const int AbsSendTimeExtensionId = 2;

    // Stable per-kind forwarder handles, wired to the send track through the owner's locked forward
    // path. Created once in the constructor so GetForwarder is total and allocation-free; they return
    // false until the corresponding send track is negotiated.
    private RtpForwarderHandle _videoForwarder = null!;
    private RtpForwarderHandle _audioForwarder = null!;

    // The inbound RTP demux table, resolving each received packet to its m-section route mid-first
    // (MID header extension, then remote-SDP SSRC, then payload type). Volatile-published from the
    // negotiation path; only read from the single ICE receive loop that drives HandleRtp.
    private RouteTable _routeTable = RouteTable.Empty;

    // Maps a remote RFC 4588 repair SSRC to the media SSRC it repairs, learned from the peer's
    // a=ssrc-group:FID lines (RFC 5576 §4.2). An inbound RTX packet is decapsulated onto this media
    // source. Volatile-published from the negotiation path; only read from the ICE receive loop.
    private Dictionary<uint, uint> _rtxSsrcToMediaSsrc = [];
    private Dictionary<string, SimulcastReceiveTracker> _simulcastByMid = new(StringComparer.Ordinal);

    // The most recently demultiplexed remote SSRC per media kind now lives on each transceiver's
    // RtpReceiver (session-model.md §3.5), still a boxed volatile snapshot written only from the single
    // ICE receive loop that drives HandleRtp and read from any thread through GetRemoteSsrc.

    // Per-SSRC receive jitter buffers, built lazily as sources appear. Only touched from the single
    // ICE receive loop that drives HandleRtp, so it needs no synchronisation; it stays empty unless
    // PeerConnectionConfig.EnableReceiveJitterBuffer is set.
    private readonly Dictionary<uint, ReceiveStream> _receiveStreams = [];

    // Per-inbound-SSRC RFC 3550 reception statistics, feeding the reception report blocks the periodic
    // RTCP report carries. Written from the single ICE receive loop (HandleRtp and the incoming-SR path)
    // and read from the RTCP timer thread when a report is built, so every access takes _receiveStatsLock.
    private readonly object _receiveStatsLock = new();
    private readonly Dictionary<uint, InboundSourceStats> _receiveStats = [];

    // Scratch list the inbound loss detector fills with the sequence numbers due for a NACK. Only touched
    // from the single ICE receive loop that drives HandleRtp, so it needs no synchronisation; it stays
    // empty unless PeerConnectionConfig.EnableReceiverNack is set and a gap is detected.
    private readonly List<ushort> _receiverNackScratch = [];
    private long _receiverNacksSent;

    // Receive-side transport-wide-cc feedback: an arrival recorder that periodically drives the
    // RtcpTransportCcFeedback builder. Built in CreateTrackSenders only when the extension was
    // negotiated and PeerConnectionConfig.EnableReceiverTransportCcFeedback is set; published there
    // (volatile) and thereafter touched only from the single ICE receive loop that drives HandleRtp, so
    // it needs no further synchronisation. The parsing id it reads was written before the volatile
    // publish, so the acquiring read of the generator makes it visible. Null disables the whole path.
    private volatile TransportCcFeedbackGenerator? _receiverTransportCc;
    private byte _receiverTransportCcExtensionId;
    private long _receiverTransportCcFeedbacksSent;

    // Receive-side REMB: a per-connection abs-send-time bandwidth estimator that periodically emits an
    // RtcpReceiverEstimatedMaxBitrate. Built in CreateTrackSenders only when the abs-send-time extension
    // was negotiated and PeerConnectionConfig.EnableReceiverRemb is set; published there (volatile) and
    // thereafter touched only from the single ICE receive loop that drives HandleRtp. The parsing id it
    // reads is written before the volatile publish, so the acquiring read makes it visible. Null disables.
    private volatile RembFeedbackGenerator? _receiverRemb;
    private byte _receiverAbsSendTimeExtensionId;
    private long _rembsSent;
    private long _rembsReceived;

    private Timer? _rtcpTimer;
    private int _firSequence;

    // The transport-wide sequence number space, shared by every outbound SSRC (media and RTX). It and
    // its stamping identifier are only touched from the send path under _sendLock, so no atomics.
    private byte? _sendTransportCcExtensionId;
    private ushort _transportWideSequenceNumber;

    // The abs-send-time extmap id this side stamps on outbound media, set whenever the extension is
    // negotiated for a sending direction — null on a receive-only answerer, which never stamps. Read only
    // from the send path under _sendLock.
    private byte? _sendAbsSendTimeExtensionId;

    // The negotiated transport-wide-cc extmap id, set whenever the extension is negotiated regardless of
    // media direction — unlike _sendTransportCcExtensionId, which a receive-only answerer leaves null
    // because it never stamps. This is the id the receive path reads to parse inbound sequence numbers.
    private byte? _negotiatedTransportCcExtensionId;

    // The negotiated abs-send-time extmap id, set whenever the extension is negotiated regardless of media
    // direction. This is the id the receive path reads to parse inbound abs-send-time for the REMB estimator.
    private byte? _negotiatedAbsSendTimeExtensionId;

    // The pacing queue that smooths outbound RTP toward the congestion controller's target, or null
    // when congestion control is disabled — in which case the send path stays immediate. Built in
    // CreateTrackSenders once the transport is up; only mutated from there and CloseAsync.
    private PacedRtpSender? _pacedSender;

    private long _videoFramesDropped;
    private long _audioFramesDropped;
    private long _rtpReceived;
    private long _rtcpReceived;
    private long _srtpFailures;
    private long _mediaBeforeReady;
    private long _pliCount;
    private long _firCount;
    private long _nackCount;
    private long _videoNackCount;
    private long _twccCount;
    private long _receiverReportCount;

    /// <summary>
    /// Packetizes one H.264 access unit and sends it over SRTP.
    /// </summary>
    /// <param name="annexBAccessUnit">
    /// The access unit in Annex B form: one or more NAL units separated by three- or four-byte start
    /// codes. It is split into single NAL unit, STAP-A and FU-A payloads sized to the negotiated MTU,
    /// with the marker bit set on the last packet (RFC 6184 §5.1).
    /// </param>
    /// <param name="rtpTimestamp90k">The presentation timestamp in 90 kHz ticks.</param>
    /// <returns>
    /// The number of RTP packets sent, or zero when the connection is not yet
    /// <see cref="PeerConnectionState.Connected"/> or no video track was negotiated — in which case
    /// the frame is dropped silently and counted in <see cref="GetStats"/>.
    /// </returns>
    public int SendVideoFrame(ReadOnlySpan<byte> annexBAccessUnit, uint rtpTimestamp90k) =>
        FirstSender(MediaKind.Video) is { } sender
            ? sender.SendFrame(annexBAccessUnit, rtpTimestamp90k)
            : DropFrame(MediaKind.Video);

    /// <summary>
    /// Sends one Opus packet as a single RTP packet over SRTP (RFC 7587 §4.2: Opus packets are never
    /// fragmented).
    /// </summary>
    /// <param name="opusPacket">One complete Opus packet.</param>
    /// <param name="rtpTimestamp48k">The presentation timestamp in 48 kHz ticks.</param>
    /// <returns>
    /// 1 when the packet was sent, 0 when it was dropped because the connection is not yet
    /// <see cref="PeerConnectionState.Connected"/> or no audio track was negotiated.
    /// </returns>
    public int SendAudioFrame(ReadOnlySpan<byte> opusPacket, uint rtpTimestamp48k) =>
        FirstSender(MediaKind.Audio) is { } sender
            ? sender.SendFrame(opusPacket, rtpTimestamp48k)
            : DropFrame(MediaKind.Audio);

    /// <summary>Records a dropped frame for <paramref name="kind"/> and returns 0.</summary>
    private int DropFrame(MediaKind kind)
    {
        IncrementFramesDropped(kind);
        return 0;
    }

    private void IncrementFramesDropped(MediaKind kind)
    {
        if (kind == MediaKind.Video)
        {
            Interlocked.Increment(ref _videoFramesDropped);
        }
        else if (kind == MediaKind.Audio)
        {
            Interlocked.Increment(ref _audioFramesDropped);
        }
    }

    /// <summary>
    /// Packetizes and sends one codec frame on <paramref name="sender"/> — the shared implementation
    /// behind <see cref="SendVideoFrame"/>, <see cref="SendAudioFrame"/> and
    /// <see cref="RtpSender.SendFrame"/>. Takes the one send lock and checks SRTP readiness, dropping
    /// (never throwing) when the connection is not yet up.
    /// </summary>
    internal int SendFrameOnSender(RtpSender sender, ReadOnlySpan<byte> frame, uint rtpTimestamp)
    {
        var track = sender.Track;
        if (track is null || State != PeerConnectionState.Connected)
        {
            IncrementFramesDropped(sender.Kind);
            return 0;
        }

        lock (_sendLock)
        {
            if (_srtp is null)
            {
                IncrementFramesDropped(sender.Kind);
                return 0;
            }

            return track.SendFrame(frame, rtpTimestamp);
        }
    }

    /// <summary>
    /// Forwards one already-packetized RTP payload verbatim on <paramref name="sender"/> — the shared
    /// implementation behind <see cref="TryForwardRtp"/> and <see cref="RtpSender.TryForwardRtp"/>. Never
    /// throws; returns false when the sender is not ready or the payload will not fit the MTU.
    /// </summary>
    internal bool ForwardRtpOnSender(
        RtpSender sender,
        ReadOnlySpan<byte> payload,
        uint rtpTimestamp,
        bool marker,
        byte payloadType)
    {
        var track = sender.Track;
        if (track is null || State != PeerConnectionState.Connected)
        {
            return false;
        }

        lock (_sendLock)
        {
            if (_srtp is null)
            {
                return false;
            }

            try
            {
                return track.ForwardRtp(payload, rtpTimestamp, marker, payloadType);
            }
            catch (Exception ex)
            {
                // TryForwardRtp is contractually total: a transient send-path failure (a torn-down
                // transport, an SRTP index-guard race) must surface as false, never as a throw that
                // could unwind a subscriber fan-out loop.
                _logger.Log(KeryxLogLevel.Warning, "Dropping a forwarded RTP packet after a send failure.", ex);
                return false;
            }
        }
    }

    /// <summary>
    /// Forwards one already-packetized RTP payload verbatim onto this connection's send track for
    /// <paramref name="kind"/>, on the SSRC and sequence space this connection owns for that kind. This
    /// is the subscriber-egress path an SFU gateway drives once this connection has negotiated a
    /// sending track as an answerer (or offerer).
    /// </summary>
    /// <param name="kind">The media kind to forward on; only <see cref="MediaKind.Video"/> and
    /// <see cref="MediaKind.Audio"/> can send.</param>
    /// <param name="payload">
    /// The RTP payload, already codec-packetized upstream. It is written into the RTP payload
    /// <em>verbatim</em> — Keryx never re-packetizes it.
    /// </param>
    /// <param name="rtpTimestamp">
    /// The RTP timestamp to stamp on the packet. The value is used as-is (the broadcaster's timestamp,
    /// forwarded unchanged on this subscriber's SSRC), so a fan-out keeps every subscriber's timeline
    /// aligned to the source.
    /// </param>
    /// <param name="marker">The marker bit to set.</param>
    /// <param name="payloadType">The payload type this subscriber negotiated for <paramref name="kind"/>.</param>
    /// <returns>
    /// True when the packet was assembled, protected and handed to the send path. False — never an
    /// exception — when the connection is not <see cref="PeerConnectionState.Connected"/>, has no
    /// negotiated send track for <paramref name="kind"/>, is closing, or the payload will not fit the
    /// negotiated MTU. A false return lets one dead subscriber never break a fan-out loop.
    /// </returns>
    /// <remarks>
    /// Keryx assigns the SSRC (the local send SSRC for <paramref name="kind"/>) and a monotonic
    /// sequence number, and records the emitted packet in the per-subscriber send history keyed by that
    /// sequence number. When RFC 4588 retransmission was negotiated, an inbound NACK is therefore
    /// served as an RTX repair automatically. Safe to call from any thread; serialises internally on
    /// the same send lock as <see cref="SendVideoFrame"/>.
    /// </remarks>
    public bool TryForwardRtp(
        MediaKind kind,
        ReadOnlySpan<byte> payload,
        uint rtpTimestamp,
        bool marker,
        byte payloadType) =>
        kind is MediaKind.Video or MediaKind.Audio
        && FirstSender(kind) is { } sender
        && sender.TryForwardRtp(payload, rtpTimestamp, marker, payloadType);

    /// <summary>
    /// The forwarder handle for <paramref name="kind"/>'s send track, for a consumer that prefers to
    /// hold it in a hot fan-out loop rather than call <see cref="TryForwardRtp"/> with the kind each
    /// time. The handle is stable for the connection's lifetime and reaches the same wire path; before
    /// a send track is negotiated its <see cref="IRtpForwarder.TryForwardRtp"/> simply returns false.
    /// </summary>
    /// <param name="kind">The media kind; only <see cref="MediaKind.Video"/> and
    /// <see cref="MediaKind.Audio"/> can send.</param>
    /// <returns>The forwarder for <paramref name="kind"/>.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="kind"/> is not audio or video.</exception>
    public IRtpForwarder GetForwarder(MediaKind kind) => kind switch
    {
        MediaKind.Video => _videoForwarder,
        MediaKind.Audio => _audioForwarder,
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Only audio and video can be forwarded."),
    };

    /// <summary>
    /// The <c>rtx</c> payload type the answer settled on for video, or <see langword="null"/> when the
    /// peer kept no RFC 4588 repair codec and retransmission is therefore disabled.
    /// </summary>
    /// <remarks>Meaningful once a remote answer has been applied.</remarks>
    public byte? NegotiatedVideoRtxPayloadType => FirstSender(MediaKind.Video)?.RtxPayloadType;

    /// <summary>
    /// The payload type the answer settled on for <paramref name="kind"/>, or <see langword="null"/>
    /// before negotiation has settled — no answer applied yet, or the answer kept no usable codec for
    /// that kind's m-section.
    /// </summary>
    /// <param name="kind">The media kind to look up; only <see cref="MediaKind.Video"/> and
    /// <see cref="MediaKind.Audio"/> can resolve.</param>
    /// <returns>The negotiated payload type, or null.</returns>
    /// <remarks>
    /// Never throws. A transient null is a soft "not yet" signal, safe to poll in a loop and cache on
    /// the first non-null value — this is deliberate so a consumer never has to guard the call with a
    /// state check first.
    /// </remarks>
    public byte? GetNegotiatedPayloadType(MediaKind kind) =>
        kind is MediaKind.Video or MediaKind.Audio ? FirstSender(kind)?.PayloadType : null;

    /// <summary>
    /// The synchronisation source Keryx sends <paramref name="kind"/> on. Assigned at construction
    /// (see <see cref="VideoSsrc"/>, <see cref="AudioSsrc"/>) and stable for the connection's lifetime,
    /// independent of negotiation state.
    /// </summary>
    /// <param name="kind">The media kind to look up.</param>
    /// <returns>The local sending SSRC for <paramref name="kind"/>; zero for any other kind.</returns>
    public uint GetLocalSsrc(MediaKind kind) =>
        kind is MediaKind.Video or MediaKind.Audio ? FirstSender(kind)?.Ssrc ?? 0 : 0;

    /// <summary>
    /// The remote sender's synchronisation source for <paramref name="kind"/>, learned from the most
    /// recently demultiplexed inbound RTP packet of that kind (the same resolution
    /// <see cref="OnRtpPacketReceived"/> reports). Null until one has arrived.
    /// </summary>
    /// <param name="kind">The media kind to look up.</param>
    /// <returns>The last observed remote SSRC for <paramref name="kind"/>, or null.</returns>
    public uint? GetRemoteSsrc(MediaKind kind) =>
        kind is MediaKind.Video or MediaKind.Audio ? FirstTransceiver(kind)?.Receiver.RemoteSsrc : null;

    /// <summary>
    /// The current inbound demux table, published from the last applied remote description. Exposed to
    /// the test assembly only (via <c>InternalsVisibleTo</c>) so the mid-first resolution can be
    /// exercised directly; not part of the public API.
    /// </summary>
    internal RouteTable InboundRoutes => Volatile.Read(ref _routeTable);

    /// <summary>
    /// The mids of the inbound video m-sections negotiated as simulcast (RFC 8853), for which per-layer
    /// demux is active. Empty until a remote offer carrying a simulcast section has been applied.
    /// </summary>
    public IReadOnlyCollection<string> SimulcastMids => [.. Volatile.Read(ref _simulcastByMid).Keys];

    /// <summary>
    /// The negotiated RID / repaired-RID / MID header-extension element ids for one simulcast
    /// m-section, so an application can build its own <see cref="SimulcastClassifier"/> against the
    /// same mapping the peer connection resolved.
    /// </summary>
    /// <param name="mid">The m-section mid.</param>
    /// <param name="extensions">On success, the negotiated element ids.</param>
    /// <returns>True when <paramref name="mid"/> is a simulcast section.</returns>
    public bool TryGetSimulcastExtensions(string mid, out RtpStreamIdentifierExtensions extensions)
    {
        ArgumentNullException.ThrowIfNull(mid);
        if (Volatile.Read(ref _simulcastByMid).TryGetValue(mid, out var tracker))
        {
            extensions = tracker.Classifier.Extensions;
            return true;
        }

        extensions = default;
        return false;
    }

    /// <summary>
    /// The classifier the peer connection drives for one simulcast m-section, exposed so an application
    /// can read a layer's learned upstream media SSRC (<see cref="SimulcastClassifier.GetMediaSsrc"/>)
    /// to route keyframe requests. Returns <see langword="null"/> when the mid is not simulcast.
    /// </summary>
    /// <param name="mid">The m-section mid.</param>
    /// <returns>The classifier, or null.</returns>
    public SimulcastClassifier? GetSimulcastClassifier(string mid)
    {
        ArgumentNullException.ThrowIfNull(mid);
        return Volatile.Read(ref _simulcastByMid).TryGetValue(mid, out var tracker) ? tracker.Classifier : null;
    }

    /// <summary>Per-layer inbound packet counts for one simulcast m-section.</summary>
    /// <param name="mid">The m-section mid.</param>
    /// <returns>One entry per layer seen; empty when the mid is not simulcast or no packet has arrived.</returns>
    public IReadOnlyList<SimulcastLayerReceiveStats> GetSimulcastLayerStats(string mid)
    {
        ArgumentNullException.ThrowIfNull(mid);
        return Volatile.Read(ref _simulcastByMid).TryGetValue(mid, out var tracker) ? tracker.Snapshot() : [];
    }

    /// <summary>
    /// Sends a Picture Loss Indication asking the peer for a fresh key frame, as a compound
    /// <c>RR + PLI</c> over SRTCP.
    /// </summary>
    /// <param name="mediaSsrc">The SSRC of the inbound stream a key frame is wanted for.</param>
    /// <returns>True when the feedback was protected and sent.</returns>
    public bool SendPictureLossIndication(uint mediaSsrc)
    {
        var report = new RtcpReceiverReport { SenderSsrc = _rtcpSenderSsrc };
        var pli = new RtcpPictureLossIndication(_rtcpSenderSsrc, mediaSsrc);
        return SendRtcpCompound([report, pli]);
    }

    /// <summary>
    /// Asks the peer to retransmit RTP packets it failed to deliver, as a compound
    /// <c>RR + Generic NACK</c> over SRTCP (RFC 4585 §6.2.1).
    /// </summary>
    /// <param name="mediaSsrc">The SSRC of the inbound stream the packets are missing from.</param>
    /// <param name="sequenceNumbers">
    /// The missing sequence numbers. They are sorted and packed greedily into PID/BLP entries, each of
    /// which covers a packet identifier and the sixteen sequence numbers that follow it.
    /// </param>
    /// <returns>
    /// True when the feedback was protected and sent; false when the transport is not ready or the
    /// list is empty.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="sequenceNumbers"/> is null.</exception>
    public bool SendNack(uint mediaSsrc, IEnumerable<ushort> sequenceNumbers)
    {
        ArgumentNullException.ThrowIfNull(sequenceNumbers);
        var nack = new RtcpGenericNack(_rtcpSenderSsrc, mediaSsrc, sequenceNumbers);
        if (nack.Entries.Count == 0)
        {
            return false;
        }

        var report = new RtcpReceiverReport { SenderSsrc = _rtcpSenderSsrc };
        return SendRtcpCompound([report, nack]);
    }

    /// <summary>
    /// Sends a Full Intra Request for one inbound stream, as a compound <c>RR + FIR</c> over SRTCP.
    /// </summary>
    /// <param name="mediaSsrc">The SSRC of the stream that must emit an intra frame.</param>
    /// <returns>
    /// The FIR command sequence number that was sent, or null when the feedback could not be sent.
    /// </returns>
    public byte? SendFullIntraRequest(uint mediaSsrc)
    {
        var sequenceNumber = unchecked((byte)Interlocked.Increment(ref _firSequence));
        var report = new RtcpReceiverReport { SenderSsrc = _rtcpSenderSsrc };
        var fir = new RtcpFullIntraRequest(_rtcpSenderSsrc, 0, mediaSsrc, sequenceNumber);
        return SendRtcpCompound([report, fir]) ? sequenceNumber : null;
    }

    /// <summary>
    /// Resolves one subscriber's keyframe request through <paramref name="coalescer"/> and, when the
    /// coalescing interval allows it, sends the corresponding PLI or FIR upstream to the resolved layer
    /// SSRC. This wires the routing primitive to the RTCP senders without Keryx choosing a layer or
    /// fanning out: the application owns the coalescer and decides when to call this.
    /// </summary>
    /// <param name="coalescer">The coalescer mapping the subscriber's outbound SSRC to an upstream layer.</param>
    /// <param name="subscriberOutboundSsrc">The SSRC the subscriber's PLI/FIR named.</param>
    /// <param name="kind">Whether to send a PLI or a FIR upstream.</param>
    /// <param name="now">The current time, for the coalescing interval.</param>
    /// <returns>True when an upstream request was sent; false when it was coalesced away or unresolved.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="coalescer"/> is null.</exception>
    public bool SendCoalescedKeyframeRequest(
        KeyframeRequestCoalescer coalescer,
        uint subscriberOutboundSsrc,
        KeyframeRequestKind kind,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(coalescer);
        return coalescer.TryResolveUpstream(subscriberOutboundSsrc, now, out var upstreamSsrc)
            && SendKeyframeRequest(kind, upstreamSsrc);
    }

    /// <summary>
    /// Sends every keyframe request that was coalesced away and whose interval has since elapsed, one
    /// per due upstream layer. Call from a periodic pump so a suppressed request is still delivered the
    /// moment the interval opens, rather than waiting for the next subscriber to ask.
    /// </summary>
    /// <param name="coalescer">The coalescer holding the deferred requests.</param>
    /// <param name="kind">Whether to send PLIs or FIRs.</param>
    /// <param name="now">The current time.</param>
    /// <returns>The number of upstream requests sent.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="coalescer"/> is null.</exception>
    public int SendDeferredKeyframeRequests(
        KeyframeRequestCoalescer coalescer,
        KeyframeRequestKind kind,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(coalescer);
        var sent = 0;
        while (coalescer.TryTakeDeferred(now, out var upstreamSsrc))
        {
            if (SendKeyframeRequest(kind, upstreamSsrc))
            {
                sent++;
            }
        }

        return sent;
    }

    private bool SendKeyframeRequest(KeyframeRequestKind kind, uint upstreamSsrc) => kind switch
    {
        KeyframeRequestKind.PictureLossIndication => SendPictureLossIndication(upstreamSsrc),
        KeyframeRequestKind.FullIntraRequest => SendFullIntraRequest(upstreamSsrc) is not null,
        _ => false,
    };

    private MediaTrackStats? VideoStats()
    {
        var sender = FirstSender(MediaKind.Video);
        var track = sender?.Track;
        var dropped = Interlocked.Read(ref _videoFramesDropped);
        var quality = sender?.Quality;
        if (track is not null)
        {
            return track.GetStats(dropped, quality, RetransmissionStatsFor(track));
        }

        return dropped == 0 && quality is null
            ? null
            : new MediaTrackStats(MediaKind.Video, _config.VideoMid, sender?.Ssrc ?? 0, 0, 0, 0, 0, dropped, quality);
    }

    private MediaTrackStats? AudioStats()
    {
        var sender = FirstSender(MediaKind.Audio);
        var track = sender?.Track;
        var dropped = Interlocked.Read(ref _audioFramesDropped);
        var quality = sender?.Quality;
        if (track is not null)
        {
            return track.GetStats(dropped, quality, null);
        }

        return dropped == 0 && quality is null
            ? null
            : new MediaTrackStats(MediaKind.Audio, _config.AudioMid, sender?.Ssrc ?? 0, 0, 0, 0, 0, dropped, quality);
    }

    /// <summary>Builds one <see cref="TransceiverStats"/> per transceiver, in m-line order (§2.2).</summary>
    private IReadOnlyList<TransceiverStats> BuildTransceiverStats()
    {
        // Iterate the lock-free snapshot: a mid-session renegotiation can append a transceiver concurrently.
        var transceivers = SnapshotTransceivers();
        var stats = new List<TransceiverStats>(transceivers.Length);
        foreach (var transceiver in transceivers)
        {
            var sender = transceiver.Sender;
            var track = sender.Track;
            var send = track?.GetStats(0, sender.Quality, RetransmissionStatsFor(track));
            stats.Add(new TransceiverStats(
                transceiver.Mid,
                transceiver.Kind,
                transceiver.Direction,
                transceiver.CurrentDirection,
                sender.Ssrc,
                sender.PayloadType,
                transceiver.Receiver.RemoteSsrc,
                send));
        }

        return stats;
    }

    private RetransmissionStats? RetransmissionStatsFor(TrackSender track)
    {
        if (track.Retransmitter is not { } rtx)
        {
            return null;
        }

        var counters = rtx.GetStats();
        return new RetransmissionStats(
            counters.Ssrc,
            counters.PayloadType,
            Interlocked.Read(ref _videoNackCount),
            counters.RequestedPackets,
            counters.PacketsRetransmitted,
            counters.BytesRetransmitted,
            counters.HistoryMisses,
            counters.Suppressed);
    }

    private void StartDriver()
    {
        lock (_lock)
        {
            if (_driver is not null || _closed != 0)
            {
                return;
            }

            _driver = Task.Run(() => RunConnectionAsync(_cts.Token), CancellationToken.None);
        }
    }

    private async Task RunConnectionAsync(CancellationToken cancellationToken)
    {
        IceAgent? ice;
        DtlsLowerTransport? lower;
        DtlsRole role;
        Sdp.SdpFingerprint? fingerprint;
        lock (_lock)
        {
            ice = _ice;
            lower = _dtlsLower;
            role = _dtlsRole;
            fingerprint = _remoteFingerprint;
        }

        if (ice is null || lower is null)
        {
            return;
        }

        // RFC 8827 §6.5: the certificate fingerprint carried in signalling is the *entire* trust
        // anchor of the WebRTC security model — the peer's certificate is self-signed and worthless
        // on its own. A remote description with no a=fingerprint therefore cannot be connected to:
        // passing a null expected fingerprint down to DtlsConfig would leave the handshake pinning
        // nothing and accept any certificate at all, which is exactly the downgrade an attacker who
        // can strip one line from the signalling channel would want. Fail closed instead.
        if (fingerprint is null)
        {
            Fail("The remote description carries no a=fingerprint, so the peer's certificate cannot be authenticated.");
            return;
        }

        // Keryx computes SHA-256 fingerprints only. Any other algorithm would be compared against a
        // SHA-256 digest and fail as a "mismatch", which is safe but tells the operator nothing.
        if (!string.Equals(fingerprint.Algorithm, "sha-256", StringComparison.OrdinalIgnoreCase))
        {
            Fail($"The remote a=fingerprint uses {fingerprint.Algorithm}; Keryx requires sha-256 (RFC 8827 §6.5).");
            return;
        }

        // Keryx.Dtls can negotiate use_srtp profiles that Keryx.Srtp has no transform for. Offering
        // one means a DTLS handshake that succeeds and then throws while deriving SRTP keys, long
        // after the point where the failure could be explained. Refuse up front instead.
        foreach (var configured in _config.SrtpProfiles)
        {
            if (configured is not (DtlsSrtpProfile.Aes128CmHmacSha1Tag80
                or DtlsSrtpProfile.Aes128CmHmacSha1Tag32
                or DtlsSrtpProfile.AeadAes128Gcm
                or DtlsSrtpProfile.AeadAes256Gcm))
            {
                Fail($"SrtpProfiles contains {configured}, which Keryx does not implement end to end.");
                return;
            }
        }

        try
        {
            SetState(PeerConnectionState.Connecting);

            // The DTLS transport is built before ICE finishes so that a ClientHello arriving the
            // instant the peer nominates a pair is observed rather than lost; it cannot transmit
            // until the ICE transport has a usable pair, and DTLS retransmits its own flights.
            var dtls = new DtlsTransport(lower, new DtlsConfig
            {
                Role = role,
                Certificate = _certificate,
                ExpectedRemoteFingerprintSha256 = fingerprint.Value,
                SrtpProfiles = [.. _config.SrtpProfiles],
                MaxDatagramSize = _config.Mtu,
                OfferedCipherSuites = _config.DtlsOfferedCipherSuites,
                OfferedNamedGroups = _config.DtlsOfferedNamedGroups,
                Logger = _logger,
            });

            lock (_lock)
            {
                if (_closed != 0)
                {
                    dtls.Dispose();
                    return;
                }

                _dtls = dtls;
            }

            if (!await ice.WaitForConnectedAsync(_config.IceConnectTimeout, cancellationToken).ConfigureAwait(false))
            {
                Fail("ICE did not establish a candidate pair.");
                return;
            }

            _logger.Log(KeryxLogLevel.Info, $"ICE connected; starting the DTLS handshake as {role}.");
            await dtls.HandshakeAsync(cancellationToken).ConfigureAwait(false);

            var negotiated = dtls.NegotiatedSrtpProfile;
            if (negotiated == DtlsSrtpProfile.None)
            {
                Fail("The DTLS handshake agreed no SRTP protection profile.");
                return;
            }

            var profile = MapSrtpProfile(negotiated);
            var material = dtls.ExportKeyingMaterial(ExporterLabel, negotiated.KeyingMaterialLength());
            SrtpContext srtp;
            try
            {
                var keys = DtlsSrtpKeyMaterial.Split(
                    profile,
                    material,
                    role == DtlsRole.Client ? DtlsSrtpRole.Client : DtlsSrtpRole.Server);
                srtp = new SrtpContext(profile, keys.Local, keys.Remote, _logger);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(material);
            }

            lock (_lock)
            {
                if (_closed != 0)
                {
                    srtp.Dispose();
                    return;
                }

                _srtp = srtp;
            }

            CreateTrackSenders(ice, profile);
            _logger.Log(KeryxLogLevel.Info, $"DTLS connected; SRTP profile {profile.Name}.");

            StartSctp(dtls, role);
            StartRtcpTimer();
            SetState(PeerConnectionState.Connected);

            if (role == DtlsRole.Client && _sctp is { } association)
            {
                try
                {
                    await association.ConnectAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Closing.
                }
                catch (Exception ex)
                {
                    _logger.Log(KeryxLogLevel.Warning, "The SCTP association did not establish.", ex);
                }
            }
        }
        catch (OperationCanceledException)
        {
            _logger.Log(KeryxLogLevel.Debug, "The connection driver was cancelled.");
        }
        catch (Exception ex)
        {
            _logger.Log(KeryxLogLevel.Error, "The connection driver failed.", ex);
            Fail(ex.Message);
        }
    }

    private void StartSctp(DtlsTransport dtls, DtlsRole role)
    {
        var association = new SctpAssociation(dtls, new SctpAssociationConfig
        {
            LocalPort = _config.SctpPort,
            RemotePort = _remoteSctpPort ?? _config.SctpPort,

            // RFC 8832 §6: the DTLS client sends INIT and owns the even stream identifiers.
            IsInitiator = role == DtlsRole.Client,
            UsesEvenStreamIds = role == DtlsRole.Client,
            MaxMessageSize = (uint)_config.MaxMessageSize,

            // Classic DATA only on the PeerConnection data path — never RFC 8260 I-DATA. Chrome does
            // not implement I-DATA at all, so it negotiates classic DATA and is unaffected. Firefox is
            // the hazard: it advertises I-DATA in its INIT Supported Extensions (so a peer concludes it
            // is supported) yet sends classic DATA itself and does not deliver a peer's ordered I-DATA —
            // an interleaving-capable Keryx would send I-DATA that Firefox opens the data channel from
            // (the DATA_CHANNEL_OPEN arrives) but then silently buffers every ordered user message
            // behind, so a reliable/ordered channel to Firefox goes permanently one-way. Classic DATA is
            // the lowest common denominator every browser handles. Keryx's I-DATA implementation stays
            // intact for direct SCTP use and its unit tests; the browser-facing PeerConnection opts out.
            EnableInterleaving = false,
            Logger = _logger,
        });

        association.OnChannelOpened += channel => OnDataChannel?.Invoke(this, channel);
        association.OnError += ex => _logger.Log(KeryxLogLevel.Warning, "SCTP association error.", ex);

        List<PendingChannel> pending;
        lock (_lock)
        {
            _sctp = association;
            pending = [.. _pendingChannels];
            _pendingChannels.Clear();
        }

        foreach (var request in pending)
        {
            try
            {
                request.Completion.TrySetResult(association.CreateChannel(
                    request.Label,
                    request.Ordered,
                    request.MaxRetransmits,
                    request.Protocol,
                    request.MaxPacketLifetime));
            }
            catch (Exception ex)
            {
                request.Completion.TrySetException(ex);
            }
        }

        association.Start();
    }

    private void CreateTrackSenders(IceAgent ice, SrtpProfile profile)
    {
        // Build a wire sender for every transceiver whose negotiation settled on a send codec, in m-line
        // order, against the just-derived SRTP context.
        BuildNegotiatedTrackSenders(_transport ?? ice.Transport, profile);

        if (_congestionController is { } controller)
        {
            // The pacer drains toward the controller's live target; media and RTX both feed its queue
            // through SendRtp, and the drain re-encrypts and emits under _sendLock. A single MTU is the
            // floor so a lone large packet is never wedged behind an empty budget.
            _pacedSender = new PacedRtpSender(
                new PacketPacer(controller.TargetBitrateBitsPerSecond, _time),
                _time,
                profile.RtpOverhead,
                SendProtectedRtpLocked,
                _logger);
        }

        // Once the transport-wide-cc extension is negotiated, a peer sending media into Keryx expects
        // transport-cc feedback back to feed its send-side estimator. The receive path reads the
        // direction-independent negotiated id (a receive-only answerer never stamps, so it has no send
        // id). Publish the generator last (volatile) so the receive loop sees the parsing id set above it.
        if (_negotiatedTransportCcExtensionId is { } extensionId && _config.EnableReceiverTransportCcFeedback)
        {
            _receiverTransportCcExtensionId = extensionId;
            _receiverTransportCc = new TransportCcFeedbackGenerator(
                TransportCcFeedbackGenerator.DefaultFeedbackInterval,
                TransportCcFeedbackGenerator.DefaultMaxReportedPacketsPerFeedback);
            _logger.Log(
                KeryxLogLevel.Info,
                $"Receiver transport-cc feedback enabled on extmap {extensionId}.");
        }

        // Once the abs-send-time extension is negotiated and REMB is opted into, run the receive-side
        // delay-gradient estimator over inbound abs-send-time and return REMB to the sender's congestion
        // controller. Publish the generator last (volatile) so the receive loop sees the parsing id above it.
        if (_negotiatedAbsSendTimeExtensionId is { } absSendTimeId && _config.EnableReceiverRemb)
        {
            _receiverAbsSendTimeExtensionId = absSendTimeId;
            _receiverRemb = new RembFeedbackGenerator(
                RembFeedbackGenerator.DefaultFeedbackInterval,
                _config.CongestionControl);
            _logger.Log(
                KeryxLogLevel.Info,
                $"Receiver REMB generation enabled on abs-send-time extmap {absSendTimeId}.");
        }
    }

    /// <summary>
    /// After a mid-session renegotiation (session-model.md §4.3), wires a wire sender for any transceiver
    /// whose negotiation just settled on a send codec but that has no live sender yet — against the
    /// <em>existing</em> SRTP context, which is never re-derived or rekeyed by an ordinary renegotiation.
    /// A no-op before the driver has derived SRTP (the driver's <see cref="CreateTrackSenders"/> then
    /// builds every sender) and a no-op when no transceiver was added, so it is safe to call after every
    /// answer apply. Senders already streaming keep their sequence/timestamp/rtx state untouched.
    /// </summary>
    private void EnsureLiveSenders()
    {
        SrtpContext? srtp;
        IDatagramTransport? transport;
        lock (_lock)
        {
            srtp = _srtp;
            transport = _transport;
        }

        if (srtp is null || transport is null)
        {
            return;
        }

        BuildNegotiatedTrackSenders(transport, srtp.Profile);
    }

    /// <summary>
    /// Builds a <see cref="TrackSender"/> for every transceiver whose negotiation settled on a send codec
    /// and that does not already have one, in m-line order, against <paramref name="profile"/>'s SRTP
    /// overhead. Each build takes <see cref="_sendLock"/> and skips a transceiver that already has a live
    /// sender, so a sender already streaming is never rebuilt (its sequence/timestamp/rtx state survives a
    /// renegotiation, session-model.md §4.2/§4.3). Runs both from the connection driver (initial) and from
    /// a mid-session apply (<see cref="EnsureLiveSenders"/>).
    /// </summary>
    private void BuildNegotiatedTrackSenders(IDatagramTransport transport, SrtpProfile profile)
    {
        var transportCcId = _sendTransportCcExtensionId;
        var absSendTimeId = _sendAbsSendTimeExtensionId;

        // When the TWCC and/or abs-send-time extensions are negotiated every packet carries the one-byte
        // header extension, so its fixed overhead comes out of the payload budget and out of the
        // send-history slab size. RTX repairs stamp only transport-cc, so reserving both here is a safe
        // over-reservation for the repair slab.
        var extensionReserve = TrackSender.HeaderExtensionOverhead(transportCcId, absSendTimeId);

        var datagram = Math.Min(_config.Mtu, transport.MaxDatagramSize);
        var maxPayload = datagram - RtpHeader.FixedLength - extensionReserve - profile.RtpOverhead;
        if (maxPayload < 64)
        {
            throw new InvalidOperationException(
                $"An MTU of {_config.Mtu} leaves only {maxPayload} byte(s) for an RTP payload.");
        }

        foreach (var transceiver in _transceivers)
        {
            var sender = transceiver.Sender;
            if (sender.Negotiated is not { } negotiated)
            {
                continue;
            }

            lock (_sendLock)
            {
                // Already streaming (from this or an earlier negotiation): leave it — and its live
                // sequence/timestamp/rtx state — untouched.
                if (sender.Track is not null)
                {
                    continue;
                }

                if (transceiver.Kind == MediaKind.Video)
                {
                    var videoMaxPayload = maxPayload;
                    RtxRetransmitter? rtx = null;

                    if (_config.EnableRetransmission && negotiated.RtxPayloadType is { } rtxPayloadType)
                    {
                        // An RTX packet is the original packet plus the two-octet OSN (RFC 4588 §4), so the
                        // media stream gives those two bytes back to keep repairs inside the same MTU.
                        videoMaxPayload = maxPayload - RtxPacket.OriginalSequenceNumberLength;
                        var history = new RtpSendHistory(
                            RtpHeader.FixedLength + extensionReserve + videoMaxPayload,
                            _config.RetransmissionHistory);
                        rtx = new RtxRetransmitter(
                            sender.RtxSsrcRaw,
                            rtxPayloadType,
                            negotiated.ClockRate,
                            history,
                            _config.Retransmission,
                            logger: _logger);

                        _logger.Log(
                            KeryxLogLevel.Info,
                            $"RTX enabled: pt {rtxPayloadType}, ssrc 0x{sender.RtxSsrcRaw:x8}, "
                            + $"{history.Capacity}-packet / {history.Retention.TotalMilliseconds:F0} ms send history.");
                    }

                    sender.Track = new TrackSender(
                        this,
                        negotiated.Mid,
                        MediaKind.Video,
                        new RtpStreamSender(sender.Ssrc, negotiated.PayloadType, negotiated.ClockRate, logger: _logger),
                        CreateVideoPayloadizer(negotiated.EncodingName),
                        videoMaxPayload,
                        profile.RtpOverhead,
                        transportCcId,
                        absSendTimeId,
                        rtx);
                }
                else if (transceiver.Kind == MediaKind.Audio)
                {
                    sender.Track = new TrackSender(
                        this,
                        negotiated.Mid,
                        MediaKind.Audio,
                        new RtpStreamSender(sender.Ssrc, negotiated.PayloadType, negotiated.ClockRate, logger: _logger),
                        new OpusPacketizer(),
                        maxPayload,
                        profile.RtpOverhead,
                        transportCcId,
                        absSendTimeId);
                }
            }
        }
    }

    /// <summary>
    /// Selects the RTP payloadizer for a negotiated video codec by its rtpmap encoding name. The
    /// negotiation layer only settles on a codec this endpoint configured, so an unrecognised name here
    /// means a codec was configured whose send path is not yet wired (a future VP9/AV1) — surfaced as a
    /// clear failure rather than silently mis-packetizing under the wrong payload type.
    /// </summary>
    /// <param name="encodingName">The negotiated codec's rtpmap encoding name, for example <c>VP8</c>.</param>
    /// <returns>A fresh payloadizer for the codec.</returns>
    private static IRtpPayloadizer CreateVideoPayloadizer(string encodingName)
    {
        if (string.Equals(encodingName, "H264", StringComparison.OrdinalIgnoreCase))
        {
            return new H264Packetizer();
        }

        if (string.Equals(encodingName, "VP8", StringComparison.OrdinalIgnoreCase))
        {
            return new Vp8Packetizer();
        }

        throw new InvalidOperationException(
            $"No send-side packetizer is wired for the negotiated video codec '{encodingName}'.");
    }

    private static SrtpProfile MapSrtpProfile(DtlsSrtpProfile profile) => profile switch
    {
        DtlsSrtpProfile.Aes128CmHmacSha1Tag80 => SrtpProfile.Aes128CmHmacSha1_80,
        DtlsSrtpProfile.Aes128CmHmacSha1Tag32 => SrtpProfile.Aes128CmHmacSha1_32,
        DtlsSrtpProfile.AeadAes128Gcm => SrtpProfile.AeadAes128Gcm,
        DtlsSrtpProfile.AeadAes256Gcm => SrtpProfile.AeadAes256Gcm,
        _ => throw new InvalidOperationException($"Keryx does not implement the SRTP profile {profile}."),
    };

    private void Fail(string reason)
    {
        _logger.Log(KeryxLogLevel.Error, $"Connection failed: {reason}");
        SetState(PeerConnectionState.Failed);
    }

    // ------------------------------------------------------------------ demultiplexing

    private void HandleTransportDatagram(ReadOnlySpan<byte> datagram)
    {
        if (datagram.IsEmpty)
        {
            return;
        }

        var first = datagram[0];
        if (first is >= DtlsFirstByteMin and <= DtlsFirstByteMax)
        {
            _dtlsLower?.Deliver(datagram);
            return;
        }

        if (first is < MediaFirstByteMin or > MediaFirstByteMax)
        {
            // RFC 7983 leaves 0-19 and 64-127 unassigned; ICE already consumed STUN.
            return;
        }

        var srtp = _srtp;
        if (srtp is null)
        {
            Interlocked.Increment(ref _mediaBeforeReady);
            return;
        }

        try
        {
            if (RtcpDemultiplexer.IsRtcp(datagram))
            {
                HandleRtcp(srtp, datagram);
            }
            else
            {
                HandleRtp(srtp, datagram);
            }
        }
        catch (ObjectDisposedException)
        {
            // The SRTP context was torn down while this datagram was in flight.
        }
    }

    private void HandleRtp(SrtpContext srtp, ReadOnlySpan<byte> datagram)
    {
        if (datagram.Length > _rxPlain.Length
            || !srtp.Inbound.TryUnprotectRtp(datagram, _rxPlain, out var length))
        {
            Interlocked.Increment(ref _srtpFailures);
            return;
        }

        ProcessDecryptedRtp(_rxPlain.AsSpan(0, length));
    }

    /// <summary>
    /// Drives one already-decrypted RTP packet through the receive path: parse, transport-cc arrival
    /// recording, mid-first demux, RFC 4588 RTX decapsulation, and delivery. Split out of
    /// <see cref="HandleRtp"/> so the post-SRTP path can be exercised deterministically by the test
    /// assembly (via <see cref="DeliverDecryptedRtpForTest"/>) without standing up a transport.
    /// </summary>
    private void ProcessDecryptedRtp(ReadOnlySpan<byte> plaintext)
    {
        if (!RtpPacket.TryParse(plaintext, out var packet))
        {
            Interlocked.Increment(ref _srtpFailures);
            return;
        }

        Interlocked.Increment(ref _rtpReceived);

        // Record the transport-wide sequence number off the raw wire packet — before the RFC 4588 RTX
        // branch, since the sender stamps the extension on media and repair packets alike and the
        // transport-wide sequence space spans both — then emit feedback when the cadence is due.
        RecordTransportCcArrival(in packet);

        // Record the abs-send-time off the same raw wire packet and, when REMB is enabled, drive the
        // receive-side estimator, emitting REMB back to the sender on the feedback cadence.
        RecordAbsSendTimeArrival(in packet);

        // Demux mid-first (RFC 8843 §9.2): the MID header extension names the m-section when the peer
        // stamped one, else the SSRC learned from the remote SDP, else the payload type — the last of
        // which is unambiguous while there is one m-section per kind, matching the prior behaviour.
        var routes = Volatile.Read(ref _routeTable);
        var route = routes.Resolve(packet.Header, packet.Header.PayloadType);

        // RFC 4588 §4: an inbound RTX packet repeats an original media packet on its own SSRC, payload
        // type and sequence space. Turn it back into the packet it repairs and feed *that* through the
        // ordinary receive path, so a recovered packet reaches the depacketizer, updates reception
        // statistics and fills the loss detector's gap exactly as a directly received packet would — and
        // so it is not re-NACKed. The raw repair packet is never surfaced to the application handler.
        if (route.IsRtx)
        {
            HandleInboundRtx(route, packet, plaintext, routes);
            return;
        }

        DeliverInboundMedia(route, packet, routes);
    }

    /// <summary>
    /// Test-only seam: feeds an already-decrypted RTP packet through the exact post-SRTP receive path,
    /// bypassing the SRTP unprotect step so a test can craft hostile packets (e.g. a flood of invented
    /// SSRCs) without holding the session key. Exposed to the test assembly via <c>InternalsVisibleTo</c>.
    /// </summary>
    internal void DeliverDecryptedRtpForTest(ReadOnlySpan<byte> rtpPacket) => ProcessDecryptedRtp(rtpPacket);

    /// <summary>Test-only: number of distinct inbound sources with retained reception statistics.</summary>
    internal int ReceiveSourceStatCountForTest
    {
        get
        {
            lock (_receiveStatsLock)
            {
                return _receiveStats.Count;
            }
        }
    }

    /// <summary>Test-only: number of distinct inbound sources with a retained receive jitter buffer.</summary>
    internal int ReceiveStreamCountForTest => _receiveStreams.Count;

    /// <summary>
    /// Test-only: the live SRTP context instance, so a test can assert by reference identity that an
    /// ordinary renegotiation neither re-derives nor rekeys it (session-model.md §4.3). Null before the
    /// DTLS handshake derives the keys.
    /// </summary>
    internal object? SrtpContextForTest => _srtp;

    /// <summary>
    /// Test-only: the ICE agent's currently selected candidate pair, so a test can assert by reference
    /// identity that an ICE restart ran a fresh connectivity-check phase and nominated a <em>new</em> pair
    /// (the old instance is discarded by <see cref="Ice.IceAgent.Restart"/>). Null before any pair
    /// succeeds, and briefly during the restart window before a new pair is nominated.
    /// </summary>
    internal object? SelectedIceCandidatePairForTest => _ice?.SelectedPair;

    /// <summary>
    /// Decapsulates one inbound RFC 4588 RTX packet back to the media packet it repairs and delivers it
    /// through the ordinary receive path. The repair carries its own SSRC, payload type and sequence
    /// number; the media SSRC is recovered from the RFC 5576 FID association (falling back to the last
    /// media SSRC learned for this kind), the media payload type from the repair route's <c>apt</c>, and
    /// the original sequence number from the RTX payload's OSN prefix.
    /// </summary>
    private void HandleInboundRtx(
        RtpRoute route,
        in RtpPacket rtxPacket,
        ReadOnlySpan<byte> rtxDatagram,
        RouteTable routes)
    {
        var rtxToMedia = Volatile.Read(ref _rtxSsrcToMediaSsrc);
        if (!rtxToMedia.TryGetValue(rtxPacket.Header.Ssrc, out var mediaSsrc))
        {
            // No FID association for this repair SSRC. A non-simulcast section carries a single media
            // source, so the last media SSRC learned for the kind is the one being repaired; without
            // even that, there is no source to attribute the repair to, so drop it rather than guess.
            var learned = FirstTransceiver(route.Kind)?.Receiver.RemoteSsrc;

            if (learned is not { } knownMediaSsrc)
            {
                return;
            }

            mediaSsrc = knownMediaSsrc;
        }

        if (!RtxPacket.TryDecapsulate(
                rtxDatagram,
                mediaSsrc,
                route.AptPayloadType,
                _rtxRecovered,
                out var recoveredLength,
                out _)
            || !RtpPacket.TryParse(_rtxRecovered.AsSpan(0, recoveredLength), out var recovered))
        {
            return;
        }

        // Route the reconstructed packet onto its media stream's kind, mid and clock rate rather than the
        // repair route it arrived on. Resolve by the recovered (media) SSRC — recovered above from the
        // FID association — then payload type; the decrypted repair datagram no longer aliases a media
        // header extension, so the MID extension is unavailable here. An unresolved recovery falls back
        // to the repair route with its rtx flag cleared, exactly as the prior payload-type lookup did.
        var mediaRoute = routes.Resolve(mediaSsrc, recovered.Header.PayloadType);
        if (mediaRoute.Kind == MediaKind.Unknown)
        {
            mediaRoute = route with { IsRtx = false };
        }

        DeliverInboundMedia(mediaRoute, recovered, routes);
    }

    /// <summary>
    /// Delivers one received media packet through the receive path: it moves the per-kind remote SSRC
    /// snapshot, folds into the RFC 3550 reception statistics and inbound loss detector, and — when a
    /// handler is attached — dispatches it in arrival order or through the per-source jitter buffer. Both
    /// directly received packets and packets reconstructed from an RTX repair flow through here.
    /// </summary>
    private void DeliverInboundMedia(RtpRoute route, in RtpPacket packet, RouteTable routes)
    {
        var payloadType = packet.Header.PayloadType;

        // Track the remote sender's SSRC on the receiver of the transceiver this packet demuxed to,
        // straight off the same demux resolution OnRtpPacketReceived is about to see. Resolve by the
        // route's mid so two same-kind m-lines each learn their own SSRC (a first-of-kind write would
        // let one transceiver's SSRC flip-flop and leave the other's null); fall back to first-of-kind
        // only for the mid-less legacy shape. A plain last-writer-wins snapshot, not a full source table.
        if (route.Kind is MediaKind.Video or MediaKind.Audio)
        {
            var transceiver = route.Mid.Length != 0 ? GetTransceiver(route.Mid) : null;
            transceiver ??= FirstTransceiver(route.Kind);
            if (transceiver is not null)
            {
                transceiver.Receiver.RemoteSsrc = packet.Header.Ssrc;
            }
        }

        TrackInboundReceipt(
            route,
            packet.Header.Ssrc,
            packet.Header.SequenceNumber,
            packet.Header.Timestamp);

        var handler = OnRtpPacketReceived;

        // Ingest demux: when the section is simulcast, key the packet to its layer (learning the
        // SSRC↔layer binding) so the RID travels on RtpPacketInfo without the handler re-parsing the
        // header, and per-layer receive counts accrue whether or not a handler is attached. The RID
        // string is materialised only when there is a handler to receive it.
        string? rid = null;
        if (route.Kind == MediaKind.Video && route.Mid.Length != 0)
        {
            var trackers = Volatile.Read(ref _simulcastByMid);
            if (trackers.TryGetValue(route.Mid, out var tracker)
                && tracker.TryClassify(packet.Header, out var classification)
                && handler is not null
                && !classification.LayerId.IsEmpty)
            {
                rid = classification.LayerId.ToString();
            }
        }

        if (handler is null)
        {
            return;
        }

        if (!_config.EnableReceiveJitterBuffer)
        {
            // Arrival-order delivery: fire immediately, exactly as the receive path always has.
            var info = new RtpPacketInfo(
                route.Kind == MediaKind.Unknown ? null : route.Mid,
                route.Kind,
                payloadType,
                packet.Header.Ssrc,
                packet.Header.SequenceNumber,
                packet.Header.Timestamp,
                packet.Header.Marker,
                rid);

            handler(in info, packet.Payload);
            return;
        }

        // Playout-order delivery: reorder the source through its jitter buffer, then drain every packet
        // that has become releasable and fire the handler for each in sequence order.
        var stream = GetOrCreateReceiveStream(packet.Header.Ssrc);
        if (stream is null)
        {
            // The distinct-source cap is reached: don't allocate another jitter buffer for a source that
            // may be an SSRC-flood forgery. Deliver this packet in arrival order instead, so a genuine
            // (if late-appearing) source is not silently dropped, exactly as the buffer-off path does.
            var arrivalInfo = new RtpPacketInfo(
                route.Kind == MediaKind.Unknown ? null : route.Mid,
                route.Kind,
                payloadType,
                packet.Header.Ssrc,
                packet.Header.SequenceNumber,
                packet.Header.Timestamp,
                packet.Header.Marker,
                rid);

            handler(in arrivalInfo, packet.Payload);
            return;
        }

        if (rid is not null)
        {
            // A layer's SSRC maps to one stable RID (RFC 8852), so caching the last resolved value is
            // enough to stamp it on packets the buffer releases later.
            stream.Rid = rid;
        }

        stream.Buffer.Insert(
            packet.Header.SequenceNumber,
            packet.Header.Timestamp,
            packet.Header.Marker,
            payloadType,
            packet.Payload);

        DrainReceiveStream(packet.Header.Ssrc, stream, routes, handler);
    }

    private ReceiveStream? GetOrCreateReceiveStream(uint ssrc)
    {
        if (_receiveStreams.TryGetValue(ssrc, out var stream))
        {
            return stream;
        }

        // Bound the number of per-source jitter buffers so a peer flooding invented SSRCs cannot pin
        // unbounded memory (each buffer holds a ring of up to Capacity payload slabs). A legitimate
        // BUNDLE session stays far below the cap; beyond it the caller falls back to arrival-order
        // delivery for the new source.
        if (_receiveStreams.Count >= _config.MaxReceiveSources)
        {
            return null;
        }

        stream = new ReceiveStream(new JitterBuffer(_config.ReceiveJitterBuffer, _config.TimeProvider));
        _receiveStreams[ssrc] = stream;
        return stream;
    }

    private void DrainReceiveStream(
        uint ssrc,
        ReceiveStream stream,
        RouteTable routes,
        RtpPacketReceivedHandler handler)
    {
        while (stream.Buffer.TryGetNext(out var released))
        {
            // The released packet's header extension is not retained by the jitter buffer, so resolve by
            // the stream's SSRC then payload type — the mid a directly received packet would have carried.
            var route = routes.Resolve(ssrc, released.PayloadType);

            var info = new RtpPacketInfo(
                route.Kind == MediaKind.Unknown ? null : route.Mid,
                route.Kind,
                released.PayloadType,
                ssrc,
                released.SequenceNumber,
                released.Timestamp,
                released.Marker,
                route.Kind == MediaKind.Video ? stream.Rid : null);

            handler(in info, released.Payload);
        }
    }

    /// <summary>One inbound synchronisation source's receive state: its jitter buffer and the last
    /// simulcast RID resolved for it, cached so packets released after classification still carry it.</summary>
    private sealed class ReceiveStream(JitterBuffer buffer)
    {
        internal JitterBuffer Buffer { get; } = buffer;

        internal string? Rid { get; set; }
    }

    /// <summary>
    /// The inbound RTP demux table. It resolves a received packet to its m-section route by the BUNDLE
    /// precedence WebRTC uses (RFC 8843 §9.2): the MID header extension first, then the SSRC learned
    /// from the remote SDP (<c>a=ssrc</c> / <c>a=ssrc-group</c>), then the payload type. Payload type is
    /// the only key a peer that signals neither a MID extension nor <c>a=ssrc</c> lines offers, and it
    /// is unambiguous while there is one m-section per kind — so for today's single-video/single-audio
    /// sessions all three keys resolve to the same route and nothing observable changes.
    /// </summary>
    internal sealed class RouteTable
    {
        private readonly Dictionary<byte, RtpRoute> _byPayloadType;
        private readonly Dictionary<string, Dictionary<byte, RtpRoute>> _byMid;
        private readonly Dictionary<uint, string> _ssrcToMid;
        private readonly byte _midExtensionId;

        internal RouteTable(
            Dictionary<byte, RtpRoute> byPayloadType,
            Dictionary<string, Dictionary<byte, RtpRoute>> byMid,
            Dictionary<uint, string> ssrcToMid,
            byte midExtensionId)
        {
            _byPayloadType = byPayloadType;
            _byMid = byMid;
            _ssrcToMid = ssrcToMid;
            _midExtensionId = midExtensionId;
        }

        /// <summary>An empty table: every lookup misses and yields the unknown route.</summary>
        internal static RouteTable Empty { get; } = new([], [], [], 0);

        /// <summary>
        /// Resolves a freshly received packet mid-first: the MID header extension when the peer stamped
        /// one naming a section we know, else the SSRC-to-mid map learned from the remote SDP, else the
        /// payload type. <paramref name="header"/> aliases the decrypted datagram and carries the MID
        /// extension body.
        /// </summary>
        internal RtpRoute Resolve(in RtpHeader header, byte payloadType)
        {
            if (_midExtensionId is >= 1 and <= 14
                && RtpStreamIdentifier.TryGetMid(header, _midExtensionId, out var midBytes)
                && TryMatchKnownMid(midBytes, out var mid)
                && TryResolveInMid(mid, payloadType, out var midRoute))
            {
                return midRoute;
            }

            return ResolveBySsrc(header.Ssrc, payloadType);
        }

        /// <summary>
        /// Resolves a packet whose header extension is unavailable — an RTX-reconstructed media packet
        /// or one drained from the jitter buffer — by its already-known SSRC then payload type.
        /// </summary>
        internal RtpRoute Resolve(uint ssrc, byte payloadType) => ResolveBySsrc(ssrc, payloadType);

        private RtpRoute ResolveBySsrc(uint ssrc, byte payloadType)
        {
            if (_ssrcToMid.TryGetValue(ssrc, out var mid)
                && TryResolveInMid(mid, payloadType, out var route))
            {
                return route;
            }

            return _byPayloadType.TryGetValue(payloadType, out var fallback)
                ? fallback
                : new RtpRoute(string.Empty, MediaKind.Unknown);
        }

        private bool TryResolveInMid(string mid, byte payloadType, out RtpRoute route)
        {
            if (_byMid.TryGetValue(mid, out var routes) && routes.TryGetValue(payloadType, out route))
            {
                return true;
            }

            route = default;
            return false;
        }

        // Match the MID extension body against a known mid without allocating a string on the hot path;
        // there are only a handful of mids, each a short ASCII token.
        private bool TryMatchKnownMid(ReadOnlySpan<byte> midBytes, out string mid)
        {
            foreach (var known in _byMid.Keys)
            {
                if (MidEquals(known, midBytes))
                {
                    mid = known;
                    return true;
                }
            }

            mid = string.Empty;
            return false;
        }

        private static bool MidEquals(string mid, ReadOnlySpan<byte> bytes)
        {
            if (mid.Length != bytes.Length)
            {
                return false;
            }

            for (var i = 0; i < mid.Length; i++)
            {
                if (mid[i] != (char)bytes[i])
                {
                    return false;
                }
            }

            return true;
        }
    }

    /// <summary>
    /// Folds one received media packet into the RFC 3550 reception statistics for its source, so the
    /// periodic RTCP report can carry a proper reception report block for it (loss, jitter, EHSN).
    /// </summary>
    /// <remarks>
    /// Only real media streams are tracked: RTX repair packets carry a different SSRC and sequence space
    /// and belong to the media stream they repair, not a receiver report of their own. The route carries
    /// the payload's clock rate, needed to express arrival time in timestamp units for the jitter
    /// estimate; a route with no kind or clock rate (an unrecognised payload type) is skipped.
    /// </remarks>
    private void TrackInboundReceipt(RtpRoute route, uint ssrc, ushort sequenceNumber, uint rtpTimestamp)
    {
        if (route.IsRtx
            || route.ClockRate == 0
            || route.Kind is not (MediaKind.Video or MediaKind.Audio))
        {
            return;
        }

        // RFC 3550 A.8: the jitter estimate compares arrival and RTP timestamps, so scale the wall-clock
        // arrival into the payload's clock. Only differences matter, so truncation to 32 bits is safe.
        var arrivalMilliseconds = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var arrivalTimestamp = unchecked((uint)(arrivalMilliseconds * route.ClockRate / 1000));

        // Automatic NACK generation is video-only: RFC 4588 retransmission is negotiated for video alone,
        // so a NACK for audio would ask for a repair no sender in this stack serves.
        var detectLoss = _config.EnableReceiverNack && route.Kind == MediaKind.Video;
        _receiverNackScratch.Clear();

        lock (_receiveStatsLock)
        {
            if (!_receiveStats.TryGetValue(ssrc, out var stats))
            {
                // Bound the source table: a peer authenticated to the SRTP context can invent an SSRC per
                // packet, and each unseen value would otherwise allocate a reception-statistics record
                // (and a NACK tracker) that is never evicted. Once the cap is reached, packets from
                // further sources are still delivered; they simply accrue no retained per-source state.
                if (_receiveStats.Count >= _config.MaxReceiveSources)
                {
                    return;
                }

                stats = new InboundSourceStats(route.Kind, route.ClockRate);
                _receiveStats[ssrc] = stats;
            }

            stats.Statistics.OnRtpPacket(sequenceNumber, rtpTimestamp, arrivalTimestamp);

            if (detectLoss)
            {
                var tracker = stats.NackTracker ??= new ReceiverNackTracker(_config.ReceiverNack);
                tracker.OnPacket(sequenceNumber, Environment.TickCount64, _receiverNackScratch);
            }
        }

        // Emit the NACK outside the reception-stats lock: SendNack takes the send lock, and keeping the
        // two locks unnested keeps this path's ordering identical to the periodic report path.
        if (_receiverNackScratch.Count > 0 && SendNack(ssrc, _receiverNackScratch))
        {
            Interlocked.Increment(ref _receiverNacksSent);
        }
    }

    /// <summary>
    /// Records an inbound sender report against its source's reception statistics, supplying the LSR and
    /// DLSR fields the next reception report block owes it (RFC 3550 §6.4.1). No-op when no media has yet
    /// been received from that source.
    /// </summary>
    private void TrackInboundSenderReport(uint sourceSsrc, ulong ntpTimestamp, DateTimeOffset receivedAt)
    {
        lock (_receiveStatsLock)
        {
            if (_receiveStats.TryGetValue(sourceSsrc, out var stats))
            {
                stats.Statistics.OnSenderReport(NtpTime.ToCompact(ntpTimestamp), receivedAt);
            }
        }
    }

    /// <summary>
    /// Snapshots the reception report blocks owed to every inbound source of <paramref name="kind"/>,
    /// computing each block's fraction-lost interval as of <paramref name="now"/> (RFC 3550 §6.4.1).
    /// </summary>
    private List<RtcpReportBlock> BuildReportBlocksFor(MediaKind kind, DateTimeOffset now)
    {
        var blocks = new List<RtcpReportBlock>();
        lock (_receiveStatsLock)
        {
            foreach (var (ssrc, stats) in _receiveStats)
            {
                if (stats.Kind == kind && stats.Statistics.PacketsReceived > 0)
                {
                    blocks.Add(stats.Statistics.BuildReportBlock(ssrc, now));
                }
            }
        }

        return blocks;
    }

    /// <summary>One inbound source's RFC 3550 reception statistics, tagged with the media kind it was
    /// demultiplexed to so the periodic report can group its block with that kind's sender report.</summary>
    private sealed class InboundSourceStats(MediaKind kind, uint clockRate)
    {
        internal MediaKind Kind { get; } = kind;

        /// <summary>The route's RTP clock rate, retained so a stats report can express jitter in seconds.</summary>
        internal uint ClockRate { get; } = clockRate;

        internal ReceptionStatistics Statistics { get; } = new();

        /// <summary>The inbound loss detector, built lazily when automatic NACK generation is enabled.</summary>
        internal ReceiverNackTracker? NackTracker { get; set; }
    }

    private void HandleRtcp(SrtpContext srtp, ReadOnlySpan<byte> datagram)
    {
        if (datagram.Length > _rxPlain.Length
            || !srtp.Inbound.TryUnprotectRtcp(datagram, _rxPlain, out var length))
        {
            Interlocked.Increment(ref _srtpFailures);
            return;
        }

        Interlocked.Increment(ref _rtcpReceived);
        var now = DateTimeOffset.UtcNow;
        var reader = new RtcpCompoundReader(_rxPlain.AsSpan(0, length));
        while (reader.MoveNext())
        {
            if (RtcpPacket.TryParse(reader.Current.Packet, out var parsed) && parsed is not null)
            {
                DispatchRtcp(parsed, now);
            }
        }
    }

    /// <summary>
    /// Routes one parsed RTCP packet to its counters, its typed event, and — for NACK and reception
    /// reports — to the retransmission and link-quality paths. Internal so tests can drive the
    /// feedback path without standing up a transport.
    /// </summary>
    internal void DispatchRtcp(RtcpPacket packet, DateTimeOffset receivedAt)
    {
        switch (packet)
        {
            case RtcpPictureLossIndication pli:
                Interlocked.Increment(ref _pliCount);
                OnPictureLossIndication?.Invoke(this, new PliEventArgs(pli.SenderSsrc, pli.MediaSsrc));
                break;

            case RtcpFullIntraRequest fir:
                Interlocked.Increment(ref _firCount);
                foreach (var entry in fir.Entries)
                {
                    OnFullIntraRequest?.Invoke(
                        this,
                        new FirEventArgs(fir.SenderSsrc, fir.MediaSsrc, entry.Ssrc, entry.SequenceNumber));
                }

                break;

            case RtcpGenericNack nack:
                Interlocked.Increment(ref _nackCount);
                ServeNack(nack);
                OnNack?.Invoke(this, new NackEventArgs(nack.SenderSsrc, nack.MediaSsrc, nack.ExpandedSequenceNumbers));
                break;

            case RtcpTransportCcFeedback twcc:
                Interlocked.Increment(ref _twccCount);
                _congestionController?.OnTransportFeedback(twcc);
                OnTransportCcFeedback?.Invoke(this, new TransportCcEventArgs(twcc));
                break;

            case RtcpReceiverEstimatedMaxBitrate remb:
                Interlocked.Increment(ref _rembsReceived);
                _congestionController?.OnReceiverEstimatedMaxBitrate(remb);
                break;

            case RtcpReceiverReport report:
                Interlocked.Increment(ref _receiverReportCount);
                IngestReportBlocks(report.ReportBlocks, receivedAt);
                OnReceiverReport?.Invoke(
                    this,
                    new ReceiverReportEventArgs(report.SenderSsrc, [.. report.ReportBlocks], receivedAt));
                break;

            case RtcpSenderReport sender:
                TrackInboundSenderReport(sender.SenderSsrc, sender.NtpTimestamp, receivedAt);
                OnSenderReport?.Invoke(
                    this,
                    new SenderReportEventArgs(sender.SenderSsrc, sender.NtpTimestamp, sender.RtpTimestamp, receivedAt));
                if (sender.ReportBlocks.Count > 0)
                {
                    Interlocked.Increment(ref _receiverReportCount);
                    IngestReportBlocks(sender.ReportBlocks, receivedAt);
                    OnReceiverReport?.Invoke(
                        this,
                        new ReceiverReportEventArgs(sender.SenderSsrc, [.. sender.ReportBlocks], receivedAt));
                }

                break;

            case RtcpGoodbye goodbye:
                _logger.Log(
                    KeryxLogLevel.Info,
                    $"Received RTCP BYE for {goodbye.Sources.Count} source(s): {goodbye.Reason ?? "no reason"}.");
                break;

            default:
                break;
        }
    }

    /// <summary>
    /// Serves an inbound Generic NACK out of the video send history as RTX packets.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 4585 §6.2.1: every FCI entry names a PID plus, in its BLP, up to sixteen further sequence
    /// numbers. The entries are expanded in place rather than through
    /// <see cref="RtcpGenericNack.ExpandedSequenceNumbers"/> so the receive loop allocates nothing on
    /// this path however many packets a NACK asks for.
    /// </para>
    /// <para>
    /// This runs on the ICE receive loop and takes the send lock, which serialises it against
    /// <see cref="SendVideoFrame"/> and against the SRTP encryption both share. The history itself is
    /// separately locked, so a NACK never tears a slab a frame is being written into.
    /// </para>
    /// </remarks>
    private void ServeNack(RtcpGenericNack nack)
    {
        // Resolve the NACKed media SSRC to the sender that owns it (session-model.md §1.5). A NACK names
        // the media source, so a repair (RTX) SSRC or an unknown SSRC is not served; a sender with no
        // retransmitter (audio) has no history to serve from.
        if (!_localSsrcOwners.TryGetValue(nack.MediaSsrc, out var owner) || owner.IsRtx)
        {
            return;
        }

        var track = owner.Sender.Track;
        if (track?.Retransmitter is null)
        {
            return;
        }

        Interlocked.Increment(ref _videoNackCount);

        lock (_sendLock)
        {
            if (_srtp is null)
            {
                return;
            }

            var entries = nack.Entries;
            for (var i = 0; i < entries.Count; i++)
            {
                var entry = entries[i];
                track.Retransmit(entry.PacketId);
                for (var bit = 0; bit < 16; bit++)
                {
                    if ((entry.Bitmask & (1 << bit)) != 0)
                    {
                        track.Retransmit((ushort)(entry.PacketId + bit + 1));
                    }
                }
            }
        }
    }

    /// <summary>
    /// Folds reception report blocks (RFC 3550 §6.4.1) describing this endpoint's own streams into the
    /// link-quality snapshot <see cref="GetStats"/> publishes. Blocks about any other source are
    /// ignored.
    /// </summary>
    private void IngestReportBlocks(IList<RtcpReportBlock> blocks, DateTimeOffset receivedAt)
    {
        for (var i = 0; i < blocks.Count; i++)
        {
            var block = blocks[i];
            if (!_localSsrcOwners.TryGetValue(block.SourceSsrc, out var owner) || owner.IsRtx)
            {
                // Report blocks for an RTX SSRC describe the repair stream, which has no separate
                // quality surface, and blocks for anything else are not about us at all.
                continue;
            }

            var sender = owner.Sender;
            var video = sender.Kind == MediaKind.Video;
            var clockRate = sender.Negotiated?.ClockRate;
            var quality = new OutboundStreamQuality(
                block.SourceSsrc,

                // RFC 3550 §6.4.1: the fraction lost is a fixed-point number with denominator 256.
                block.FractionLost / 256.0,
                block.CumulativePacketsLost,
                block.ExtendedHighestSequenceNumber,
                block.Jitter,
                clockRate is > 0 ? TimeSpan.FromSeconds(block.Jitter / (double)clockRate.Value) : null,
                ReceiverReportEventArgs.CalculateRoundTripTime(block, receivedAt),
                receivedAt);

            sender.Quality = quality;

            // Feed reception-report loss to the loss-based estimator. Video carries the bitrate the
            // estimator is protecting, so prefer it; fall back to audio only when no video is sent.
            if (video || FirstSender(MediaKind.Video)?.Negotiated is null)
            {
                _congestionController?.OnReportedLoss(quality.FractionLost);
            }
        }
    }

    // ------------------------------------------------------------------ RTCP transmission

    private void StartRtcpTimer()
    {
        var interval = _config.RtcpInterval;
        if (interval <= TimeSpan.Zero)
        {
            return;
        }

        var timer = new Timer(_ => SendRtcpReports(), null, interval, interval);
        Timer? previous;
        lock (_lock)
        {
            previous = _rtcpTimer;
            _rtcpTimer = timer;
        }

        previous?.Dispose();
    }

    private void StopRtcpTimer()
    {
        Timer? timer;
        lock (_lock)
        {
            timer = _rtcpTimer;
            _rtcpTimer = null;
        }

        timer?.Dispose();
    }

    private void SendRtcpReports()
    {
        try
        {
            var now = DateTimeOffset.UtcNow;

            // Iterate the transceiver set in m-line order (video then audio for the legacy set), so the
            // reports emit in the same order as before. Iterate the lock-free snapshot: a mid-session
            // renegotiation can append a transceiver from another thread while this timer callback runs.
            foreach (var transceiver in SnapshotTransceivers())
            {
                SendReportFor(transceiver.Kind, transceiver.Sender.Track, now);
            }
        }
        catch (Exception ex)
        {
            _logger.Log(KeryxLogLevel.Warning, "Sending an RTCP sender report failed.", ex);
        }
    }

    private void SendReportFor(MediaKind kind, TrackSender? track, DateTimeOffset now)
    {
        // The reception report blocks owed to every inbound source of this kind (RFC 3550 §6.4.1). Built
        // once per cycle because BuildReportBlock advances each source's fraction-lost interval.
        var reportBlocks = BuildReportBlocksFor(kind, now);

        if (track is null)
        {
            // Receive-only for this kind: nothing to send unless a source is being received, in which
            // case a standalone receiver report (RFC 3550 §6.4.2) carries its blocks.
            if (reportBlocks.Count > 0)
            {
                var receiverReport = new RtcpReceiverReport { SenderSsrc = _rtcpSenderSsrc };
                foreach (var block in reportBlocks)
                {
                    receiverReport.ReportBlocks.Add(block);
                }

                SendRtcpCompound([receiverReport, RtcpSourceDescription.CreateCname(_rtcpSenderSsrc, _cname)]);
            }

            return;
        }

        // RFC 3550 §6.4.1: a sender report carries the same reception report blocks a receiver report
        // would, so ride this kind's blocks on its sender report rather than sending a separate one.
        var senderReport = track.Stream.CreateSenderReport(now);
        foreach (var block in reportBlocks)
        {
            senderReport.ReportBlocks.Add(block);
        }

        var packets = new List<RtcpPacket>(4)
        {
            senderReport,
            RtcpSourceDescription.CreateCname(track.Stream.Ssrc, _cname),
        };

        // RFC 4588 §4 makes the repair stream a source in its own right, so it reports separately once
        // it has actually sent something.
        if (track.Retransmitter is { } rtx && rtx.PacketCount > 0)
        {
            packets.Add(rtx.CreateSenderReport(now));
            packets.Add(RtcpSourceDescription.CreateCname(rtx.Ssrc, _cname));
        }

        SendRtcpCompound(packets);
    }

    private void TrySendGoodbye()
    {
        try
        {
            var packets = new List<RtcpPacket>();
            var sources = new List<uint>();
            var now = DateTimeOffset.UtcNow;

            foreach (var transceiver in SnapshotTransceivers())
            {
                var track = transceiver.Sender.Track;
                if (track is null)
                {
                    continue;
                }

                packets.Add(track.Stream.CreateSenderReport(now));
                packets.Add(RtcpSourceDescription.CreateCname(track.Stream.Ssrc, _cname));
                sources.Add(track.Stream.Ssrc);
                if (track.Retransmitter is { } rtx && rtx.PacketCount > 0)
                {
                    sources.Add(rtx.Ssrc);
                }
            }

            if (packets.Count == 0)
            {
                packets.Add(new RtcpReceiverReport { SenderSsrc = _rtcpSenderSsrc });
                sources.Add(_rtcpSenderSsrc);
            }

            var goodbye = new RtcpGoodbye { Reason = "closing" };
            foreach (var ssrc in sources)
            {
                goodbye.Sources.Add(ssrc);
            }

            packets.Add(goodbye);
            SendRtcpCompound(packets);
        }
        catch (Exception ex)
        {
            _logger.Log(KeryxLogLevel.Debug, "Could not send the RTCP BYE.", ex);
        }
    }

    private bool SendRtcpCompound(IReadOnlyList<RtcpPacket> packets)
    {
        lock (_sendLock)
        {
            var srtp = _srtp;
            var transport = _transport;
            if (srtp is null || transport is null)
            {
                return false;
            }

            try
            {
                var length = RtcpPacket.WriteCompound(packets, _rtcpTx);
                var protectedLength = srtp.Outbound.ProtectRtcp(_rtcpTx.AsSpan(0, length), _rtcpTx);
                transport.Send(_rtcpTx.AsSpan(0, protectedLength));
                return true;
            }
            catch (InvalidOperationException)
            {
                // The ICE transport lost its pair, or a layer was disposed mid-send.
                return false;
            }
        }
    }

    /// <summary>
    /// Allocates the next transport-wide sequence number for the congestion-control header extension.
    /// Must be called under <see cref="_sendLock"/>, which serialises every outbound RTP packet across
    /// the media and RTX streams so the space stays gap-free and monotonic. Wraps at 65535.
    /// </summary>
    private ushort NextTransportWideSequenceNumber()
    {
        var sequenceNumber = _transportWideSequenceNumber;
        _transportWideSequenceNumber = unchecked((ushort)(sequenceNumber + 1));
        return sequenceNumber;
    }

    private void SendProtectedRtp(byte[] buffer, int length)
    {
        var srtp = _srtp;
        var transport = _transport;
        if (srtp is null || transport is null)
        {
            return;
        }

        var protectedLength = srtp.Outbound.ProtectRtp(buffer.AsSpan(0, length), buffer);
        try
        {
            transport.Send(buffer.AsSpan(0, protectedLength));
        }
        catch (InvalidOperationException)
        {
            // The transport went away between the state check and the send.
        }
    }

    /// <summary>
    /// Routes one assembled, still-plaintext RTP packet to the wire: straight through SRTP when
    /// congestion control is off, or into the pacing queue when it is on. Called under
    /// <see cref="_sendLock"/>.
    /// </summary>
    private void SendRtp(byte[] buffer, int length)
    {
        var paced = _pacedSender;
        if (paced is not null)
        {
            // The pacer copies the plaintext out of the caller's reusable buffer, so the buffer is free
            // to be reused for the next packet; the drain encrypts and sends each copy in send order.
            paced.Enqueue(buffer.AsSpan(0, length));
            return;
        }

        SendProtectedRtp(buffer, length);
    }

    /// <summary>Encrypts and sends one paced RTP packet, serialised against every other outbound write.</summary>
    private void SendProtectedRtpLocked(byte[] buffer, int length)
    {
        lock (_sendLock)
        {
            SendProtectedRtp(buffer, length);
        }
    }

    /// <summary>The current send clock in microseconds, monotonic, for the send-time history.</summary>
    private long SendTimestampMicroseconds() => MonotonicMicroseconds();

    /// <summary>A monotonic microsecond clock, shared by the send-time history and the receive-time
    /// recording transport-cc feedback reports arrivals against.</summary>
    private long MonotonicMicroseconds() =>
        (long)(_time.GetTimestamp() * (1_000_000.0 / _time.TimestampFrequency));

    /// <summary>
    /// Records one inbound packet's transport-wide sequence number and arrival time against the receiver
    /// transport-cc generator, then flushes a feedback packet back to the sender when the draft's cadence
    /// is due. No-op unless the extension was negotiated and receiver feedback is enabled. Runs on the
    /// single ICE receive loop, so the generator needs no locking; the flush itself sends under the send
    /// lock through <see cref="SendRtcpCompound"/>.
    /// </summary>
    private void RecordTransportCcArrival(in RtpPacket packet)
    {
        var generator = _receiverTransportCc;
        if (generator is null
            || !TransportCcExtension.TryRead(packet.Header, _receiverTransportCcExtensionId, out var transportSequenceNumber))
        {
            return;
        }

        var now = MonotonicMicroseconds();
        generator.OnPacketReceived(transportSequenceNumber, now);

        // The feedback's media source SSRC names the stream whose arrivals it is reporting on. TWCC is
        // transport-wide, so the most recently observed inbound SSRC is a valid choice and matches what
        // browsers put on the field.
        if (generator.ShouldBuildFeedback(now)
            && generator.TryBuildFeedback(_rtcpSenderSsrc, packet.Header.Ssrc, out var feedback)
            && feedback is not null
            && SendRtcpCompound([feedback]))
        {
            Interlocked.Increment(ref _receiverTransportCcFeedbacksSent);
        }
    }

    /// <summary>
    /// Records one inbound packet's abs-send-time and arrival time against the receive-side REMB estimator,
    /// then emits an RtcpReceiverEstimatedMaxBitrate back to the sender when the feedback cadence is due.
    /// No-op unless the extension was negotiated and REMB generation is enabled. Runs on the single ICE
    /// receive loop, so the generator needs no locking; the flush itself sends under the send lock through
    /// <see cref="SendRtcpCompound"/>.
    /// </summary>
    private void RecordAbsSendTimeArrival(in RtpPacket packet)
    {
        var generator = _receiverRemb;
        if (generator is null
            || !AbsoluteSendTimeExtension.TryRead(packet.Header, _receiverAbsSendTimeExtensionId, out var absSendTime))
        {
            return;
        }

        var now = MonotonicMicroseconds();
        var sizeBytes = RtpHeader.FixedLength + packet.Payload.Length + packet.PaddingLength;
        generator.OnPacketReceived(absSendTime, now, sizeBytes, packet.Header.Ssrc);

        if (generator.ShouldBuildFeedback(now)
            && generator.TryBuildFeedback(_rtcpSenderSsrc, out var remb)
            && remb is not null
            && SendRtcpCompound([remb]))
        {
            Interlocked.Increment(ref _rembsSent);
        }
    }

    /// <summary>
    /// Records that an outbound RTP packet carrying <paramref name="transportSequenceNumber"/> left the
    /// send path, so returning transport-cc feedback can be paired with its send time. Called under
    /// <see cref="_sendLock"/> at the point the sequence number is drawn.
    /// </summary>
    private void OnTransportRtpSent(ushort transportSequenceNumber, int sizeBytes) =>
        _congestionController?.OnPacketSent(transportSequenceNumber, SendTimestampMicroseconds(), sizeBytes);

    /// <summary>
    /// A stable, per-kind implementation of <see cref="IRtpForwarder"/> that delegates to the owner's
    /// locked forward path. Holds no state of its own, so it is valid before the send track exists —
    /// <see cref="TryForwardRtp"/> simply returns false until then.
    /// </summary>
    private sealed class RtpForwarderHandle(PeerConnection owner, MediaKind kind) : IRtpForwarder
    {
        public MediaKind Kind => kind;

        public uint Ssrc => owner.GetLocalSsrc(kind);

        public bool TryForwardRtp(ReadOnlySpan<byte> payload, uint rtpTimestamp, bool marker, byte payloadType) =>
            owner.TryForwardRtp(kind, payload, rtpTimestamp, marker, payloadType);
    }

    /// <summary>
    /// One outbound RTP stream: the payloadizer, the sequence/timestamp state, and a single reusable
    /// datagram buffer that the payloadizer fills in place and SRTP encrypts in place. When RFC 4588
    /// retransmission is negotiated it also owns the repair stream and a second buffer for it.
    /// </summary>
    internal sealed class TrackSender : IRtpPayloadWriter
    {
        private readonly PeerConnection _owner;
        private readonly IRtpPayloadizer _payloadizer;
        private readonly byte[] _buffer;
        private readonly byte[]? _rtxBuffer;
        private readonly int _maxPayload;
        private readonly int _headerReserve;
        private readonly byte? _transportCcExtensionId;
        private readonly byte? _absSendTimeExtensionId;
        private uint _timestamp;
        private long _packets;
        private long _bytes;
        private long _frames;

        internal TrackSender(
            PeerConnection owner,
            string mid,
            MediaKind kind,
            RtpStreamSender stream,
            IRtpPayloadizer payloadizer,
            int maxPayload,
            int srtpOverhead,
            byte? transportCcExtensionId = null,
            byte? absSendTimeExtensionId = null,
            RtxRetransmitter? retransmitter = null)
        {
            _owner = owner;
            _payloadizer = payloadizer;
            _maxPayload = maxPayload;
            _transportCcExtensionId = transportCcExtensionId;
            _absSendTimeExtensionId = absSendTimeExtensionId;

            // Reserve the fixed header plus, when negotiated, the one-byte header extension holding the
            // transport-cc sequence number and/or the abs-send-time timestamp, so the payloadizer writes
            // exactly where the assembled header ends and the packet copy stays a self-copy.
            _headerReserve = RtpHeader.FixedLength + HeaderExtensionOverhead(transportCcExtensionId, absSendTimeExtensionId);
            _buffer = new byte[_headerReserve + maxPayload + srtpOverhead];
            _rtxBuffer = retransmitter is null
                ? null
                : new byte[retransmitter.MaxPacketSize + srtpOverhead];
            Mid = mid;
            Kind = kind;
            Stream = stream;
            Retransmitter = retransmitter;
        }

        internal string Mid { get; }

        internal MediaKind Kind { get; }

        internal RtpStreamSender Stream { get; }

        /// <summary>The repair stream, or null when the answer kept no rtx codec.</summary>
        internal RtxRetransmitter? Retransmitter { get; }

        public Span<byte> GetPayloadBuffer(int sizeHint) => _buffer.AsSpan(_headerReserve, _maxPayload);

        public void Commit(int length, bool marker)
        {
            // The payload already sits at the offset the RTP header (fixed part plus any stamped
            // extension) will end at, so WritePacket's copy is a no-op self-copy and the packet is
            // assembled without a second buffer.
            EmitPacket(_buffer.AsSpan(_headerReserve, length), marker, _timestamp);
        }

        /// <summary>
        /// Forwards one already-packetized RTP payload verbatim onto this send track: the track's
        /// owned SSRC, the next monotonic sequence number, the supplied timestamp, marker bit and
        /// payload type. The payload is never re-packetized. The emitted packet is recorded in the
        /// send history keyed by its outbound sequence number, so an inbound NACK is served as an
        /// RFC 4588 RTX repair by the same path <see cref="Retransmit"/> drives. Called under the
        /// owner's send lock, exactly like <see cref="SendFrame"/>. Never throws.
        /// </summary>
        /// <param name="payload">The RTP payload, written verbatim.</param>
        /// <param name="timestamp">The RTP timestamp to stamp on the packet.</param>
        /// <param name="marker">The marker bit.</param>
        /// <param name="payloadType">The payload type to stamp; the subscriber's negotiated type.</param>
        /// <returns>True when the packet was assembled and handed to the send path; false when the
        /// payload cannot fit the negotiated MTU.</returns>
        internal bool ForwardRtp(ReadOnlySpan<byte> payload, uint timestamp, bool marker, byte payloadType)
        {
            if (payload.Length > _maxPayload)
            {
                // A single packet that will not fit the negotiated MTU is dropped rather than
                // fragmented — the upstream already chose the packetization, and re-splitting it
                // would corrupt the codec framing.
                return false;
            }

            // The forwarder owns the wire format: stamp the subscriber's negotiated payload type and
            // publish the rebased timestamp so this track's sender reports describe what it emitted.
            Stream.PayloadType = payloadType;
            Stream.Timestamp = timestamp;
            _timestamp = timestamp;
            EmitPacket(payload, marker, timestamp);
            _frames++;
            return true;
        }

        private void EmitPacket(ReadOnlySpan<byte> payload, bool marker, uint timestamp)
        {
            int packetLength;
            ushort transportSequenceNumber = 0;
            var stampedTransportCc = false;

            if (_transportCcExtensionId is null && _absSendTimeExtensionId is null)
            {
                packetLength = Stream.WritePacket(payload, marker, timestamp, _buffer);
            }
            else
            {
                // Build one RFC 8285 §4.2 one-byte-header extension body carrying whichever of the
                // transport-cc sequence number and abs-send-time timestamp are negotiated. Transport-cc is
                // appended first so a transport-cc-only body is byte-identical to the prior single-element
                // encoding and the golden send-path bytes are unchanged.
                Span<byte> extensionBuffer = stackalloc byte[TransportCcExtension.OneByteBodyLength
                    + AbsoluteSendTimeExtension.OneByteBodyLength];
                var writer = new RtpOneByteExtensionWriter(extensionBuffer);

                if (_transportCcExtensionId is { } ccId)
                {
                    transportSequenceNumber = _owner.NextTransportWideSequenceNumber();
                    stampedTransportCc = true;
                    Span<byte> seq = stackalloc byte[2];
                    System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(seq, transportSequenceNumber);
                    writer.TryAppend(ccId, seq);
                }

                if (_absSendTimeExtensionId is { } absId)
                {
                    var absSendTime = AbsoluteSendTimeExtension.FromMicroseconds(_owner.MonotonicMicroseconds());
                    Span<byte> stamp = stackalloc byte[AbsoluteSendTimeExtension.TimestampLength];
                    stamp[0] = (byte)(absSendTime >> 16);
                    stamp[1] = (byte)(absSendTime >> 8);
                    stamp[2] = (byte)absSendTime;
                    writer.TryAppend(absId, stamp);
                }

                writer.Finish();
                packetLength = Stream.WritePacket(
                    payload,
                    marker,
                    timestamp,
                    RtpHeaderExtension.OneByteProfile,
                    writer.Written,
                    _buffer);
            }

            // Capture the plaintext before SRTP encrypts the same buffer in place.
            Retransmitter?.History.Store(Stream.LastSequenceNumber, _buffer.AsSpan(0, packetLength));

            if (stampedTransportCc)
            {
                _owner.OnTransportRtpSent(transportSequenceNumber, packetLength);
            }

            _owner.SendRtp(_buffer, packetLength);
            _packets++;
            _bytes += payload.Length;
        }

        /// <summary>
        /// The bytes an RFC 8285 one-byte-header extension adds to the RTP header for the given negotiated
        /// elements: the four-byte profile/word-count prefix plus the concatenated element bodies padded to
        /// a four-byte boundary. Zero when neither extension is negotiated.
        /// </summary>
        internal static int HeaderExtensionOverhead(byte? transportCcExtensionId, byte? absSendTimeExtensionId)
        {
            // Each element is a one-octet id|len header plus its body: two octets for the transport-cc
            // sequence number, three for the abs-send-time timestamp.
            var body = (transportCcExtensionId is null ? 0 : 1 + 2)
                + (absSendTimeExtensionId is null ? 0 : 1 + AbsoluteSendTimeExtension.TimestampLength);
            if (body == 0)
            {
                return 0;
            }

            var padded = (body + 3) & ~3;
            return 4 + padded;
        }

        internal int SendFrame(ReadOnlySpan<byte> frame, uint timestamp)
        {
            _timestamp = timestamp;
            Stream.Timestamp = timestamp;
            var packets = _payloadizer.Packetize(frame, timestamp, _maxPayload, this);
            _frames++;
            return packets;
        }

        /// <summary>
        /// Resends one NACKed packet as an RTX packet. The caller holds the send lock, which is what
        /// serialises the repair stream's sequence numbering and the SRTP context it shares with the
        /// media stream.
        /// </summary>
        /// <param name="sequenceNumber">The media stream sequence number the peer reported missing.</param>
        /// <returns>True when a repair packet was sent.</returns>
        internal bool Retransmit(ushort sequenceNumber)
        {
            if (Retransmitter is not { } rtx || _rtxBuffer is null)
            {
                return false;
            }

            // A repair packet is an outbound RTP packet like any other, so it draws the next
            // transport-wide sequence number when the TWCC extension is negotiated.
            int length;
            ushort transportSequenceNumber = 0;
            var stamped = false;
            RtxRetransmitResult result;
            if (_transportCcExtensionId is { } extensionId)
            {
                transportSequenceNumber = _owner.NextTransportWideSequenceNumber();
                stamped = true;
                result = rtx.TryRetransmit(sequenceNumber, extensionId, transportSequenceNumber, _rtxBuffer, out length);
            }
            else
            {
                result = rtx.TryRetransmit(sequenceNumber, _rtxBuffer, out length);
            }

            if (result != RtxRetransmitResult.Retransmitted)
            {
                return false;
            }

            if (stamped)
            {
                _owner.OnTransportRtpSent(transportSequenceNumber, length);
            }

            _owner.SendRtp(_rtxBuffer, length);
            return true;
        }

        internal MediaTrackStats GetStats(
            long dropped,
            OutboundStreamQuality? quality,
            RetransmissionStats? retransmission) => new(
            Kind,
            Mid,
            Stream.Ssrc,
            Stream.PayloadType,
            _packets,
            _bytes,
            _frames,
            dropped,
            quality,
            retransmission);
    }

    /// <summary>
    /// A leaky-bucket pacing queue for outbound RTP. The send path enqueues copies of assembled,
    /// plaintext packets; a timer drains them toward the congestion controller's target through a
    /// <see cref="PacketPacer"/>, encrypting and sending each under the owner's send lock.
    /// </summary>
    /// <remarks>
    /// The send path already holds <see cref="_sendLock"/> when it calls <see cref="Enqueue"/>, and
    /// <see cref="Enqueue"/> only ever also takes <c>_gate</c>. The drain takes <c>_gate</c> to pull the
    /// packets the budget admits, releases it, and only then invokes <c>_send</c> (which takes
    /// <see cref="_sendLock"/>) — so <c>_gate</c> and <see cref="_sendLock"/> are never held at once on
    /// the drain path and the orderings cannot deadlock. A separate <c>_drainLock</c> serialises whole
    /// drains so two timer callbacks can never interleave their sends: without it a callback that
    /// emptied the queue could race a freshly scheduled one for <see cref="_sendLock"/> and protect a
    /// later packet before an earlier one, which the SRTP index guard (RFC 3711 §9.1) rejects.
    /// </remarks>
    internal sealed class PacedRtpSender : IDisposable
    {
        private static readonly TimeSpan MinDrainInterval = TimeSpan.FromMilliseconds(1);

        private readonly PacketPacer _pacer;
        private readonly TimeProvider _time;
        private readonly int _srtpOverhead;
        private readonly Action<byte[], int> _send;
        private readonly IKeryxLogger _logger;
        private readonly object _gate = new();
        private readonly object _drainLock = new();
        private readonly Queue<QueuedPacket> _queue = new();
        private ITimer? _timer;
        private bool _timerArmed;
        private bool _disposed;

        internal PacedRtpSender(
            PacketPacer pacer,
            TimeProvider time,
            int srtpOverhead,
            Action<byte[], int> send,
            IKeryxLogger logger)
        {
            _pacer = pacer;
            _time = time;
            _srtpOverhead = srtpOverhead;
            _send = send;
            _logger = logger;
            _timer = _time.CreateTimer(_ => Drain(), null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        }

        /// <summary>Retargets the pacer from a congestion-controller change.</summary>
        internal void SetTargetBitrate(long targetBitrateBitsPerSecond)
        {
            lock (_gate)
            {
                _pacer.SetTargetBitrate(targetBitrateBitsPerSecond);
            }
        }

        /// <summary>Copies one plaintext RTP packet into the queue and wakes the drain. Called under _sendLock.</summary>
        internal void Enqueue(ReadOnlySpan<byte> packet)
        {
            // Pacing is opt-in, so this copy — out of the caller's reusable buffer and into the queue —
            // only happens when congestion control is enabled. The copy is oversized by the SRTP
            // overhead so the drain can protect the packet in place, exactly as the direct path does.
            var copy = new byte[packet.Length + _srtpOverhead];
            packet.CopyTo(copy);
            var arm = false;
            lock (_gate)
            {
                if (_disposed)
                {
                    return;
                }

                _queue.Enqueue(new QueuedPacket(copy, packet.Length));
                if (!_timerArmed)
                {
                    _timerArmed = true;
                    arm = true;
                }
            }

            if (arm)
            {
                _timer?.Change(TimeSpan.Zero, Timeout.InfiniteTimeSpan);
            }
        }

        private void Drain()
        {
            // _drainLock serialises whole drains so a callback scheduled while this one is still
            // sending cannot reorder its packets ahead of ours (see the class remarks).
            lock (_drainLock)
            {
                try
                {
                    DrainOnce();
                }
                catch (Exception ex)
                {
                    // Nothing may escape a timer callback: an unhandled throw on the thread-pool
                    // thread would fault the host process. The per-packet handling below already
                    // absorbs send failures; this is the final safety net for anything else.
                    _logger.Log(KeryxLogLevel.Error, "The paced RTP drain failed unexpectedly.", ex);
                }
            }
        }

        private void DrainOnce()
        {
            List<QueuedPacket>? ready = null;
            var wait = Timeout.InfiniteTimeSpan;
            lock (_gate)
            {
                _timerArmed = false;
                if (_disposed)
                {
                    return;
                }

                while (_queue.Count > 0)
                {
                    var head = _queue.Peek();
                    if (_pacer.TryConsume(head.Length))
                    {
                        (ready ??= []).Add(_queue.Dequeue());
                    }
                    else
                    {
                        wait = _pacer.TimeUntilNextSend(head.Length);
                        break;
                    }
                }

                if (_queue.Count > 0)
                {
                    _timerArmed = true;
                }

                if (wait != Timeout.InfiniteTimeSpan)
                {
                    // Re-arm under _gate, where the timer is guaranteed live (Dispose can only run
                    // between critical sections), so a teardown race cannot fault Change. A zero or
                    // negative wait would spin the timer hot; hold it to a 1 ms floor.
                    _timer?.Change(wait < MinDrainInterval ? MinDrainInterval : wait, Timeout.InfiniteTimeSpan);
                }
            }

            if (ready is null)
            {
                return;
            }

            foreach (var packet in ready)
            {
                try
                {
                    _send(packet.Buffer, packet.Length);
                }
                catch (Exception ex)
                {
                    // A send can throw transiently — most notably the SRTP index guard refusing a
                    // reused index (RFC 3711 §9.1) during a teardown/reset race. Drop this packet
                    // and keep draining the rest rather than crashing the host; RTP tolerates loss.
                    _logger.Log(KeryxLogLevel.Warning, "Dropping a paced RTP packet after a send failure.", ex);
                }
            }
        }

        public void Dispose()
        {
            ITimer? timer;
            lock (_gate)
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;
                _queue.Clear();
                timer = _timer;
                _timer = null;
            }

            timer?.Dispose();
        }

        private readonly record struct QueuedPacket(byte[] Buffer, int Length);
    }
}
