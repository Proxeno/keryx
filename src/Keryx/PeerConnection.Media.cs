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

    private TrackSender? _videoTrack;
    private TrackSender? _audioTrack;
    private NegotiatedTrack? _negotiatedVideo;
    private NegotiatedTrack? _negotiatedAudio;

    // Stable per-kind forwarder handles, wired to the send track through the owner's locked forward
    // path. Created once in the constructor so GetForwarder is total and allocation-free; they return
    // false until the corresponding send track is negotiated.
    private RtpForwarderHandle _videoForwarder = null!;
    private RtpForwarderHandle _audioForwarder = null!;
    private Dictionary<byte, RtpRoute> _routes = [];

    // Maps a remote RFC 4588 repair SSRC to the media SSRC it repairs, learned from the peer's
    // a=ssrc-group:FID lines (RFC 5576 §4.2). An inbound RTX packet is decapsulated onto this media
    // source. Volatile-published from the negotiation path; only read from the ICE receive loop.
    private Dictionary<uint, uint> _rtxSsrcToMediaSsrc = [];
    private Dictionary<string, SimulcastReceiveTracker> _simulcastByMid = new(StringComparer.Ordinal);

    // The most recently demultiplexed remote SSRC per media kind, boxed so a reference write/read is
    // enough to publish it without locking. Only written from the single ICE receive loop that drives
    // HandleRtp; read from any thread through GetRemoteSsrc. Null until a packet of that kind arrives.
    private volatile object? _remoteVideoSsrc;
    private volatile object? _remoteAudioSsrc;

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

    private Timer? _rtcpTimer;
    private int _firSequence;

    // The transport-wide sequence number space, shared by every outbound SSRC (media and RTX). It and
    // its stamping identifier are only touched from the send path under _sendLock, so no atomics.
    private byte? _sendTransportCcExtensionId;
    private ushort _transportWideSequenceNumber;

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

    private volatile OutboundStreamQuality? _videoQuality;
    private volatile OutboundStreamQuality? _audioQuality;

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
    public int SendVideoFrame(ReadOnlySpan<byte> annexBAccessUnit, uint rtpTimestamp90k)
    {
        var track = _videoTrack;
        if (track is null || State != PeerConnectionState.Connected)
        {
            Interlocked.Increment(ref _videoFramesDropped);
            return 0;
        }

        lock (_sendLock)
        {
            if (_srtp is null)
            {
                Interlocked.Increment(ref _videoFramesDropped);
                return 0;
            }

            return track.SendFrame(annexBAccessUnit, rtpTimestamp90k);
        }
    }

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
    public int SendAudioFrame(ReadOnlySpan<byte> opusPacket, uint rtpTimestamp48k)
    {
        var track = _audioTrack;
        if (track is null || State != PeerConnectionState.Connected)
        {
            Interlocked.Increment(ref _audioFramesDropped);
            return 0;
        }

        lock (_sendLock)
        {
            if (_srtp is null)
            {
                Interlocked.Increment(ref _audioFramesDropped);
                return 0;
            }

            return track.SendFrame(opusPacket, rtpTimestamp48k);
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
        byte payloadType)
    {
        var track = kind switch
        {
            MediaKind.Video => _videoTrack,
            MediaKind.Audio => _audioTrack,
            _ => null,
        };

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
    public byte? NegotiatedVideoRtxPayloadType => _negotiatedVideo?.RtxPayloadType;

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
    public byte? GetNegotiatedPayloadType(MediaKind kind) => kind switch
    {
        MediaKind.Video => _negotiatedVideo?.PayloadType,
        MediaKind.Audio => _negotiatedAudio?.PayloadType,
        _ => null,
    };

    /// <summary>
    /// The synchronisation source Keryx sends <paramref name="kind"/> on. Assigned at construction
    /// (see <see cref="VideoSsrc"/>, <see cref="AudioSsrc"/>) and stable for the connection's lifetime,
    /// independent of negotiation state.
    /// </summary>
    /// <param name="kind">The media kind to look up.</param>
    /// <returns>The local sending SSRC for <paramref name="kind"/>; zero for any other kind.</returns>
    public uint GetLocalSsrc(MediaKind kind) => kind switch
    {
        MediaKind.Video => _videoSsrc,
        MediaKind.Audio => _audioSsrc,
        _ => 0,
    };

    /// <summary>
    /// The remote sender's synchronisation source for <paramref name="kind"/>, learned from the most
    /// recently demultiplexed inbound RTP packet of that kind (the same resolution
    /// <see cref="OnRtpPacketReceived"/> reports). Null until one has arrived.
    /// </summary>
    /// <param name="kind">The media kind to look up.</param>
    /// <returns>The last observed remote SSRC for <paramref name="kind"/>, or null.</returns>
    public uint? GetRemoteSsrc(MediaKind kind) => kind switch
    {
        MediaKind.Video => (uint?)_remoteVideoSsrc,
        MediaKind.Audio => (uint?)_remoteAudioSsrc,
        _ => null,
    };

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
        var track = _videoTrack;
        var dropped = Interlocked.Read(ref _videoFramesDropped);
        var quality = _videoQuality;
        if (track is not null)
        {
            return track.GetStats(dropped, quality, RetransmissionStatsFor(track));
        }

        return dropped == 0 && quality is null
            ? null
            : new MediaTrackStats(MediaKind.Video, _config.VideoMid, _videoSsrc, 0, 0, 0, 0, dropped, quality);
    }

    private MediaTrackStats? AudioStats()
    {
        var track = _audioTrack;
        var dropped = Interlocked.Read(ref _audioFramesDropped);
        var quality = _audioQuality;
        if (track is not null)
        {
            return track.GetStats(dropped, quality, null);
        }

        return dropped == 0 && quality is null
            ? null
            : new MediaTrackStats(MediaKind.Audio, _config.AudioMid, _audioSsrc, 0, 0, 0, 0, dropped, quality);
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
                    request.Protocol));
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
        var transportCcId = _sendTransportCcExtensionId;

        // When the TWCC extension is negotiated every packet carries the one-byte header extension, so
        // its fixed overhead comes out of the payload budget and out of the send-history slab size.
        var extensionReserve = transportCcId is null ? 0 : TransportCcExtension.OneByteHeaderOverhead;

        var datagram = Math.Min(_config.Mtu, (_transport ?? ice.Transport).MaxDatagramSize);
        var maxPayload = datagram - RtpHeader.FixedLength - extensionReserve - profile.RtpOverhead;
        if (maxPayload < 64)
        {
            throw new InvalidOperationException(
                $"An MTU of {_config.Mtu} leaves only {maxPayload} byte(s) for an RTP payload.");
        }

        if (_negotiatedVideo is { } video)
        {
            var videoMaxPayload = maxPayload;
            RtxRetransmitter? rtx = null;

            if (_config.EnableRetransmission && video.RtxPayloadType is { } rtxPayloadType)
            {
                // An RTX packet is the original packet plus the two-octet OSN (RFC 4588 §4), so the
                // media stream gives those two bytes back to keep repairs inside the same MTU.
                videoMaxPayload = maxPayload - RtxPacket.OriginalSequenceNumberLength;
                var history = new RtpSendHistory(
                    RtpHeader.FixedLength + extensionReserve + videoMaxPayload,
                    _config.RetransmissionHistory);
                rtx = new RtxRetransmitter(
                    _videoRtxSsrc,
                    rtxPayloadType,
                    video.ClockRate,
                    history,
                    _config.Retransmission,
                    logger: _logger);

                _logger.Log(
                    KeryxLogLevel.Info,
                    $"RTX enabled: pt {rtxPayloadType}, ssrc 0x{_videoRtxSsrc:x8}, "
                    + $"{history.Capacity}-packet / {history.Retention.TotalMilliseconds:F0} ms send history.");
            }

            _videoTrack = new TrackSender(
                this,
                video.Mid,
                MediaKind.Video,
                new RtpStreamSender(_videoSsrc, video.PayloadType, video.ClockRate, logger: _logger),
                new H264Packetizer(),
                videoMaxPayload,
                profile.RtpOverhead,
                transportCcId,
                rtx);
        }

        if (_negotiatedAudio is { } audio)
        {
            _audioTrack = new TrackSender(
                this,
                audio.Mid,
                MediaKind.Audio,
                new RtpStreamSender(_audioSsrc, audio.PayloadType, audio.ClockRate, logger: _logger),
                new OpusPacketizer(),
                maxPayload,
                profile.RtpOverhead,
                transportCcId);
        }

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

        if (!RtpPacket.TryParse(_rxPlain.AsSpan(0, length), out var packet))
        {
            Interlocked.Increment(ref _srtpFailures);
            return;
        }

        Interlocked.Increment(ref _rtpReceived);

        var routes = Volatile.Read(ref _routes);
        var route = routes.TryGetValue(packet.Header.PayloadType, out var found)
            ? found
            : new RtpRoute(string.Empty, MediaKind.Unknown);

        // RFC 4588 §4: an inbound RTX packet repeats an original media packet on its own SSRC, payload
        // type and sequence space. Turn it back into the packet it repairs and feed *that* through the
        // ordinary receive path, so a recovered packet reaches the depacketizer, updates reception
        // statistics and fills the loss detector's gap exactly as a directly received packet would — and
        // so it is not re-NACKed. The raw repair packet is never surfaced to the application handler.
        if (route.IsRtx)
        {
            HandleInboundRtx(route, packet, _rxPlain.AsSpan(0, length), routes);
            return;
        }

        DeliverInboundMedia(route, packet, routes);
    }

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
        Dictionary<byte, RtpRoute> routes)
    {
        var rtxToMedia = Volatile.Read(ref _rtxSsrcToMediaSsrc);
        if (!rtxToMedia.TryGetValue(rtxPacket.Header.Ssrc, out var mediaSsrc))
        {
            // No FID association for this repair SSRC. A non-simulcast section carries a single media
            // source, so the last media SSRC learned for the kind is the one being repaired; without
            // even that, there is no source to attribute the repair to, so drop it rather than guess.
            var learned = route.Kind switch
            {
                MediaKind.Video => (uint?)_remoteVideoSsrc,
                MediaKind.Audio => (uint?)_remoteAudioSsrc,
                _ => null,
            };

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

        // Route the reconstructed packet by its recovered (media) payload type so it lands on the media
        // stream's kind, mid and clock rate rather than the repair route it arrived on.
        var mediaRoute = routes.TryGetValue(recovered.Header.PayloadType, out var mediaFound)
            ? mediaFound
            : route with { IsRtx = false };

        DeliverInboundMedia(mediaRoute, recovered, routes);
    }

    /// <summary>
    /// Delivers one received media packet through the receive path: it moves the per-kind remote SSRC
    /// snapshot, folds into the RFC 3550 reception statistics and inbound loss detector, and — when a
    /// handler is attached — dispatches it in arrival order or through the per-source jitter buffer. Both
    /// directly received packets and packets reconstructed from an RTX repair flow through here.
    /// </summary>
    private void DeliverInboundMedia(RtpRoute route, in RtpPacket packet, Dictionary<byte, RtpRoute> routes)
    {
        var payloadType = packet.Header.PayloadType;

        // Track the sender's SSRC per kind for GetRemoteSsrc, straight off the same demux resolution
        // OnRtpPacketReceived is about to see. This is a plain last-writer-wins snapshot, not a full
        // source table.
        if (route.Kind == MediaKind.Video)
        {
            _remoteVideoSsrc = packet.Header.Ssrc;
        }
        else if (route.Kind == MediaKind.Audio)
        {
            _remoteAudioSsrc = packet.Header.Ssrc;
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

    private ReceiveStream GetOrCreateReceiveStream(uint ssrc)
    {
        if (!_receiveStreams.TryGetValue(ssrc, out var stream))
        {
            stream = new ReceiveStream(new JitterBuffer(_config.ReceiveJitterBuffer, _config.TimeProvider));
            _receiveStreams[ssrc] = stream;
        }

        return stream;
    }

    private void DrainReceiveStream(
        uint ssrc,
        ReceiveStream stream,
        Dictionary<byte, RtpRoute> routes,
        RtpPacketReceivedHandler handler)
    {
        while (stream.Buffer.TryGetNext(out var released))
        {
            var route = routes.TryGetValue(released.PayloadType, out var found)
                ? found
                : new RtpRoute(string.Empty, MediaKind.Unknown);

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
                stats = new InboundSourceStats(route.Kind);
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
    private sealed class InboundSourceStats(MediaKind kind)
    {
        internal MediaKind Kind { get; } = kind;

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
        var track = _videoTrack;
        if (track?.Retransmitter is null || nack.MediaSsrc != _videoSsrc)
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
            var video = block.SourceSsrc == _videoSsrc;
            if (!video && block.SourceSsrc != _audioSsrc)
            {
                // Report blocks for the RTX SSRC describe the repair stream, which has no separate
                // quality surface, and blocks for anything else are not about us at all.
                continue;
            }

            var clockRate = video ? _negotiatedVideo?.ClockRate : _negotiatedAudio?.ClockRate;
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

            if (video)
            {
                _videoQuality = quality;
            }
            else
            {
                _audioQuality = quality;
            }

            // Feed reception-report loss to the loss-based estimator. Video carries the bitrate the
            // estimator is protecting, so prefer it; fall back to audio only when no video is sent.
            if (video || _negotiatedVideo is null)
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
            SendReportFor(MediaKind.Video, _videoTrack, now);
            SendReportFor(MediaKind.Audio, _audioTrack, now);
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

            foreach (var track in new[] { _videoTrack, _audioTrack })
            {
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
    private long SendTimestampMicroseconds() =>
        (long)(_time.GetTimestamp() * (1_000_000.0 / _time.TimestampFrequency));

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
    private sealed class TrackSender : IRtpPayloadWriter
    {
        private readonly PeerConnection _owner;
        private readonly IRtpPayloadizer _payloadizer;
        private readonly byte[] _buffer;
        private readonly byte[]? _rtxBuffer;
        private readonly int _maxPayload;
        private readonly int _headerReserve;
        private readonly byte? _transportCcExtensionId;
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
            RtxRetransmitter? retransmitter = null)
        {
            _owner = owner;
            _payloadizer = payloadizer;
            _maxPayload = maxPayload;
            _transportCcExtensionId = transportCcExtensionId;

            // Reserve the fixed header plus, when TWCC is negotiated, the one-byte header extension, so the
            // payloadizer writes exactly where the assembled header ends and the packet copy is a self-copy.
            _headerReserve = RtpHeader.FixedLength
                + (transportCcExtensionId is null ? 0 : TransportCcExtension.OneByteHeaderOverhead);
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
            var stamped = false;
            if (_transportCcExtensionId is { } extensionId)
            {
                transportSequenceNumber = _owner.NextTransportWideSequenceNumber();
                stamped = true;
                Span<byte> extensionBody = stackalloc byte[TransportCcExtension.OneByteBodyLength];
                TransportCcExtension.WriteOneByteBody(extensionBody, extensionId, transportSequenceNumber);
                packetLength = Stream.WritePacket(
                    payload,
                    marker,
                    timestamp,
                    RtpHeaderExtension.OneByteProfile,
                    extensionBody,
                    _buffer);
            }
            else
            {
                packetLength = Stream.WritePacket(payload, marker, timestamp, _buffer);
            }

            // Capture the plaintext before SRTP encrypts the same buffer in place.
            Retransmitter?.History.Store(Stream.LastSequenceNumber, _buffer.AsSpan(0, packetLength));

            if (stamped)
            {
                _owner.OnTransportRtpSent(transportSequenceNumber, packetLength);
            }

            _owner.SendRtp(_buffer, packetLength);
            _packets++;
            _bytes += payload.Length;
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
