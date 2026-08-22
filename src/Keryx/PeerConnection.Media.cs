using System.Security.Cryptography;
using Keryx.Core;
using Keryx.Dtls;
using Keryx.Ice;
using Keryx.Rtp;
using Keryx.Rtp.Packetization;
using Keryx.Rtp.Rtcp;
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
    private readonly byte[] _rtcpTx = new byte[1500];

    private TrackSender? _videoTrack;
    private TrackSender? _audioTrack;
    private NegotiatedTrack? _negotiatedVideo;
    private NegotiatedTrack? _negotiatedAudio;
    private Dictionary<byte, RtpRoute> _routes = [];
    private Timer? _rtcpTimer;
    private int _firSequence;

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
    /// The <c>rtx</c> payload type the answer settled on for video, or <see langword="null"/> when the
    /// peer kept no RFC 4588 repair codec and retransmission is therefore disabled.
    /// </summary>
    /// <remarks>Meaningful once a remote answer has been applied.</remarks>
    public byte? NegotiatedVideoRtxPayloadType => _negotiatedVideo?.RtxPayloadType;

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
            if (configured is not (DtlsSrtpProfile.Aes128CmHmacSha1Tag80 or DtlsSrtpProfile.AeadAes128Gcm))
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
        var datagram = Math.Min(_config.Mtu, (_transport ?? ice.Transport).MaxDatagramSize);
        var maxPayload = datagram - RtpHeader.FixedLength - profile.RtpOverhead;
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
                    RtpHeader.FixedLength + videoMaxPayload,
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
                profile.RtpOverhead);
        }
    }

    private static SrtpProfile MapSrtpProfile(DtlsSrtpProfile profile) => profile switch
    {
        DtlsSrtpProfile.Aes128CmHmacSha1Tag80 => SrtpProfile.Aes128CmHmacSha1_80,
        DtlsSrtpProfile.AeadAes128Gcm => SrtpProfile.AeadAes128Gcm,
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

        var handler = OnRtpPacketReceived;
        if (handler is null)
        {
            return;
        }

        var payloadType = packet.Header.PayloadType;
        var routes = Volatile.Read(ref _routes);
        var route = routes.TryGetValue(payloadType, out var found) ? found : new RtpRoute(string.Empty, MediaKind.Unknown);
        var info = new RtpPacketInfo(
            route.Kind == MediaKind.Unknown ? null : route.Mid,
            route.Kind,
            payloadType,
            packet.Header.Ssrc,
            packet.Header.SequenceNumber,
            packet.Header.Timestamp,
            packet.Header.Marker);

        handler(in info, packet.Payload);
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
                OnTransportCcFeedback?.Invoke(this, new TransportCcEventArgs(twcc));
                break;

            case RtcpReceiverReport report:
                Interlocked.Increment(ref _receiverReportCount);
                IngestReportBlocks(report.ReportBlocks, receivedAt);
                OnReceiverReport?.Invoke(
                    this,
                    new ReceiverReportEventArgs(report.SenderSsrc, [.. report.ReportBlocks], receivedAt));
                break;

            case RtcpSenderReport sender when sender.ReportBlocks.Count > 0:
                Interlocked.Increment(ref _receiverReportCount);
                IngestReportBlocks(sender.ReportBlocks, receivedAt);
                OnReceiverReport?.Invoke(
                    this,
                    new ReceiverReportEventArgs(sender.SenderSsrc, [.. sender.ReportBlocks], receivedAt));
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
            SendReportFor(_videoTrack, now);
            SendReportFor(_audioTrack, now);
        }
        catch (Exception ex)
        {
            _logger.Log(KeryxLogLevel.Warning, "Sending an RTCP sender report failed.", ex);
        }
    }

    private void SendReportFor(TrackSender? track, DateTimeOffset now)
    {
        if (track is null)
        {
            return;
        }

        var packets = new List<RtcpPacket>(4)
        {
            track.Stream.CreateSenderReport(now),
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
            RtxRetransmitter? retransmitter = null)
        {
            _owner = owner;
            _payloadizer = payloadizer;
            _maxPayload = maxPayload;
            _buffer = new byte[RtpHeader.FixedLength + maxPayload + srtpOverhead];
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

        public Span<byte> GetPayloadBuffer(int sizeHint) => _buffer.AsSpan(RtpHeader.FixedLength, _maxPayload);

        public void Commit(int length, bool marker)
        {
            // The payload already sits at the offset the RTP header will end at, so WritePacket's
            // copy is a no-op self-copy and the packet is assembled without a second buffer.
            var packetLength = Stream.WritePacket(
                _buffer.AsSpan(RtpHeader.FixedLength, length),
                marker,
                _timestamp,
                _buffer);

            // Capture the plaintext before SRTP encrypts the same buffer in place.
            Retransmitter?.History.Store(Stream.LastSequenceNumber, _buffer.AsSpan(0, packetLength));

            _owner.SendProtectedRtp(_buffer, packetLength);
            _packets++;
            _bytes += length;
        }

        internal int SendFrame(ReadOnlySpan<byte> frame, uint timestamp)
        {
            _timestamp = timestamp;
            Stream.Timestamp = timestamp;
            var packets = _payloadizer.Packetize(frame, _maxPayload, this);
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

            if (rtx.TryRetransmit(sequenceNumber, _rtxBuffer, out var length) != RtxRetransmitResult.Retransmitted)
            {
                return false;
            }

            _owner.SendProtectedRtp(_rtxBuffer, length);
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
}
