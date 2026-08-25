using Keryx.Ice;

namespace Keryx;

/// <content>
/// The W3C-shaped statistics view. <see cref="GetStatsReport"/> reshapes the same aggregated counters
/// <see cref="GetStats"/> already exposes into the standard
/// <see href="https://www.w3.org/TR/webrtc-stats/">webrtc-stats</see> dictionaries, so consumers get a
/// portable <c>RTCStatsReport</c> alongside the Keryx-specific <see cref="PeerConnectionStats"/>. It is
/// purely additive: nothing here changes <see cref="GetStats"/> or <see cref="PeerConnectionStats"/>.
/// </content>
public sealed partial class PeerConnection
{
    /// <summary>
    /// Takes a W3C-<c>RTCStatsReport</c>-shaped snapshot of the connection: one <c>codec</c>,
    /// <c>inbound-rtp</c>, <c>outbound-rtp</c>, <c>remote-inbound-rtp</c>, <c>transport</c>,
    /// <c>candidate-pair</c> and <c>local-candidate</c>/<c>remote-candidate</c> stat per applicable
    /// object, built from the same counters <see cref="GetStats"/> reads.
    /// </summary>
    /// <returns>The report; empty of RTP entries before media flows, but never null.</returns>
    public RtcStatsReport GetStatsReport()
    {
        var now = _time.GetUtcNow();
        var stats = new List<RtcStat>();

        AddCodecStats(stats, now);
        AddRtpStreamStats(stats, now);
        AddTransportAndIceStats(stats, now);

        return new RtcStatsReport(stats);
    }

    /// <summary>The stable report id of the codec stat for <paramref name="payloadType"/>.</summary>
    private static string CodecStatId(uint payloadType) =>
        string.Create(System.Globalization.CultureInfo.InvariantCulture, $"codec_{payloadType}");

    private void AddCodecStats(List<RtcStat> stats, DateTimeOffset now)
    {
        var seen = new HashSet<uint>();
        foreach (var transceiver in _transceivers)
        {
            if (transceiver.NegotiatedCodec is not { } codec || codec.IsRtx || !seen.Add((uint)codec.PayloadType))
            {
                continue;
            }

            var rtpMap = codec.RtpMap;
            stats.Add(new RtcCodecStats(CodecStatId((uint)codec.PayloadType), now)
            {
                PayloadType = (uint)codec.PayloadType,
                MimeType = MimeTypeFor(transceiver.Kind, codec.EncodingName),
                ClockRate = (uint)rtpMap.ClockRate,
                Channels = rtpMap.Channels is { } channels ? (uint)channels : null,
                SdpFmtpLine = codec.Fmtp,
            });
        }
    }

    private void AddRtpStreamStats(List<RtcStat> stats, DateTimeOffset now)
    {
        // Outbound and remote-inbound (from the peer's reception reports), per send transceiver.
        foreach (var transceiver in _transceivers)
        {
            var sender = transceiver.Sender;
            if (sender.Track is not { } track || sender.Ssrc == 0)
            {
                continue;
            }

            var retransmission = RetransmissionStatsFor(track);
            var send = track.GetStats(0, sender.Quality, retransmission);
            var codecId = sender.PayloadType is { } pt ? CodecStatId(pt) : null;
            var outboundId = OutboundStatId(sender.Ssrc);
            var isVideo = transceiver.Kind == MediaKind.Video;

            stats.Add(new RtcOutboundRtpStreamStats(outboundId, now)
            {
                Ssrc = sender.Ssrc,
                Kind = KindToken(transceiver.Kind),
                PacketsSent = send.PacketsSent,
                BytesSent = send.BytesSent,
                CodecId = codecId,
                PayloadType = sender.PayloadType,
                RetransmittedPacketsSent = retransmission?.PacketsRetransmitted,
                RetransmittedBytesSent = retransmission?.BytesRetransmitted,
                NackCount = retransmission?.NacksReceived,
                FirCount = isVideo ? Interlocked.Read(ref _firCount) : null,
                PliCount = isVideo ? Interlocked.Read(ref _pliCount) : null,
                TargetBitrate = isVideo && _congestionController is { } controller
                    ? (double)controller.TargetBitrateBitsPerSecond
                    : null,
            });

            if (sender.Quality is { } quality)
            {
                stats.Add(new RtcRemoteInboundRtpStreamStats(RemoteInboundStatId(sender.Ssrc), quality.ReportedAt)
                {
                    Ssrc = sender.Ssrc,
                    Kind = KindToken(transceiver.Kind),
                    PacketsLost = quality.CumulativePacketsLost,
                    FractionLost = quality.FractionLost,
                    Jitter = quality.JitterInterval?.TotalSeconds,
                    RoundTripTime = quality.RoundTripTime?.TotalSeconds,
                    LocalId = outboundId,
                });
            }
        }

        // Inbound, per received source. Map each source to its receiving transceiver for the codec.
        var receiverNacks = Interlocked.Read(ref _receiverNacksSent);
        foreach (var source in SnapshotInboundSources())
        {
            var transceiver = FindReceivingTransceiver(source.Ssrc, source.Kind);
            var codecPt = transceiver?.NegotiatedCodec is { IsRtx: false } codec ? (uint?)codec.PayloadType : null;

            stats.Add(new RtcInboundRtpStreamStats(InboundStatId(source.Ssrc), now)
            {
                Ssrc = source.Ssrc,
                Kind = KindToken(source.Kind),
                PacketsReceived = source.PacketsReceived,
                PacketsLost = source.PacketsLost,
                Jitter = source.ClockRate > 0 ? (double)source.Jitter / source.ClockRate : null,
                CodecId = codecPt is { } pt ? CodecStatId(pt) : null,
                PayloadType = codecPt,
                NackCount = source.Kind == MediaKind.Video && _config.EnableReceiverNack ? receiverNacks : null,
            });
        }
    }

    private void AddTransportAndIceStats(List<RtcStat> stats, DateTimeOffset now)
    {
        var selected = _ice?.SelectedPair;
        string? selectedPairId = null;

        if (selected is not null)
        {
            var localId = IceCandidateStatId("local", selected.Local);
            var remoteId = IceCandidateStatId("remote", selected.Remote);
            selectedPairId = CandidatePairStatId(selected);

            stats.Add(BuildCandidateStat(localId, "local-candidate", selected.Local, now));
            stats.Add(BuildCandidateStat(remoteId, "remote-candidate", selected.Remote, now));
            stats.Add(new RtcCandidatePairStats(selectedPairId, now)
            {
                LocalCandidateId = localId,
                RemoteCandidateId = remoteId,
                State = CandidatePairStateToken(selected.State),
                Nominated = selected.Nominated,
            });
        }

        stats.Add(new RtcTransportStats("transport", now)
        {
            DtlsState = DtlsState.ToString().ToLowerInvariant(),
            SelectedCandidatePairId = selectedPairId,
            DtlsCipher = _dtls?.NegotiatedCipherSuite,
            SrtpCipher = NegotiatedSrtpProfile?.Name,
        });
    }

    private static RtcIceCandidateStats BuildCandidateStat(
        string id, string type, IceCandidate candidate, DateTimeOffset now) =>
        new(id, type, now)
        {
            Address = candidate.Address.ToString(),
            Port = candidate.Port,
            Protocol = candidate.Transport,
            CandidateType = IceCandidate.TypeToken(candidate.Type),
        };

    /// <summary>Snapshots every inbound source with at least one received packet, under the stats lock.</summary>
    private List<InboundSourceSnapshot> SnapshotInboundSources()
    {
        var snapshots = new List<InboundSourceSnapshot>();
        lock (_receiveStatsLock)
        {
            foreach (var (ssrc, source) in _receiveStats)
            {
                var statistics = source.Statistics;
                if (statistics.PacketsReceived == 0)
                {
                    continue;
                }

                snapshots.Add(new InboundSourceSnapshot(
                    ssrc,
                    source.Kind,
                    source.ClockRate,
                    statistics.PacketsReceived,
                    statistics.CumulativePacketsLost,
                    statistics.Jitter));
            }
        }

        return snapshots;
    }

    /// <summary>Finds the transceiver receiving <paramref name="ssrc"/>, else the first of its kind.</summary>
    private RtpTransceiver? FindReceivingTransceiver(uint ssrc, MediaKind kind)
    {
        RtpTransceiver? kindMatch = null;
        foreach (var transceiver in _transceivers)
        {
            if (transceiver.Receiver.RemoteSsrc == ssrc)
            {
                return transceiver;
            }

            if (kindMatch is null && transceiver.Kind == kind)
            {
                kindMatch = transceiver;
            }
        }

        return kindMatch;
    }

    private static string MimeTypeFor(MediaKind kind, string encodingName) =>
        string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{KindToken(kind)}/{encodingName}");

    private static string KindToken(MediaKind kind) => kind switch
    {
        MediaKind.Video => "video",
        MediaKind.Audio => "audio",
        _ => "unknown",
    };

    private static string CandidatePairStateToken(IceCandidatePairState state) => state switch
    {
        IceCandidatePairState.Frozen => "frozen",
        IceCandidatePairState.Waiting => "waiting",
        IceCandidatePairState.InProgress => "in-progress",
        IceCandidatePairState.Succeeded => "succeeded",
        IceCandidatePairState.Failed => "failed",
        _ => "waiting",
    };

    private static string OutboundStatId(uint ssrc) =>
        string.Create(System.Globalization.CultureInfo.InvariantCulture, $"outbound-rtp_{ssrc}");

    private static string InboundStatId(uint ssrc) =>
        string.Create(System.Globalization.CultureInfo.InvariantCulture, $"inbound-rtp_{ssrc}");

    private static string RemoteInboundStatId(uint ssrc) =>
        string.Create(System.Globalization.CultureInfo.InvariantCulture, $"remote-inbound-rtp_{ssrc}");

    private static string CandidatePairStatId(IceCandidatePair pair) =>
        string.Create(
            System.Globalization.CultureInfo.InvariantCulture,
            $"candidate-pair_{pair.Local.EndPoint}_{pair.Remote.EndPoint}");

    private static string IceCandidateStatId(string side, IceCandidate candidate) =>
        string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{side}-candidate_{candidate.EndPoint}");

    /// <summary>A lock-free snapshot of one inbound source's reception statistics.</summary>
    private readonly record struct InboundSourceSnapshot(
        uint Ssrc,
        MediaKind Kind,
        uint ClockRate,
        long PacketsReceived,
        long PacketsLost,
        long Jitter);
}
