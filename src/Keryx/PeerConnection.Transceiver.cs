using Keryx.Sdp;

namespace Keryx;

/// <content>
/// The internal transceiver model (Epic D, PR 2). Everything the connection sends and receives is
/// keyed by <see cref="RtpTransceiver"/> — an ordered set of media objects, each with its own mid,
/// direction, codec and SSRC — rather than by the historical per-kind scalar fields. In this phase the
/// model is internal and drives the existing single-per-kind behaviour exactly: the constructor builds
/// one video and one audio transceiver from the legacy config, the offer/answer builders walk the
/// transceiver set, and the legacy per-kind API resolves "the video/audio thing" to the first
/// transceiver of that kind. No public API changes; see <c>docs/design/session-model.md</c> §5–6.
/// </content>
public sealed partial class PeerConnection
{
    // The ordered RTP transceiver set, in m-line order. The data channel section is not a transceiver
    // (session-model.md §8.4). In this phase it is built once in the constructor — one Video transceiver
    // then one Audio transceiver, matching the historical section order — and never restructured.
    private readonly List<RtpTransceiver> _transceivers = [];

    // Cached first-of-kind handles for the legacy per-kind shim. "First of kind" is exact and stable
    // because the constructor creates the video transceiver before the audio one, so for every existing
    // single-video/single-audio consumer the first-of-kind transceiver is the only one of its kind.
    private RtpTransceiver? _firstVideoTransceiver;
    private RtpTransceiver? _firstAudioTransceiver;

    // Every local media and RTX SSRC mapped to the sender that owns it, with a flag marking RTX SSRCs.
    // Built once in the constructor — SSRCs are allocated there and stable for the connection's life —
    // and read-only thereafter, so the RTCP receive loop resolves "whose packet is this" by SSRC
    // (session-model.md §1.5) without locking.
    private readonly Dictionary<uint, LocalSsrcOwner> _localSsrcOwners = [];

    /// <summary>A local SSRC's owning sender, and whether the SSRC is the RFC 4588 repair source.</summary>
    private readonly record struct LocalSsrcOwner(RtpSender Sender, bool IsRtx);

    /// <summary>
    /// Builds the legacy per-kind transceivers from the existing config (session-model.md §5.1): a
    /// sendonly video transceiver pinned to <c>VideoMid</c> when video codecs are configured, then a
    /// sendonly audio transceiver pinned to <c>AudioMid</c> when audio codecs are configured. Their
    /// senders carry the pre-allocated SSRCs, so <see cref="VideoSsrc"/> / <see cref="AudioSsrc"/> are
    /// known before negotiation exactly as before.
    /// </summary>
    private void BuildLegacyTransceivers()
    {
        if (_config.VideoCodecs.Count > 0)
        {
            var sender = new RtpSender(
                MediaKind.Video,
                NewSsrc(),
                NewSsrc(),
                _config.VideoTrackId ?? NewIdentifier("video"));
            AddTransceiverInternal(
                new RtpTransceiver(MediaKind.Video, MediaDirection.SendOnly, sender, new RtpReceiver(), _config.VideoMid));
        }

        if (_config.AudioCodecs.Count > 0)
        {
            var sender = new RtpSender(
                MediaKind.Audio,
                NewSsrc(),
                0,
                _config.AudioTrackId ?? NewIdentifier("audio"));
            AddTransceiverInternal(
                new RtpTransceiver(MediaKind.Audio, MediaDirection.SendOnly, sender, new RtpReceiver(), _config.AudioMid));
        }
    }

    /// <summary>Appends a transceiver, updating the first-of-kind caches and the local-SSRC ownership map.</summary>
    private void AddTransceiverInternal(RtpTransceiver transceiver)
    {
        _transceivers.Add(transceiver);
        switch (transceiver.Kind)
        {
            case MediaKind.Video:
                _firstVideoTransceiver ??= transceiver;
                break;
            case MediaKind.Audio:
                _firstAudioTransceiver ??= transceiver;
                break;
            default:
                break;
        }

        var sender = transceiver.Sender;
        _localSsrcOwners[sender.Ssrc] = new LocalSsrcOwner(sender, false);
        if (sender.RtxSsrc != 0)
        {
            _localSsrcOwners[sender.RtxSsrc] = new LocalSsrcOwner(sender, true);
        }
    }

    /// <summary>The first transceiver of <paramref name="kind"/>, or null when none is of that kind.</summary>
    private RtpTransceiver? FirstTransceiver(MediaKind kind) => kind switch
    {
        MediaKind.Video => _firstVideoTransceiver,
        MediaKind.Audio => _firstAudioTransceiver,
        _ => null,
    };

    /// <summary>The sender of the first transceiver of <paramref name="kind"/>, or null when none.</summary>
    private RtpSender? FirstSender(MediaKind kind) => FirstTransceiver(kind)?.Sender;

    /// <summary>
    /// Binds a remote offer's RTP m-line to a transceiver (RFC 8829 §5.10, session-model.md §3.2): an
    /// existing transceiver already associated with the offered mid is reused, otherwise the first
    /// non-stopped, unassociated transceiver of the same kind adopts the offered mid, otherwise a
    /// transceiver is auto-created for it. The bound transceiver's direction defaults to the complement
    /// of the offered direction (a <c>recvonly</c> offer makes this side the sender, everything else
    /// makes it a receiver), reproducing the historical answerer rule exactly.
    /// </summary>
    private RtpTransceiver BindOfferedMediaLine(MediaKind kind, string mid, MediaDirection offeredDirection, HashSet<RtpTransceiver> associated)
    {
        RtpTransceiver? bound = null;
        foreach (var transceiver in _transceivers)
        {
            if (transceiver.Kind == kind && !transceiver.Stopped && !associated.Contains(transceiver))
            {
                bound = transceiver;
                break;
            }
        }

        if (bound is null)
        {
            // Auto-create for an m-line beyond what the local side prepared. In this phase the shipping
            // consumers never reach here (they present one video and one audio m-line, already bound);
            // this keeps a multi-m-line offer from crashing rather than exposing new public surface.
            var sender = new RtpSender(kind, NewSsrc(), kind == MediaKind.Video ? NewSsrc() : 0, NewIdentifier(kind == MediaKind.Video ? "video" : "audio"));
            bound = new RtpTransceiver(kind, MediaDirection.RecvOnly, sender, new RtpReceiver(), mid);
            AddTransceiverInternal(bound);
        }

        associated.Add(bound);
        bound.Mid = mid;
        bound.Direction = offeredDirection == MediaDirection.RecvOnly ? MediaDirection.SendOnly : MediaDirection.RecvOnly;
        return bound;
    }

    /// <summary>
    /// One RTP transceiver: an ordered media object with its own mid, direction, codec and SSRC. In this
    /// phase the type is internal; PR 3 promotes it (and its sender/receiver) to the public API.
    /// </summary>
    private sealed class RtpTransceiver
    {
        internal RtpTransceiver(
            MediaKind kind,
            MediaDirection direction,
            RtpSender sender,
            RtpReceiver receiver,
            string? mid)
        {
            Kind = kind;
            Direction = direction;
            Sender = sender;
            Receiver = receiver;
            Mid = mid;
        }

        /// <summary>The negotiated a=mid, or the pinned offer mid; fixed at creation for legacy transceivers.</summary>
        internal string? Mid { get; set; }

        /// <summary>audio or video. Fixed at creation; a transceiver never changes kind.</summary>
        internal MediaKind Kind { get; }

        /// <summary>The direction the application wants, settable before the next negotiation.</summary>
        internal MediaDirection Direction { get; set; }

        /// <summary>The direction actually negotiated (RFC 8829), null before negotiation settles.</summary>
        internal MediaDirection? CurrentDirection { get; set; }

        internal RtpSender Sender { get; }

        internal RtpReceiver Receiver { get; }

        /// <summary>Marks the transceiver stopped; a stopped slot emits a rejected (port 0) m-line.</summary>
        internal bool Stopped { get; private set; }

        internal void Stop() => Stopped = true;
    }

    /// <summary>
    /// The send half of a transceiver: the local SSRCs it owns, the negotiated send codec, and — once
    /// the connection is up — the live wire sender. A public face over the private
    /// <see cref="TrackSender"/> arrives in PR 3; here it holds the reference the driver wires.
    /// </summary>
    private sealed class RtpSender
    {
        internal RtpSender(MediaKind kind, uint ssrc, uint rtxSsrc, string trackId)
        {
            Kind = kind;
            Ssrc = ssrc;
            RtxSsrc = rtxSsrc;
            TrackId = trackId;
        }

        /// <summary>The media kind this sender emits.</summary>
        internal MediaKind Kind { get; }

        /// <summary>The local SSRC this sender owns; stable for the transceiver's life.</summary>
        internal uint Ssrc { get; }

        /// <summary>The RFC 4588 rtx repair SSRC, or 0 when this sender carries no repair stream.</summary>
        internal uint RtxSsrc { get; }

        /// <summary>The msid track id this sender publishes.</summary>
        internal string TrackId { get; }

        /// <summary>What negotiation settled on for this sender, null before it settles.</summary>
        internal NegotiatedTrack? Negotiated { get; set; }

        /// <summary>The live wire sender, null until the connection driver builds it.</summary>
        internal TrackSender? Track { get; set; }

        /// <summary>The last reception-report-derived outbound link quality snapshot for this stream.</summary>
        internal volatile OutboundStreamQuality? Quality;

        /// <summary>The negotiated send payload type, null before negotiation settles.</summary>
        internal byte? PayloadType => Negotiated?.PayloadType;

        /// <summary>The negotiated rtx payload type, null when the peer kept no repair codec.</summary>
        internal byte? RtxPayloadType => Negotiated?.RtxPayloadType;
    }

    /// <summary>
    /// The receive half of a transceiver: the remote sender's SSRC learned from inbound RTP. The boxed
    /// volatile snapshot reproduces the historical <c>_remoteVideoSsrc</c> / <c>_remoteAudioSsrc</c>
    /// publication — a single reference write/read, no lock — exactly.
    /// </summary>
    private sealed class RtpReceiver
    {
        private volatile object? _remoteSsrc;

        /// <summary>The remote sender's SSRC, learned from inbound RTP; null until one arrives.</summary>
        internal uint? RemoteSsrc
        {
            get => (uint?)_remoteSsrc;
            set => _remoteSsrc = value;
        }
    }
}
