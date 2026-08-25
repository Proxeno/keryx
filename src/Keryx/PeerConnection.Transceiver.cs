using System.Globalization;
using Keryx.Sdp;

namespace Keryx;

/// <content>
/// The transceiver model (Epic D). Everything the connection sends and receives is keyed by
/// <see cref="RtpTransceiver"/> — an ordered set of media objects, each with its own mid, direction,
/// codec and SSRC — rather than by the historical per-kind scalar fields. The constructor builds the
/// legacy per-kind transceivers from the config, and the legacy per-kind API resolves "the video/audio
/// thing" to the first transceiver of that kind, so a single-video/single-audio consumer is unchanged.
/// PR 3 promotes the model to the public API additively: <see cref="AddTransceiver"/> /
/// <see cref="AddTrack"/> offer N m-lines of any kind, the answerer binds or auto-creates per RFC 8829
/// §5.10 firing <see cref="OnTransceiver"/>, and the offer carries the MID header extension on every RTP
/// m-line. See <c>docs/design/session-model.md</c> §2–3.
/// </content>
public sealed partial class PeerConnection
{
    // The ordered RTP transceiver set, in m-line order. The data channel section is not a transceiver
    // (session-model.md §8.4). The constructor builds the legacy set — one Video then one Audio; the
    // public AddTransceiver/AddTrack append more before the first negotiation.
    private readonly List<RtpTransceiver> _transceivers = [];

    // A non-mutable, non-castable view over _transceivers for the public Transceivers property. Assigned
    // in the constructor (a field initializer cannot reference another instance field).
    private readonly System.Collections.ObjectModel.ReadOnlyCollection<RtpTransceiver> _transceiversView;

    // A lock-free immutable copy of the transceiver set, swapped whole under _lock whenever a transceiver
    // is appended. The receive path resolves a packet's transceiver by mid (GetTransceiver) per packet,
    // and a mid-session renegotiation can append a transceiver concurrently — reading this array snapshot
    // rather than iterating the live list keeps that hot path allocation- and lock-free and race-free.
    private volatile RtpTransceiver[] _transceiverSnapshot = [];

    // Cached first-of-kind handles for the legacy per-kind shim. "First of kind" is exact and stable
    // because the constructor creates the video transceiver before the audio one, so for every existing
    // single-video/single-audio consumer the first-of-kind transceiver is the only one of its kind.
    private RtpTransceiver? _firstVideoTransceiver;
    private RtpTransceiver? _firstAudioTransceiver;

    // Set once the public AddTransceiver/AddTrack API is used, so the MID header-extension extmap is
    // offered on every RTP m-line (session-model.md §3.5) only when multiple m-lines can actually appear.
    // A pure legacy single-per-kind config leaves this false, keeping its offer byte-identical.
    private bool _transceiverApiUsed;

    // Every local media and RTX SSRC mapped to the sender that owns it, with a flag marking RTX SSRCs.
    // Read-mostly and swapped whole: the RTCP receive loop resolves "whose packet is this" by SSRC
    // (session-model.md §1.5) lock-free, while a mid-session renegotiation may append a sender's SSRCs
    // from the negotiation thread — so an append builds a new dictionary and publishes it atomically
    // rather than mutating the live one under the reader.
    private volatile Dictionary<uint, LocalSsrcOwner> _localSsrcOwners = [];

    /// <summary>
    /// Raised when applying a remote offer binds or creates a transceiver this application did not
    /// explicitly add (RFC 8829 §5.10 auto-create, session-model.md §3.2). Raised from
    /// <see cref="SetRemoteDescriptionAsync"/> before <see cref="CreateAnswerAsync"/> builds the answer,
    /// so a handler may set <see cref="RtpTransceiver.Direction"/> or attach to the receiver first.
    /// </summary>
    public event EventHandler<RtpTransceiver>? OnTransceiver;

    /// <summary>Every transceiver, in m-line order. The data channel is not a transceiver.</summary>
    /// <remarks>
    /// This is a read-only view over the live set, not a snapshot: it reflects transceivers appended by a
    /// mid-session <see cref="AddTransceiver"/> and ones auto-created while a remote offer is applied. The
    /// set is only ever appended to (never reordered or removed from — a stopped transceiver keeps its
    /// slot), so an index, once observed, stays valid; enumerate the collection off the negotiation path
    /// rather than concurrently with an add. The internal receive and diagnostic paths read a lock-free
    /// snapshot instead, so they are unaffected by a concurrent add.
    /// </remarks>
    public IReadOnlyList<RtpTransceiver> Transceivers => _transceiversView;

    /// <summary>The transceiver associated with <paramref name="mid"/>, or null when none is.</summary>
    /// <param name="mid">The <c>a=mid</c> to look up.</param>
    /// <returns>The transceiver, or null.</returns>
    public RtpTransceiver? GetTransceiver(string mid)
    {
        ArgumentNullException.ThrowIfNull(mid);

        // Read the lock-free snapshot: this runs per packet on the receive path, concurrently with a
        // possible mid-session append.
        foreach (var transceiver in _transceiverSnapshot)
        {
            if (string.Equals(transceiver.Mid, mid, StringComparison.Ordinal))
            {
                return transceiver;
            }
        }

        return null;
    }

    /// <summary>
    /// Adds a transceiver for a media kind with an explicit direction (session-model.md §2.2). Its
    /// sender SSRC (and, for video, its rtx SSRC) is allocated immediately, so
    /// <see cref="RtpSender.Ssrc"/> is readable before negotiation; the mid is allocated when the next
    /// offer is built. Valid before the first negotiation or mid-session: a transceiver added after the
    /// connection is negotiated appears as a new m-line in the next offer (session-model.md §4.2) and,
    /// once that renegotiation settles a send codec, streams against the existing SRTP context without a
    /// rekey (§4.3). Raises <see cref="OnNegotiationNeeded"/> when the machine is
    /// <see cref="SignalingState.Stable"/>.
    /// </summary>
    /// <param name="kind">The media kind; <see cref="MediaKind.Video"/> or <see cref="MediaKind.Audio"/>.</param>
    /// <param name="direction">The direction this side wants for the m-line.</param>
    /// <param name="init">Optional codec preference, pinned mid, rtx and simulcast declaration.</param>
    /// <returns>The new transceiver.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="kind"/> is not audio or video.</exception>
    /// <exception cref="InvalidOperationException">The connection is closed.</exception>
    public RtpTransceiver AddTransceiver(
        MediaKind kind,
        MediaDirection direction = MediaDirection.SendRecv,
        RtpTransceiverInit? init = null)
    {
        if (kind is not (MediaKind.Video or MediaKind.Audio))
        {
            throw new ArgumentOutOfRangeException(nameof(kind), kind, "Only audio and video transceivers can be added.");
        }

        // A codec source must exist: either the init supplies one, or the per-kind config does. Without
        // one the offer would emit an m-line with zero formats (invalid SDP), so fail fast here.
        var hasCodecs = init is { Codecs.Count: > 0 }
            || (kind == MediaKind.Video ? _config.VideoCodecs.Count > 0 : _config.AudioCodecs.Count > 0);
        if (!hasCodecs)
        {
            throw new ArgumentException(
                $"No codecs are available for a {kind} transceiver; provide init.Codecs or configure {kind}Codecs.",
                nameof(init));
        }

        RtpTransceiver transceiver;
        lock (_lock)
        {
            ObjectDisposedException.ThrowIf(_closed != 0, this);

            // A pinned mid must be unique across the session, or the offer emits duplicate a=mid lines.
            if (init?.Mid is { } pinnedMid)
            {
                if (string.Equals(pinnedMid, _config.ApplicationMid, StringComparison.Ordinal))
                {
                    throw new ArgumentException(
                        $"init.Mid '{pinnedMid}' collides with the application (data channel) mid.", nameof(init));
                }

                foreach (var existing in _transceivers)
                {
                    if (string.Equals(existing.Mid, pinnedMid, StringComparison.Ordinal))
                    {
                        throw new ArgumentException(
                            $"init.Mid '{pinnedMid}' is already used by another transceiver.", nameof(init));
                    }
                }
            }

            var sender = new RtpSender(
                this,
                kind,
                NewSsrc(),
                kind == MediaKind.Video ? NewSsrc() : 0,
                NewIdentifier(kind == MediaKind.Video ? "video" : "audio"),
                _config.EnableFlexFec && kind == MediaKind.Video ? NewSsrc() : 0);

            transceiver = new RtpTransceiver(kind, direction, sender, new RtpReceiver(), init?.Mid)
            {
                // An application-added transceiver keeps its explicit direction when it binds to a remote
                // offer's m-line (session-model.md §3.2); only the internally built legacy transceivers and
                // auto-created ones take the complement-of-offered default.
                PreserveDirectionOnBind = true,
                OfferCodecs = init is { Codecs.Count: > 0 } ? [.. init.Codecs] : [],
                EnableRetransmissionOnOffer = kind == MediaKind.Video && (init?.EnableRetransmission ?? _config.EnableRetransmission),

                // An application-added track needs to be negotiated; this arms the JSEP negotiation-needed
                // check below. Legacy and auto-created transceivers leave this false (session-model.md §4.1).
                NegotiationPending = true,
            };

            AddTransceiverInternal(transceiver);
            _transceiverApiUsed = true;
        }

        // Raise OnNegotiationNeeded outside the lock: the new track means the current descriptions no
        // longer reflect the transceiver set (session-model.md §4.1). Coalesced across a burst of adds.
        UpdateNegotiationNeeded();
        return transceiver;
    }

    /// <summary>
    /// Convenience for the single published-track case (session-model.md §2.2): adds a
    /// <see cref="MediaDirection.SendOnly"/> transceiver wired to send the given codecs. The
    /// <see cref="AddTrack"/> of this model.
    /// </summary>
    /// <param name="kind">The media kind; <see cref="MediaKind.Video"/> or <see cref="MediaKind.Audio"/>.</param>
    /// <param name="codecs">The codecs to offer for the track, in preference order.</param>
    /// <returns>The new transceiver.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="codecs"/> is null.</exception>
    public RtpTransceiver AddTrack(MediaKind kind, IReadOnlyList<SdpCodec> codecs)
    {
        ArgumentNullException.ThrowIfNull(codecs);
        var init = new RtpTransceiverInit();
        foreach (var codec in codecs)
        {
            init.Codecs.Add(codec);
        }

        return AddTransceiver(kind, MediaDirection.SendOnly, init);
    }

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
                this,
                MediaKind.Video,
                NewSsrc(),
                NewSsrc(),
                _config.VideoTrackId ?? NewIdentifier("video"),
                _config.EnableFlexFec ? NewSsrc() : 0);
            AddTransceiverInternal(
                new RtpTransceiver(MediaKind.Video, MediaDirection.SendOnly, sender, new RtpReceiver(), _config.VideoMid)
                {
                    EnableRetransmissionOnOffer = _config.EnableRetransmission,
                });
        }

        if (_config.AudioCodecs.Count > 0)
        {
            var sender = new RtpSender(
                this,
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

        // Publish the lock-free snapshot the receive path and the diagnostic readers consult. Callers
        // hold _lock (the constructor runs single-threaded; every other add is under _lock), so the
        // whole-array swap is atomic with respect to those readers.
        _transceiverSnapshot = [.. _transceivers];

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
        var owners = new Dictionary<uint, LocalSsrcOwner>(_localSsrcOwners)
        {
            [sender.Ssrc] = new LocalSsrcOwner(sender, false),
        };
        if (sender.RtxSsrcRaw != 0)
        {
            owners[sender.RtxSsrcRaw] = new LocalSsrcOwner(sender, true);
        }

        _localSsrcOwners = owners;
    }

    /// <summary>
    /// The lock-free immutable copy of the transceiver set, for iteration off the negotiation thread. A
    /// mid-session renegotiation can append a transceiver under <see cref="_lock"/> while a diagnostic or
    /// timer-thread reader enumerates, so those readers iterate this snapshot rather than the live list.
    /// </summary>
    private RtpTransceiver[] SnapshotTransceivers() => _transceiverSnapshot;

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
    /// Allocates mids for every transceiver still lacking one, in insertion order, skipping mids already
    /// pinned by a legacy transceiver or the data channel (session-model.md §3.1). Called once when the
    /// offer is built; a pinned mid is kept and the free mids count up past it.
    /// </summary>
    private void AllocateOfferMids()
    {
        var claimed = new HashSet<string>(StringComparer.Ordinal) { _config.ApplicationMid };
        foreach (var transceiver in _transceivers)
        {
            if (transceiver.Mid is { } mid)
            {
                claimed.Add(mid);
            }
        }

        var next = 0;
        foreach (var transceiver in _transceivers)
        {
            if (transceiver.Mid is not null)
            {
                continue;
            }

            string candidate;
            do
            {
                candidate = next.ToString(CultureInfo.InvariantCulture);
                next++;
            }
            while (!claimed.Add(candidate));

            transceiver.Mid = candidate;
        }
    }

    /// <summary>
    /// Binds a remote offer's RTP m-line to a transceiver (RFC 8829 §5.10, session-model.md §3.2): an
    /// existing transceiver already associated with the offered mid is reused, otherwise the first
    /// non-stopped, unassociated transceiver of the same kind adopts the offered mid, otherwise a
    /// transceiver is auto-created for it. Unless the transceiver was application-added with an explicit
    /// direction, its direction defaults to the complement of the offered direction (a <c>recvonly</c>
    /// offer makes this side the sender, everything else makes it a receiver), reproducing the historical
    /// answerer rule exactly. <paramref name="created"/> reports whether a transceiver was auto-created,
    /// so the caller can raise <see cref="OnTransceiver"/> for it.
    /// </summary>
    private RtpTransceiver BindOfferedMediaLine(
        MediaKind kind,
        string mid,
        MediaDirection offeredDirection,
        HashSet<RtpTransceiver> associated,
        out bool created)
    {
        created = false;
        RtpTransceiver? bound = null;
        foreach (var transceiver in _transceivers)
        {
            if (string.Equals(transceiver.Mid, mid, StringComparison.Ordinal)
                && !transceiver.Stopped
                && !associated.Contains(transceiver))
            {
                // Already associated with this exact mid — reuse it.
                bound = transceiver;
                break;
            }
        }

        if (bound is null)
        {
            foreach (var transceiver in _transceivers)
            {
                if (transceiver.Kind == kind && !transceiver.Stopped && !associated.Contains(transceiver))
                {
                    bound = transceiver;
                    break;
                }
            }
        }

        if (bound is null)
        {
            // Auto-create for an m-line beyond what the local side prepared.
            var sender = new RtpSender(
                this,
                kind,
                NewSsrc(),
                kind == MediaKind.Video ? NewSsrc() : 0,
                NewIdentifier(kind == MediaKind.Video ? "video" : "audio"),
                _config.EnableFlexFec && kind == MediaKind.Video ? NewSsrc() : 0);
            bound = new RtpTransceiver(kind, MediaDirection.RecvOnly, sender, new RtpReceiver(), mid);
            AddTransceiverInternal(bound);
            created = true;
        }

        associated.Add(bound);
        bound.Mid = mid;
        if (!bound.PreserveDirectionOnBind)
        {
            bound.Direction = offeredDirection == MediaDirection.RecvOnly
                ? MediaDirection.SendOnly
                : MediaDirection.RecvOnly;
        }

        return bound;
    }
}
