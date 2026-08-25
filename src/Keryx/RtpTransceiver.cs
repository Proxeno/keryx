using Keryx.Sdp;

namespace Keryx;

/// <summary>
/// One RTP transceiver: an ordered media object with its own mid, direction, negotiated codec and
/// SSRC (session-model.md §2.1). Everything a <see cref="PeerConnection"/> sends and receives on an RTP
/// m-line is keyed by a transceiver; the data channel section is not a transceiver.
/// </summary>
/// <remarks>
/// Obtain one from <see cref="PeerConnection.AddTransceiver(MediaKind, MediaDirection, RtpTransceiverInit?)"/>
/// or <see cref="PeerConnection.AddTrack(MediaKind, System.Collections.Generic.IReadOnlyList{SdpCodec})"/>,
/// enumerate the set with <see cref="PeerConnection.Transceivers"/>, or receive one auto-created for an
/// offered m-line through <see cref="PeerConnection.OnTransceiver"/>. Transceivers may be added before
/// the first negotiation or mid-session: a mid-session add appears as a new m-line in the next offer and
/// <see cref="Stop"/> re-emits its slot as a rejected (port-0) section, both driven by a renegotiation
/// (session-model.md §4.2).
/// </remarks>
public sealed class RtpTransceiver
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

    /// <summary>The negotiated <c>a=mid</c>, or <see langword="null"/> until the first offer/answer assigns one.</summary>
    public string? Mid { get; internal set; }

    /// <summary>audio or video. Fixed at creation; a transceiver never changes kind.</summary>
    public MediaKind Kind { get; }

    /// <summary>The direction the application wants, settable before the next negotiation.</summary>
    public MediaDirection Direction { get; set; }

    /// <summary>
    /// The direction actually negotiated (RFC 8829), <see langword="null"/> before negotiation settles
    /// — and still <see langword="null"/> when the answer rejects the m-line (no common codec).
    /// </summary>
    public MediaDirection? CurrentDirection { get; internal set; }

    /// <summary>The send half of this transceiver.</summary>
    public RtpSender Sender { get; }

    /// <summary>The receive half of this transceiver.</summary>
    public RtpReceiver Receiver { get; }

    /// <summary>The primary codec negotiated for this m-line, <see langword="null"/> before it settles.</summary>
    /// <remarks>
    /// A convenience view of the first non-rtx entry in <see cref="NegotiatedCodecs"/>: the codec that
    /// drives this transceiver's sender for the session. Kept for the common single-codec case.
    /// </remarks>
    public NegotiatedCodec? NegotiatedCodec { get; internal set; }

    /// <summary>
    /// Every media codec the peer accepted for this m-line, in negotiated preference order, each with its
    /// own payload type — empty before negotiation settles or when the m-line was rejected. RFC 4588 rtx
    /// repair codecs are not listed here (retransmission is plumbed separately through the sender). The
    /// first entry is the primary, mirrored by <see cref="NegotiatedCodec"/>. The sender keeps to the
    /// primary for the session (no mid-stream switching); the list lets an application see the full set
    /// the peer agreed to.
    /// </summary>
    public IReadOnlyList<NegotiatedCodec> NegotiatedCodecs { get; internal set; } = [];

    /// <summary>
    /// Marks this transceiver stopped (session-model.md §3.3/§4.2): the next offer re-emits its m-line
    /// slot as a rejected (port-0) section at its fixed index and mid, and once that renegotiation
    /// settles the m-line carries no media. The slot is kept, never reordered or freed (recycling is a
    /// later optimisation). Idempotent. A stop dirties the connection, so
    /// <see cref="PeerConnection.OnNegotiationNeeded"/> is raised when the machine is
    /// <see cref="SignalingState.Stable"/>, prompting the renegotiation.
    /// </summary>
    public void Stop()
    {
        var owner = Sender.Owner;
        lock (owner.NegotiationLock)
        {
            if (_stopped)
            {
                return;
            }

            _stopped = true;
            NegotiationPending = true;
        }

        owner.RaiseNegotiationNeeded();
    }

    /// <summary>Whether <see cref="Stop"/> has been called; a stopped transceiver never sends or receives.</summary>
    public bool Stopped => _stopped;

    private volatile bool _stopped;

    /// <summary>The per-transceiver codec preference list used when THIS side offers, or empty to fall
    /// back to the connection's per-kind codec config.</summary>
    internal IReadOnlyList<SdpCodec> OfferCodecs { get; set; } = [];

    /// <summary>Whether an RFC 4588 rtx codec is offered for this (video) transceiver when THIS side offers.</summary>
    internal bool EnableRetransmissionOnOffer { get; set; }

    /// <summary>
    /// When true, this transceiver keeps its <see cref="Direction"/> when it binds to a remote offer's
    /// m-line; when false (the internally built legacy transceivers and auto-created ones), binding sets
    /// the complement-of-offered default (session-model.md §3.2).
    /// </summary>
    internal bool PreserveDirectionOnBind { get; init; }

    /// <summary>
    /// Whether this transceiver was added by the application and has not yet been folded into a local
    /// description — the JSEP negotiation-needed signal (session-model.md §4.1). Set when
    /// <see cref="PeerConnection.AddTransceiver"/> / <see cref="PeerConnection.AddTrack"/> create it,
    /// cleared when the next offer or answer that covers it is applied. The internally built legacy
    /// transceivers and offer-bound auto-created ones leave it false: the former are driven through the
    /// existing single-shot flow, the latter are answered in the same exchange.
    /// </summary>
    internal bool NegotiationPending { get; set; }
}

/// <summary>
/// The send half of a transceiver (session-model.md §2.1): the local SSRCs it owns, the negotiated
/// send codec, and the frame/forward entry points. Implements <see cref="IRtpForwarder"/> so an SFU
/// fan-out loop can hold the sender directly. Every member is safe on the hot path — the send entry
/// points take the connection's send lock, check SRTP readiness, and return 0/false rather than
/// throwing when the connection is not yet ready.
/// </summary>
public sealed class RtpSender : IRtpForwarder
{
    private readonly PeerConnection _owner;

    internal RtpSender(PeerConnection owner, MediaKind kind, uint ssrc, uint rtxSsrc, string trackId, uint flexFecSsrc = 0)
    {
        _owner = owner;
        Kind = kind;
        Ssrc = ssrc;
        RtxSsrcRaw = rtxSsrc;
        FlexFecSsrcRaw = flexFecSsrc;
        TrackId = trackId;
    }

    /// <summary>The connection that owns this sender, for internal callbacks (e.g. negotiation-needed).</summary>
    internal PeerConnection Owner => _owner;

    /// <summary>The media kind this sender emits.</summary>
    public MediaKind Kind { get; }

    /// <summary>The local SSRC this sender owns; stable for the transceiver's life.</summary>
    public uint Ssrc { get; }

    /// <summary>
    /// The RFC 4588 rtx repair SSRC this sender owns. A video sender is allocated one at creation (so
    /// this is non-null for video whether or not rtx is ultimately negotiated — read
    /// <see cref="RtxPayloadType"/> to learn whether a repair codec was kept); <see langword="null"/>
    /// for audio, which never uses RTX.
    /// </summary>
    public uint? RtxSsrc => RtxSsrcRaw == 0 ? null : RtxSsrcRaw;

    /// <summary>The negotiated send payload type, <see langword="null"/> before negotiation settles.</summary>
    public byte? PayloadType => Negotiated?.PayloadType;

    /// <summary>The negotiated rtx payload type, <see langword="null"/> when the peer kept no repair codec.</summary>
    public byte? RtxPayloadType => Negotiated?.RtxPayloadType;

    /// <summary>The raw repair SSRC (0 when none), for the internal SDP/RTX wiring.</summary>
    internal uint RtxSsrcRaw { get; }

    /// <summary>
    /// The RFC 8627 FlexFEC repair SSRC this sender owns, allocated only when
    /// <see cref="PeerConnectionConfig.EnableFlexFec"/> is set (0 otherwise). Published as the second
    /// member of <c>a=ssrc-group:FEC-FR</c> so the peer can bind the FlexFEC stream to the media stream.
    /// </summary>
    public uint? FlexFecSsrc => FlexFecSsrcRaw == 0 ? null : FlexFecSsrcRaw;

    /// <summary>The raw FlexFEC repair SSRC (0 when none), for the internal SDP/FlexFEC wiring.</summary>
    internal uint FlexFecSsrcRaw { get; }

    /// <summary>The msid track id this sender publishes.</summary>
    internal string TrackId { get; }

    /// <summary>What negotiation settled on for this sender, <see langword="null"/> before it settles.</summary>
    internal PeerConnection.NegotiatedTrack? Negotiated { get; set; }

    /// <summary>The live wire sender, <see langword="null"/> until the connection driver builds it.</summary>
    internal PeerConnection.TrackSender? Track { get; set; }

    /// <summary>The last reception-report-derived outbound link-quality snapshot for this stream.</summary>
    internal volatile OutboundStreamQuality? Quality;

    /// <summary>
    /// Packetizes one codec frame (an H.264 Annex B access unit, one Opus packet, …) and sends it over
    /// SRTP on this sender's SSRC.
    /// </summary>
    /// <param name="frame">The codec frame to packetize and send.</param>
    /// <param name="rtpTimestamp">The presentation timestamp in the codec's clock rate.</param>
    /// <returns>
    /// The number of RTP packets sent, or 0 when the connection is not yet
    /// <see cref="PeerConnectionState.Connected"/> or no send codec was negotiated for this transceiver.
    /// </returns>
    public int SendFrame(ReadOnlySpan<byte> frame, uint rtpTimestamp) =>
        _owner.SendFrameOnSender(this, frame, rtpTimestamp);

    /// <summary>
    /// Forwards one already-packetized RTP payload verbatim onto this sender's SSRC and sequence space
    /// — the SFU subscriber-egress path. See <see cref="PeerConnection.TryForwardRtp"/> for the exact
    /// semantics; this never throws and returns false when the sender is not ready.
    /// </summary>
    /// <param name="payload">The RTP payload, written verbatim; never re-packetized.</param>
    /// <param name="rtpTimestamp">The RTP timestamp to stamp on the packet.</param>
    /// <param name="marker">The marker bit.</param>
    /// <param name="payloadType">The payload type this subscriber negotiated.</param>
    /// <returns>True when the packet reached the send path; false when the sender is not ready.</returns>
    public bool TryForwardRtp(ReadOnlySpan<byte> payload, uint rtpTimestamp, bool marker, byte payloadType) =>
        _owner.ForwardRtpOnSender(this, payload, rtpTimestamp, marker, payloadType);
}

/// <summary>
/// The receive half of a transceiver (session-model.md §2.1): the remote sender's SSRC learned from
/// inbound RTP, and the receive payload types negotiated for this m-line.
/// </summary>
public sealed class RtpReceiver
{
    /// <summary>Sentinel for "no remote SSRC learned yet"; any real uint SSRC encodes as a non-negative long.</summary>
    private const long NoRemoteSsrc = -1;

    // The last demultiplexed remote SSRC, held as a sentinel long rather than a boxed uint? so the
    // per-packet write on the inbound path never allocates. -1 means "none learned yet"; otherwise the
    // low 32 bits hold the uint SSRC (every uint encodes as a non-negative long, disjoint from -1).
    // Volatile.Read/Write reproduce the exact publication/visibility the prior volatile reference field
    // gave: the single ICE receive loop publishes it, any thread reads it back through the uint? getters.
    private long _remoteSsrc = NoRemoteSsrc;

    /// <summary>The remote sender's SSRC, learned from inbound RTP; <see langword="null"/> until one arrives.</summary>
    public uint? Ssrc => ReadRemoteSsrc();

    /// <summary>The negotiated receive payload type(s) for this m-line.</summary>
    public IReadOnlyList<byte> PayloadTypes { get; internal set; } = [];

    /// <summary>The last demultiplexed remote SSRC snapshot; a single volatile long write/read, no lock, no boxing.</summary>
    internal uint? RemoteSsrc
    {
        get => ReadRemoteSsrc();
        set
        {
            var encoded = value is { } ssrc ? ssrc : NoRemoteSsrc;

            // Only publish on an actual change (the receive loop is the sole writer, so this read is
            // race-free) so a steady stream from one source neither writes nor boxes: zero-alloc,
            // zero-write in the common case.
            if (Volatile.Read(ref _remoteSsrc) != encoded)
            {
                Volatile.Write(ref _remoteSsrc, encoded);
            }
        }
    }

    private uint? ReadRemoteSsrc()
    {
        var value = Volatile.Read(ref _remoteSsrc);
        return value < 0 ? null : (uint)value;
    }
}

/// <summary>
/// Optional initialization for <see cref="PeerConnection.AddTransceiver(MediaKind, MediaDirection, RtpTransceiverInit?)"/>
/// (session-model.md §2.2).
/// </summary>
public sealed class RtpTransceiverInit
{
    /// <summary>Per-transceiver codec preference list. Empty falls back to the connection's per-kind config.</summary>
    public IList<SdpCodec> Codecs { get; } = new List<SdpCodec>();

    /// <summary>
    /// The preferred mid to use when THIS side builds the offer (for example the legacy <c>"0"</c>).
    /// Ignored when binding to a remote offer's m-line, whose mid always wins.
    /// </summary>
    public string? Mid { get; set; }

    /// <summary>
    /// Whether to offer an RFC 4588 rtx codec for this (video) transceiver, or <see langword="null"/>
    /// (the default) to inherit <see cref="PeerConnectionConfig.EnableRetransmission"/>. Ignored for
    /// audio, which does not use RTX.
    /// </summary>
    public bool? EnableRetransmission { get; set; }
}
