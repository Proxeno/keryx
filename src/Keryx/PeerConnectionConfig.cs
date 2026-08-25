using System.Net;
using Keryx.Core;
using Keryx.Dtls;
using Keryx.Rtp;
using Keryx.Rtp.CongestionControl;
using Keryx.Rtp.Rtcp;
using Keryx.Sdp;
using Keryx.Stun;
using Keryx.Turn;

namespace Keryx;

/// <summary>
/// Everything a <see cref="PeerConnection"/> needs to build its offer and stand its transports up.
/// </summary>
/// <remarks>
/// <para>
/// A config is read when the <see cref="PeerConnection"/> is constructed and when it gathers; mutating
/// it afterwards is not supported. Every collection starts populated with the WebRTC defaults a
/// browser expects, and every one of them may be cleared and refilled — the advertised codec list in
/// particular is meant to be replaced, not merely appended to.
/// </para>
/// </remarks>
public sealed class PeerConnectionConfig
{
    /// <summary>
    /// The DTLS identity to present. When null the <see cref="PeerConnection"/> generates a
    /// self-signed ECDSA certificate and disposes it with itself; when set, the caller keeps ownership.
    /// </summary>
    public DtlsCertificate? Certificate { get; set; }

    /// <summary>
    /// STUN servers queried during gathering to learn a server-reflexive candidate, as
    /// already-resolved transport addresses. Empty by default, which gathers host candidates only —
    /// the right choice on a public-facing server. To configure a STUN server by host name (resolved
    /// via DNS when gathering starts, the way <see cref="TurnServers"/> already accepts a host), add
    /// a <see cref="StunServerOptions"/> to <see cref="StunServerHosts"/> instead.
    /// </summary>
    public IList<IPEndPoint> StunServers { get; } = [];

    /// <summary>
    /// STUN servers queried during gathering, addressed by host name and port and resolved via DNS
    /// when gathering starts, symmetric with <see cref="TurnServers"/>. Empty by default. Both this
    /// list and <see cref="StunServers"/> are queried.
    /// </summary>
    public IList<StunServerOptions> StunServerHosts { get; } = [];

    /// <summary>
    /// TURN servers to allocate a relayed candidate on during gathering, each with its long-term
    /// credentials. Empty by default. A relayed candidate is the fallback that lets a session cross
    /// a symmetric NAT, where a server-reflexive candidate alone cannot: it is gathered over the
    /// same socket as the host candidate, so DTLS and SRTP above are oblivious to the relay.
    /// </summary>
    public IList<TurnServerOptions> TurnServers { get; } = [];

    /// <summary>
    /// Restricts this connection to a relayed candidate only, mirroring a browser's
    /// <c>iceTransportPolicy: "relay"</c> (see <see cref="Keryx.Ice.IceAgentOptions.RelayOnly"/>).
    /// Host and server-reflexive candidates are still gathered internally - a host candidate is the
    /// base a TURN allocation is computed from - but never offered in the SDP or paired against a
    /// remote candidate, so the session can only connect through a <see cref="TurnServers"/>
    /// allocation. Off by default; requires at least one <see cref="TurnServers"/> entry to be of any
    /// use.
    /// </summary>
    public bool RelayOnly { get; set; }

    /// <summary>
    /// Also gather passive TCP host candidates (RFC 6544, see
    /// <see cref="Keryx.Ice.IceAgentOptions.GatherTcpCandidates"/>), so a session can traverse a TCP
    /// pair when UDP is blocked. Off by default, which keeps gathering UDP-only and the default
    /// golden SDP byte-identical (no extra <c>a=candidate ... tcp ...</c> lines).
    /// </summary>
    public bool GatherTcpCandidates { get; set; }

    /// <summary>
    /// The local address to bind. Null binds every up, non-loopback IPv4 interface; set it to
    /// <see cref="IPAddress.Loopback"/> to keep a session on the loopback interface.
    /// </summary>
    public IPAddress? BindAddress { get; set; }

    /// <summary>Lowest local UDP port to bind, inclusive. Zero (with <see cref="MaxPort"/>) uses an ephemeral port.</summary>
    public int MinPort { get; set; }

    /// <summary>Highest local UDP port to bind, inclusive.</summary>
    public int MaxPort { get; set; }

    /// <summary>Diagnostics sink for every layer this connection composes.</summary>
    public IKeryxLogger Logger { get; set; } = NullLogger.Instance;

    /// <summary>
    /// Video codecs to advertise, in preference order. Defaults to exactly one entry: H.264 payload
    /// type 96, 90 kHz, <c>level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f</c>,
    /// with <c>nack</c>, <c>nack pli</c>, <c>ccm fir</c> and <c>transport-cc</c> feedback. Clear the
    /// list to offer no video.
    /// </summary>
    /// <remarks>
    /// The offer builder never mutates these entries. When <see cref="EnableRetransmission"/> is set it
    /// offers a copy of each entry alongside a generated RFC 4588 <c>rtx</c> codec, so bare
    /// <c>nack</c> is backed by a real repair stream.
    /// </remarks>
    public IList<SdpCodec> VideoCodecs { get; } = [SdpCodec.H264()];

    /// <summary>
    /// Audio codecs to advertise, in preference order. Defaults to exactly one entry: Opus payload
    /// type 111, 48 kHz stereo, <c>minptime=10;useinbandfec=1</c>, with <c>transport-cc</c> feedback.
    /// Clear the list to offer no audio.
    /// </summary>
    public IList<SdpCodec> AudioCodecs { get; } = [SdpCodec.Opus()];

    /// <summary>
    /// SRTP protection profiles to offer through DTLS <c>use_srtp</c>, most preferred first. Keryx
    /// implements all four profiles the DTLS layer can negotiate — <c>AES128_CM_HMAC_SHA1_80</c>,
    /// <c>AES128_CM_HMAC_SHA1_32</c>, <c>AEAD_AES_128_GCM</c> and <c>AEAD_AES_256_GCM</c> — but only
    /// the first and third are offered by default; add the others to prefer them.
    /// </summary>
    public IList<SrtpProtectionProfile> SrtpProfiles { get; } =
    [
        SrtpProtectionProfile.Aes128CmHmacSha1Tag80,
        SrtpProtectionProfile.AeadAes128Gcm,
    ];

    /// <summary>The RTCP canonical name published in SDES and <c>a=ssrc … cname:</c>. Random when null.</summary>
    public string? Cname { get; set; }

    /// <summary>The MediaStream identifier published in <c>a=msid</c>. Random when null.</summary>
    public string? StreamId { get; set; }

    /// <summary>The MediaStreamTrack identifier for the video track. Random when null.</summary>
    public string? VideoTrackId { get; set; }

    /// <summary>The MediaStreamTrack identifier for the audio track. Random when null.</summary>
    public string? AudioTrackId { get; set; }

    /// <summary>
    /// Largest datagram Keryx will emit on the wire, before IP/UDP headers. 1200 is the value browsers
    /// use to stay inside the path MTU; it caps DTLS records, SRTP packets and SCTP chunks alike.
    /// </summary>
    public int Mtu { get; set; } = 1200;

    /// <summary>How long to wait for an ICE candidate pair to succeed before failing the connection.</summary>
    public TimeSpan IceConnectTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>How often a sender report / SDES compound is emitted for each active send stream.</summary>
    public TimeSpan RtcpInterval { get; set; } = TimeSpan.FromSeconds(1);

    /// <summary>The local SCTP port published as <c>a=sctp-port</c>. Browsers use 5000.</summary>
    public int SctpPort { get; set; } = 5000;

    /// <summary>The <c>a=max-message-size</c> value, and the local reassembly limit, in bytes.</summary>
    public int MaxMessageSize { get; set; } = 262144;

    /// <summary>
    /// Offer RFC 4588 retransmission for video: an <c>rtx</c> codec per video codec, a dedicated repair
    /// SSRC published through <c>a=ssrc-group:FID</c>, and NACK-driven resends once the answer keeps
    /// the <c>rtx</c> entry. On by default.
    /// </summary>
    /// <remarks>
    /// Audio is deliberately excluded: browsers do not negotiate RTX for Opus, whose in-band FEC
    /// (<c>useinbandfec=1</c>) already repairs isolated loss without a round trip.
    /// </remarks>
    public bool EnableRetransmission { get; set; } = true;

    /// <summary>
    /// Offer proactive forward error correction for video: an RFC 2198 <c>red</c> codec and an RFC 5109
    /// <c>ulpfec</c> codec per video codec, so a receiver can rebuild an isolated lost media packet from
    /// the survivors of its protection group without a retransmission round trip. Off by default.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Off by default, and opt-in for the same reason the receive jitter buffer, receiver NACK and REMB
    /// are: enabling it changes the wire shape — extra <c>a=rtpmap:… red/</c> and <c>ulpfec/</c> entries
    /// and their payload types in the video <c>m=</c> line — so with the flag off the default golden SDP
    /// stays byte-identical. FEC also spends steady uplink on repair packets whether or not loss occurs,
    /// which retransmission does not, so it is the right tool only where the path loses packets and the
    /// round trip is too long for NACK/RTX to repair in time.
    /// </para>
    /// <para>
    /// Audio is deliberately excluded, as with retransmission: Opus repairs isolated loss with its own
    /// in-band FEC (<c>useinbandfec=1</c>).
    /// </para>
    /// </remarks>
    public bool EnableUlpfec { get; set; }

    /// <summary>
    /// Offer the transport-wide congestion-control header extension
    /// (<c>draft-holmer-rmcat-transport-wide-cc-extensions-01</c>) via <c>a=extmap</c> and, once the
    /// answer keeps it, stamp a monotonically increasing transport-wide sequence number on every
    /// outbound RTP packet. This is what lets the remote return TWCC feedback. On by default.
    /// </summary>
    public bool EnableTransportWideCc { get; set; } = true;

    /// <summary>
    /// Once the transport-wide congestion-control extension is negotiated, record every inbound packet's
    /// transport-wide sequence number and arrival time and return transport-cc feedback
    /// (<c>draft-holmer-rmcat-transport-wide-cc-extensions-01</c> §3.1) to the sender on a feedback
    /// cadence, so a peer sending media into Keryx has the send-side bandwidth-estimation input its
    /// encoder rate controller needs. On by default.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Gated on <see cref="EnableTransportWideCc"/> actually being negotiated: with no extension there is
    /// no transport-wide sequence number to report, so the path stays dormant. This is why it defaults on
    /// where the receive jitter buffer and automatic NACK generation default off — those change the
    /// delivery contract or spend uplink asking a peer to retransmit, whereas transport-cc feedback is the
    /// standard, passive telemetry any conformant WebRTC receiver returns whenever the extension is
    /// negotiated, and a sender that negotiated the extension is expecting it. Without it the peer's
    /// delay-based estimator starves and its encoder oscillates.
    /// </para>
    /// <para>
    /// The feedback is emitted as reduced-size RTCP (the feedback packet alone, no leading report), on the
    /// receive loop, at most a few tens of milliseconds after an arrival. Set this false to suppress it
    /// while still offering and honouring the extension for the send path.
    /// </para>
    /// </remarks>
    public bool EnableReceiverTransportCcFeedback { get; set; } = true;

    /// <summary>
    /// Offer the absolute send time header extension
    /// (<c>http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time</c>) via <c>a=extmap</c> and, once
    /// it is negotiated, run the classic receive-side delay-gradient bandwidth estimator over the
    /// abs-send-time each inbound packet carries and return the estimate to the sender as REMB
    /// (<c>draft-alvestrand-rmcat-remb-03</c>). A sender that also negotiates the extension stamps its
    /// transmit timestamp on every outbound packet, so two Keryx peers estimate each other's forward path
    /// end to end.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Off by default, like the receive jitter buffer and automatic NACK — enabling it changes the wire
    /// shape (an extra <c>a=extmap</c> in the offer, an extra header extension on every outbound packet)
    /// and spends a little uplink returning REMB, so it stays opt-in and the default golden SDP is
    /// byte-identical. REMB is the legacy congestion-control signal; where a peer also negotiates
    /// transport-wide-cc the sender's estimator prefers that and REMB only ever caps it, so this is most
    /// useful for interop with endpoints that speak REMB but not transport-cc.
    /// </para>
    /// <para>
    /// The abs-send-time <c>a=extmap</c> appears only when this is set, and the receive-side estimator is
    /// built only when the extension is actually negotiated, so with the flag off the path stays entirely
    /// dormant.
    /// </para>
    /// </remarks>
    public bool EnableReceiverRemb { get; set; }

    /// <summary>
    /// Enable the send-side Google Congestion Control estimator and its leaky-bucket pacer. When set,
    /// inbound transport-wide-cc feedback, reception-report loss and REMB drive a
    /// <see cref="Keryx.Rtp.CongestionControl.GccCongestionController"/> whose target bitrate is
    /// published through <c>PeerConnection.TargetBitrateChanged</c> and used to pace outbound RTP.
    /// </summary>
    /// <remarks>
    /// Off by default. Enabling it routes every outbound RTP packet through a pacing queue drained on a
    /// timer, which reshapes send timing and so is opt-in; it also relies on
    /// <see cref="EnableTransportWideCc"/> being negotiated for the delay-based estimate to receive
    /// feedback (loss and REMB still apply without it). Leaving it off keeps the immediate,
    /// unbuffered send path that the loopback and retransmission tests assert against.
    /// </remarks>
    public bool EnableCongestionControl { get; set; }

    /// <summary>
    /// Bitrate clamps and filter tunables for the congestion controller, honoured only when
    /// <see cref="EnableCongestionControl"/> is set. Defaults track draft-ietf-rmcat-gcc-02.
    /// </summary>
    public CongestionControllerOptions CongestionControl { get; set; } = new();

    /// <summary>
    /// Clock used for congestion-control timing and pacing, so tests can drive an
    /// <see cref="System.TimeProvider"/> fake instead of the wall clock. Defaults to
    /// <see cref="System.TimeProvider.System"/>.
    /// </summary>
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;

    /// <summary>
    /// When answering an offer whose video m-section is simulcast (RFC 8853), echo the
    /// <c>a=simulcast</c> line with its directions reversed, keep the <c>a=rid</c> declarations the
    /// answerer accepts, and negotiate the RID / repaired-RID / MID header extensions so each incoming
    /// packet's simulcast layer can be resolved. The answerer receives every offered layer; layer
    /// selection and fan-out remain an application concern. On by default.
    /// </summary>
    public bool EnableSimulcast { get; set; } = true;

    /// <summary>
    /// Payload type to advertise for the first video codec's <c>rtx</c> entry. Null picks the lowest
    /// unused dynamic payload type, which is what browsers do.
    /// </summary>
    public int? RtxPayloadType { get; set; }

    /// <summary>
    /// Payload type to advertise for the RFC 2198 <c>red</c> codec when <see cref="EnableUlpfec"/> is set.
    /// Null picks the lowest unused dynamic payload type, which is what browsers do.
    /// </summary>
    public int? RedPayloadType { get; set; }

    /// <summary>
    /// Payload type to advertise for the RFC 5109 <c>ulpfec</c> codec when <see cref="EnableUlpfec"/> is
    /// set. Null picks the lowest unused dynamic payload type, which is what browsers do.
    /// </summary>
    public int? UlpfecPayloadType { get; set; }

    /// <summary>
    /// Retention limits for the ring of recently sent video packets a NACK is served from. The
    /// ring reserves <c>Capacity × MTU</c> bytes per connection when retransmission is negotiated.
    /// </summary>
    public RtpSendHistoryOptions RetransmissionHistory { get; } = new();

    /// <summary>Rate and bandwidth limits applied to NACK-driven retransmission.</summary>
    public RtxRetransmitOptions Retransmission { get; } = new();

    /// <summary>
    /// Reorder inbound RTP through a per-SSRC <see cref="Keryx.Rtp.JitterBuffer"/> before firing
    /// <see cref="PeerConnection.OnRtpPacketReceived"/>, so a handler that feeds a depacketizer sees a
    /// sequence-ordered, duplicate-free stream even when the link reordered or duplicated packets.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Off by default. The event contract is unchanged either way — the same packets fire, with their
    /// payload spans valid only for the duration of the call — but with the buffer on they arrive in
    /// playout order rather than arrival order, which adds the buffer's holding latency to any packet
    /// delivered behind a reordered or missing one (bounded by <see cref="JitterBufferOptions.MaxWait"/>).
    /// A packet the buffer declares lost manifests as a gap in the delivered sequence numbers.
    /// </para>
    /// <para>
    /// It is opt-in because the right depth and wait are workload-specific, and because a receiver that
    /// only samples <see cref="PeerConnection.GetStats"/> or drives its own loss detection wants the raw
    /// arrival stream. Enable it when handing packets straight to a decoder-facing depacketizer.
    /// </para>
    /// </remarks>
    public bool EnableReceiveJitterBuffer { get; set; }

    /// <summary>
    /// Depth and wait bounds for the per-SSRC receive jitter buffer, applied to every inbound stream
    /// when <see cref="EnableReceiveJitterBuffer"/> is set. Ignored when it is not.
    /// </summary>
    public JitterBufferOptions ReceiveJitterBuffer { get; } = new();

    /// <summary>
    /// Automatically generate RFC 4585 Generic NACK feedback for gaps detected in the inbound video
    /// sequence stream, so a remote sender's RFC 4588 retransmission can repair the loss without the
    /// application running its own loss detector. Detection is per received video SSRC, on the raw
    /// arrival sequence <see cref="PeerConnection.OnRtpPacketReceived"/> sees, rate-limited and bounded to
    /// a recovery window by <see cref="ReceiverNack"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Off by default, and opt-in for the same reason the receive jitter buffer and congestion control
    /// are: it adds behaviour to the receive path — emitting RTCP the endpoint never sent before — that a
    /// receiver driving its own loss detection, or one that never wants to spend uplink on repair
    /// requests, should not have forced on it. Enabling it keeps the default caller-driven
    /// <see cref="PeerConnection.SendNack"/> path allocation-free and untouched.
    /// </para>
    /// <para>
    /// Only video is tracked: RFC 4588 retransmission is negotiated for video alone (Opus repairs
    /// isolated loss with in-band FEC), so a NACK for an audio stream would ask for a repair no sender in
    /// this stack serves.
    /// </para>
    /// </remarks>
    public bool EnableReceiverNack { get; set; }

    /// <summary>
    /// Rate and window limits for automatic receiver NACK generation, applied to every inbound video
    /// stream when <see cref="EnableReceiverNack"/> is set. Ignored when it is not.
    /// </summary>
    public ReceiverNackOptions ReceiverNack { get; } = new();

    /// <summary>
    /// Hard cap on the number of distinct inbound synchronisation sources (SSRCs) whose per-source
    /// receive state Keryx retains: RFC 3550 reception statistics, and — when enabled — a jitter buffer
    /// and NACK loss detector. Defaults to 256, far above any legitimate BUNDLE session's source count
    /// (a handful of media and RTX SSRCs per m-section, plus simulcast layers).
    /// </summary>
    /// <remarks>
    /// A peer authenticated to the SRTP context can stamp an arbitrary SSRC on every packet it sends;
    /// each unseen value would otherwise allocate a fresh statistics record — and, with the jitter buffer
    /// on, a ring buffer that is never evicted — so a flood of invented SSRCs would pin unbounded memory,
    /// the RTP analogue of the bounded SCTP reassembly path. Once the cap is reached, packets from further
    /// sources are still parsed, demultiplexed and delivered to <see cref="PeerConnection.OnRtpPacketReceived"/>
    /// in arrival order; they simply accrue no retained per-source state. Must be at least one.
    /// </remarks>
    public int MaxReceiveSources { get; set; } = 256;

    /// <summary>
    /// A testing and diagnostics seam: called once with the ICE agent's datagram transport, and the
    /// transport it returns is what the connection sends on and receives from. Null (the default)
    /// uses the ICE transport directly.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The seam sits at the datagram level, <em>below</em> DTLS and SRTP: everything it observes is
    /// already protected, and everything it hands back is decrypted by the peer, so a wrapper can
    /// count, delay or drop datagrams without being able to forge one. That makes it the right place
    /// to model a lossy link — which is exactly what the fault-injection tests do — and the wrong
    /// place to try to modify media.
    /// </para>
    /// <para>
    /// The factory runs while the connection is building its ICE agent, before gathering. The
    /// returned transport must forward <see cref="IDatagramTransport.OnReceived"/> from the transport
    /// it was given, or the DTLS handshake will never complete; the connection does not dispose it.
    /// </para>
    /// </remarks>
    public Func<IDatagramTransport, IDatagramTransport>? TransportInterceptor { get; set; }

    /// <summary>The <c>a=mid</c> of the video m-section.</summary>
    public string VideoMid { get; set; } = "0";

    /// <summary>The <c>a=mid</c> of the audio m-section.</summary>
    public string AudioMid { get; set; } = "1";

    /// <summary>The <c>a=mid</c> of the data channel m-section.</summary>
    public string ApplicationMid { get; set; } = "2";

    /// <summary>
    /// Overrides the DTLS cipher suites this connection offers (as DTLS client) or prefers (as DTLS
    /// server), most preferred first. Null uses Keryx's default suite preference for
    /// <see cref="Certificate"/>'s key type. Not part of the public surface: it exists so the
    /// Chrome-interop DTLS suite matrix can force a single suite and prove it against a real browser.
    /// </summary>
    internal IReadOnlyList<ushort>? DtlsOfferedCipherSuites { get; set; }

    /// <summary>
    /// Overrides the DTLS ECDHE named groups this connection offers (as DTLS client) or prefers (as
    /// DTLS server), most preferred first. Null uses Keryx's default curve preference. Not part of
    /// the public surface: it exists so the Chrome-interop DTLS suite matrix can force a single curve
    /// and prove it against a real browser.
    /// </summary>
    internal IReadOnlyList<ushort>? DtlsOfferedNamedGroups { get; set; }
}
