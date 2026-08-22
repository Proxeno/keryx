using System.Net;
using Keryx.Core;
using Keryx.Dtls;
using Keryx.Rtp;
using Keryx.Rtp.CongestionControl;
using Keryx.Sdp;
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
    /// STUN servers queried during gathering to learn a server-reflexive candidate. Empty by default,
    /// which gathers host candidates only — the right choice on a public-facing server.
    /// </summary>
    public IList<IPEndPoint> StunServers { get; } = [];

    /// <summary>
    /// TURN servers to allocate a relayed candidate on during gathering, each with its long-term
    /// credentials. Empty by default. A relayed candidate is the fallback that lets a session cross
    /// a symmetric NAT, where a server-reflexive candidate alone cannot: it is gathered over the
    /// same socket as the host candidate, so DTLS and SRTP above are oblivious to the relay.
    /// </summary>
    public IList<TurnServerOptions> TurnServers { get; } = [];

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
    /// SRTP protection profiles to offer through DTLS <c>use_srtp</c>, most preferred first. Only the
    /// two profiles Keryx implements end to end are supported.
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
    /// Offer the transport-wide congestion-control header extension
    /// (<c>draft-holmer-rmcat-transport-wide-cc-extensions-01</c>) via <c>a=extmap</c> and, once the
    /// answer keeps it, stamp a monotonically increasing transport-wide sequence number on every
    /// outbound RTP packet. This is what lets the remote return TWCC feedback. On by default.
    /// </summary>
    public bool EnableTransportWideCc { get; set; } = true;

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
    /// Payload type to advertise for the first video codec's <c>rtx</c> entry. Null picks the lowest
    /// unused dynamic payload type, which is what browsers do.
    /// </summary>
    public int? RtxPayloadType { get; set; }

    /// <summary>
    /// Retention limits for the ring of recently sent video packets a NACK is served from. The
    /// ring reserves <c>Capacity × MTU</c> bytes per connection when retransmission is negotiated.
    /// </summary>
    public RtpSendHistoryOptions RetransmissionHistory { get; } = new();

    /// <summary>Rate and bandwidth limits applied to NACK-driven retransmission.</summary>
    public RtxRetransmitOptions Retransmission { get; } = new();

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
}
