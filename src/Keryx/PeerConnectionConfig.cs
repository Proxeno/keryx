using System.Net;
using Keryx.Core;
using Keryx.Dtls;
using Keryx.Sdp;

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
    /// with <c>nack pli</c>, <c>ccm fir</c> and <c>transport-cc</c> feedback and deliberately no bare
    /// <c>nack</c> (Keryx has no RTX path). Clear the list to offer no video.
    /// </summary>
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

    /// <summary>The <c>a=mid</c> of the video m-section.</summary>
    public string VideoMid { get; set; } = "0";

    /// <summary>The <c>a=mid</c> of the audio m-section.</summary>
    public string AudioMid { get; set; } = "1";

    /// <summary>The <c>a=mid</c> of the data channel m-section.</summary>
    public string ApplicationMid { get; set; } = "2";
}
