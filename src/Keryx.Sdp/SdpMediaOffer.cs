namespace Keryx.Sdp;

/// <summary>
/// Describes one m-section for <see cref="SdpOfferBuilder"/>. Session-level ICE credentials,
/// fingerprint and DTLS role apply unless overridden here.
/// </summary>
public sealed class SdpMediaOffer
{
    /// <summary>The RTP profile WebRTC uses for audio and video.</summary>
    public const string RtpProtocol = "UDP/TLS/RTP/SAVPF";

    /// <summary>The protocol WebRTC uses for the data channel m-section.</summary>
    public const string SctpProtocol = "UDP/DTLS/SCTP";

    /// <summary>The single format token of an SCTP data channel m-section.</summary>
    public const string DataChannelFormat = "webrtc-datachannel";

    /// <summary>Creates an m-section description.</summary>
    /// <param name="mid">The <c>a=mid</c> value. Must be unique within the session.</param>
    /// <param name="mediaType">Media type: <c>audio</c>, <c>video</c> or <c>application</c>.</param>
    /// <param name="protocol">Transport protocol for the <c>m=</c> line.</param>
    public SdpMediaOffer(string mid, string mediaType, string protocol = RtpProtocol)
    {
        ArgumentException.ThrowIfNullOrEmpty(mid);
        ArgumentException.ThrowIfNullOrEmpty(mediaType);
        ArgumentException.ThrowIfNullOrEmpty(protocol);
        Mid = mid;
        MediaType = mediaType;
        Protocol = protocol;
    }

    /// <summary>The <c>a=mid</c> value, also used as the BUNDLE identifier.</summary>
    public string Mid { get; set; }

    /// <summary>Media type: <c>audio</c>, <c>video</c> or <c>application</c>.</summary>
    public string MediaType { get; set; }

    /// <summary>Transport protocol written to the <c>m=</c> line.</summary>
    public string Protocol { get; set; }

    /// <summary>Port written to the <c>m=</c> line. 9 is the WebRTC placeholder; 0 rejects the section.</summary>
    public int Port { get; set; } = 9;

    /// <summary>
    /// Direction attribute, or <see langword="null"/> to emit none (the data channel m-section carries
    /// no direction).
    /// </summary>
    public MediaDirection? Direction { get; set; }

    /// <summary>Codecs to offer, in preference order. Their payload types form the <c>m=</c> format list.</summary>
    public IList<SdpCodec> Codecs { get; } = new List<SdpCodec>();

    /// <summary>RTP header extensions to offer as <c>a=extmap</c>.</summary>
    public IList<SdpExtMap> HeaderExtensions { get; } = new List<SdpExtMap>();

    /// <summary>
    /// RID declarations to offer as <c>a=rid</c> lines (RFC 8851). A simulcast video source lists one
    /// per layer; pair them with a matching <see cref="Simulcast"/> value.
    /// </summary>
    public IList<SdpRid> Rids { get; } = new List<SdpRid>();

    /// <summary>
    /// The <c>a=simulcast</c> description to offer (RFC 8853), or <see langword="null"/> for a single
    /// stream. When set, the referenced RIDs should also appear in <see cref="Rids"/>.
    /// </summary>
    public SdpSimulcast? Simulcast { get; set; }

    /// <summary>Synchronisation sources this section will transmit, emitted as <c>a=ssrc</c> lines.</summary>
    public IList<uint> Ssrcs { get; } = new List<uint>();

    /// <summary>Source groupings such as <c>FID</c> for RTX, emitted before the <c>a=ssrc</c> lines.</summary>
    public IList<SsrcGroup> SsrcGroups { get; } = new List<SsrcGroup>();

    /// <summary>Canonical name for the sources. Falls back to the builder's value when null.</summary>
    public string? Cname { get; set; }

    /// <summary>MediaStream identifier for <c>a=msid</c>. Falls back to the builder's value when null.</summary>
    public string? StreamId { get; set; }

    /// <summary>MediaStreamTrack identifier for <c>a=msid</c>. No msid line is written when null.</summary>
    public string? TrackId { get; set; }

    /// <summary>Emit <c>a=rtcp-mux</c>. Required by WebRTC and on by default.</summary>
    public bool RtcpMux { get; set; } = true;

    /// <summary>Emit <c>a=rtcp-rsize</c> (reduced-size RTCP).</summary>
    public bool RtcpReducedSize { get; set; }

    /// <summary>Emit the <c>a=rtcp:9 IN IP4 0.0.0.0</c> placeholder Chrome writes on RTP sections.</summary>
    public bool IncludeRtcpAttribute { get; set; } = true;

    /// <summary>Per-section ICE credentials. Falls back to the builder's value when null.</summary>
    public SdpIceCredentials? IceCredentials { get; set; }

    /// <summary>Per-section DTLS fingerprint. Falls back to the builder's value when null.</summary>
    public SdpFingerprint? Fingerprint { get; set; }

    /// <summary>Per-section DTLS role. Falls back to the builder's value when null.</summary>
    public SdpSetupRole? Setup { get; set; }

    /// <summary><c>a=sctp-port</c>, emitted only for the data channel m-section.</summary>
    public int? SctpPort { get; set; }

    /// <summary><c>a=max-message-size</c>, emitted only for the data channel m-section.</summary>
    public int? MaxMessageSize { get; set; }

    /// <summary>Attributes appended verbatim at the end of the m-section.</summary>
    public IList<SdpAttribute> ExtraAttributes { get; } = new List<SdpAttribute>();

    /// <summary>Creates a send-only audio m-section.</summary>
    /// <param name="mid">The <c>a=mid</c> value.</param>
    /// <param name="codecs">Audio codecs in preference order.</param>
    /// <returns>The m-section description.</returns>
    public static SdpMediaOffer Audio(string mid, params SdpCodec[] codecs) =>
        Rtp(mid, "audio", codecs);

    /// <summary>Creates a send-only video m-section.</summary>
    /// <param name="mid">The <c>a=mid</c> value.</param>
    /// <param name="codecs">Video codecs in preference order.</param>
    /// <returns>The m-section description.</returns>
    public static SdpMediaOffer Video(string mid, params SdpCodec[] codecs) =>
        Rtp(mid, "video", codecs);

    /// <summary>Creates the SCTP data channel m-section.</summary>
    /// <param name="mid">The <c>a=mid</c> value.</param>
    /// <param name="sctpPort">The <c>a=sctp-port</c> value; browsers use 5000.</param>
    /// <param name="maxMessageSize">The <c>a=max-message-size</c> value in bytes.</param>
    /// <returns>The m-section description.</returns>
    public static SdpMediaOffer Application(string mid, int sctpPort = 5000, int maxMessageSize = 262144)
    {
        var offer = new SdpMediaOffer(mid, "application", SctpProtocol)
        {
            SctpPort = sctpPort,
            MaxMessageSize = maxMessageSize,
            RtcpMux = false,
            IncludeRtcpAttribute = false,
        };
        return offer;
    }

    private static SdpMediaOffer Rtp(string mid, string mediaType, SdpCodec[] codecs)
    {
        ArgumentNullException.ThrowIfNull(codecs);
        var offer = new SdpMediaOffer(mid, mediaType) { Direction = MediaDirection.SendOnly };
        foreach (var codec in codecs)
        {
            offer.Codecs.Add(codec);
        }

        return offer;
    }
}
