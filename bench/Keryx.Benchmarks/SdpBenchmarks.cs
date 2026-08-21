using BenchmarkDotNet.Attributes;
using Keryx.Sdp;

namespace Keryx.Benchmarks;

/// <summary>
/// Two SDP scenarios, each comparing Keryx against SIPSorcery: (a) generating a full WebRTC offer
/// (audio + video + a data channel, bundled) and (b) parsing a fixed, realistic Chrome answer string.
/// </summary>
/// <remarks>
/// <para>
/// <b>Offer generation parity gap.</b> SIPSorcery has no standalone equivalent to
/// <see cref="SdpOfferBuilder"/>: producing a WebRTC offer through its public API means driving a
/// fully wired <c>RTCPeerConnection</c> (ICE agent, DTLS certificate, codec negotiation), which is out
/// of scope for a synthetic microbenchmark and would measure far more than SDP text generation. The
/// SIPSorcery side of the offer-generation benchmark instead constructs a comparable
/// <c>SIPSorcery.Net.SDP</c> object directly — the same three m-sections (audio/opus, video/H264,
/// a data channel), the same ICE credentials, DTLS fingerprint, mid values and ssrc/cname — and calls
/// its own <c>ToString()</c>. This is "the same work" in the sense of producing a similarly-shaped
/// WebRTC offer through each library's own object model, but it is not asserted to be byte-identical
/// SDP text: <see cref="SdpOfferBuilder"/> reproduces Chrome's exact attribute order and defaults
/// (verified byte-for-byte in <c>Keryx.Sdp.Tests</c>), while the SIPSorcery object here is a
/// hand-built approximation of the same session. Both sides rebuild their object graph from scratch
/// on every invocation, so the comparison is fair for "cost of producing an offer," even though the
/// exact bytes produced differ.
/// </para>
/// <para>
/// <b>Answer parsing is apples-to-apples.</b> Both sides parse the exact same literal Chrome answer
/// string (a realistic sendrecv-offer/recvonly-answer pair, audio+video+datachannel, bundled,
/// unified-plan — the same fixture shape used in <c>Keryx.Sdp.Tests.SdpTestData</c>) through their own
/// top-level parse entry point: <see cref="SessionDescription.Parse(string, Keryx.Core.IKeryxLogger?)"/>
/// vs <c>SIPSorcery.Net.SDP.ParseSDPDescription(string)</c>.
/// </para>
/// </remarks>
[MemoryDiagnoser]
public class SdpBenchmarks
{
    private const string Fingerprint =
        "75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24";

    private const string IceUfrag = "hT7a";
    private const string IcePwd = "XKQVjJ9wRVWy3zNsL6mQ0pTb";
    private const string Cname = "keryx-cname-01";
    private const string StreamId = "keryx-stream";

    /// <summary>
    /// A realistic Chrome (unified-plan, M120+) answer to a sendrecv audio/video/datachannel offer:
    /// recvonly, no ssrcs, no ICE candidates trickled in yet. Kept as a fixed literal so both parsers
    /// see byte-identical input.
    /// </summary>
    private const string ChromeAnswer =
        "v=0\r\n" +
        "o=- 1092376891452871093 3 IN IP4 127.0.0.1\r\n" +
        "s=-\r\n" +
        "t=0 0\r\n" +
        "a=group:BUNDLE 0 1 2\r\n" +
        "a=extmap-allow-mixed\r\n" +
        "a=msid-semantic: WMS\r\n" +
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" +
        "c=IN IP4 0.0.0.0\r\n" +
        "a=rtcp:9 IN IP4 0.0.0.0\r\n" +
        "a=ice-ufrag:4ZcD\r\n" +
        "a=ice-pwd:2/1muCWoOi3uLifh0NuRHlZ6cKr\r\n" +
        "a=ice-options:trickle\r\n" +
        "a=fingerprint:sha-256 EE:2D:1B:70:1C:0F:39:A6:1D:47:23:8A:41:66:9C:0B:5F:AE:2C:73:88:14:D5:6E:9A:B1:03:F7:52:C4:60:1A\r\n" +
        "a=setup:active\r\n" +
        "a=mid:0\r\n" +
        "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n" +
        "a=extmap:2 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n" +
        "a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid\r\n" +
        "a=recvonly\r\n" +
        "a=rtcp-mux\r\n" +
        "a=rtcp-rsize\r\n" +
        "a=rtpmap:111 opus/48000/2\r\n" +
        "a=rtcp-fb:111 transport-cc\r\n" +
        "a=fmtp:111 minptime=10;useinbandfec=1\r\n" +
        "m=video 9 UDP/TLS/RTP/SAVPF 102 103\r\n" +
        "c=IN IP4 0.0.0.0\r\n" +
        "a=rtcp:9 IN IP4 0.0.0.0\r\n" +
        "a=ice-ufrag:4ZcD\r\n" +
        "a=ice-pwd:2/1muCWoOi3uLifh0NuRHlZ6cKr\r\n" +
        "a=ice-options:trickle\r\n" +
        "a=fingerprint:sha-256 EE:2D:1B:70:1C:0F:39:A6:1D:47:23:8A:41:66:9C:0B:5F:AE:2C:73:88:14:D5:6E:9A:B1:03:F7:52:C4:60:1A\r\n" +
        "a=setup:active\r\n" +
        "a=mid:1\r\n" +
        "a=extmap:14 urn:ietf:params:rtp-hdrext:toffset\r\n" +
        "a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n" +
        "a=extmap:13 urn:3gpp:video-orientation\r\n" +
        "a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid\r\n" +
        "a=recvonly\r\n" +
        "a=rtcp-mux\r\n" +
        "a=rtcp-rsize\r\n" +
        "a=rtpmap:102 H264/90000\r\n" +
        "a=rtcp-fb:102 goog-remb\r\n" +
        "a=rtcp-fb:102 transport-cc\r\n" +
        "a=rtcp-fb:102 ccm fir\r\n" +
        "a=rtcp-fb:102 nack\r\n" +
        "a=rtcp-fb:102 nack pli\r\n" +
        "a=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n" +
        "a=rtpmap:103 rtx/90000\r\n" +
        "a=fmtp:103 apt=102\r\n" +
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" +
        "c=IN IP4 0.0.0.0\r\n" +
        "a=ice-ufrag:4ZcD\r\n" +
        "a=ice-pwd:2/1muCWoOi3uLifh0NuRHlZ6cKr\r\n" +
        "a=ice-options:trickle\r\n" +
        "a=fingerprint:sha-256 EE:2D:1B:70:1C:0F:39:A6:1D:47:23:8A:41:66:9C:0B:5F:AE:2C:73:88:14:D5:6E:9A:B1:03:F7:52:C4:60:1A\r\n" +
        "a=setup:active\r\n" +
        "a=mid:2\r\n" +
        "a=sctp-port:5000\r\n" +
        "a=max-message-size:262144\r\n";

    private SdpOfferBuilder _offerBuilder = null!;

    [GlobalSetup]
    public void Setup()
    {
        var audio = SdpMediaOffer.Audio("0", SdpCodec.Opus(111));
        audio.TrackId = "keryx-audio-track";
        audio.Ssrcs.Add(1657320245u);

        var video = SdpMediaOffer.Video("1", SdpCodec.H264(96));
        video.TrackId = "keryx-video-track";
        video.Ssrcs.Add(3204773231u);

        _offerBuilder = new SdpOfferBuilder
        {
            SessionId = "4611731400430051336",
            IceCredentials = new SdpIceCredentials(IceUfrag, IcePwd),
            Fingerprint = new SdpFingerprint("sha-256", Fingerprint),
            Cname = Cname,
            StreamId = StreamId,
        }
        .AddMedia(audio)
        .AddMedia(video)
        .AddDataChannel("2");

        Console.WriteLine($"[SdpBenchmarks] Keryx offer length = {_offerBuilder.Build().ToSdpString().Length} chars.");
        Console.WriteLine($"[SdpBenchmarks] SIPSorcery-equivalent offer length = {BuildSipSorceryOffer().Length} chars.");
    }

    /// <summary>Keryx: <see cref="SdpOfferBuilder.Build"/> then <see cref="SessionDescription.ToSdpString"/>.</summary>
    /// <returns>The serialized offer, so the call cannot be dead-code eliminated.</returns>
    [Benchmark(Baseline = true)]
    public string Keryx_GenerateOffer() => _offerBuilder.Build().ToSdpString();

    /// <summary>
    /// SIPSorcery: builds a comparable <c>SDP</c> object (same m-sections, ICE/DTLS attributes, ssrcs)
    /// from scratch and calls <c>ToString()</c>, matching Keryx's per-call object-graph construction.
    /// </summary>
    /// <returns>The serialized offer, so the call cannot be dead-code eliminated.</returns>
    [Benchmark]
    public string SipSorcery_GenerateOffer() => BuildSipSorceryOffer();

    /// <summary>Keryx: <see cref="SessionDescription.Parse(string, Keryx.Core.IKeryxLogger?)"/> on the fixed Chrome answer.</summary>
    /// <returns>The parsed session description, so the call cannot be dead-code eliminated.</returns>
    [Benchmark]
    public SessionDescription Keryx_ParseAnswer() => SessionDescription.Parse(ChromeAnswer);

    /// <summary>SIPSorcery: <c>SDP.ParseSDPDescription(string)</c> on the same fixed Chrome answer.</summary>
    /// <returns>The parsed SDP, so the call cannot be dead-code eliminated.</returns>
    [Benchmark]
    public SIPSorcery.Net.SDP SipSorcery_ParseAnswer() => SIPSorcery.Net.SDP.ParseSDPDescription(ChromeAnswer);

    private static string BuildSipSorceryOffer()
    {
        var sdp = new SIPSorcery.Net.SDP
        {
            Username = "-",
            SessionId = "4611731400430051336",
            AnnouncementVersion = 2,
            NetworkType = "IN",
            AddressType = "IP4",
            AddressOrHost = "127.0.0.1",
            SessionName = "-",
            Timing = "0 0",
            Group = "BUNDLE 0 1 2",
        };

        var connection = SIPSorcery.Net.SDPConnectionInformation.ParseConnectionInformation("IN IP4 0.0.0.0");

        var opus = new SIPSorcery.Net.SDPAudioVideoMediaFormat(
            SIPSorcery.Net.SDPMediaTypesEnum.audio, 111, "opus", 48000, 2, "minptime=10;useinbandfec=1");
        var audio = new SIPSorcery.Net.SDPMediaAnnouncement(
            SIPSorcery.Net.SDPMediaTypesEnum.audio, 9, new List<SIPSorcery.Net.SDPAudioVideoMediaFormat> { opus })
        {
            Transport = "UDP/TLS/RTP/SAVPF",
            Connection = connection,
            IceUfrag = IceUfrag,
            IcePwd = IcePwd,
            IceOptions = "trickle",
            DtlsFingerprint = "sha-256 " + Fingerprint,
            MediaID = "0",
            MLineIndex = 0,
        };
        audio.ExtraMediaAttributes.Add("a=rtcp-mux");
        audio.SsrcAttributes.Add(new SIPSorcery.Net.SDPSsrcAttribute(1657320245u, Cname, null));

        var h264 = new SIPSorcery.Net.SDPAudioVideoMediaFormat(
            SIPSorcery.Net.SDPMediaTypesEnum.video,
            96,
            "H264",
            90000,
            0,
            "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f");
        var video = new SIPSorcery.Net.SDPMediaAnnouncement(
            SIPSorcery.Net.SDPMediaTypesEnum.video, 9, new List<SIPSorcery.Net.SDPAudioVideoMediaFormat> { h264 })
        {
            Transport = "UDP/TLS/RTP/SAVPF",
            Connection = connection,
            IceUfrag = IceUfrag,
            IcePwd = IcePwd,
            IceOptions = "trickle",
            DtlsFingerprint = "sha-256 " + Fingerprint,
            MediaID = "1",
            MLineIndex = 1,
        };
        video.ExtraMediaAttributes.Add("a=rtcp-mux");
        video.SsrcAttributes.Add(new SIPSorcery.Net.SDPSsrcAttribute(3204773231u, Cname, null));

        var dataChannel = new SIPSorcery.Net.SDPMediaAnnouncement(
            SIPSorcery.Net.SDPMediaTypesEnum.application,
            9,
            new List<SIPSorcery.Net.SDPApplicationMediaFormat> { new("webrtc-datachannel") })
        {
            Transport = "UDP/DTLS/SCTP",
            Connection = connection,
            IceUfrag = IceUfrag,
            IcePwd = IcePwd,
            IceOptions = "trickle",
            DtlsFingerprint = "sha-256 " + Fingerprint,
            MediaID = "2",
            MLineIndex = 2,
            SctpPort = 5000,
            MaxMessageSize = 262144,
        };

        sdp.Media.Add(audio);
        sdp.Media.Add(video);
        sdp.Media.Add(dataChannel);

        return sdp.ToString();
    }
}
