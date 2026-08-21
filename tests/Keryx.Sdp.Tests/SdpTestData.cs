namespace Keryx.Sdp.Tests;

/// <summary>
/// Realistic Chrome (M120+, unified plan) offer/answer pairs. Kept verbatim so the round-trip tests
/// have something a browser would actually emit.
/// </summary>
internal static class SdpTestData
{
    internal const string Fingerprint =
        "75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24";

    /// <summary>A Chrome offer: sendrecv audio and video plus a data channel, all bundled.</summary>
    internal static string ChromeOffer { get; } = Crlf(ChromeOfferBody);

    /// <summary>The Chrome answer to <see cref="ChromeOffer"/>: recvonly, no ssrcs, no candidates yet.</summary>
    internal static string ChromeAnswer { get; } = Crlf(ChromeAnswerBody);

    /// <summary>The same answer with bare LF line endings, as some non-browser stacks emit.</summary>
    internal static string ChromeAnswerLf { get; } = Lf(ChromeAnswerBody);

    private const string ChromeOfferBody =
        """
        v=0
        o=- 4611731400430051336 2 IN IP4 127.0.0.1
        s=-
        t=0 0
        a=group:BUNDLE 0 1 2
        a=extmap-allow-mixed
        a=msid-semantic: WMS 9e1ba9e2-c1f5-4f7a-9a0c-1b1a9f0c1d2e
        m=audio 9 UDP/TLS/RTP/SAVPF 111 63 9 0 8 13 110 126
        c=IN IP4 0.0.0.0
        a=rtcp:9 IN IP4 0.0.0.0
        a=ice-ufrag:hT7a
        a=ice-pwd:XKQVjJ9wRVWy3zNsL6mQ0pTb
        a=ice-options:trickle
        a=fingerprint:sha-256 75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24
        a=setup:actpass
        a=mid:0
        a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
        a=extmap:2 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
        a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid
        a=sendrecv
        a=msid:9e1ba9e2-c1f5-4f7a-9a0c-1b1a9f0c1d2e 6b0c8f3d-2a5e-4c11-9b7d-3f2a1c0e9d84
        a=rtcp-mux
        a=rtcp-rsize
        a=rtpmap:111 opus/48000/2
        a=rtcp-fb:111 transport-cc
        a=fmtp:111 minptime=10;useinbandfec=1
        a=rtpmap:63 red/48000/2
        a=fmtp:63 111/111
        a=rtpmap:9 G722/8000
        a=rtpmap:0 PCMU/8000
        a=rtpmap:8 PCMA/8000
        a=rtpmap:13 CN/8000
        a=rtpmap:110 telephone-event/48000
        a=rtpmap:126 telephone-event/8000
        a=ssrc:1657320245 cname:JnQ3z0/M0zPjNq2h
        a=ssrc:1657320245 msid:9e1ba9e2-c1f5-4f7a-9a0c-1b1a9f0c1d2e 6b0c8f3d-2a5e-4c11-9b7d-3f2a1c0e9d84
        m=video 9 UDP/TLS/RTP/SAVPF 96 97 102 103
        c=IN IP4 0.0.0.0
        b=AS:2000
        a=rtcp:9 IN IP4 0.0.0.0
        a=ice-ufrag:hT7a
        a=ice-pwd:XKQVjJ9wRVWy3zNsL6mQ0pTb
        a=ice-options:trickle
        a=fingerprint:sha-256 75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24
        a=setup:actpass
        a=mid:1
        a=extmap:14 urn:ietf:params:rtp-hdrext:toffset
        a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
        a=extmap:13 urn:3gpp:video-orientation
        a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid
        a=sendrecv
        a=msid:9e1ba9e2-c1f5-4f7a-9a0c-1b1a9f0c1d2e 1d5f8c07-6b9a-4c2e-8f11-7a3d2b4c5e60
        a=rtcp-mux
        a=rtcp-rsize
        a=rtpmap:96 H264/90000
        a=rtcp-fb:96 goog-remb
        a=rtcp-fb:96 transport-cc
        a=rtcp-fb:96 ccm fir
        a=rtcp-fb:96 nack
        a=rtcp-fb:96 nack pli
        a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f
        a=rtpmap:97 rtx/90000
        a=fmtp:97 apt=96
        a=rtpmap:102 H264/90000
        a=rtcp-fb:102 goog-remb
        a=rtcp-fb:102 transport-cc
        a=rtcp-fb:102 ccm fir
        a=rtcp-fb:102 nack
        a=rtcp-fb:102 nack pli
        a=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f
        a=rtpmap:103 rtx/90000
        a=fmtp:103 apt=102
        a=ssrc-group:FID 3204773231 1245781936
        a=ssrc:3204773231 cname:JnQ3z0/M0zPjNq2h
        a=ssrc:3204773231 msid:9e1ba9e2-c1f5-4f7a-9a0c-1b1a9f0c1d2e 1d5f8c07-6b9a-4c2e-8f11-7a3d2b4c5e60
        a=ssrc:1245781936 cname:JnQ3z0/M0zPjNq2h
        a=ssrc:1245781936 msid:9e1ba9e2-c1f5-4f7a-9a0c-1b1a9f0c1d2e 1d5f8c07-6b9a-4c2e-8f11-7a3d2b4c5e60
        m=application 9 UDP/DTLS/SCTP webrtc-datachannel
        c=IN IP4 0.0.0.0
        a=ice-ufrag:hT7a
        a=ice-pwd:XKQVjJ9wRVWy3zNsL6mQ0pTb
        a=ice-options:trickle
        a=fingerprint:sha-256 75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24
        a=setup:actpass
        a=mid:2
        a=sctp-port:5000
        a=max-message-size:262144
        """;

    private const string ChromeAnswerBody =
        """
        v=0
        o=- 1092376891452871093 3 IN IP4 127.0.0.1
        s=-
        t=0 0
        a=group:BUNDLE 0 1 2
        a=extmap-allow-mixed
        a=msid-semantic: WMS
        m=audio 9 UDP/TLS/RTP/SAVPF 111
        c=IN IP4 0.0.0.0
        a=rtcp:9 IN IP4 0.0.0.0
        a=ice-ufrag:4ZcD
        a=ice-pwd:2/1muCWoOi3uLifh0NuRHlZ6cKr
        a=ice-options:trickle
        a=fingerprint:sha-256 EE:2D:1B:70:1C:0F:39:A6:1D:47:23:8A:41:66:9C:0B:5F:AE:2C:73:88:14:D5:6E:9A:B1:03:F7:52:C4:60:1A
        a=setup:active
        a=mid:0
        a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
        a=extmap:2 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
        a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid
        a=recvonly
        a=rtcp-mux
        a=rtcp-rsize
        a=rtpmap:111 opus/48000/2
        a=rtcp-fb:111 transport-cc
        a=fmtp:111 minptime=10;useinbandfec=1
        m=video 9 UDP/TLS/RTP/SAVPF 102 103
        c=IN IP4 0.0.0.0
        a=rtcp:9 IN IP4 0.0.0.0
        a=ice-ufrag:4ZcD
        a=ice-pwd:2/1muCWoOi3uLifh0NuRHlZ6cKr
        a=ice-options:trickle
        a=fingerprint:sha-256 EE:2D:1B:70:1C:0F:39:A6:1D:47:23:8A:41:66:9C:0B:5F:AE:2C:73:88:14:D5:6E:9A:B1:03:F7:52:C4:60:1A
        a=setup:active
        a=mid:1
        a=extmap:14 urn:ietf:params:rtp-hdrext:toffset
        a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
        a=extmap:13 urn:3gpp:video-orientation
        a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid
        a=recvonly
        a=rtcp-mux
        a=rtcp-rsize
        a=rtpmap:102 H264/90000
        a=rtcp-fb:102 goog-remb
        a=rtcp-fb:102 transport-cc
        a=rtcp-fb:102 ccm fir
        a=rtcp-fb:102 nack
        a=rtcp-fb:102 nack pli
        a=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f
        a=rtpmap:103 rtx/90000
        a=fmtp:103 apt=102
        m=application 9 UDP/DTLS/SCTP webrtc-datachannel
        c=IN IP4 0.0.0.0
        a=ice-ufrag:4ZcD
        a=ice-pwd:2/1muCWoOi3uLifh0NuRHlZ6cKr
        a=ice-options:trickle
        a=fingerprint:sha-256 EE:2D:1B:70:1C:0F:39:A6:1D:47:23:8A:41:66:9C:0B:5F:AE:2C:73:88:14:D5:6E:9A:B1:03:F7:52:C4:60:1A
        a=setup:active
        a=mid:2
        a=sctp-port:5000
        a=max-message-size:262144
        """;

    internal static string Crlf(string body) => body.ReplaceLineEndings("\r\n") + "\r\n";

    internal static string Lf(string body) => body.ReplaceLineEndings("\n") + "\n";
}
