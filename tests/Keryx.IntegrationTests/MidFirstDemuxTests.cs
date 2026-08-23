using System.Text;
using FluentAssertions;
using Keryx.Rtp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// Coverage for the mid-first inbound RTP demux (PR 1 of the session-model work). A received packet is
/// routed to its m-section by the BUNDLE precedence of RFC 8843 §9.2: the MID header extension first,
/// then the SSRC learned from the remote SDP, then the payload type. The precedence is exercised both
/// directly on the <see cref="PeerConnection.RouteTable"/> — where a payload-type collision across two
/// sections is only resolvable by mid or SSRC — and end to end through an applied remote offer, and the
/// consume-only guarantee (Keryx does not yet advertise the MID extension) is pinned on the emitted
/// offer.
/// </summary>
public sealed class MidFirstDemuxTests
{
    private const byte MidExtensionId = 3;
    private const byte VideoPayloadType = 96;
    private const byte AudioPayloadType = 111;

    private static CancellationToken TestTimeout() =>
        new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;

    /// <summary>
    /// A demux table with two video sections that both use payload type 96 — the collision the global
    /// payload-type map cannot resolve. Section "0" runs at a 90 kHz clock, section "1" at 45 kHz, so the
    /// resolved route's clock rate reveals which section a packet was attributed to.
    /// </summary>
    private static PeerConnection.RouteTable TwoSectionTable()
    {
        var route0 = new PeerConnection.RtpRoute("0", MediaKind.Video, 90000);
        var route1 = new PeerConnection.RtpRoute("1", MediaKind.Video, 45000);

        return new PeerConnection.RouteTable(
            byPayloadType: new Dictionary<byte, PeerConnection.RtpRoute> { [VideoPayloadType] = route0 },
            byMid: new Dictionary<string, Dictionary<byte, PeerConnection.RtpRoute>>(StringComparer.Ordinal)
            {
                ["0"] = new() { [VideoPayloadType] = route0 },
                ["1"] = new() { [VideoPayloadType] = route1 },
            },
            ssrcToMid: new Dictionary<uint, string> { [1000] = "0", [2000] = "1" },
            midExtensionId: MidExtensionId);
    }

    private static byte[] MidExtensionBody(byte id, string mid)
    {
        var body = new byte[16];
        var writer = new RtpOneByteExtensionWriter(body);
        writer.TryAppend(id, Encoding.ASCII.GetBytes(mid)).Should().BeTrue();
        var length = writer.Finish();
        return body[..length];
    }

    private static RtpHeader HeaderWithMid(byte payloadType, uint ssrc, ReadOnlySpan<byte> extension) => new()
    {
        Version = 2,
        PayloadType = payloadType,
        Ssrc = ssrc,
        HasExtension = true,
        ExtensionProfile = RtpHeaderExtension.OneByteProfile,
        ExtensionData = extension,
    };

    private static RtpHeader PlainHeader(byte payloadType, uint ssrc) => new()
    {
        Version = 2,
        PayloadType = payloadType,
        Ssrc = ssrc,
    };

    [Fact]
    public void The_mid_header_extension_routes_a_packet_over_a_colliding_payload_type()
    {
        var table = TwoSectionTable();

        // The MID extension names section "1"; even though payload type 96 and the SSRC would both point
        // elsewhere, the mid wins and the packet lands on section "1" (45 kHz).
        var toOne = MidExtensionBody(MidExtensionId, "1");
        table.Resolve(HeaderWithMid(VideoPayloadType, ssrc: 1000, toOne), VideoPayloadType)
            .Should().Be(new PeerConnection.RtpRoute("1", MediaKind.Video, 45000));

        var toZero = MidExtensionBody(MidExtensionId, "0");
        table.Resolve(HeaderWithMid(VideoPayloadType, ssrc: 2000, toZero), VideoPayloadType)
            .Should().Be(new PeerConnection.RtpRoute("0", MediaKind.Video, 90000));
    }

    [Fact]
    public void An_ssrc_known_from_the_remote_sdp_routes_when_no_mid_extension_is_present()
    {
        var table = TwoSectionTable();

        // No MID extension: the SSRC learned from the SDP disambiguates the colliding payload type.
        table.Resolve(PlainHeader(VideoPayloadType, ssrc: 2000), VideoPayloadType)
            .Should().Be(new PeerConnection.RtpRoute("1", MediaKind.Video, 45000));

        table.Resolve(PlainHeader(VideoPayloadType, ssrc: 1000), VideoPayloadType)
            .Should().Be(new PeerConnection.RtpRoute("0", MediaKind.Video, 90000));
    }

    [Fact]
    public void The_payload_type_is_the_last_resort_when_neither_mid_nor_ssrc_resolve()
    {
        var table = TwoSectionTable();

        // Neither a MID extension nor a known SSRC: fall back to the global payload-type map, which is
        // exactly the prior behaviour for a peer that signals neither.
        table.Resolve(PlainHeader(VideoPayloadType, ssrc: 9999), VideoPayloadType)
            .Should().Be(new PeerConnection.RtpRoute("0", MediaKind.Video, 90000));

        // An unknown payload type with no other key resolves to the unknown route, unchanged.
        table.Resolve(PlainHeader(payloadType: 200, ssrc: 9999), 200)
            .Kind.Should().Be(MediaKind.Unknown);
    }

    [Fact]
    public void A_mid_extension_naming_an_unknown_section_falls_through_to_ssrc_then_payload_type()
    {
        var table = TwoSectionTable();

        // The MID extension names a section that is not in the table (a data-channel mid, say); the demux
        // must not treat that as a resolution — it falls through to the SSRC map, which knows section "1".
        var unknownMid = MidExtensionBody(MidExtensionId, "9");
        table.Resolve(HeaderWithMid(VideoPayloadType, ssrc: 2000, unknownMid), VideoPayloadType)
            .Should().Be(new PeerConnection.RtpRoute("1", MediaKind.Video, 45000));

        // And with no SSRC either, all the way down to the payload-type map.
        table.Resolve(HeaderWithMid(VideoPayloadType, ssrc: 9999, unknownMid), VideoPayloadType)
            .Should().Be(new PeerConnection.RtpRoute("0", MediaKind.Video, 90000));
    }

    [Fact]
    public void The_ssrc_and_payload_type_overload_resolves_headerless_packets()
    {
        var table = TwoSectionTable();

        // The RTX-reconstructed and jitter-buffer-drained paths have no header extension; they resolve by
        // SSRC then payload type.
        table.Resolve(ssrc: 2000, VideoPayloadType)
            .Should().Be(new PeerConnection.RtpRoute("1", MediaKind.Video, 45000));

        table.Resolve(ssrc: 9999, VideoPayloadType)
            .Should().Be(new PeerConnection.RtpRoute("0", MediaKind.Video, 90000));
    }

    [Fact]
    public async Task Applying_a_remote_offer_wires_mid_ssrc_and_payload_type_resolution()
    {
        await using var peer = new PeerConnection(TestSupport.NewConfig());
        await peer.SetRemoteDescriptionAsync(RemoteOffer, SdpType.Offer, TestTimeout());

        var table = peer.InboundRoutes;

        // MID extension "1" → the video section.
        var videoMid = MidExtensionBody(MidExtensionId, "1");
        var byMid = table.Resolve(HeaderWithMid(VideoPayloadType, ssrc: 999, videoMid), VideoPayloadType);
        byMid.Kind.Should().Be(MediaKind.Video);
        byMid.Mid.Should().Be("1");

        // No extension, but the video media SSRC from the offer's a=ssrc line → the video section.
        var bySsrc = table.Resolve(PlainHeader(VideoPayloadType, ssrc: VideoSsrc), VideoPayloadType);
        bySsrc.Kind.Should().Be(MediaKind.Video);
        bySsrc.Mid.Should().Be("1");

        // The audio MID extension "0" with the Opus payload type → the audio section.
        var audioMid = MidExtensionBody(MidExtensionId, "0");
        var audio = table.Resolve(HeaderWithMid(AudioPayloadType, ssrc: 111, audioMid), AudioPayloadType);
        audio.Kind.Should().Be(MediaKind.Audio);
        audio.Mid.Should().Be("0");

        // Neither key: the payload type still resolves the single video section, unchanged.
        var byPt = table.Resolve(PlainHeader(VideoPayloadType, ssrc: 424242), VideoPayloadType);
        byPt.Kind.Should().Be(MediaKind.Video);
    }

    [Fact]
    public async Task The_emitted_offer_does_not_advertise_the_mid_extension_yet()
    {
        // Consume-only: PR 1 reads the MID extension a peer negotiated but adds nothing to Keryx's own
        // SDP. Advertising it on egress begins in PR 3; until then the offer must stay byte-identical.
        await using var peer = new PeerConnection(TestSupport.NewConfig());
        var offer = await peer.CreateOfferAsync(TestTimeout());

        offer.Should().NotContain("sdes:mid");
    }

    private const uint VideoSsrc = 3204773231;

    private static readonly string RemoteOffer = string.Join("\r\n",
        "v=0",
        "o=- 4611731400430051336 2 IN IP4 127.0.0.1",
        "s=-",
        "t=0 0",
        "a=group:BUNDLE 0 1",
        "a=extmap-allow-mixed",
        "a=msid-semantic: WMS stream",
        "m=audio 9 UDP/TLS/RTP/SAVPF 111",
        "c=IN IP4 0.0.0.0",
        "a=rtcp:9 IN IP4 0.0.0.0",
        "a=ice-ufrag:hT7a",
        "a=ice-pwd:XKQVjJ9wRVWy3zNsL6mQ0pTb",
        "a=ice-options:trickle",
        "a=fingerprint:sha-256 75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24",
        "a=setup:actpass",
        "a=mid:0",
        "a=extmap:2 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
        "a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid",
        "a=sendrecv",
        "a=rtcp-mux",
        "a=rtpmap:111 opus/48000/2",
        "a=rtcp-fb:111 transport-cc",
        "a=fmtp:111 minptime=10;useinbandfec=1",
        "a=ssrc:1657320245 cname:JnQ3z0",
        "m=video 9 UDP/TLS/RTP/SAVPF 96 97",
        "c=IN IP4 0.0.0.0",
        "a=rtcp:9 IN IP4 0.0.0.0",
        "a=ice-ufrag:hT7a",
        "a=ice-pwd:XKQVjJ9wRVWy3zNsL6mQ0pTb",
        "a=ice-options:trickle",
        "a=fingerprint:sha-256 75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24",
        "a=setup:actpass",
        "a=mid:1",
        "a=extmap:2 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
        "a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid",
        "a=sendrecv",
        "a=rtcp-mux",
        "a=rtpmap:96 H264/90000",
        "a=rtcp-fb:96 nack",
        "a=rtcp-fb:96 nack pli",
        "a=rtcp-fb:96 transport-cc",
        "a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
        "a=rtpmap:97 rtx/90000",
        "a=fmtp:97 apt=96",
        $"a=ssrc-group:FID {VideoSsrc} 1245781936",
        $"a=ssrc:{VideoSsrc} cname:JnQ3z0",
        "a=ssrc:1245781936 cname:JnQ3z0",
        "");
}
