using FluentAssertions;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// String-level assertions on the offer <see cref="PeerConnection.CreateOfferAsync"/> produces.
/// These are the exact regressions the previous stack forced us to fix by splicing SDP by hand.
/// </summary>
public sealed class SdpOfferShapeTests
{
    [Fact]
    public async Task OfferHasTheShapeABrowserExpects()
    {
        await using var peer = new PeerConnection(TestSupport.NewConfig());
        var offer = await peer.CreateOfferAsync(TestTimeout());

        // Feedback: pli and fir are offered, bare nack is not — Keryx has no RTX path and must not
        // claim one, because a browser that sees bare nack will ask for retransmissions forever.
        offer.Should().Contain("a=rtcp-fb:96 nack pli");
        offer.Should().Contain("a=rtcp-fb:96 ccm fir");
        offer.Should().Contain("a=rtcp-fb:96 transport-cc");
        offer.Split("\r\n").Should().NotContain("a=rtcp-fb:96 nack");

        // Codecs.
        offer.Should().Contain("a=rtpmap:96 H264/90000");
        offer.Should().Contain("a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f");
        offer.Should().Contain("a=rtpmap:111 opus/48000/2");
        offer.Should().Contain("a=fmtp:111 minptime=10;useinbandfec=1");
        offer.Should().Contain("a=rtcp-fb:111 transport-cc");

        // Transport.
        offer.Should().Contain("a=group:BUNDLE 0 1 2");
        offer.Should().Contain("a=setup:actpass");
        offer.Should().Contain("a=rtcp-mux");
        offer.Should().Contain("a=fingerprint:sha-256 ");
        offer.Should().Contain("a=ice-ufrag:");
        offer.Should().Contain("a=ice-pwd:");
        offer.Should().Contain("a=ice-options:trickle");

        // Vanilla ICE out: the offer is complete on its own.
        offer.Should().Contain("a=candidate:");
        offer.Should().Contain("a=end-of-candidates");
        offer.Should().Contain("127.0.0.1");

        // Media directions and the data channel section.
        offer.Should().Contain("m=video 9 UDP/TLS/RTP/SAVPF 96");
        offer.Should().Contain("m=audio 9 UDP/TLS/RTP/SAVPF 111");
        offer.Should().Contain("m=application 9 UDP/DTLS/SCTP webrtc-datachannel");
        offer.Should().Contain("a=sctp-port:5000");
        offer.Should().Contain("a=max-message-size:262144");
        offer.Should().Contain("a=sendonly");

        // And it round-trips through the parser it will meet on the far side.
        var parsed = SessionDescription.Parse(offer);
        parsed.MediaDescriptions.Should().HaveCount(3);
        parsed.GetBundleGroup().Should().Equal("0", "1", "2");
    }

    [Fact]
    public async Task AdvertisedCodecsAreFullyConfigurable()
    {
        var config = TestSupport.NewConfig();
        config.VideoCodecs.Clear();
        config.VideoCodecs.Add(
            new SdpCodec(100, "VP8", 90000)
                .WithFmtp("max-fr=60")
                .WithFeedback(RtcpFeedback.NackPli, RtcpFeedback.GoogRemb));
        config.AudioCodecs.Clear();

        await using var peer = new PeerConnection(config);
        var offer = await peer.CreateOfferAsync(TestTimeout());

        offer.Should().Contain("m=video 9 UDP/TLS/RTP/SAVPF 100");
        offer.Should().Contain("a=rtpmap:100 VP8/90000");
        offer.Should().Contain("a=fmtp:100 max-fr=60");
        offer.Should().Contain("a=rtcp-fb:100 goog-remb");
        offer.Should().NotContain("H264");
        offer.Should().NotContain("m=audio");
        offer.Should().Contain("a=group:BUNDLE 0 2");
    }

    [Fact]
    public async Task MediaSentBeforeConnectingIsDroppedAndCounted()
    {
        await using var peer = new PeerConnection(TestSupport.NewConfig());

        peer.SendVideoFrame([0, 0, 0, 1, 0x65, 0x88], 0).Should().Be(0);
        peer.SendAudioFrame([0xFC, 0x01, 0x02], 0).Should().Be(0);

        var stats = peer.GetStats();
        stats.State.Should().Be(PeerConnectionState.New);
        stats.Video!.Value.FramesDropped.Should().Be(1);
        stats.Audio!.Value.FramesDropped.Should().Be(1);
        stats.Video!.Value.PacketsSent.Should().Be(0);
    }

    private static CancellationToken TestTimeout() =>
        new CancellationTokenSource(TimeSpan.FromSeconds(20)).Token;
}
