using FluentAssertions;
using Xunit;

namespace Keryx.Sdp.Tests;

public class SdpOfferBuilderTests
{
    private const string Cname = "keryx-cname-01";
    private const string StreamId = "keryx-stream";
    private const string AudioTrack = "keryx-audio-track";
    private const string VideoTrack = "keryx-video-track";

    private static SdpOfferBuilder ProxenoOffer()
    {
        var builder = new SdpOfferBuilder
        {
            SessionId = "4611731400430051336",
            IceCredentials = new SdpIceCredentials("hT7a", "XKQVjJ9wRVWy3zNsL6mQ0pTb"),
            Fingerprint = new SdpFingerprint("sha-256", SdpTestData.Fingerprint),
            Cname = Cname,
            StreamId = StreamId,
        };

        var audio = SdpMediaOffer.Audio("0", SdpCodec.Opus(111));
        audio.TrackId = AudioTrack;
        audio.Ssrcs.Add(1657320245u);

        var video = SdpMediaOffer.Video("1", SdpCodec.H264(96));
        video.TrackId = VideoTrack;
        video.Ssrcs.Add(3204773231u);

        return builder
            .AddMedia(audio)
            .AddMedia(video)
            .AddDataChannel("2");
    }

    [Fact]
    public void Build_ProducesTheExactOfferShape()
    {
        var text = ProxenoOffer().Build().ToSdpString();

        var expected = SdpTestData.Crlf($"""
            v=0
            o=- 4611731400430051336 2 IN IP4 127.0.0.1
            s=-
            t=0 0
            a=group:BUNDLE 0 1 2
            a=msid-semantic: WMS {StreamId}
            m=audio 9 UDP/TLS/RTP/SAVPF 111
            c=IN IP4 0.0.0.0
            a=rtcp:9 IN IP4 0.0.0.0
            a=ice-ufrag:hT7a
            a=ice-pwd:XKQVjJ9wRVWy3zNsL6mQ0pTb
            a=ice-options:trickle
            a=fingerprint:sha-256 {SdpTestData.Fingerprint}
            a=setup:actpass
            a=mid:0
            a=sendonly
            a=msid:{StreamId} {AudioTrack}
            a=rtcp-mux
            a=rtpmap:111 opus/48000/2
            a=rtcp-fb:111 transport-cc
            a=fmtp:111 minptime=10;useinbandfec=1
            a=ssrc:1657320245 cname:{Cname}
            a=ssrc:1657320245 msid:{StreamId} {AudioTrack}
            m=video 9 UDP/TLS/RTP/SAVPF 96
            c=IN IP4 0.0.0.0
            a=rtcp:9 IN IP4 0.0.0.0
            a=ice-ufrag:hT7a
            a=ice-pwd:XKQVjJ9wRVWy3zNsL6mQ0pTb
            a=ice-options:trickle
            a=fingerprint:sha-256 {SdpTestData.Fingerprint}
            a=setup:actpass
            a=mid:1
            a=sendonly
            a=msid:{StreamId} {VideoTrack}
            a=rtcp-mux
            a=rtpmap:96 H264/90000
            a=rtcp-fb:96 nack
            a=rtcp-fb:96 nack pli
            a=rtcp-fb:96 ccm fir
            a=rtcp-fb:96 transport-cc
            a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f
            a=ssrc:3204773231 cname:{Cname}
            a=ssrc:3204773231 msid:{StreamId} {VideoTrack}
            m=application 9 UDP/DTLS/SCTP webrtc-datachannel
            c=IN IP4 0.0.0.0
            a=ice-ufrag:hT7a
            a=ice-pwd:XKQVjJ9wRVWy3zNsL6mQ0pTb
            a=ice-options:trickle
            a=fingerprint:sha-256 {SdpTestData.Fingerprint}
            a=setup:actpass
            a=mid:2
            a=sctp-port:5000
            a=max-message-size:262144
            """);

        text.Should().Be(expected);
    }

    [Fact]
    public void Build_VideoAdvertisesBareNackInChromesOrder()
    {
        // RFC 4585 §4: bare nack is generic NACK feedback, distinct from nack pli. Keryx offers it
        // because it serves retransmissions over RFC 4588 RTX.
        var video = ProxenoOffer().Build().MediaDescriptions[1];

        video.GetRtcpFeedback(96).Should().Equal(
            RtcpFeedback.Nack,
            RtcpFeedback.NackPli,
            RtcpFeedback.CcmFir,
            RtcpFeedback.TransportCc);
    }

    [Fact]
    public void Build_BareNackCanBeRemovedForASenderWithNoRepairStream()
    {
        var codec = SdpCodec.H264(96);
        codec.Feedback.Remove(RtcpFeedback.Nack);
        var media = new SdpOfferBuilder
        {
            IceCredentials = new SdpIceCredentials("u", "p"),
            Fingerprint = new SdpFingerprint("sha-256", "AA:BB"),
        }.AddVideo("0", codec).Build().MediaDescriptions[0];

        media.GetRtcpFeedback(96).Should().NotContain(RtcpFeedback.Nack);
        media.GetRtcpFeedback(96).Should().Contain(RtcpFeedback.NackPli);
    }

    [Fact]
    public void Build_EmitsTheRtxCodecAndFidGroupForARepairStream()
    {
        // RFC 4588 §8.1 pairs a=rtpmap:<pt> rtx/<clock> with a=fmtp:<pt> apt=<media pt>, and
        // RFC 5576 §4.2 binds the repair SSRC to the media SSRC with a=ssrc-group:FID.
        var video = SdpMediaOffer.Video("1", SdpCodec.H264(96), SdpCodec.Rtx(97, 96));
        video.TrackId = VideoTrack;
        video.Ssrcs.Add(3204773231u);
        video.Ssrcs.Add(1245781936u);
        video.SsrcGroups.Add(new SsrcGroup(SsrcGroup.FidSemantics, [3204773231u, 1245781936u]));

        var media = new SdpOfferBuilder
        {
            IceCredentials = new SdpIceCredentials("u", "p"),
            Fingerprint = new SdpFingerprint("sha-256", "AA:BB"),
            Cname = Cname,
            StreamId = StreamId,
        }.AddMedia(video).Build().MediaDescriptions[0];

        var text = media.ToSdpString();
        text.Should().Contain("m=video 9 UDP/TLS/RTP/SAVPF 96 97");
        text.Should().Contain("a=rtpmap:97 rtx/90000");
        text.Should().Contain("a=fmtp:97 apt=96");
        text.Should().Contain("a=ssrc-group:FID 3204773231 1245781936");
        media.GetSsrcCname(1245781936u).Should().Be(Cname);
        media.GetSsrcCname(3204773231u).Should().Be(Cname);
    }

    [Fact]
    public void Build_RoundTripsThroughTheParser()
    {
        var text = ProxenoOffer().Build().ToSdpString();

        SessionDescription.Parse(text).ToSdpString().Should().Be(text);
    }

    [Fact]
    public void Build_BundleGroupListsEveryMidInOrder()
    {
        ProxenoOffer().Build().GetBundleGroup().Should().Equal("0", "1", "2");
    }

    [Fact]
    public void Build_BundleGroupExcludesRejectedSections_ReAnchoringTheTag()
    {
        // A rejected (port-0) m-section must not appear in the BUNDLE group (RFC 8843 §6, §8.3), and in
        // particular must never be the tag. Reject the first (audio) section: the group re-anchors onto
        // the first surviving section (video, mid 1) rather than pointing a peer's transport at the dead
        // m-line, and the rejected section keeps its aligned m-line slot.
        var builder = ProxenoOffer();
        builder.Media[0].Port = 0;

        var sdp = builder.Build();

        sdp.GetBundleGroup().Should().Equal("1", "2");
        sdp.MediaDescriptions.Should().HaveCount(3, "a rejected section keeps its m-line slot for alignment");
        sdp.MediaDescriptions[0].Mid.Should().Be("0");
    }

    [Fact]
    public void Build_BundleDisabledEmitsNoGroup()
    {
        var builder = ProxenoOffer();
        builder.BundlePolicy = SdpBundlePolicy.Disabled;

        var sdp = builder.Build();

        sdp.HasAttribute(SdpAttributeNames.Group).Should().BeFalse();
        sdp.GetBundleGroup().Should().BeEmpty();
    }

    [Fact]
    public void Build_TrickleCanBeDisabled()
    {
        var builder = ProxenoOffer();
        builder.TrickleIce = false;

        var sdp = builder.Build();

        sdp.MediaDescriptions.Should().OnlyContain(m => !m.HasAttribute(SdpAttributeNames.IceOptions));
    }

    [Fact]
    public void Build_ExtMapAllowMixedIsOptIn()
    {
        var builder = ProxenoOffer();
        builder.ExtMapAllowMixed = true;

        builder.Build().ToSdpString().Should().Contain("a=extmap-allow-mixed\r\n");
    }

    [Fact]
    public void Build_HonoursPerSectionOverrides()
    {
        var builder = ProxenoOffer();
        builder.Media[1].IceCredentials = new SdpIceCredentials("other", "otherpassword0123456789");
        builder.Media[1].Setup = SdpSetupRole.Passive;
        builder.Media[1].RtcpReducedSize = true;

        var video = builder.Build().MediaDescriptions[1];

        video.IceUfrag.Should().Be("other");
        video.Setup.Should().Be(SdpSetupRole.Passive);
        video.RtcpReducedSize.Should().BeTrue();
    }

    [Fact]
    public void Build_EmitsHeaderExtensionsAndSsrcGroups()
    {
        var builder = ProxenoOffer();
        builder.Media[1].HeaderExtensions.Add(new SdpExtMap(3, "urn:ietf:params:rtp-hdrext:sdes:mid"));
        builder.Media[1].Ssrcs.Add(1245781936u);
        builder.Media[1].SsrcGroups.Add(new SsrcGroup("FID", [3204773231u, 1245781936u]));

        var video = builder.Build().MediaDescriptions[1];

        video.GetExtMaps().Should().ContainSingle();
        video.GetSsrcs().Should().Equal(3204773231u, 1245781936u);
        video.GetSsrcGroups().Should().ContainSingle();
        video.ToSdpString().Should().Contain("a=ssrc-group:FID 3204773231 1245781936\r\na=ssrc:3204773231 cname:");
    }

    [Fact]
    public void Build_AcceptsACommunityCodecWithNoWellKnownFactory()
    {
        var av1 = new SdpCodec(45, "AV1", 90000)
            .WithFmtp("level-idx=5;profile=0;tier=0")
            .WithFeedback(RtcpFeedback.NackPli, new RtcpFeedback("nack", "raps"));

        var builder = new SdpOfferBuilder
        {
            IceCredentials = new SdpIceCredentials("u", "p"),
            Fingerprint = new SdpFingerprint("sha-256", "AA:BB"),
        }.AddVideo("0", av1);

        var media = builder.Build().MediaDescriptions[0];

        media.Formats.Should().Equal("45");
        media.GetRtpMap(45).Should().Be(new RtpMap(45, "AV1", 90000));
        media.GetFmtp(45).Should().Be("level-idx=5;profile=0;tier=0");
        media.GetRtcpFeedback(45).Should().Equal(RtcpFeedback.NackPli, new RtcpFeedback("nack", "raps"));
    }

    [Fact]
    public void Build_SupportsRtxCodecs()
    {
        var builder = new SdpOfferBuilder
        {
            IceCredentials = new SdpIceCredentials("u", "p"),
            Fingerprint = new SdpFingerprint("sha-256", "AA:BB"),
        }.AddVideo("0", SdpCodec.H264(96), SdpCodec.Rtx(97, 96));

        var media = builder.Build().MediaDescriptions[0];

        media.Formats.Should().Equal("96", "97");
        media.GetFmtp(97).Should().Be("apt=96");
    }

    [Fact]
    public void Build_DataChannelSectionCarriesNoDirectionOrRtcpMux()
    {
        var application = ProxenoOffer().Build().MediaDescriptions[2];

        application.Direction.Should().BeNull();
        application.RtcpMux.Should().BeFalse();
        application.Rtcp.Should().BeNull();
        application.SctpPort.Should().Be(5000);
        application.MaxMessageSize.Should().Be(262144);
    }

    [Fact]
    public void Build_DataChannelSizesAreConfigurable()
    {
        var builder = new SdpOfferBuilder
        {
            IceCredentials = new SdpIceCredentials("u", "p"),
            Fingerprint = new SdpFingerprint("sha-256", "AA:BB"),
        }.AddDataChannel("0", sctpPort: 5001, maxMessageSize: 65536);

        var media = builder.Build().MediaDescriptions[0];

        media.SctpPort.Should().Be(5001);
        media.MaxMessageSize.Should().Be(65536);
    }

    [Fact]
    public void Build_WithoutMediaThrows()
    {
        var build = () => new SdpOfferBuilder().Build();

        build.Should().Throw<SdpException>().WithMessage("*at least one m-section*");
    }

    [Fact]
    public void Build_WithDuplicateMidThrows()
    {
        var builder = new SdpOfferBuilder
        {
            IceCredentials = new SdpIceCredentials("u", "p"),
            Fingerprint = new SdpFingerprint("sha-256", "AA:BB"),
        }.AddAudio("0", SdpCodec.Opus()).AddVideo("0", SdpCodec.H264());

        var build = builder.Build;

        build.Should().Throw<SdpException>().WithMessage("*Duplicate mid '0'*");
    }

    [Fact]
    public void Build_WithoutIceCredentialsThrows()
    {
        var builder = new SdpOfferBuilder { Fingerprint = new SdpFingerprint("sha-256", "AA:BB") }
            .AddAudio("0", SdpCodec.Opus());

        var build = builder.Build;

        build.Should().Throw<SdpException>().WithMessage("*no ICE credentials*");
    }

    [Fact]
    public void Build_WithoutFingerprintThrows()
    {
        var builder = new SdpOfferBuilder { IceCredentials = new SdpIceCredentials("u", "p") }
            .AddAudio("0", SdpCodec.Opus());

        var build = builder.Build;

        build.Should().Throw<SdpException>().WithMessage("*no DTLS fingerprint*");
    }

    [Fact]
    public void Build_DefaultSessionIdIsRandom()
    {
        var first = new SdpOfferBuilder().SessionId;
        var second = new SdpOfferBuilder().SessionId;

        first.Should().NotBe(second);
    }

    [Fact]
    public void Build_WithoutAStreamIdEmitsABareWmsToken()
    {
        var builder = new SdpOfferBuilder
        {
            IceCredentials = new SdpIceCredentials("u", "p"),
            Fingerprint = new SdpFingerprint("sha-256", "AA:BB"),
        }.AddDataChannel("0");

        builder.Build().ToSdpString().Should().Contain("a=msid-semantic: WMS\r\n");
    }

    [Fact]
    public void Opus_UsesChromeDefaults()
    {
        var opus = SdpCodec.Opus();

        opus.PayloadType.Should().Be(111);
        opus.EncodingName.Should().Be("opus");
        opus.ClockRate.Should().Be(48000);
        opus.Channels.Should().Be(2);
        opus.Fmtp.Should().Be("minptime=10;useinbandfec=1");
        opus.Feedback.Should().Equal(RtcpFeedback.TransportCc);
    }

    [Fact]
    public void H264_UsesConstrainedBaselineDefaults()
    {
        var h264 = SdpCodec.H264();

        h264.PayloadType.Should().Be(96);
        h264.EncodingName.Should().Be("H264");
        h264.ClockRate.Should().Be(90000);
        h264.Channels.Should().BeNull();
        h264.Fmtp.Should().Be("level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f");
        h264.Feedback.Should().Equal(
            RtcpFeedback.Nack,
            RtcpFeedback.NackPli,
            RtcpFeedback.CcmFir,
            RtcpFeedback.TransportCc);
    }

    [Fact]
    public void Vp8_UsesChromesFeedbackOrderAndNoFmtp()
    {
        var vp8 = SdpCodec.Vp8();

        vp8.PayloadType.Should().Be(96);
        vp8.EncodingName.Should().Be("VP8");
        vp8.ClockRate.Should().Be(90000);
        vp8.Channels.Should().BeNull();
        vp8.Fmtp.Should().BeNull();
        vp8.Feedback.Should().Equal(
            RtcpFeedback.Nack,
            RtcpFeedback.NackPli,
            RtcpFeedback.CcmFir,
            RtcpFeedback.GoogRemb,
            RtcpFeedback.TransportCc);
        vp8.IsRtx.Should().BeFalse();
        vp8.GetAssociatedPayloadType().Should().BeNull();
    }

    [Fact]
    public void Vp8_PayloadTypeIsConfigurable()
    {
        SdpCodec.Vp8(98).PayloadType.Should().Be(98);
    }

    [Fact]
    public void Vp9_UsesChromesFeedbackOrderAndProfileFmtp()
    {
        var vp9 = SdpCodec.Vp9();

        vp9.PayloadType.Should().Be(98);
        vp9.EncodingName.Should().Be("VP9");
        vp9.ClockRate.Should().Be(90000);
        vp9.Channels.Should().BeNull();
        vp9.Fmtp.Should().Be("profile-id=0");
        vp9.Feedback.Should().Equal(
            RtcpFeedback.Nack,
            RtcpFeedback.NackPli,
            RtcpFeedback.CcmFir,
            RtcpFeedback.GoogRemb,
            RtcpFeedback.TransportCc);
        vp9.IsRtx.Should().BeFalse();
        vp9.GetAssociatedPayloadType().Should().BeNull();
    }

    [Fact]
    public void Vp9_PayloadTypeAndProfileAreConfigurable()
    {
        var vp9 = SdpCodec.Vp9(100, profileId: "2");
        vp9.PayloadType.Should().Be(100);
        vp9.Fmtp.Should().Be("profile-id=2");
    }

    [Fact]
    public void Av1_UsesChromesFeedbackOrderAndMinimalFmtp()
    {
        var av1 = SdpCodec.Av1();

        av1.PayloadType.Should().Be(45);
        av1.EncodingName.Should().Be("AV1");
        av1.ClockRate.Should().Be(90000);
        av1.Channels.Should().BeNull();
        av1.Fmtp.Should().Be("level-idx=5;profile=0;tier=0");
        av1.Feedback.Should().Equal(
            RtcpFeedback.Nack,
            RtcpFeedback.NackPli,
            RtcpFeedback.CcmFir,
            RtcpFeedback.GoogRemb,
            RtcpFeedback.TransportCc);
        av1.IsRtx.Should().BeFalse();
        av1.GetAssociatedPayloadType().Should().BeNull();
    }

    [Fact]
    public void Av1_PayloadTypeIsConfigurable()
    {
        SdpCodec.Av1(46).PayloadType.Should().Be(46);
    }

    [Fact]
    public void Rtx_BindsToTheRepairedPayloadTypeThroughApt()
    {
        // RFC 4588 §8.1: "apt ... the payload type of the associated original stream".
        var rtx = SdpCodec.Rtx(97, 96);

        rtx.PayloadType.Should().Be(97);
        rtx.EncodingName.Should().Be("rtx");
        rtx.ClockRate.Should().Be(90000);
        rtx.Fmtp.Should().Be("apt=96");
        rtx.IsRtx.Should().BeTrue();
        rtx.GetAssociatedPayloadType().Should().Be(96);
        rtx.ToRtpMap().ToAttributeValue().Should().Be("97 rtx/90000");
        SdpCodec.H264().IsRtx.Should().BeFalse();
        SdpCodec.H264().GetAssociatedPayloadType().Should().BeNull();
    }

    [Fact]
    public void H264_ProfileAndPacketizationModeAreConfigurable()
    {
        var h264 = SdpCodec.H264(102, "640c1f", packetizationMode: 0);

        h264.Fmtp.Should().Be("level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=640c1f");
    }
}
