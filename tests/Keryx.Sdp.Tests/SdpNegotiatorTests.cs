using FluentAssertions;
using Xunit;

namespace Keryx.Sdp.Tests;

public class SdpNegotiatorTests
{
    private const string AnswerFingerprint =
        "EE:2D:1B:70:1C:0F:39:A6:1D:47:23:8A:41:66:9C:0B:5F:AE:2C:73:88:14:D5:6E:9A:B1:03:F7:52:C4:60:1A";

    private static SessionDescription Offer() => SessionDescription.Parse(SdpTestData.ChromeOffer);

    private static SessionDescription Answer() => SessionDescription.Parse(SdpTestData.ChromeAnswer);

    private static SdpNegotiationResult Negotiate() => SdpNegotiator.Negotiate(Offer(), Answer());

    [Fact]
    public void Validate_AcceptsAMatchingAnswer()
    {
        var result = SdpNegotiator.Validate(Offer(), Answer());

        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
        result.ToString().Should().Be("valid");
    }

    [Fact]
    public void Validate_RejectsAnAnswerWithFewerMSections()
    {
        var answer = Answer();
        answer.MediaDescriptions.RemoveAt(2);

        var result = SdpNegotiator.Validate(Offer(), answer);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().Contain("2 m-section(s), offer has 3");
    }

    [Fact]
    public void Validate_RejectsReorderedMSections()
    {
        var answer = Answer();
        (answer.MediaDescriptions[0], answer.MediaDescriptions[1]) =
            (answer.MediaDescriptions[1], answer.MediaDescriptions[0]);

        var result = SdpNegotiator.Validate(Offer(), answer);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.Contains("media type 'video' does not match offer 'audio'"));
        result.Errors.Should().Contain(e => e.Contains("mid '1' does not match offer mid '0'"));
    }

    [Fact]
    public void Validate_RejectsAProtocolChange()
    {
        var answer = Answer();
        answer.MediaDescriptions[0].Protocol = "RTP/AVP";

        var result = SdpNegotiator.Validate(Offer(), answer);

        result.Errors.Should().Contain(e => e.Contains("protocol 'RTP/AVP' does not match"));
    }

    [Fact]
    public void Validate_RejectsABundleMidTheOfferNeverSent()
    {
        var answer = Answer();
        answer.SetBundleGroup(["0", "1", "9"]);

        var result = SdpNegotiator.Validate(Offer(), answer);

        result.Errors.Should().ContainSingle().Which.Should().Contain("mid '9'");
    }

    [Fact]
    public void Negotiate_ThrowsOnAnInvalidAnswer()
    {
        var answer = Answer();
        answer.MediaDescriptions.RemoveAt(2);

        var negotiate = () => SdpNegotiator.Negotiate(Offer(), answer);

        negotiate.Should().Throw<SdpException>().WithMessage("*Invalid SDP answer*");
    }

    [Fact]
    public void Negotiate_ReportsOneEntryPerMSectionInOrder()
    {
        var result = Negotiate();

        result.Media.Should().HaveCount(3);
        result.Media.Select(m => m.Mid).Should().Equal("0", "1", "2");
        result.Media.Select(m => m.Index).Should().Equal(0, 1, 2);
        result.Media.Select(m => m.MediaType).Should().Equal("audio", "video", "application");
    }

    [Fact]
    public void Negotiate_ReportsTheBundleGroup()
    {
        var result = Negotiate();

        result.BundleMids.Should().Equal("0", "1", "2");
        result.IsBundled.Should().BeTrue();
    }

    [Fact]
    public void Negotiate_IntersectsDirectionFromTheOfferersPointOfView()
    {
        var audio = Negotiate().GetByMid("0")!;

        audio.OfferedDirection.Should().Be(MediaDirection.SendRecv);
        audio.AnsweredDirection.Should().Be(MediaDirection.RecvOnly);
        audio.Direction.Should().Be(MediaDirection.SendOnly);
        audio.CanSend.Should().BeTrue();
        audio.CanReceive.Should().BeFalse();
    }

    [Theory]
    [InlineData(MediaDirection.SendOnly, MediaDirection.RecvOnly, MediaDirection.SendOnly)]
    [InlineData(MediaDirection.SendRecv, MediaDirection.SendRecv, MediaDirection.SendRecv)]
    [InlineData(MediaDirection.SendRecv, MediaDirection.SendOnly, MediaDirection.RecvOnly)]
    [InlineData(MediaDirection.SendOnly, MediaDirection.Inactive, MediaDirection.Inactive)]
    [InlineData(MediaDirection.RecvOnly, MediaDirection.RecvOnly, MediaDirection.Inactive)]
    public void Negotiate_DirectionIntersectionTable(
        MediaDirection offered,
        MediaDirection answered,
        MediaDirection expected)
    {
        SdpDirection.Negotiate(offered, answered).Should().Be(expected);
    }

    [Fact]
    public void Negotiate_SelectsPayloadTypesInOfferOrder()
    {
        var result = Negotiate();

        result.GetByMid("0")!.Codecs.Select(c => c.PayloadType).Should().Equal(111);
        result.GetByMid("1")!.Codecs.Select(c => c.PayloadType).Should().Equal(102, 103);
    }

    [Fact]
    public void Negotiate_ExposesFmtpSoCallersCanPickTheRightH264PayloadType()
    {
        var video = Negotiate().GetByMid("1")!;

        var h264 = video.FindCodec("H264", "profile-level-id", "42e01f")!;
        h264.PayloadType.Should().Be(102);
        h264.EncodingName.Should().Be("H264");
        h264.ClockRate.Should().Be(90000);
        h264.Fmtp.Should().Be("level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f");
        h264.GetFmtpParameters()["packetization-mode"].Should().Be("1");
        h264.HasFmtp("packetization-mode", "1").Should().BeTrue();
    }

    [Fact]
    public void Negotiate_H264PayloadTypeTheAnswerDroppedIsNotSelected()
    {
        var video = Negotiate().GetByMid("1")!;

        video.Codecs.Should().NotContain(c => c.PayloadType == 96);
        video.FindCodec("H264", "profile-level-id", "42001f").Should().BeNull();
    }

    [Fact]
    public void Negotiate_ReportsTheFeedbackTheAnswerConfirmed()
    {
        var h264 = Negotiate().GetByMid("1")!.FindCodec("H264")!;

        h264.Feedback.Should().Equal(
            RtcpFeedback.GoogRemb,
            RtcpFeedback.TransportCc,
            RtcpFeedback.CcmFir,
            RtcpFeedback.Nack,
            RtcpFeedback.NackPli);
        h264.SupportsFeedback(RtcpFeedback.NackPli).Should().BeTrue();
    }

    [Fact]
    public void Negotiate_FindCodecMatchesEncodingNameCaseInsensitively()
    {
        var audio = Negotiate().GetByMid("0")!;

        audio.FindCodec("OPUS")!.PayloadType.Should().Be(111);
        audio.FindCodec("VP8").Should().BeNull();
    }

    [Fact]
    public void Negotiate_ReportsRemoteIceCredentials()
    {
        var audio = Negotiate().GetByMid("0")!;

        audio.IceUfrag.Should().Be("4ZcD");
        audio.IcePwd.Should().Be("2/1muCWoOi3uLifh0NuRHlZ6cKr");
        audio.IceOptions.Should().Equal("trickle");
        audio.SupportsTrickleIce.Should().BeTrue();
    }

    [Fact]
    public void Negotiate_ReportsRemoteFingerprintAndSetup()
    {
        var video = Negotiate().GetByMid("1")!;

        video.Fingerprint.Should().Be(new SdpFingerprint("sha-256", AnswerFingerprint));
        video.Setup.Should().Be(SdpSetupRole.Active);
        video.LocalSetup.Should().Be(SdpSetupRole.Passive);
    }

    [Fact]
    public void Negotiate_FallsBackToSessionLevelIceAndFingerprint()
    {
        var answer = Answer();
        var session = answer;
        session.IceUfrag = "sess";
        session.IcePwd = "sessionpassword012345678";
        session.Fingerprint = new SdpFingerprint("sha-256", "AA:BB");
        session.Setup = SdpSetupRole.Passive;
        foreach (var media in answer.MediaDescriptions)
        {
            media.RemoveAttributes(SdpAttributeNames.IceUfrag);
            media.RemoveAttributes(SdpAttributeNames.IcePwd);
            media.RemoveAttributes(SdpAttributeNames.IceOptions);
            media.RemoveAttributes(SdpAttributeNames.Fingerprint);
            media.RemoveAttributes(SdpAttributeNames.Setup);
        }

        var audio = SdpNegotiator.Negotiate(Offer(), answer).GetByMid("0")!;

        audio.IceUfrag.Should().Be("sess");
        audio.IcePwd.Should().Be("sessionpassword012345678");
        audio.Fingerprint!.Value.Should().Be("AA:BB");
        audio.Setup.Should().Be(SdpSetupRole.Passive);
        audio.IceOptions.Should().BeEmpty();
    }

    [Fact]
    public void Negotiate_ReportsRtcpMuxAndReducedSize()
    {
        var audio = Negotiate().GetByMid("0")!;

        audio.RtcpMux.Should().BeTrue();
        audio.RtcpReducedSize.Should().BeTrue();
    }

    [Fact]
    public void Negotiate_ReportsHeaderExtensions()
    {
        var video = Negotiate().GetByMid("1")!;

        video.HeaderExtensions.Should().HaveCount(4);
        video.HeaderExtensions.Select(e => e.Id).Should().Equal(14, 2, 13, 3);
    }

    [Fact]
    public void Negotiate_RecvOnlyAnswerCarriesNoSsrcs()
    {
        var video = Negotiate().GetByMid("1")!;

        video.Ssrcs.Should().BeEmpty();
        video.Cname.Should().BeNull();
        video.Msid.Should().BeNull();
    }

    [Fact]
    public void Negotiate_ReportsSsrcsWhenTheAnswerSends()
    {
        var answer = Answer();
        var video = answer.MediaDescriptions[1];
        video.Direction = MediaDirection.SendRecv;
        video.AddSsrcAttribute(99u, "cname", "remote-cname");
        video.Msid = new SdpMsid("remote-stream", "remote-track");

        var negotiated = SdpNegotiator.Negotiate(Offer(), answer).GetByMid("1")!;

        negotiated.Ssrcs.Should().Equal(99u);
        negotiated.Cname.Should().Be("remote-cname");
        negotiated.Msid.Should().Be(new SdpMsid("remote-stream", "remote-track"));
        negotiated.Direction.Should().Be(MediaDirection.SendRecv);
    }

    [Fact]
    public void Negotiate_ReportsSctpParameters()
    {
        var application = Negotiate().GetByMid("2")!;

        application.SctpPort.Should().Be(5000);
        application.MaxMessageSize.Should().Be(262144);
        application.Codecs.Should().BeEmpty();
    }

    [Fact]
    public void Negotiate_TricklingAnswerCarriesNoCandidates()
    {
        var audio = Negotiate().GetByMid("0")!;

        audio.Candidates.Should().BeEmpty();
        audio.EndOfCandidates.Should().BeFalse();
    }

    [Fact]
    public void Negotiate_ReportsCandidatesWhenTheAnswerCarriesThem()
    {
        var answer = Answer();
        answer.MediaDescriptions[0].AddCandidate("1 1 UDP 2122252543 192.0.2.9 51234 typ host");
        answer.MediaDescriptions[0].EndOfCandidates = true;

        var audio = SdpNegotiator.Negotiate(Offer(), answer).GetByMid("0")!;

        audio.Candidates.Should().Equal("1 1 UDP 2122252543 192.0.2.9 51234 typ host");
        audio.EndOfCandidates.Should().BeTrue();
    }

    [Fact]
    public void Negotiate_HandlesARejectedMSection()
    {
        var answer = Answer();
        answer.MediaDescriptions[1].Port = 0;

        var result = SdpNegotiator.Negotiate(Offer(), answer);
        var video = result.GetByMid("1")!;

        video.IsRejected.Should().BeTrue();
        video.Direction.Should().Be(MediaDirection.Inactive);
        video.Codecs.Should().BeEmpty();
        video.CanSend.Should().BeFalse();
        result.ActiveMedia.Select(m => m.Mid).Should().Equal("0", "2");
        result.IsBundled.Should().BeFalse();
    }

    [Fact]
    public void Negotiate_ExposesTheUnderlyingDescriptions()
    {
        var result = Negotiate();

        result.Offer.MediaDescriptions.Should().HaveCount(3);
        result.Answer.Origin.SessionId.Should().Be("1092376891452871093");
        result.Media[0].Offered.Media.Should().Be("audio");
        result.Media[0].Answered.Media.Should().Be("audio");
    }

    [Fact]
    public void GetByMediaType_FindsTheFirstMatchingSection()
    {
        var result = Negotiate();

        result.GetByMediaType("video")!.Mid.Should().Be("1");
        result.GetByMediaType("text").Should().BeNull();
    }

    [Fact]
    public void GetByMid_ReturnsNullForAnUnknownMid()
    {
        Negotiate().GetByMid("nope").Should().BeNull();
    }

    [Fact]
    public void Interpret_SkipsValidationForBestEffortReads()
    {
        var answer = Answer();
        answer.MediaDescriptions.RemoveAt(2);

        var result = SdpNegotiator.Interpret(Offer(), answer);

        result.Media.Should().HaveCount(2);
    }

    [Fact]
    public void Negotiate_FallsBackToTheOffersRtpmapWhenTheAnswerOmitsIt()
    {
        var answer = Answer();
        answer.MediaDescriptions[0].RemoveAttributes(SdpAttributeNames.RtpMap);
        answer.MediaDescriptions[0].RemoveAttributes(SdpAttributeNames.Fmtp);

        var audio = SdpNegotiator.Negotiate(Offer(), answer).GetByMid("0")!;

        audio.Codecs.Should().ContainSingle();
        audio.Codecs[0].RtpMap.Should().Be(new RtpMap(111, "opus", 48000, 2));
        audio.Codecs[0].Fmtp.Should().Be("minptime=10;useinbandfec=1");
    }

    [Fact]
    public void Validate_NullArgumentsThrow()
    {
        var withNullOffer = () => SdpNegotiator.Validate(null!, Answer());
        var withNullAnswer = () => SdpNegotiator.Validate(Offer(), null!);

        withNullOffer.Should().Throw<ArgumentNullException>();
        withNullAnswer.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void ThrowIfInvalid_IsANoOpForAValidResult()
    {
        var result = SdpNegotiator.Validate(Offer(), Answer());

        var act = result.ThrowIfInvalid;

        act.Should().NotThrow();
    }
}
