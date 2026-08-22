using FluentAssertions;
using Xunit;

namespace Keryx.Sdp.Tests;

public class TypedAccessorTests
{
    private static SessionDescription Offer() => SessionDescription.Parse(SdpTestData.ChromeOffer);

    private static SessionDescription Answer() => SessionDescription.Parse(SdpTestData.ChromeAnswer);

    [Fact]
    public void BundleGroup_IsRead()
    {
        Offer().GetBundleGroup().Should().Equal("0", "1", "2");
    }

    [Fact]
    public void Groups_AreRead()
    {
        var groups = Offer().GetGroups();

        groups.Should().ContainSingle();
        groups[0].Semantics.Should().Be("BUNDLE");
        groups[0].ToAttributeValue().Should().Be("BUNDLE 0 1 2");
    }

    [Fact]
    public void SetBundleGroup_ReplacesExistingGroup()
    {
        var sdp = Offer();

        sdp.SetBundleGroup(["0", "2"]);

        sdp.GetBundleGroup().Should().Equal("0", "2");
        sdp.FindAttributes(SdpAttributeNames.Group).Should().ContainSingle();
    }

    [Fact]
    public void SetBundleGroup_WithNoMids_RemovesTheGroup()
    {
        var sdp = Offer();

        sdp.SetBundleGroup([]);

        sdp.GetBundleGroup().Should().BeEmpty();
        sdp.HasAttribute(SdpAttributeNames.Group).Should().BeFalse();
    }

    [Fact]
    public void MsidSemantic_KeepsRawValueAndParsesStreamIds()
    {
        Offer().GetWmsStreamIds().Should().Equal("9e1ba9e2-c1f5-4f7a-9a0c-1b1a9f0c1d2e");
        Answer().GetWmsStreamIds().Should().BeEmpty();
    }

    [Fact]
    public void SetWmsStreamIds_UsesChromeLeadingSpace()
    {
        var sdp = new SessionDescription();

        sdp.SetWmsStreamIds("stream-a");

        sdp.MsidSemantic.Should().Be(" WMS stream-a");
        sdp.ToSdpString().Should().Contain("a=msid-semantic: WMS stream-a\r\n");
    }

    [Fact]
    public void ExtMapAllowMixed_IsRead()
    {
        Offer().ExtMapAllowMixed.Should().BeTrue();
        new SessionDescription().ExtMapAllowMixed.Should().BeFalse();
    }

    [Fact]
    public void Mid_IsRead()
    {
        Offer().MediaDescriptions.Select(m => m.Mid).Should().Equal("0", "1", "2");
    }

    [Fact]
    public void GetMediaByMid_FindsTheSection()
    {
        Offer().GetMediaByMid("1")!.Media.Should().Be("video");
        Offer().GetMediaByMid("nope").Should().BeNull();
    }

    [Fact]
    public void IceCredentialsAndOptions_AreRead()
    {
        var audio = Offer().MediaDescriptions[0];

        audio.IceUfrag.Should().Be("hT7a");
        audio.IcePwd.Should().Be("XKQVjJ9wRVWy3zNsL6mQ0pTb");
        audio.GetIceOptions().Should().Equal("trickle");
        audio.SupportsTrickleIce.Should().BeTrue();
    }

    [Fact]
    public void IceCredentials_AreWritable()
    {
        var media = new MediaDescription();

        media.IceUfrag = "abcd";
        media.IcePwd = "0123456789abcdefghijklmn";
        media.SetIceOptions("trickle", "renomination");

        media.GetIceOptions().Should().Equal("trickle", "renomination");
        media.IceUfrag = null;
        media.IceUfrag.Should().BeNull();
        media.HasAttribute(SdpAttributeNames.IceUfrag).Should().BeFalse();
    }

    [Fact]
    public void SetIceOptions_WithNoTokens_RemovesTheAttribute()
    {
        var media = Offer().MediaDescriptions[0];

        media.SetIceOptions();

        media.HasAttribute(SdpAttributeNames.IceOptions).Should().BeFalse();
        media.SupportsTrickleIce.Should().BeFalse();
    }

    [Fact]
    public void Fingerprint_IsParsed()
    {
        var fingerprint = Offer().MediaDescriptions[0].Fingerprint!;

        fingerprint.Algorithm.Should().Be("sha-256");
        fingerprint.Value.Should().Be(SdpTestData.Fingerprint);
        fingerprint.ToAttributeValue().Should().Be("sha-256 " + SdpTestData.Fingerprint);
    }

    [Fact]
    public void Fingerprint_NormalisesToUppercase()
    {
        SdpFingerprint.TryParse("sha-256 ab:cd:ef", out var fingerprint).Should().BeTrue();

        fingerprint!.Value.Should().Be("AB:CD:EF");
    }

    [Fact]
    public void Fingerprint_FromHash_RendersColonSeparatedUppercaseHex()
    {
        var fingerprint = SdpFingerprint.FromHash("sha-256", [0xDE, 0xAD, 0xBE, 0xEF]);

        fingerprint.Value.Should().Be("DE:AD:BE:EF");
        fingerprint.ToString().Should().Be("a=fingerprint:sha-256 DE:AD:BE:EF");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("sha-256")]
    public void Fingerprint_TryParse_RejectsIncompleteValues(string? value)
    {
        SdpFingerprint.TryParse(value, out var fingerprint).Should().BeFalse();
        fingerprint.Should().BeNull();
    }

    [Fact]
    public void Setup_IsReadAndWritten()
    {
        var media = Offer().MediaDescriptions[0];
        media.Setup.Should().Be(SdpSetupRole.ActPass);

        media.Setup = SdpSetupRole.Passive;
        media.GetAttributeValue(SdpAttributeNames.Setup).Should().Be("passive");

        media.Setup = null;
        media.Setup.Should().BeNull();
    }

    [Theory]
    [InlineData(SdpSetupRole.Active, SdpSetupRole.Passive)]
    [InlineData(SdpSetupRole.Passive, SdpSetupRole.Active)]
    [InlineData(SdpSetupRole.ActPass, SdpSetupRole.Active)]
    public void Setup_ComplementPicksTheOppositeRole(SdpSetupRole remote, SdpSetupRole expected)
    {
        remote.Complement().Should().Be(expected);
    }

    [Fact]
    public void RtcpMuxAndReducedSize_AreRead()
    {
        var audio = Offer().MediaDescriptions[0];

        audio.RtcpMux.Should().BeTrue();
        audio.RtcpReducedSize.Should().BeTrue();
        audio.Rtcp.Should().Be("9 IN IP4 0.0.0.0");
    }

    [Fact]
    public void RtcpMux_IsWritable()
    {
        var media = new MediaDescription();

        media.RtcpMux = true;
        media.Attributes.Should().ContainSingle(a => a.Name == "rtcp-mux" && a.IsFlag);

        media.RtcpMux = false;
        media.RtcpMux.Should().BeFalse();
        media.Attributes.Should().BeEmpty();
    }

    [Fact]
    public void Direction_IsRead()
    {
        Offer().MediaDescriptions[0].Direction.Should().Be(MediaDirection.SendRecv);
        Answer().MediaDescriptions[0].Direction.Should().Be(MediaDirection.RecvOnly);
        Answer().MediaDescriptions[2].Direction.Should().BeNull();
        Answer().MediaDescriptions[2].DirectionOrDefault.Should().Be(MediaDirection.SendRecv);
    }

    [Fact]
    public void Direction_SetReplacesInPlaceWithoutDuplicating()
    {
        var media = Offer().MediaDescriptions[0];
        var index = media.Attributes.ToList().FindIndex(a => a.Name == "sendrecv");

        media.Direction = MediaDirection.SendOnly;

        media.Attributes[index].Name.Should().Be("sendonly");
        media.Attributes.Count(a => SdpDirection.TryParse(a.Name, out _)).Should().Be(1);
    }

    [Fact]
    public void Direction_SetNullRemovesTheAttribute()
    {
        var media = Offer().MediaDescriptions[0];

        media.Direction = null;

        media.Direction.Should().BeNull();
        media.Attributes.Any(a => SdpDirection.TryParse(a.Name, out _)).Should().BeFalse();
    }

    [Fact]
    public void Direction_SetCollapsesDuplicateDirectionAttributes()
    {
        var media = new MediaDescription();
        media.AddAttribute("sendrecv");
        media.AddAttribute("mid", "0");
        media.AddAttribute("recvonly");

        media.Direction = MediaDirection.Inactive;

        media.Attributes.Select(a => a.Name).Should().Equal("inactive", "mid");
    }

    [Theory]
    [InlineData(MediaDirection.SendRecv, true, true)]
    [InlineData(MediaDirection.SendOnly, true, false)]
    [InlineData(MediaDirection.RecvOnly, false, true)]
    [InlineData(MediaDirection.Inactive, false, false)]
    public void Direction_SendsAndReceivesFlags(MediaDirection direction, bool sends, bool receives)
    {
        direction.Sends().Should().Be(sends);
        direction.Receives().Should().Be(receives);
        SdpDirection.FromFlags(sends, receives).Should().Be(direction);
    }

    [Fact]
    public void Direction_ReverseMirrorsSendAndReceive()
    {
        MediaDirection.SendOnly.Reverse().Should().Be(MediaDirection.RecvOnly);
        MediaDirection.RecvOnly.Reverse().Should().Be(MediaDirection.SendOnly);
        MediaDirection.SendRecv.Reverse().Should().Be(MediaDirection.SendRecv);
        MediaDirection.Inactive.Reverse().Should().Be(MediaDirection.Inactive);
    }

    [Fact]
    public void RtpMap_IsReadPerPayloadType()
    {
        var audio = Offer().MediaDescriptions[0];

        audio.GetRtpMap(111).Should().Be(new RtpMap(111, "opus", 48000, 2));
        audio.GetRtpMap(0).Should().Be(new RtpMap(0, "PCMU", 8000));
        audio.GetRtpMap(200).Should().BeNull();
        audio.GetRtpMaps().Should().HaveCount(8);
    }

    [Fact]
    public void RtpMap_SetReplacesTheExistingEntry()
    {
        var media = Offer().MediaDescriptions[0];

        media.SetRtpMap(new RtpMap(111, "opus", 48000, 1));

        media.GetRtpMap(111)!.Channels.Should().Be(1);
        media.GetAttributeValues(SdpAttributeNames.RtpMap).Count(v => v.StartsWith("111 ", StringComparison.Ordinal))
            .Should().Be(1);
    }

    [Fact]
    public void RtpMap_SetAppendsWhenAbsent()
    {
        var media = new MediaDescription("video", 9, "UDP/TLS/RTP/SAVPF", "96");

        media.SetRtpMap(new RtpMap(96, "VP8", 90000));

        media.ToSdpString().Should().Contain("a=rtpmap:96 VP8/90000");
    }

    [Fact]
    public void RtpMap_RendersChannelsOnlyWhenPresent()
    {
        new RtpMap(111, "opus", 48000, 2).ToAttributeValue().Should().Be("111 opus/48000/2");
        new RtpMap(96, "H264", 90000).ToAttributeValue().Should().Be("96 H264/90000");
        new RtpMap(96, "H264", 90000).ToString().Should().Be("a=rtpmap:96 H264/90000");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("111")]
    [InlineData("abc opus/48000")]
    [InlineData("111 opus")]
    [InlineData("111 opus/abc")]
    public void RtpMap_TryParse_RejectsMalformedValues(string? value)
    {
        RtpMap.TryParse(value, out var map).Should().BeFalse();
        map.Should().BeNull();
    }

    [Fact]
    public void Fmtp_IsReadPerPayloadType()
    {
        var video = Offer().MediaDescriptions[1];

        video.GetFmtp(102).Should().Be("level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f");
        video.GetFmtp(97).Should().Be("apt=96");
        video.GetFmtp(999).Should().BeNull();
    }

    [Fact]
    public void Fmtp_IsWritable()
    {
        var media = new MediaDescription("video", 9, "UDP/TLS/RTP/SAVPF", "96");

        media.SetFmtp(96, "apt=95");
        media.SetFmtp(96, "packetization-mode=1");

        media.GetFmtp(96).Should().Be("packetization-mode=1");
        media.GetAttributeValues(SdpAttributeNames.Fmtp).Should().ContainSingle();
    }

    [Fact]
    public void Ssrc_AttributesAreRead()
    {
        var video = Offer().MediaDescriptions[1];

        video.GetSsrcs().Should().Equal(3204773231u, 1245781936u);
        video.GetSsrcCname(3204773231u).Should().Be("JnQ3z0/M0zPjNq2h");
        video.GetSsrcMsid(3204773231u).Should().Be(new SdpMsid(
            "9e1ba9e2-c1f5-4f7a-9a0c-1b1a9f0c1d2e",
            "1d5f8c07-6b9a-4c2e-8f11-7a3d2b4c5e60"));
        video.GetSsrcAttribute(1u, "cname").Should().BeNull();
    }

    [Fact]
    public void SsrcGroup_IsRead()
    {
        var groups = Offer().MediaDescriptions[1].GetSsrcGroups();

        groups.Should().ContainSingle();
        groups[0].Semantics.Should().Be("FID");
        groups[0].Ssrcs.Should().Equal(3204773231u, 1245781936u);
        groups[0].ToString().Should().Be("a=ssrc-group:FID 3204773231 1245781936");
    }

    [Fact]
    public void Ssrc_AddWritesTheAttribute()
    {
        var media = new MediaDescription();

        media.AddSsrcAttribute(42u, "cname", "abc");

        media.ToSdpString().Should().Contain("a=ssrc:42 cname:abc");
        media.GetSsrcCname(42u).Should().Be("abc");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("notanumber cname:x")]
    [InlineData("42")]
    public void Ssrc_TryParse_RejectsMalformedValues(string? value)
    {
        SsrcAttribute.TryParse(value, out var attribute).Should().BeFalse();
        attribute.Should().BeNull();
    }

    [Fact]
    public void Msid_IsReadAndWritten()
    {
        var media = Offer().MediaDescriptions[0];

        media.Msid.Should().Be(new SdpMsid(
            "9e1ba9e2-c1f5-4f7a-9a0c-1b1a9f0c1d2e",
            "6b0c8f3d-2a5e-4c11-9b7d-3f2a1c0e9d84"));

        media.Msid = new SdpMsid("s", "t");
        media.GetAttributeValue(SdpAttributeNames.Msid).Should().Be("s t");

        media.Msid = null;
        media.Msid.Should().BeNull();
    }

    [Fact]
    public void Msid_ParsesStreamOnlyForm()
    {
        SdpMsid.TryParse("stream-only", out var msid).Should().BeTrue();

        msid.Should().Be(new SdpMsid("stream-only"));
        msid!.ToAttributeValue().Should().Be("stream-only");
    }

    [Fact]
    public void ExtMap_IsRead()
    {
        var extMaps = Offer().MediaDescriptions[1].GetExtMaps();

        extMaps.Should().HaveCount(4);
        extMaps[0].Should().Be(new SdpExtMap(14, "urn:ietf:params:rtp-hdrext:toffset"));
        extMaps[3].Uri.Should().Be("urn:ietf:params:rtp-hdrext:sdes:mid");
    }

    [Fact]
    public void ExtMap_ParsesDirectionQualifier()
    {
        SdpExtMap.TryParse("2/sendonly urn:ietf:params:rtp-hdrext:toffset", out var extMap).Should().BeTrue();

        extMap!.Id.Should().Be(2);
        extMap.Direction.Should().Be(MediaDirection.SendOnly);
        extMap.ToAttributeValue().Should().Be("2/sendonly urn:ietf:params:rtp-hdrext:toffset");
    }

    [Fact]
    public void ExtMap_IsWritable()
    {
        var media = new MediaDescription();

        media.AddExtMap(new SdpExtMap(3, "urn:ietf:params:rtp-hdrext:sdes:mid"));

        media.ToSdpString().Should().Contain("a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("urn:only")]
    [InlineData("abc urn:x")]
    public void ExtMap_TryParse_RejectsMalformedValues(string? value)
    {
        SdpExtMap.TryParse(value, out var extMap).Should().BeFalse();
        extMap.Should().BeNull();
    }

    [Fact]
    public void Candidates_AreKeptAsRawStrings()
    {
        var media = new MediaDescription();

        media.AddCandidate("1 1 UDP 2122252543 192.0.2.1 54321 typ host");
        media.EndOfCandidates = true;

        media.GetCandidates().Should().Equal("1 1 UDP 2122252543 192.0.2.1 54321 typ host");
        media.EndOfCandidates.Should().BeTrue();
        media.ToSdpString().Should().Contain("a=candidate:1 1 UDP 2122252543 192.0.2.1 54321 typ host\r\n");
        media.ToSdpString().Should().Contain("a=end-of-candidates\r\n");
    }

    [Fact]
    public void Candidates_AbsentFromATricklingAnswer()
    {
        Answer().MediaDescriptions[0].GetCandidates().Should().BeEmpty();
        Answer().MediaDescriptions[0].EndOfCandidates.Should().BeFalse();
    }

    [Fact]
    public void SctpPortAndMaxMessageSize_AreRead()
    {
        var application = Offer().MediaDescriptions[2];

        application.SctpPort.Should().Be(5000);
        application.MaxMessageSize.Should().Be(262144);
        application.IsRtp.Should().BeFalse();
        application.Formats.Should().Equal("webrtc-datachannel");
        application.GetPayloadTypes().Should().BeEmpty();
    }

    [Fact]
    public void SctpPortAndMaxMessageSize_AreWritable()
    {
        var media = new MediaDescription("application", 9, "UDP/DTLS/SCTP", "webrtc-datachannel");

        media.SctpPort = 5000;
        media.MaxMessageSize = 65536;

        media.ToSdpString().Should().Contain("a=sctp-port:5000\r\na=max-message-size:65536\r\n");

        media.MaxMessageSize = null;
        media.MaxMessageSize.Should().BeNull();
    }

    [Fact]
    public void SetAttribute_ReplacesInPlaceAndRemovesDuplicates()
    {
        var media = new MediaDescription();
        media.AddAttribute("mid", "0");
        media.AddAttribute("rtcp-mux");
        media.AddAttribute("mid", "9");

        media.SetAttribute("mid", "7");

        media.Attributes.Select(a => a.ToAttributeValue()).Should().Equal("mid:7", "rtcp-mux");
    }

    [Fact]
    public void RemoveAttributes_ReturnsTheRemovedCount()
    {
        var media = Offer().MediaDescriptions[1];

        media.RemoveAttributes(SdpAttributeNames.RtcpFeedback).Should().Be(10);
        media.HasAttribute(SdpAttributeNames.RtcpFeedback).Should().BeFalse();
    }

    [Fact]
    public void SdpAttribute_ParsesFlagAndValueForms()
    {
        SdpAttribute.Parse("rtcp-mux").Should().Be(new SdpAttribute("rtcp-mux"));
        SdpAttribute.Parse("mid:0").Should().Be(new SdpAttribute("mid", "0"));
        SdpAttribute.Parse("msid-semantic: WMS x").Should().Be(new SdpAttribute("msid-semantic", " WMS x"));
        SdpAttribute.Parse("rtcp-mux").ToString().Should().Be("a=rtcp-mux");
    }

    [Fact]
    public void SdpOrigin_NewSessionIdIsPositiveAndRandom()
    {
        var first = SdpOrigin.NewSessionId();
        var second = SdpOrigin.NewSessionId();

        ulong.Parse(first, System.Globalization.CultureInfo.InvariantCulture).Should().BeLessThan(1UL << 63);
        first.Should().NotBe(second);
    }
}
