using FluentAssertions;
using Xunit;

namespace Keryx.Sdp.Tests;

public class RtcpFeedbackTests
{
    [Theory]
    [InlineData("96 nack pli", 96, "nack", "pli")]
    [InlineData("96 ccm fir", 96, "ccm", "fir")]
    [InlineData("111 transport-cc", 111, "transport-cc", null)]
    [InlineData("96 goog-remb", 96, "goog-remb", null)]
    [InlineData("96 nack", 96, "nack", null)]
    public void TryParse_ReadsPayloadTypeSpecificLines(string value, int pt, string type, string? parameter)
    {
        RtcpFeedbackEntry.TryParse(value, out var entry).Should().BeTrue();

        entry!.PayloadType.Should().Be(pt);
        entry.IsWildcard.Should().BeFalse();
        entry.Feedback.Should().Be(new RtcpFeedback(type, parameter));
        entry.ToAttributeValue().Should().Be(value);
    }

    [Fact]
    public void TryParse_ReadsWildcardLines()
    {
        RtcpFeedbackEntry.TryParse("* transport-cc", out var entry).Should().BeTrue();

        entry!.PayloadType.Should().BeNull();
        entry.IsWildcard.Should().BeTrue();
        entry.AppliesTo(96).Should().BeTrue();
        entry.AppliesTo(111).Should().BeTrue();
        entry.ToAttributeValue().Should().Be("* transport-cc");
        entry.ToString().Should().Be("a=rtcp-fb:* transport-cc");
    }

    [Fact]
    public void AppliesTo_MatchesOnlyTheNamedPayloadType()
    {
        var entry = new RtcpFeedbackEntry(96, RtcpFeedback.NackPli);

        entry.AppliesTo(96).Should().BeTrue();
        entry.AppliesTo(97).Should().BeFalse();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("96")]
    [InlineData("abc nack")]
    public void TryParse_RejectsMalformedValues(string? value)
    {
        RtcpFeedbackEntry.TryParse(value, out var entry).Should().BeFalse();
        entry.Should().BeNull();
    }

    [Fact]
    public void WellKnownCapabilities_RenderAsExpected()
    {
        RtcpFeedback.Nack.ToString().Should().Be("nack");
        RtcpFeedback.NackPli.ToString().Should().Be("nack pli");
        RtcpFeedback.CcmFir.ToString().Should().Be("ccm fir");
        RtcpFeedback.TransportCc.ToString().Should().Be("transport-cc");
        RtcpFeedback.GoogRemb.ToString().Should().Be("goog-remb");
    }

    [Fact]
    public void BareNackAndNackPliAreDistinctCapabilities()
    {
        RtcpFeedback.Nack.Should().NotBe(RtcpFeedback.NackPli);
    }

    [Fact]
    public void GetRtcpFeedback_ReturnsPayloadTypeSpecificCapabilitiesInOrder()
    {
        var video = SessionDescription.Parse(SdpTestData.ChromeOffer).MediaDescriptions[1];

        video.GetRtcpFeedback(102).Should().Equal(
            RtcpFeedback.GoogRemb,
            RtcpFeedback.TransportCc,
            RtcpFeedback.CcmFir,
            RtcpFeedback.Nack,
            RtcpFeedback.NackPli);
        video.GetRtcpFeedback(97).Should().BeEmpty();
    }

    [Fact]
    public void GetRtcpFeedback_IncludesWildcardLinesWithoutDuplicating()
    {
        var media = new MediaDescription("video", 9, "UDP/TLS/RTP/SAVPF", "96");
        media.AddRtcpFeedback(null, RtcpFeedback.TransportCc);
        media.AddRtcpFeedback(96, RtcpFeedback.NackPli);
        media.AddRtcpFeedback(96, RtcpFeedback.TransportCc);

        media.GetRtcpFeedback(96).Should().Equal(RtcpFeedback.TransportCc, RtcpFeedback.NackPli);
        media.GetRtcpFeedback(99).Should().Equal(RtcpFeedback.TransportCc);
    }

    [Fact]
    public void AddRtcpFeedback_SerializesBothForms()
    {
        var media = new MediaDescription("video", 9, "UDP/TLS/RTP/SAVPF", "96");
        media.AddRtcpFeedback(96, RtcpFeedback.CcmFir);
        media.AddRtcpFeedback(null, RtcpFeedback.GoogRemb);

        media.ToSdpString().Should().Contain("a=rtcp-fb:96 ccm fir\r\na=rtcp-fb:* goog-remb\r\n");
    }

    [Fact]
    public void GetRtcpFeedbackEntries_SkipsMalformedLines()
    {
        var media = new MediaDescription("video", 9, "UDP/TLS/RTP/SAVPF", "96");
        media.AddAttribute(SdpAttributeNames.RtcpFeedback, "96 nack pli");
        media.AddAttribute(SdpAttributeNames.RtcpFeedback, "garbage");

        media.GetRtcpFeedbackEntries().Should().ContainSingle();
    }

    [Fact]
    public void AddRtcpFeedback_NullFeedback_Throws()
    {
        var media = new MediaDescription();

        var act = () => media.AddRtcpFeedback(96, null!);

        act.Should().Throw<ArgumentNullException>();
    }
}
