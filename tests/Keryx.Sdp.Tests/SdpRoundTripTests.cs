using FluentAssertions;
using Xunit;

namespace Keryx.Sdp.Tests;

public class SdpRoundTripTests
{
    [Fact]
    public void RoundTrip_ChromeOffer_IsByteIdentical()
    {
        var text = SdpTestData.ChromeOffer;

        SessionDescription.Parse(text).ToSdpString().Should().Be(text);
    }

    [Fact]
    public void RoundTrip_ChromeAnswer_IsByteIdentical()
    {
        var text = SdpTestData.ChromeAnswer;

        SessionDescription.Parse(text).ToSdpString().Should().Be(text);
    }

    [Fact]
    public void RoundTrip_LfInput_ProducesCrlfOutput()
    {
        var result = SessionDescription.Parse(SdpTestData.ChromeAnswerLf).ToSdpString();

        result.Should().Be(SdpTestData.ChromeAnswer);
    }

    [Fact]
    public void Serialize_UsesCrlfExclusively()
    {
        var text = SessionDescription.Parse(SdpTestData.ChromeOffer).ToSdpString();

        text.Replace("\r\n", string.Empty, StringComparison.Ordinal)
            .Should().NotContain("\n").And.NotContain("\r");
        text.Should().EndWith("\r\n");
    }

    [Fact]
    public void Serialize_PreservesMsidSemanticLeadingSpace()
    {
        var sdp = SessionDescription.Parse(SdpTestData.ChromeOffer);

        sdp.MsidSemantic.Should().StartWith(" WMS ");
        sdp.ToSdpString().Should().Contain("a=msid-semantic: WMS 9e1ba9e2-c1f5-4f7a-9a0c-1b1a9f0c1d2e\r\n");
    }

    [Fact]
    public void ToString_MatchesToSdpString()
    {
        var sdp = SessionDescription.Parse(SdpTestData.ChromeAnswer);

        sdp.ToString().Should().Be(sdp.ToSdpString());
    }

    [Fact]
    public void RoundTrip_SurvivesTwoPasses()
    {
        var once = SessionDescription.Parse(SdpTestData.ChromeOffer).ToSdpString();
        var twice = SessionDescription.Parse(once).ToSdpString();

        twice.Should().Be(once);
    }
}
