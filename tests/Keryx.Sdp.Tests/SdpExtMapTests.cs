using FluentAssertions;
using Xunit;

namespace Keryx.Sdp.Tests;

public class SdpExtMapTests
{
    [Fact]
    public void TransportWideCc_MapsTheIdToTheDraftUri()
    {
        var extMap = SdpExtMap.TransportWideCc(3);

        extMap.Id.Should().Be(3);
        extMap.Uri.Should().Be(
            "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01");
        extMap.IsTransportWideCc.Should().BeTrue();
        extMap.ToString().Should().Be(
            "a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01");
    }

    [Fact]
    public void TransportWideCc_RoundTripsThroughTheParser()
    {
        var rendered = SdpExtMap.TransportWideCc(5).ToAttributeValue();

        SdpExtMap.TryParse(rendered, out var parsed).Should().BeTrue();
        parsed!.Id.Should().Be(5);
        parsed.IsTransportWideCc.Should().BeTrue();
    }

    [Fact]
    public void IsTransportWideCc_IsFalseForOtherExtensions()
    {
        new SdpExtMap(3, "urn:ietf:params:rtp-hdrext:sdes:mid").IsTransportWideCc.Should().BeFalse();
    }
}
