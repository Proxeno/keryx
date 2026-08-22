using FluentAssertions;
using Xunit;

namespace Keryx.Sdp.Tests;

public class SdpSimulcastTests
{
    [Fact]
    public void TryParse_ReadsSendListOfSimpleStreams()
    {
        SdpSimulcast.TryParse("send hi;mid;lo", out var simulcast).Should().BeTrue();

        simulcast!.Send.Should().HaveCount(3);
        simulcast.Recv.Should().BeEmpty();
        simulcast.Send[0].Alternatives.Should().ContainSingle().Which.Id.Should().Be("hi");
        simulcast.Send[2].Alternatives.Should().ContainSingle().Which.Id.Should().Be("lo");
        simulcast.ToAttributeValue().Should().Be("send hi;mid;lo");
    }

    [Fact]
    public void TryParse_ReadsAlternativesAndPausedMarker()
    {
        SdpSimulcast.TryParse("send hi,mid;~lo", out var simulcast).Should().BeTrue();

        simulcast!.Send.Should().HaveCount(2);
        simulcast.Send[0].Alternatives.Should().Equal(
            new SdpSimulcastAlternative("hi"),
            new SdpSimulcastAlternative("mid"));
        simulcast.Send[1].Alternatives.Should().ContainSingle()
            .Which.Should().Be(new SdpSimulcastAlternative("lo", Paused: true));
        simulcast.ToAttributeValue().Should().Be("send hi,mid;~lo");
    }

    [Fact]
    public void TryParse_ReadsBothDirections()
    {
        SdpSimulcast.TryParse("send hi;lo recv q", out var simulcast).Should().BeTrue();

        simulcast!.Send.Should().HaveCount(2);
        simulcast.Recv.Should().ContainSingle().Which.Alternatives[0].Id.Should().Be("q");
        simulcast.ToAttributeValue().Should().Be("send hi;lo recv q");
    }

    [Fact]
    public void Reversed_SwapsSendAndRecv()
    {
        SdpSimulcast.TryParse("send hi;mid;lo", out var offer).Should().BeTrue();

        var answer = offer!.Reversed();
        answer.Send.Should().BeEmpty();
        answer.Recv.Should().HaveCount(3);
        answer.ToAttributeValue().Should().Be("recv hi;mid;lo");
    }

    [Fact]
    public void ToString_RoundTripsThroughTryParse()
    {
        const string value = "send hi,mid;lo recv ~q";
        SdpSimulcast.TryParse(value, out var simulcast).Should().BeTrue();

        simulcast!.ToString().Should().Be("a=simulcast:" + value);
        SdpSimulcast.TryParse(simulcast.ToAttributeValue(), out var again).Should().BeTrue();
        again!.ToAttributeValue().Should().Be(simulcast.ToAttributeValue());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("send")]                 // direction with no list
    [InlineData("sideways hi")]          // unknown direction token
    [InlineData("send hi recv")]         // trailing direction with no list
    [InlineData("send hi send lo")]      // duplicate direction
    public void TryParse_RejectsMalformedInput(string? value)
    {
        SdpSimulcast.TryParse(value, out var simulcast).Should().BeFalse();
        simulcast.Should().BeNull();
    }
}
