using FluentAssertions;
using Xunit;

namespace Keryx.Sdp.Tests;

public class SdpRidTests
{
    [Theory]
    [InlineData("hi send", "hi", RidDirection.Send)]
    [InlineData("lo recv", "lo", RidDirection.Recv)]
    [InlineData("0 send", "0", RidDirection.Send)]
    public void TryParse_ReadsIdAndDirection(string value, string id, RidDirection direction)
    {
        SdpRid.TryParse(value, out var rid).Should().BeTrue();

        rid!.Id.Should().Be(id);
        rid.Direction.Should().Be(direction);
        rid.Restrictions.Should().BeEmpty();
        rid.ToAttributeValue().Should().Be(value);
    }

    [Fact]
    public void TryParse_ReadsRestrictionsInOrder()
    {
        SdpRid.TryParse("hi send pt=96,97;max-width=1280;max-height=720", out var rid).Should().BeTrue();

        rid!.Id.Should().Be("hi");
        rid.Direction.Should().Be(RidDirection.Send);
        rid.Restrictions.Should().Equal(
            new SdpRidRestriction("pt", "96,97"),
            new SdpRidRestriction("max-width", "1280"),
            new SdpRidRestriction("max-height", "720"));
    }

    [Fact]
    public void ToString_RoundTripsThroughTryParse()
    {
        const string value = "q send max-width=640;max-fps=15";
        SdpRid.TryParse(value, out var rid).Should().BeTrue();

        rid!.ToString().Should().Be("a=rid:" + value);
        SdpRid.TryParse(rid.ToAttributeValue(), out var again).Should().BeTrue();
        again!.ToAttributeValue().Should().Be(rid.ToAttributeValue());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("hi")]                 // no direction
    [InlineData("hi sideways")]        // invalid direction
    [InlineData("bad id send")]        // space in id splits to invalid direction 'id'
    [InlineData("bad!id send")]        // illegal id character
    public void TryParse_RejectsMalformedInput(string? value)
    {
        SdpRid.TryParse(value, out var rid).Should().BeFalse();
        rid.Should().BeNull();
    }

    [Fact]
    public void IsValidId_RejectsOverlongIdentifiers()
    {
        SdpRid.IsValidId(new string('a', 255)).Should().BeTrue();
        SdpRid.IsValidId(new string('a', 256)).Should().BeFalse();
        SdpRid.IsValidId(string.Empty).Should().BeFalse();
    }
}
