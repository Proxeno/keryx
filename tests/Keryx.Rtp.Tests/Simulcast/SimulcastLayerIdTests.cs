using FluentAssertions;
using Keryx.Rtp.Simulcast;
using Xunit;

namespace Keryx.Rtp.Tests.Simulcast;

public class SimulcastLayerIdTests
{
    [Fact]
    public void Parse_And_ToString_RoundTrip()
    {
        var id = SimulcastLayerId.Parse("hi");
        id.Length.Should().Be(2);
        id.IsEmpty.Should().BeFalse();
        id.ToString().Should().Be("hi");
    }

    [Fact]
    public void Equality_IsByValue()
    {
        SimulcastLayerId.Parse("mid").Should().Be(SimulcastLayerId.Parse("mid"));
        (SimulcastLayerId.Parse("hi") == SimulcastLayerId.Parse("lo")).Should().BeFalse();
        SimulcastLayerId.Parse("hi").GetHashCode().Should().Be(SimulcastLayerId.Parse("hi").GetHashCode());
    }

    [Fact]
    public void Matches_ComparesAgainstRawBytes()
    {
        var id = SimulcastLayerId.Parse("q");
        id.Matches("q"u8).Should().BeTrue();
        id.Matches("h"u8).Should().BeFalse();
        id.Matches("qq"u8).Should().BeFalse();
    }

    [Fact]
    public void TryCreate_RejectsOutOfRangeAndNonPrintable()
    {
        SimulcastLayerId.TryCreate(default, out _).Should().BeFalse();
        SimulcastLayerId.TryCreate(new byte[SimulcastLayerId.MaxLength + 1], out _).Should().BeFalse();
        SimulcastLayerId.TryCreate([0x00, 0x01], out _).Should().BeFalse();
    }

    [Fact]
    public void DefaultValue_IsEmpty()
    {
        default(SimulcastLayerId).IsEmpty.Should().BeTrue();
        default(SimulcastLayerId).ToString().Should().BeEmpty();
    }
}
