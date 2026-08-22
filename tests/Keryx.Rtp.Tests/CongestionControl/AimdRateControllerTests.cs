using FluentAssertions;
using Keryx.Rtp.CongestionControl;
using Xunit;

namespace Keryx.Rtp.Tests.CongestionControl;

/// <summary>Coverage for the AIMD rate controller's increase, decrease and clamp behaviour.</summary>
public class AimdRateControllerTests
{
    private static CongestionControllerOptions Options() => new()
    {
        StartBitrateBitsPerSecond = 500_000,
        MinBitrateBitsPerSecond = 100_000,
        MaxBitrateBitsPerSecond = 1_000_000,
        DecreaseFactor = 0.85,
    };

    [Fact]
    public void Decreases_to_beta_times_bitrate_on_overuse()
    {
        var controller = new AimdRateController(Options());

        controller.Update(BandwidthUsage.Overusing, TimeSpan.Zero);

        controller.BitrateBitsPerSecond.Should().Be((long)(0.85 * 500_000));
    }

    [Fact]
    public void Backs_off_to_throughput_when_it_is_the_bottleneck()
    {
        var controller = new AimdRateController(Options());
        controller.SetThroughputEstimate(400_000);

        controller.Update(BandwidthUsage.Overusing, TimeSpan.Zero);

        controller.BitrateBitsPerSecond.Should().Be((long)(0.85 * 400_000));
    }

    [Fact]
    public void Ramps_up_while_normal()
    {
        var controller = new AimdRateController(Options());
        controller.SetThroughputEstimate(2_000_000);
        var start = controller.BitrateBitsPerSecond;

        controller.Update(BandwidthUsage.Normal, TimeSpan.FromSeconds(1));

        controller.BitrateBitsPerSecond.Should().BeGreaterThan(start);
    }

    [Fact]
    public void Holds_while_underusing()
    {
        var controller = new AimdRateController(Options());
        var start = controller.BitrateBitsPerSecond;

        controller.Update(BandwidthUsage.Underusing, TimeSpan.FromSeconds(1));

        controller.BitrateBitsPerSecond.Should().Be(start);
    }

    [Fact]
    public void Clamps_to_the_configured_maximum()
    {
        var controller = new AimdRateController(Options());
        controller.SetThroughputEstimate(10_000_000);

        for (var i = 0; i < 200; i++)
        {
            controller.Update(BandwidthUsage.Normal, TimeSpan.FromSeconds(1));
        }

        controller.BitrateBitsPerSecond.Should().Be(1_000_000);
    }
}
