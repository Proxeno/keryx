using FluentAssertions;
using Keryx.Rtp.CongestionControl;
using Xunit;

namespace Keryx.Rtp.Tests.CongestionControl;

/// <summary>Coverage for the loss-based controller's low/mid/high loss rules.</summary>
public class LossBasedBandwidthEstimatorTests
{
    private static CongestionControllerOptions Options() => new()
    {
        StartBitrateBitsPerSecond = 500_000,
        MinBitrateBitsPerSecond = 50_000,
        MaxBitrateBitsPerSecond = 2_000_000,
    };

    [Fact]
    public void Increases_when_loss_is_below_two_percent()
    {
        var estimator = new LossBasedBandwidthEstimator(Options());
        var start = estimator.BitrateBitsPerSecond;

        estimator.Update(0.01);

        estimator.BitrateBitsPerSecond.Should().BeGreaterThan(start);
    }

    [Fact]
    public void Holds_in_the_middle_band()
    {
        var estimator = new LossBasedBandwidthEstimator(Options());
        var start = estimator.BitrateBitsPerSecond;

        estimator.Update(0.05);

        estimator.BitrateBitsPerSecond.Should().Be(start);
    }

    [Fact]
    public void Decreases_when_loss_exceeds_ten_percent()
    {
        var estimator = new LossBasedBandwidthEstimator(Options());
        var start = estimator.BitrateBitsPerSecond;

        estimator.Update(0.20);

        estimator.BitrateBitsPerSecond.Should().Be((long)(start * (1.0 - (0.5 * 0.20))));
    }
}
