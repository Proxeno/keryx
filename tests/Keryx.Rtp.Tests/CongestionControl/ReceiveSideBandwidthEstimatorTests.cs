using FluentAssertions;
using Keryx.Rtp;
using Keryx.Rtp.CongestionControl;
using Xunit;

namespace Keryx.Rtp.Tests.CongestionControl;

/// <summary>
/// Drives the receive-side abs-send-time estimator with synthetic arrivals (no network): it must ramp
/// its estimate up while one-way delay is steady and back it off once queuing delay grows — the same
/// delay-gradient behaviour the send-side estimator has, but fed from abs-send-time rather than
/// transport-cc feedback.
/// </summary>
public class ReceiveSideBandwidthEstimatorTests
{
    private const int PacketSize = 1200;
    private static readonly CongestionControllerOptions Options = new()
    {
        StartBitrateBitsPerSecond = 300_000,
        MinBitrateBitsPerSecond = 30_000,
        MaxBitrateBitsPerSecond = 5_000_000,
    };

    [Fact]
    public void Ramps_up_while_one_way_delay_is_steady()
    {
        var estimator = new ReceiveSideBandwidthEstimator(Options);
        var start = estimator.BitrateBitsPerSecond;

        long send = 0;
        long arrival = 5_000_000;
        for (var round = 0; round < 12; round++)
        {
            FeedRun(estimator, 60, ref send, ref arrival, sendSpacingUs: 5_000, arrivalSpacingUs: 5_000);
        }

        estimator.Usage.Should().Be(BandwidthUsage.Normal);
        estimator.BitrateBitsPerSecond.Should().BeGreaterThan(start);
    }

    [Fact]
    public void Backs_off_when_queuing_delay_grows()
    {
        var estimator = new ReceiveSideBandwidthEstimator(Options);
        var start = estimator.BitrateBitsPerSecond;

        // Arrivals spread faster than sends: one-way delay climbs ~3 ms per packet.
        long send = 0;
        long arrival = 5_000_000;
        FeedRun(estimator, 60, ref send, ref arrival, sendSpacingUs: 5_000, arrivalSpacingUs: 8_000);

        estimator.Usage.Should().Be(BandwidthUsage.Overusing);
        estimator.BitrateBitsPerSecond.Should().BeLessThan(start);
    }

    [Fact]
    public void The_estimate_stays_within_the_configured_clamps()
    {
        var estimator = new ReceiveSideBandwidthEstimator(Options);

        long send = 0;
        long arrival = 5_000_000;
        for (var round = 0; round < 8; round++)
        {
            FeedRun(estimator, 60, ref send, ref arrival, sendSpacingUs: 5_000, arrivalSpacingUs: 5_000);
        }

        estimator.BitrateBitsPerSecond.Should().BeInRange(
            Options.MinBitrateBitsPerSecond, Options.MaxBitrateBitsPerSecond);
    }

    private static void FeedRun(
        ReceiveSideBandwidthEstimator estimator,
        int count,
        ref long send,
        ref long arrival,
        long sendSpacingUs,
        long arrivalSpacingUs)
    {
        for (var i = 0; i < count; i++)
        {
            var absSendTime = AbsoluteSendTimeExtension.FromMicroseconds(send);
            estimator.OnPacketReceived(absSendTime, arrival, PacketSize);
            send += sendSpacingUs;
            arrival += arrivalSpacingUs;
        }
    }
}
