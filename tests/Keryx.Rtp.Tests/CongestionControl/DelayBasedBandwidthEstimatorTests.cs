using FluentAssertions;
using Keryx.Rtp.CongestionControl;
using Xunit;

namespace Keryx.Rtp.Tests.CongestionControl;

/// <summary>
/// Drives the delay-based estimator with synthetic transport-cc feedback (no network): it must ramp
/// the target up while one-way delay is steady and back it off once queuing delay grows, then recover.
/// </summary>
public class DelayBasedBandwidthEstimatorTests
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
        var time = new TestTimeProvider();
        var history = new SendTimeHistory();
        var estimator = new DelayBasedBandwidthEstimator(Options, time);
        var start = estimator.BitrateBitsPerSecond;

        long send = 0;
        long arrival = 5_000_000;
        ushort seq = 0;
        for (var round = 0; round < 12; round++)
        {
            var feedback = SyntheticFeedback.Burst(
                seq, 30, send, arrival,
                sendSpacingMs: 5, arrivalSpacingMs: 5, PacketSize, history.Add,
                out send, out arrival);
            time.Advance(TimeSpan.FromMilliseconds(200));
            estimator.ProcessFeedback(feedback, history);
            seq += 30;
        }

        estimator.Usage.Should().Be(BandwidthUsage.Normal);
        estimator.BitrateBitsPerSecond.Should().BeGreaterThan(start);
    }

    [Fact]
    public void Backs_off_when_queuing_delay_grows()
    {
        var time = new TestTimeProvider();
        var history = new SendTimeHistory();
        var estimator = new DelayBasedBandwidthEstimator(Options, time);
        var start = estimator.BitrateBitsPerSecond;

        // Arrivals spread faster than sends: one-way delay climbs ~3 ms per packet.
        var feedback = SyntheticFeedback.Burst(
            0, 60, firstSendMicroseconds: 0, firstArrivalMicroseconds: 5_000_000,
            sendSpacingMs: 5, arrivalSpacingMs: 8, PacketSize, history.Add,
            out _, out _);
        time.Advance(TimeSpan.FromMilliseconds(200));
        estimator.ProcessFeedback(feedback, history);

        estimator.Usage.Should().Be(BandwidthUsage.Overusing);
        estimator.BitrateBitsPerSecond.Should().BeLessThan(start);
    }

    [Fact]
    public void Recovers_to_normal_once_delay_stops_growing()
    {
        var time = new TestTimeProvider();
        var history = new SendTimeHistory();
        var estimator = new DelayBasedBandwidthEstimator(Options, time);

        long send = 0;
        long arrival = 5_000_000;
        var growing = SyntheticFeedback.Burst(
            0, 60, send, arrival, sendSpacingMs: 5, arrivalSpacingMs: 8, PacketSize, history.Add,
            out send, out arrival);
        time.Advance(TimeSpan.FromMilliseconds(200));
        estimator.ProcessFeedback(growing, history);
        estimator.Usage.Should().Be(BandwidthUsage.Overusing);
        var backedOff = estimator.BitrateBitsPerSecond;

        // Delay now steady again; the detector should clear and the rate stop falling.
        for (var round = 0; round < 4; round++)
        {
            var flat = SyntheticFeedback.Burst(
                (ushort)(60 + (round * 30)), 30, send, arrival,
                sendSpacingMs: 5, arrivalSpacingMs: 5, PacketSize, history.Add,
                out send, out arrival);
            time.Advance(TimeSpan.FromMilliseconds(200));
            estimator.ProcessFeedback(flat, history);
        }

        estimator.Usage.Should().Be(BandwidthUsage.Normal);
        estimator.BitrateBitsPerSecond.Should().BeGreaterThanOrEqualTo(backedOff);
    }
}
