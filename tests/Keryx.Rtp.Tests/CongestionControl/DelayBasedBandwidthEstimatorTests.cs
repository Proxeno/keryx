using FluentAssertions;
using Keryx.Rtp.CongestionControl;
using Keryx.Rtp.Rtcp;
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

        // Delay now steady again; the detector should clear and the rate stop falling. With the
        // InterArrival grouping stage a steady stretch must span at least a full trendline window of
        // groups (not just packets) before the growth-era samples age out of the fit, so drive 60-packet
        // flat bursts here — matching the ramp burst — rather than the half-window 30-packet bursts.
        for (var round = 0; round < 4; round++)
        {
            var flat = SyntheticFeedback.Burst(
                (ushort)(60 + (round * 60)), 60, send, arrival,
                sendSpacingMs: 5, arrivalSpacingMs: 5, PacketSize, history.Add,
                out send, out arrival);
            time.Advance(TimeSpan.FromMilliseconds(200));
            estimator.ProcessFeedback(flat, history);
        }

        estimator.Usage.Should().Be(BandwidthUsage.Normal);
        estimator.BitrateBitsPerSecond.Should().BeGreaterThanOrEqualTo(backedOff);
    }

    [Fact]
    public void High_packet_rate_jitter_at_steady_delay_does_not_trip_false_overuse()
    {
        // A high packet-rate stream (1 ms send spacing) whose one-way delay is steady on average but
        // carries realistic per-packet arrival jitter (+/-6 ms, zero mean). Fed one sample per packet the
        // old pipeline reads the jitter as a rising trend and falsely declares overuse; the InterArrival
        // grouping stage averages the jitter within ~5 ms bursts, so the grouped estimator stays Normal
        // and keeps ramping.
        var (send, arrival) = SteadyDelayWithJitter(count: 300, jitterMilliseconds: 6, seed: 7);

        // Reconstruct the old per-packet path to show it *would* have tripped on this same stream.
        PerPacketPathTrips(send, arrival).Should().BeTrue();

        var time = new TestTimeProvider();
        var history = new SendTimeHistory();
        var estimator = new DelayBasedBandwidthEstimator(Options, time);
        var start = estimator.BitrateBitsPerSecond;

        var feedback = BuildFeedback(send, arrival, history);
        time.Advance(TimeSpan.FromMilliseconds(200));
        estimator.ProcessFeedback(feedback, history);

        estimator.Usage.Should().Be(BandwidthUsage.Normal);
        estimator.BitrateBitsPerSecond.Should().BeGreaterThanOrEqualTo(start);
    }

    [Fact]
    public void High_packet_rate_genuine_delay_ramp_still_detects_overuse()
    {
        // Same high packet rate (1 ms send spacing) but a genuine queuing ramp: arrivals spread 1.5 ms
        // apart, so one-way delay climbs 0.5 ms per packet. Grouping must not mask a real ramp.
        var count = 300;
        var send = new long[count];
        var arrival = new long[count];
        for (var i = 0; i < count; i++)
        {
            send[i] = i * 1000L;                    // 1 ms send spacing
            arrival[i] = 5_000_000 + (long)(i * 1500L); // 1.5 ms arrival spacing => rising delay
        }

        var time = new TestTimeProvider();
        var history = new SendTimeHistory();
        var estimator = new DelayBasedBandwidthEstimator(Options, time);
        var start = estimator.BitrateBitsPerSecond;

        var feedback = BuildFeedback(send, arrival, history);
        time.Advance(TimeSpan.FromMilliseconds(200));
        estimator.ProcessFeedback(feedback, history);

        estimator.Usage.Should().Be(BandwidthUsage.Overusing);
        estimator.BitrateBitsPerSecond.Should().BeLessThan(start);
    }

    private static (long[] Send, long[] Arrival) SteadyDelayWithJitter(int count, int jitterMilliseconds, int seed)
    {
        var rng = new Random(seed);
        var send = new long[count];
        var arrival = new long[count];
        for (var i = 0; i < count; i++)
        {
            send[i] = i * 1000L; // 1 ms send spacing
            var jitter = (long)((rng.NextDouble() - 0.5) * 2 * jitterMilliseconds * 1000);
            arrival[i] = 5_000_000 + (i * 1000L) + jitter; // steady mean delay, zero-mean jitter
        }

        // The receiver clock never runs backwards, so clamp any reordering the jitter introduced.
        for (var i = 1; i < count; i++)
        {
            if (arrival[i] < arrival[i - 1])
            {
                arrival[i] = arrival[i - 1];
            }
        }

        return (send, arrival);
    }

    private static RtcpTransportCcFeedback BuildFeedback(long[] send, long[] arrival, SendTimeHistory history)
    {
        var feedback = new RtcpTransportCcFeedback();
        for (var i = 0; i < send.Length; i++)
        {
            history.Add((ushort)i, send[i], PacketSize);
            feedback.AddPacket((ushort)i, arrival[i]);
        }

        return feedback;
    }

    // Mirrors the pre-grouping estimator: one trendline sample per received packet.
    private static bool PerPacketPathTrips(long[] send, long[] arrival)
    {
        var trendline = new TrendlineEstimator(Options.TrendlineWindowSize);
        var detector = new OveruseDetector();
        for (var i = 1; i < send.Length; i++)
        {
            var delayVariationMs = ((arrival[i] - arrival[i - 1]) - (send[i] - send[i - 1])) / 1000.0;
            trendline.Add(delayVariationMs, arrival[i] / 1000.0);
            if (trendline.HasEstimate
                && detector.Detect(trendline.ModifiedTrend, arrival[i] / 1000.0) == BandwidthUsage.Overusing)
            {
                return true;
            }
        }

        return false;
    }
}
