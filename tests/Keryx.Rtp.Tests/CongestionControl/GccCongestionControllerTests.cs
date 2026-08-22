using FluentAssertions;
using Keryx.Rtp.CongestionControl;
using Keryx.Rtp.Rtcp;
using Xunit;

namespace Keryx.Rtp.Tests.CongestionControl;

/// <summary>End-to-end coverage for the arbitrating controller: ramp, event, REMB cap and fallback.</summary>
public class GccCongestionControllerTests
{
    private const int PacketSize = 1200;
    private static CongestionControllerOptions Options() => new()
    {
        StartBitrateBitsPerSecond = 300_000,
        MinBitrateBitsPerSecond = 30_000,
        MaxBitrateBitsPerSecond = 5_000_000,
    };

    [Fact]
    public void Raises_the_change_event_as_the_target_ramps_on_low_delay()
    {
        var time = new TestTimeProvider();
        var controller = new GccCongestionController(Options(), time);
        long lastTarget = 0;
        controller.TargetBitrateChanged += (_, e) => lastTarget = e.TargetBitrateBitsPerSecond;

        DriveLowDelay(controller, time, rounds: 12);

        lastTarget.Should().BeGreaterThan(300_000);
        controller.TargetBitrateBitsPerSecond.Should().Be(lastTarget);
    }

    [Fact]
    public void Remb_caps_the_delay_based_estimate()
    {
        var time = new TestTimeProvider();
        var controller = new GccCongestionController(Options(), time);

        DriveLowDelay(controller, time, rounds: 12);
        controller.TargetBitrateBitsPerSecond.Should().BeGreaterThan(150_000);

        controller.OnReceiverEstimatedMaxBitrate(new RtcpReceiverEstimatedMaxBitrate(1, 150_000, 2));

        controller.TargetBitrateBitsPerSecond.Should().Be(150_000);
    }

    [Fact]
    public void Falls_back_to_remb_when_no_transport_feedback_has_arrived()
    {
        var time = new TestTimeProvider();
        var controller = new GccCongestionController(Options(), time);

        controller.OnReceiverEstimatedMaxBitrate(new RtcpReceiverEstimatedMaxBitrate(1, 220_000, 2));

        controller.TargetBitrateBitsPerSecond.Should().Be(220_000);
    }

    private static void DriveLowDelay(GccCongestionController controller, TestTimeProvider time, int rounds)
    {
        long send = 0;
        long arrival = 5_000_000;
        ushort seq = 0;
        for (var round = 0; round < rounds; round++)
        {
            var feedback = SyntheticFeedback.Burst(
                seq, 30, send, arrival, sendSpacingMs: 5, arrivalSpacingMs: 5, PacketSize,
                controller.OnPacketSent, out send, out arrival);
            time.Advance(TimeSpan.FromMilliseconds(200));
            controller.OnTransportFeedback(feedback);
            seq += 30;
        }
    }
}
