using FluentAssertions;
using Keryx.Rtp.CongestionControl;
using Xunit;

namespace Keryx.Rtp.Tests.CongestionControl;

/// <summary>Coverage for the leaky-bucket pacer: budget accrual, burst refusal, and wait estimates.</summary>
public class PacketPacerTests
{
    [Fact]
    public void Accrues_budget_at_the_target_times_the_pacing_factor()
    {
        var time = new TestTimeProvider();
        var pacer = new PacketPacer(800_000, time, pacingFactor: 2.5, burstSeconds: 1.0);

        // 800 kbit/s * 2.5 = 2 Mbit/s = 250_000 bytes/s. After 100 ms, ~25_000 bytes are available.
        time.Advance(TimeSpan.FromMilliseconds(100));

        pacer.TryConsume(20_000).Should().BeTrue();
    }

    [Fact]
    public void Refuses_a_burst_larger_than_the_accrued_budget()
    {
        var time = new TestTimeProvider();
        var pacer = new PacketPacer(800_000, time, pacingFactor: 2.5, burstSeconds: 0.02);

        time.Advance(TimeSpan.FromMilliseconds(5));

        pacer.TryConsume(50_000).Should().BeFalse();
    }

    [Fact]
    public void Reports_a_positive_wait_when_the_budget_is_short()
    {
        var time = new TestTimeProvider();
        var pacer = new PacketPacer(800_000, time, pacingFactor: 2.5, burstSeconds: 0.02);

        var wait = pacer.TimeUntilNextSend(10_000);

        wait.Should().BeGreaterThan(TimeSpan.Zero);
    }

    [Fact]
    public void Retargeting_changes_the_drain_rate()
    {
        var time = new TestTimeProvider();
        var pacer = new PacketPacer(400_000, time);
        var slow = pacer.PacingRateBytesPerSecond;

        pacer.SetTargetBitrate(1_600_000);

        pacer.PacingRateBytesPerSecond.Should().BeApproximately(slow * 4, 1.0);
    }
}
