using FluentAssertions;
using Keryx.Rtp;
using Keryx.Rtp.CongestionControl;
using Keryx.Rtp.Rtcp;
using Xunit;

namespace Keryx.Rtp.Tests.Rtcp;

/// <summary>
/// Coverage for the receive-side REMB generator: it feeds inbound abs-send-time arrivals into the
/// delay-gradient estimator and, on the feedback cadence, emits a well-formed
/// <see cref="RtcpReceiverEstimatedMaxBitrate"/> carrying a sane bitrate over the observed SSRCs — the
/// packet a sender's Google Congestion Control path consumes.
/// </summary>
public class RembFeedbackGeneratorTests
{
    private const int PacketSize = 1200;
    private static readonly TimeSpan Interval = TimeSpan.FromMilliseconds(200);
    private static readonly CongestionControllerOptions Options = new()
    {
        StartBitrateBitsPerSecond = 300_000,
        MinBitrateBitsPerSecond = 30_000,
        MaxBitrateBitsPerSecond = 5_000_000,
    };

    [Fact]
    public void No_feedback_is_due_before_any_traffic_is_seen()
    {
        var generator = new RembFeedbackGenerator(Interval, Options);

        generator.ShouldBuildFeedback(1_000_000_000).Should().BeFalse();
        generator.TryBuildFeedback(0x1234_5678, out var remb).Should().BeFalse();
        remb.Should().BeNull();
    }

    [Fact]
    public void Emits_a_well_formed_remb_with_a_sane_bitrate_over_the_observed_ssrc()
    {
        var generator = new RembFeedbackGenerator(Interval, Options);
        const uint mediaSsrc = 0xDEAD_BEEF;

        // Feed a second of steady-delay traffic across time.
        long send = 0;
        long arrival = 5_000_000;
        for (var i = 0; i < 200; i++)
        {
            var absSendTime = AbsoluteSendTimeExtension.FromMicroseconds(send);
            generator.OnPacketReceived(absSendTime, arrival, PacketSize, mediaSsrc);
            send += 5_000;
            arrival += 5_000;
        }

        generator.HasObservedTraffic.Should().BeTrue();
        generator.ShouldBuildFeedback(arrival).Should().BeTrue();

        generator.TryBuildFeedback(0xAAAA_AAAA, out var remb).Should().BeTrue();
        remb!.SenderSsrc.Should().Be(0xAAAA_AAAA);
        remb.Ssrcs.Should().ContainSingle().Which.Should().Be(mediaSsrc);
        remb.BitrateBitsPerSecond.Should().BeInRange(
            (ulong)Options.MinBitrateBitsPerSecond, (ulong)Options.MaxBitrateBitsPerSecond);

        // The packet round-trips on the wire and a sender's GCC consumes it without complaint — proof it
        // is well-formed feedback the send-side estimator can act on.
        RtcpReceiverEstimatedMaxBitrate.TryParse(remb.ToByteArray(), out var parsed).Should().BeTrue();
        parsed!.BitrateBitsPerSecond.Should().Be(remb.BitrateBitsPerSecond);
        parsed.Ssrcs.Should().Equal(mediaSsrc);

        var controller = new GccCongestionController(Options);
        var act = () => controller.OnReceiverEstimatedMaxBitrate(parsed);
        act.Should().NotThrow();
    }

    [Fact]
    public void The_first_report_waits_one_interval_after_the_first_arrival()
    {
        var generator = new RembFeedbackGenerator(Interval, Options);
        const uint mediaSsrc = 1;

        var absSendTime = AbsoluteSendTimeExtension.FromMicroseconds(0);
        generator.OnPacketReceived(absSendTime, 10_000_000, PacketSize, mediaSsrc);

        // Only a hair after the first arrival: not yet due.
        generator.ShouldBuildFeedback(10_050_000).Should().BeFalse();

        // A full interval later: due.
        generator.ShouldBuildFeedback(10_000_000 + (long)(Interval.TotalMilliseconds * 1000)).Should().BeTrue();
    }

    [Fact]
    public void Names_every_observed_ssrc_once()
    {
        var generator = new RembFeedbackGenerator(Interval, Options);

        long arrival = 5_000_000;
        foreach (var ssrc in new uint[] { 10, 20, 10, 30, 20 })
        {
            generator.OnPacketReceived(AbsoluteSendTimeExtension.FromMicroseconds(arrival - 5_000_000), arrival, PacketSize, ssrc);
            arrival += 5_000;
        }

        generator.TryBuildFeedback(0xAAAA_AAAA, out var remb).Should().BeTrue();
        remb!.Ssrcs.Should().BeEquivalentTo(new uint[] { 10, 20, 30 });
    }
}
