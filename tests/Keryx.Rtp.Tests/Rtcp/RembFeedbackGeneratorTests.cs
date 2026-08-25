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

    // Adversarial: a peer authenticated to the SRTP context can stamp a fresh SSRC on every packet it
    // sends. Every such packet reaches the REMB path (it runs before route resolution), so an uncapped
    // generator would retain one entry per invented SSRC — unbounded memory, a wrapped 8-bit Num-SSRC
    // count once past 255, and a REMB that no longer fits the RTCP MTU buffer, throwing on the receive loop
    // that builds it. The retained set must stay bounded however many sources the peer invents.
    [Fact]
    public void A_flood_of_invented_ssrcs_cannot_grow_the_reported_ssrc_set_without_bound()
    {
        var generator = new RembFeedbackGenerator(Interval, Options);

        long arrival = 5_000_000;
        const int floodSize = 5_000;
        for (var i = 0; i < floodSize; i++)
        {
            // A distinct, well-formed SSRC on every packet — the withheld-source flood.
            var ssrc = 0x4000_0000u + (uint)i;
            generator.OnPacketReceived(AbsoluteSendTimeExtension.FromMicroseconds(arrival - 5_000_000), arrival, PacketSize, ssrc);
            arrival += 5_000;
        }

        generator.TryBuildFeedback(0xAAAA_AAAA, out var remb).Should().BeTrue();

        // The set the REMB names is capped at the 8-bit wire limit, not grown to one entry per invented SSRC.
        remb!.Ssrcs.Count.Should().Be(RembFeedbackGenerator.MaxTrackedSsrcs);

        // The emitted packet fits a single 1500-byte RTCP datagram (the buffer PeerConnection serialises
        // into), so building it never overflows — the count byte also holds the SSRC count without wrapping.
        var wire = remb.ToByteArray();
        wire.Length.Should().BeLessThanOrEqualTo(1500);
        RtcpReceiverEstimatedMaxBitrate.TryParse(wire, out var parsed).Should().BeTrue();
        parsed!.Ssrcs.Count.Should().Be(RembFeedbackGenerator.MaxTrackedSsrcs);
    }

    // Sources past the cap still drive the estimator (only their naming in the feedback is dropped), so the
    // bitrate the flood reports is a real, clamped estimate rather than a degenerate value.
    [Fact]
    public void A_flood_still_reports_a_sane_clamped_bitrate()
    {
        var generator = new RembFeedbackGenerator(Interval, Options);

        long send = 0;
        long arrival = 5_000_000;
        for (var i = 0; i < 1_000; i++)
        {
            var ssrc = 0x5000_0000u + (uint)i;
            generator.OnPacketReceived(AbsoluteSendTimeExtension.FromMicroseconds(send), arrival, PacketSize, ssrc);
            send += 5_000;
            arrival += 5_000;
        }

        generator.HasObservedTraffic.Should().BeTrue();
        generator.TryBuildFeedback(0xAAAA_AAAA, out var remb).Should().BeTrue();
        remb!.BitrateBitsPerSecond.Should().BeInRange(
            (ulong)Options.MinBitrateBitsPerSecond, (ulong)Options.MaxBitrateBitsPerSecond);
    }
}
