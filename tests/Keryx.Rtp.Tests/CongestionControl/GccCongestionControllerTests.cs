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

    /// <summary>
    /// A barge-in cut draws transport-wide sequence numbers for packets that are then discarded, leaving
    /// a gap in the TWCC space. The delay-based estimator must skip those not-received entries, so the
    /// estimate holds (and keeps ramping exactly like a cut-free controller), never mistaking the gap
    /// for loss.
    /// </summary>
    [Fact]
    public void TransportCcGapFromACutDoesNotLowerTheEstimate()
    {
        var timeA = new TestTimeProvider();
        var timeB = new TestTimeProvider();
        var a = new GccCongestionController(Options(), timeA);
        var b = new GccCongestionController(Options(), timeB);

        const int packetsPerRound = 30;
        const int rounds = 14;
        const int gapRound = 6;
        const int gapStart = 10;
        const int gapCount = 10;

        long sendA = 0;
        long arrivalA = 5_000_000;
        long sendB = 0;
        long arrivalB = 5_000_000;
        ushort seqA = 0;
        ushort seqB = 0;

        for (var round = 0; round < rounds; round++)
        {
            var feedbackA = SyntheticFeedback.Burst(
                seqA, packetsPerRound, sendA, arrivalA, sendSpacingMs: 5, arrivalSpacingMs: 5, PacketSize,
                a.OnPacketSent, out sendA, out arrivalA);

            RtcpTransportCcFeedback feedbackB;
            if (round == gapRound)
            {
                // The cut: these ten sequence numbers were drawn by the send path but never reached the
                // wire, so they are absent from the feedback (the builder marks the hole NotReceived).
                feedbackB = new RtcpTransportCcFeedback();
                for (var i = 0; i < packetsPerRound; i++)
                {
                    if (i is >= gapStart and < gapStart + gapCount)
                    {
                        continue;
                    }

                    var sequenceNumber = unchecked((ushort)(seqB + i));
                    b.OnPacketSent(sequenceNumber, sendB + i * 5_000L, PacketSize);
                    feedbackB.AddPacket(sequenceNumber, arrivalB + i * 5_000L);
                }

                sendB += packetsPerRound * 5_000L;
                arrivalB += packetsPerRound * 5_000L;
            }
            else
            {
                feedbackB = SyntheticFeedback.Burst(
                    seqB, packetsPerRound, sendB, arrivalB, sendSpacingMs: 5, arrivalSpacingMs: 5, PacketSize,
                    b.OnPacketSent, out sendB, out arrivalB);
            }

            timeA.Advance(TimeSpan.FromMilliseconds(200));
            timeB.Advance(TimeSpan.FromMilliseconds(200));
            a.OnTransportFeedback(feedbackA);
            b.OnTransportFeedback(feedbackB);

            seqA = unchecked((ushort)(seqA + packetsPerRound));
            seqB = unchecked((ushort)(seqB + packetsPerRound));

            b.TargetBitrateBitsPerSecond.Should().BeGreaterThanOrEqualTo(
                a.TargetBitrateBitsPerSecond,
                $"round {round}: a TWCC gap must never put the gapped controller below the cut-free one");
        }

        b.TargetBitrateBitsPerSecond.Should().Be(a.TargetBitrateBitsPerSecond,
            "the not-received entries are skipped, so the two controllers ramp identically");
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
