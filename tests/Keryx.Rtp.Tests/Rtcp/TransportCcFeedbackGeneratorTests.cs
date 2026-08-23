using FluentAssertions;
using Keryx.Rtp.Rtcp;
using Xunit;

namespace Keryx.Rtp.Tests.Rtcp;

/// <summary>
/// Coverage for the receive-side transport-cc feedback generator: it records inbound arrivals and drives
/// <see cref="RtcpTransportCcFeedback"/> to emit feedback whose decoded statuses and deltas match the
/// arrivals, reporting gaps as not-received, and firing on the feedback cadence.
/// </summary>
public class TransportCcFeedbackGeneratorTests
{
    private const int Tick = RtcpTransportCcFeedback.DeltaTickMicroseconds;

    [Fact]
    public void Emits_feedback_whose_decoded_arrivals_match_the_recorded_packets()
    {
        var generator = new TransportCcFeedbackGenerator();
        var baseTime = 64_000_000L; // an exact multiple of the 64 ms reference-time tick

        generator.OnPacketReceived(100, baseTime);
        generator.OnPacketReceived(101, baseTime + (10 * Tick));
        generator.OnPacketReceived(102, baseTime + (20 * Tick));

        generator.TryBuildFeedback(0xAAAA_AAAA, 0xBBBB_BBBB, out var feedback).Should().BeTrue();

        RtcpTransportCcFeedback.TryParse(feedback!.ToByteArray(), out var parsed).Should().BeTrue();
        parsed!.SenderSsrc.Should().Be(0xAAAA_AAAA);
        parsed.MediaSsrc.Should().Be(0xBBBB_BBBB);
        parsed.BaseSequenceNumber.Should().Be(100);
        parsed.FeedbackPacketCount.Should().Be(0);
        parsed.PacketStatuses.Select(s => s.SequenceNumber).Should().Equal((ushort)100, (ushort)101, (ushort)102);
        parsed.PacketStatuses.Should().OnlyContain(s => s.Received);
        parsed.PacketStatuses[0].ArrivalTimeMicroseconds.Should().Be(baseTime);
        parsed.PacketStatuses[1].ArrivalTimeMicroseconds.Should().Be(baseTime + (10 * Tick));
        parsed.PacketStatuses[2].ArrivalTimeMicroseconds.Should().Be(baseTime + (20 * Tick));
    }

    [Fact]
    public void Reports_a_missing_sequence_number_as_not_received()
    {
        var generator = new TransportCcFeedbackGenerator();
        var baseTime = 64_000_000L;

        generator.OnPacketReceived(10, baseTime);
        generator.OnPacketReceived(11, baseTime + (4 * Tick));
        // 12 is lost.
        generator.OnPacketReceived(13, baseTime + (12 * Tick));

        generator.TryBuildFeedback(1, 2, out var feedback).Should().BeTrue();
        RtcpTransportCcFeedback.TryParse(feedback!.ToByteArray(), out var parsed).Should().BeTrue();

        parsed!.PacketStatuses.Select(s => s.SequenceNumber)
            .Should().Equal((ushort)10, (ushort)11, (ushort)12, (ushort)13);
        parsed.PacketStatuses.Select(s => s.Received).Should().Equal(true, true, false, true);
        parsed.PacketStatuses[3].ArrivalTimeMicroseconds.Should().Be(baseTime + (12 * Tick));
    }

    [Fact]
    public void Files_a_reordered_arrival_at_its_true_sequence_position()
    {
        var generator = new TransportCcFeedbackGenerator();
        var baseTime = 64_000_000L;

        // 21 arrives before 20 (reordered on the wire); the generator must still report them in order.
        generator.OnPacketReceived(20, baseTime + (8 * Tick));
        generator.OnPacketReceived(22, baseTime + (16 * Tick));
        generator.OnPacketReceived(21, baseTime + (4 * Tick));

        generator.TryBuildFeedback(1, 2, out var feedback).Should().BeTrue();
        RtcpTransportCcFeedback.TryParse(feedback!.ToByteArray(), out var parsed).Should().BeTrue();

        parsed!.BaseSequenceNumber.Should().Be(20);
        parsed.PacketStatuses.Select(s => s.SequenceNumber).Should().Equal((ushort)20, (ushort)21, (ushort)22);
        parsed.PacketStatuses.Should().OnlyContain(s => s.Received);
    }

    [Fact]
    public void Handles_a_sequence_number_wrap_across_65535()
    {
        var generator = new TransportCcFeedbackGenerator();
        var baseTime = 64_000_000L;

        generator.OnPacketReceived(65534, baseTime);
        generator.OnPacketReceived(65535, baseTime + (4 * Tick));
        generator.OnPacketReceived(0, baseTime + (8 * Tick));
        generator.OnPacketReceived(1, baseTime + (12 * Tick));

        generator.TryBuildFeedback(1, 2, out var feedback).Should().BeTrue();
        RtcpTransportCcFeedback.TryParse(feedback!.ToByteArray(), out var parsed).Should().BeTrue();

        parsed!.BaseSequenceNumber.Should().Be(65534);
        parsed.PacketStatuses.Select(s => s.SequenceNumber)
            .Should().Equal((ushort)65534, (ushort)65535, (ushort)0, (ushort)1);
        parsed.PacketStatuses.Should().OnlyContain(s => s.Received);
    }

    [Fact]
    public void Feedback_is_due_when_the_interval_elapses_and_the_packet_count_bumps_each_flush()
    {
        var interval = TimeSpan.FromMilliseconds(100);
        var generator = new TransportCcFeedbackGenerator(interval, maxReportedPacketsPerFeedback: 200);
        var baseTime = 64_000_000L;

        generator.OnPacketReceived(1, baseTime);
        generator.HasPendingArrivals.Should().BeTrue();

        // Not yet due before the interval elapses.
        generator.ShouldBuildFeedback(baseTime + 50_000).Should().BeFalse();
        // Due once the interval has passed since the oldest pending arrival.
        generator.ShouldBuildFeedback(baseTime + 100_000).Should().BeTrue();

        generator.TryBuildFeedback(1, 2, out var first).Should().BeTrue();
        first!.FeedbackPacketCount.Should().Be(0);
        generator.HasPendingArrivals.Should().BeFalse();
        generator.ShouldBuildFeedback(baseTime + 200_000).Should().BeFalse();

        generator.OnPacketReceived(2, baseTime + 200_000);
        generator.TryBuildFeedback(1, 2, out var second).Should().BeTrue();
        second!.FeedbackPacketCount.Should().Be(1); // count advances per emitted feedback packet
    }

    [Fact]
    public void A_full_window_of_received_packets_makes_feedback_due_before_the_interval()
    {
        var generator = new TransportCcFeedbackGenerator(TimeSpan.FromSeconds(10), maxReportedPacketsPerFeedback: 4);
        var baseTime = 64_000_000L;

        for (var i = 0; i < 4; i++)
        {
            generator.OnPacketReceived((ushort)(500 + i), baseTime + (i * 4L * Tick));
        }

        // The interval is nowhere near elapsed, but the per-packet cap has been reached.
        generator.ShouldBuildFeedback(baseTime + 1_000).Should().BeTrue();
    }

    [Fact]
    public void A_late_reorder_below_the_flushed_window_is_dropped()
    {
        var generator = new TransportCcFeedbackGenerator();
        var baseTime = 64_000_000L;

        generator.OnPacketReceived(30, baseTime);
        generator.OnPacketReceived(31, baseTime + (4 * Tick));
        generator.TryBuildFeedback(1, 2, out _).Should().BeTrue();

        // 30 arriving again (a duplicate or a very late reorder) must not reopen the closed window.
        generator.OnPacketReceived(30, baseTime + (8 * Tick));
        generator.HasPendingArrivals.Should().BeFalse();
        generator.TryBuildFeedback(1, 2, out var feedback).Should().BeFalse();
        feedback.Should().BeNull();
    }

    [Fact]
    public void Building_with_no_pending_arrivals_returns_false()
    {
        var generator = new TransportCcFeedbackGenerator();
        generator.TryBuildFeedback(1, 2, out var feedback).Should().BeFalse();
        feedback.Should().BeNull();
    }
}
