using FluentAssertions;
using Keryx.Rtp.Rtcp;
using Xunit;

namespace Keryx.Rtp.Tests.Rtcp;

/// <summary>
/// Coverage for the inbound loss detector that drives receiver-side NACK generation: gaps become NACKs,
/// late and duplicate packets do not, and repeated requests for the same loss are rate-limited and
/// bounded to a recovery window.
/// </summary>
public class ReceiverNackTrackerTests
{
    private static ReceiverNackTracker New(ReceiverNackOptions? options = null) =>
        new(options ?? new ReceiverNackOptions());

    private static List<ushort> Feed(ReceiverNackTracker tracker, long nowMilliseconds, params ushort[] sequenceNumbers)
    {
        var due = new List<ushort>();
        foreach (var sequenceNumber in sequenceNumbers)
        {
            tracker.OnPacket(sequenceNumber, nowMilliseconds, due);
        }

        return due;
    }

    [Fact]
    public void An_in_order_stream_never_asks_for_anything()
    {
        var tracker = New();

        var due = Feed(tracker, 0, 100, 101, 102, 103, 104);

        due.Should().BeEmpty();
        tracker.OutstandingCount.Should().Be(0);
    }

    [Fact]
    public void A_gap_is_NACKed_for_exactly_the_missing_sequence_numbers()
    {
        var tracker = New();

        // 100, 101, then 105: 102, 103, 104 are missing and detected when 105 arrives.
        var due = Feed(tracker, 0, 100, 101, 105);

        due.Should().Equal((ushort)102, (ushort)103, (ushort)104);
        tracker.OutstandingCount.Should().Be(3);
    }

    [Fact]
    public void A_late_packet_that_fills_a_gap_recovers_it_without_a_spurious_NACK()
    {
        var tracker = New();

        var due = new List<ushort>();
        tracker.OnPacket(100, 0, due);
        tracker.OnPacket(103, 0, due); // 101, 102 missing, both NACKed once at t=0
        due.Should().Equal((ushort)101, (ushort)102);

        // 102 then 101 arrive late (reordered), inside the retry interval so no re-NACK is due. Filling a
        // gap must not itself produce a NACK, and once filled the packet is not asked for again.
        due.Clear();
        tracker.OnPacket(102, 5, due);
        tracker.OnPacket(101, 5, due);

        due.Should().BeEmpty("a reordered arrival fills the gap rather than revealing a new one");
        tracker.OutstandingCount.Should().Be(0);
    }

    [Fact]
    public void A_duplicate_packet_is_not_NACKed()
    {
        var tracker = New();

        var due = Feed(tracker, 0, 100, 101, 102, 101, 100, 102);

        due.Should().BeEmpty();
        tracker.OutstandingCount.Should().Be(0);
    }

    [Fact]
    public void The_same_loss_is_not_re_NACKed_inside_the_retry_interval()
    {
        var options = new ReceiverNackOptions { RetryInterval = TimeSpan.FromMilliseconds(20) };
        var tracker = New(options);

        // Detect the loss of 101 at t=0.
        var due = Feed(tracker, 0, 100, 102);
        due.Should().Equal((ushort)101);

        // More packets arrive at t=5ms and t=15ms, inside the 20ms retry interval: no re-NACK.
        due = Feed(tracker, 5, 103);
        due.Should().BeEmpty();
        due = Feed(tracker, 15, 104);
        due.Should().BeEmpty();

        // At t=25ms the interval has elapsed, so 101 is asked for again.
        due = Feed(tracker, 25, 105);
        due.Should().Contain((ushort)101);
    }

    [Fact]
    public void A_missing_packet_is_abandoned_after_the_retry_budget_is_spent()
    {
        var options = new ReceiverNackOptions
        {
            RetryInterval = TimeSpan.FromMilliseconds(10),
            MaxRetries = 3,
        };
        var tracker = New(options);

        // Detect the loss of 101 (first NACK at t=0).
        var due = Feed(tracker, 0, 100, 102);
        due.Should().Equal((ushort)101);

        // Drive well past three retries; each arrival is a fresh interval so a re-NACK is eligible.
        var nacks = 1;
        for (var t = 10; t <= 200; t += 10)
        {
            due = Feed(tracker, t, (ushort)(102 + (t / 10)));
            nacks += due.Count(s => s == 101);
        }

        nacks.Should().Be(3, "the retry budget caps how many times one loss is asked for");
        tracker.OutstandingCount.Should().Be(0, "the packet is dropped from the set once the budget is spent");
    }

    [Fact]
    public void A_loss_that_falls_out_of_the_window_is_not_NACKed()
    {
        var options = new ReceiverNackOptions { MaxNackDistance = 8 };
        var tracker = New(options);

        var due = new List<ushort>();
        tracker.OnPacket(100, 0, due); // establish the first sequence number

        // Jump forward by more than the window: the whole gap is a discontinuity, not repairable loss.
        due.Clear();
        tracker.OnPacket(200, 0, due);

        due.Should().BeEmpty();
        tracker.OutstandingCount.Should().Be(0);
    }

    [Fact]
    public void A_recovered_repair_stops_further_NACKs()
    {
        var options = new ReceiverNackOptions { RetryInterval = TimeSpan.FromMilliseconds(10) };
        var tracker = New(options);

        var due = Feed(tracker, 0, 100, 102);
        due.Should().Equal((ushort)101);

        // The RFC 4588 repair for 101 arrives on the RTX stream and is bridged back by original seq.
        tracker.OnRecovered(101);
        tracker.OutstandingCount.Should().Be(0);

        // A later arrival past the retry interval must not re-NACK the recovered packet.
        due = Feed(tracker, 50, 103);
        due.Should().BeEmpty();
    }

    [Fact]
    public void Sequence_number_wraparound_is_handled()
    {
        var tracker = New();

        // 65534, 65535, then wrap to 1: sequence number 0 is the single missing packet.
        var due = Feed(tracker, 0, 65534, 65535, 1);

        due.Should().Equal((ushort)0);
    }

    [Fact]
    public void A_burst_of_gaps_coalesces_into_one_scan()
    {
        var tracker = New();

        // A single arrival after a burst loss reveals many missing sequence numbers at once; they are all
        // handed back together so the caller emits them as one NACK rather than a flood.
        var due = Feed(tracker, 0, 100, 116);

        var expected = Enumerable.Range(101, 15).Select(i => (ushort)i);
        due.Should().HaveCount(15).And.BeEquivalentTo(expected);
    }
}
