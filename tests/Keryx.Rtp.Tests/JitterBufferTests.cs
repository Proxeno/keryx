using FluentAssertions;
using Xunit;

namespace Keryx.Rtp.Tests;

/// <summary>
/// Coverage for the receive jitter buffer: in-order passthrough with no added latency, recovery from
/// reordering, duplicate rejection, loss declared on wait or on a full ring, and sequence-number
/// wraparound.
/// </summary>
public class JitterBufferTests
{
    private static readonly byte[] Payload = [0xAA, 0xBB, 0xCC];

    private static JitterBufferInsertResult Insert(JitterBuffer buffer, ushort sequenceNumber, byte payloadType = 96) =>
        buffer.Insert(sequenceNumber, timestamp: sequenceNumber * 90u, marker: false, payloadType, Payload);

    private static List<ushort> Drain(JitterBuffer buffer)
    {
        var released = new List<ushort>();
        while (buffer.TryGetNext(out var packet))
        {
            released.Add(packet.SequenceNumber);
        }

        return released;
    }

    [Fact]
    public void Rounds_the_capacity_up_to_a_power_of_two()
    {
        var buffer = new JitterBuffer(new JitterBufferOptions { Capacity = 100 });
        buffer.Capacity.Should().Be(128);
    }

    [Fact]
    public void Passes_an_in_order_stream_straight_through_without_holding_it()
    {
        var buffer = new JitterBuffer(new JitterBufferOptions { Capacity = 16 }, new TestTimeProvider());

        for (ushort seq = 100; seq < 110; seq++)
        {
            Insert(buffer, seq).Should().Be(JitterBufferInsertResult.Buffered);

            // Each in-order packet is immediately releasable; nothing accumulates behind it.
            buffer.TryGetNext(out var packet).Should().BeTrue();
            packet.SequenceNumber.Should().Be(seq);
            buffer.Count.Should().Be(0);
        }

        buffer.PacketsLost.Should().Be(0);
        buffer.DuplicatesDropped.Should().Be(0);
    }

    [Fact]
    public void Hands_back_the_payload_and_header_fields_verbatim()
    {
        var buffer = new JitterBuffer(new JitterBufferOptions { Capacity = 8 }, new TestTimeProvider());
        buffer.Insert(5, timestamp: 4242, marker: true, payloadType: 111, [1, 2, 3, 4]);

        buffer.TryGetNext(out var packet).Should().BeTrue();
        packet.SequenceNumber.Should().Be(5);
        packet.Timestamp.Should().Be(4242);
        packet.Marker.Should().BeTrue();
        packet.PayloadType.Should().Be(111);
        packet.Payload.ToArray().Should().Equal(1, 2, 3, 4);
    }

    [Fact]
    public void Recovers_the_order_of_a_reordered_run()
    {
        var buffer = new JitterBuffer(new JitterBufferOptions { Capacity = 16 }, new TestTimeProvider());

        // The head arrives, then three packets overtake a gap at 101 before it finally lands.
        Insert(buffer, 100);
        Drain(buffer).Should().Equal((ushort)100);

        Insert(buffer, 103);
        Insert(buffer, 102);
        Insert(buffer, 104);

        // 101 is still missing, so nothing behind it may be released yet.
        Drain(buffer).Should().BeEmpty();
        buffer.Count.Should().Be(3);

        Insert(buffer, 101);

        // With the gap filled the whole run comes out in order, in one drain.
        Drain(buffer).Should().Equal((ushort)101, 102, 103, 104);
        buffer.PacketsLost.Should().Be(0);
    }

    [Fact]
    public void Drops_a_duplicate_sequence_number()
    {
        var buffer = new JitterBuffer(new JitterBufferOptions { Capacity = 16 }, new TestTimeProvider());

        Insert(buffer, 200);
        Insert(buffer, 202);
        Insert(buffer, 202).Should().Be(JitterBufferInsertResult.Duplicate);
        buffer.DuplicatesDropped.Should().Be(1);

        Insert(buffer, 201);
        Drain(buffer).Should().Equal((ushort)200, 201, 202);
    }

    [Fact]
    public void Rejects_a_packet_that_arrives_after_its_playout_point_passed()
    {
        var buffer = new JitterBuffer(new JitterBufferOptions { Capacity = 16 }, new TestTimeProvider());

        Insert(buffer, 50);
        Insert(buffer, 51);
        Drain(buffer).Should().Equal((ushort)50, 51);

        // 50 and 51 have already been released; a late copy of either is behind the cursor.
        Insert(buffer, 50).Should().Be(JitterBufferInsertResult.Late);
        buffer.LatePacketsDropped.Should().Be(1);
    }

    [Fact]
    public void Declares_a_missing_packet_lost_once_the_wait_elapses()
    {
        var time = new TestTimeProvider();
        var buffer = new JitterBuffer(
            new JitterBufferOptions { Capacity = 16, MaxWait = TimeSpan.FromMilliseconds(100) },
            time);

        Insert(buffer, 10);
        Drain(buffer).Should().Equal((ushort)10);

        // 11 never arrives; 12 and 13 wait behind it.
        Insert(buffer, 12);
        Insert(buffer, 13);
        Drain(buffer).Should().BeEmpty();

        // Before the wait elapses the run is still held.
        time.Advance(TimeSpan.FromMilliseconds(50));
        Drain(buffer).Should().BeEmpty();

        // Once it elapses, 11 is declared lost and the packets behind it are released.
        time.Advance(TimeSpan.FromMilliseconds(60));
        Drain(buffer).Should().Equal((ushort)12, 13);
        buffer.PacketsLost.Should().Be(1);
    }

    [Fact]
    public void Collapses_a_run_of_consecutive_holes_in_one_release()
    {
        var time = new TestTimeProvider();
        var buffer = new JitterBuffer(
            new JitterBufferOptions { Capacity = 16, MaxWait = TimeSpan.FromMilliseconds(100) },
            time);

        Insert(buffer, 10);
        Drain(buffer).Should().Equal((ushort)10);

        // 11, 12, 13 are all missing; only 14 is buffered behind the gap.
        Insert(buffer, 14);
        time.Advance(TimeSpan.FromMilliseconds(150));

        Drain(buffer).Should().Equal((ushort)14);
        buffer.PacketsLost.Should().Be(3);
    }

    [Fact]
    public void Declares_the_head_lost_when_the_ring_fills_before_the_wait_elapses()
    {
        var time = new TestTimeProvider();
        var buffer = new JitterBuffer(
            new JitterBufferOptions { Capacity = 4, MaxWait = TimeSpan.FromSeconds(10) },
            time);

        // Head 0 lands and is released, then 1 goes missing and 2..5 fill the four-slot ring.
        Insert(buffer, 0);
        Drain(buffer).Should().Equal((ushort)0);

        Insert(buffer, 2);
        Insert(buffer, 3);
        Insert(buffer, 4);
        Insert(buffer, 5);

        // The wait has not elapsed, but a full ring must make room, so 1 is declared lost.
        var released = Drain(buffer);
        released.Should().Equal((ushort)2, 3, 4, 5);
        buffer.PacketsLost.Should().Be(1);
    }

    [Fact]
    public void Handles_sequence_number_wraparound()
    {
        var buffer = new JitterBuffer(new JitterBufferOptions { Capacity = 16 }, new TestTimeProvider());

        Insert(buffer, 65534);
        Drain(buffer).Should().Equal((ushort)65534);

        // A gap that straddles the 16-bit wrap: 65535, 0, 1 arrive out of order around the boundary.
        Insert(buffer, 0);
        Insert(buffer, 1);
        Drain(buffer).Should().BeEmpty();

        Insert(buffer, 65535);
        Drain(buffer).Should().Equal((ushort)65535, 0, 1);
        buffer.PacketsLost.Should().Be(0);
    }

    [Fact]
    public void Fast_forwards_past_a_jump_larger_than_the_window()
    {
        var time = new TestTimeProvider();
        var buffer = new JitterBuffer(
            new JitterBufferOptions { Capacity = 8, MaxWait = TimeSpan.FromMilliseconds(100) },
            time);

        Insert(buffer, 100);
        Drain(buffer).Should().Equal((ushort)100);

        // A packet lands far beyond the window while 101 is still owed. The cursor fast-forwards to
        // bring it in range, declaring the skipped span lost; the packet then waits out its window at
        // the head of the new range, just like any gap, before being released.
        Insert(buffer, 1000).Should().Be(JitterBufferInsertResult.Buffered);
        buffer.PacketsLost.Should().BeGreaterThan(0);

        time.Advance(TimeSpan.FromMilliseconds(150));
        Drain(buffer).Should().Equal((ushort)1000);
    }

    [Fact]
    public void Reset_forgets_the_cursor_and_starts_fresh()
    {
        var buffer = new JitterBuffer(new JitterBufferOptions { Capacity = 8 }, new TestTimeProvider());

        Insert(buffer, 500);
        Insert(buffer, 502);
        buffer.Count.Should().Be(2);

        buffer.Reset();
        buffer.Count.Should().Be(0);

        // After a reset the next packet sets a brand-new cursor, so a lower sequence number is welcome.
        Insert(buffer, 10).Should().Be(JitterBufferInsertResult.Buffered);
        Drain(buffer).Should().Equal((ushort)10);
    }

    [Fact]
    public void Rejects_a_capacity_outside_the_supported_range()
    {
        var act = () => new JitterBuffer(new JitterBufferOptions { Capacity = 0 });
        act.Should().Throw<ArgumentOutOfRangeException>();

        var tooBig = () => new JitterBuffer(new JitterBufferOptions { Capacity = 40_000 });
        tooBig.Should().Throw<ArgumentOutOfRangeException>();
    }

    // ---------------------------------------------------------------- arrival time + loss-before surface

    private static (ushort SequenceNumber, long ArrivalTimestamp, int LostBefore) Next(JitterBuffer buffer)
    {
        buffer.TryGetNext(out var packet).Should().BeTrue();
        return (packet.SequenceNumber, packet.ArrivalTimestamp, packet.LostBefore);
    }

    [Fact]
    public void In_order_stream_reports_no_loss_and_the_arrival_timestamp_it_was_inserted_with()
    {
        var buffer = new JitterBuffer(new JitterBufferOptions { Capacity = 16 }, new TestTimeProvider());

        for (ushort seq = 100; seq < 110; seq++)
        {
            var arrival = 1_000L + seq;
            buffer.Insert(seq, timestamp: seq * 960u, marker: false, payloadType: 111, Payload, arrival)
                .Should().Be(JitterBufferInsertResult.Buffered);

            var released = Next(buffer);
            released.SequenceNumber.Should().Be(seq);
            released.LostBefore.Should().Be(0);
            released.ArrivalTimestamp.Should().Be(arrival);
        }

        buffer.PacketsLost.Should().Be(0);
    }

    [Fact]
    public void A_single_missing_packet_stamps_LostBefore_on_the_packet_that_follows_it()
    {
        var time = new TestTimeProvider();
        var buffer = new JitterBuffer(
            new JitterBufferOptions { Capacity = 16, MaxWait = TimeSpan.FromMilliseconds(100) },
            time);

        Insert(buffer, 10);
        Next(buffer);

        Insert(buffer, 12);
        Insert(buffer, 13);
        buffer.TryGetNext(out _).Should().BeFalse();

        time.Advance(TimeSpan.FromMilliseconds(150));

        var first = Next(buffer);
        first.SequenceNumber.Should().Be(12);
        first.LostBefore.Should().Be(1);

        var second = Next(buffer);
        second.SequenceNumber.Should().Be(13);
        second.LostBefore.Should().Be(0);
    }

    [Fact]
    public void Three_consecutive_missing_packets_stamp_LostBefore_three()
    {
        var time = new TestTimeProvider();
        var buffer = new JitterBuffer(
            new JitterBufferOptions { Capacity = 16, MaxWait = TimeSpan.FromMilliseconds(100) },
            time);

        Insert(buffer, 10);
        Next(buffer);

        // 11, 12 and 13 never arrive; 14 is buffered behind the hole.
        Insert(buffer, 14);
        time.Advance(TimeSpan.FromMilliseconds(150));

        var released = Next(buffer);
        released.SequenceNumber.Should().Be(14);
        released.LostBefore.Should().Be(3);
        buffer.PacketsLost.Should().Be(3);
    }

    [Fact]
    public void Fast_forward_reports_the_whole_skipped_span_as_LostBefore()
    {
        var time = new TestTimeProvider();
        var buffer = new JitterBuffer(
            new JitterBufferOptions { Capacity = 8, MaxWait = TimeSpan.FromMilliseconds(100) },
            time);

        Insert(buffer, 100);
        Next(buffer);

        // A packet far beyond the 8-slot window forces the cursor forward at insert time; the packet
        // then waits out its window at the head of the new range before release.
        Insert(buffer, 1000).Should().Be(JitterBufferInsertResult.Buffered);
        buffer.PacketsLost.Should().BeGreaterThan(0);

        time.Advance(TimeSpan.FromMilliseconds(150));

        var released = Next(buffer);
        released.SequenceNumber.Should().Be(1000);

        // 101 through 999 inclusive were all declared lost before 1000 played out.
        released.LostBefore.Should().Be(899);
        buffer.PacketsLost.Should().Be(899);
    }

    [Fact]
    public void A_reordered_packet_that_fills_the_gap_before_the_wait_stamps_no_loss()
    {
        var time = new TestTimeProvider();
        var buffer = new JitterBuffer(
            new JitterBufferOptions { Capacity = 16, MaxWait = TimeSpan.FromMilliseconds(100) },
            time);

        Insert(buffer, 100);
        Next(buffer);

        Insert(buffer, 102);
        Insert(buffer, 103);
        buffer.TryGetNext(out _).Should().BeFalse();

        time.Advance(TimeSpan.FromMilliseconds(50));
        Insert(buffer, 101);

        var one = Next(buffer);
        var two = Next(buffer);
        var three = Next(buffer);
        new[] { one, two, three }.Select(static r => r.SequenceNumber).Should().Equal((ushort)101, 102, 103);
        new[] { one, two, three }.Select(static r => r.LostBefore).Should().OnlyContain(static lost => lost == 0);
        buffer.PacketsLost.Should().Be(0);
    }

    [Fact]
    public void The_five_argument_Insert_stamps_arrival_from_the_time_provider()
    {
        var time = new TestTimeProvider();
        time.Advance(TimeSpan.FromMilliseconds(123));
        var expected = time.GetTimestamp();

        var buffer = new JitterBuffer(new JitterBufferOptions { Capacity = 8 }, time);
        buffer.Insert(7, timestamp: 0, marker: false, payloadType: 111, Payload)
            .Should().Be(JitterBufferInsertResult.Buffered);

        var released = Next(buffer);
        released.SequenceNumber.Should().Be(7);
        released.ArrivalTimestamp.Should().Be(expected);
    }
}
