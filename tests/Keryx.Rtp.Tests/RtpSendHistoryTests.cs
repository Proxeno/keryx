using FluentAssertions;
using Keryx.Core;
using Xunit;

namespace Keryx.Rtp.Tests;

/// <summary>
/// Coverage for the send-history ring that serves RFC 4585 §6.2.1 NACKs: eviction by wrap, by age and
/// by byte budget, sequence-number wraparound, and the per-packet resend rate limit.
/// </summary>
public class RtpSendHistoryTests
{
    private static byte[] Packet(ushort sequenceNumber, int payloadLength = 8)
    {
        var sender = new RtpStreamSender(0x1234_5678, 96, 90_000, sequenceNumber, initialTimestamp: 1000);
        var buffer = new byte[RtpHeader.FixedLength + payloadLength];
        var length = sender.WritePacket(new byte[payloadLength], marker: false, buffer);
        return buffer[..length];
    }

    [Fact]
    public void Stores_a_packet_and_hands_it_back_verbatim()
    {
        var history = new RtpSendHistory(1200, new RtpSendHistoryOptions { Capacity = 8 });
        var packet = Packet(100);

        history.Store(100, packet).Should().BeTrue();
        history.Count.Should().Be(1);
        history.ByteCount.Should().Be(packet.Length);

        var destination = new byte[1200];
        history.TryCopy(100, TimeSpan.Zero, destination, out var length)
            .Should().Be(RtpSendHistoryResult.Found);
        destination[..length].Should().Equal(packet);
    }

    [Fact]
    public void Reports_a_miss_for_a_sequence_number_that_was_never_stored()
    {
        var history = new RtpSendHistory(1200, new RtpSendHistoryOptions { Capacity = 8 });
        history.Store(100, Packet(100));

        history.TryCopy(101, TimeSpan.Zero, new byte[1200], out _)
            .Should().Be(RtpSendHistoryResult.Missing);
    }

    [Fact]
    public void Rounds_the_capacity_up_to_a_power_of_two()
    {
        var history = new RtpSendHistory(64, new RtpSendHistoryOptions { Capacity = 100 });
        history.Capacity.Should().Be(128);
    }

    [Fact]
    public void Evicts_the_oldest_packet_when_the_ring_wraps()
    {
        var history = new RtpSendHistory(1200, new RtpSendHistoryOptions { Capacity = 4 });
        for (ushort seq = 0; seq < 4; seq++)
        {
            history.Store(seq, Packet(seq));
        }

        history.Count.Should().Be(4);
        history.Store(4, Packet(4));

        // Slot 0 now belongs to sequence number 4, so 0 is gone but 1..4 survive.
        history.Count.Should().Be(4);
        history.TryCopy(0, TimeSpan.Zero, new byte[1200], out _).Should().Be(RtpSendHistoryResult.Missing);
        history.TryCopy(1, TimeSpan.Zero, new byte[1200], out _).Should().Be(RtpSendHistoryResult.Found);
        history.TryCopy(4, TimeSpan.Zero, new byte[1200], out _).Should().Be(RtpSendHistoryResult.Found);
    }

    [Fact]
    public void Evicts_by_age_once_the_retention_window_has_passed()
    {
        var clock = new TestTimeProvider();
        var history = new RtpSendHistory(
            1200,
            new RtpSendHistoryOptions { Capacity = 64, Retention = TimeSpan.FromMilliseconds(500) },
            clock);

        history.Store(1, Packet(1));
        clock.Advance(TimeSpan.FromMilliseconds(300));
        history.Store(2, Packet(2));
        history.Count.Should().Be(2);

        clock.Advance(TimeSpan.FromMilliseconds(300));

        // 1 is now 600 ms old and 2 is 300 ms old; storing 3 trims the expired head.
        history.Store(3, Packet(3));
        history.Count.Should().Be(2);
        history.TryCopy(1, TimeSpan.Zero, new byte[1200], out _).Should().Be(RtpSendHistoryResult.Missing);
        history.TryCopy(2, TimeSpan.Zero, new byte[1200], out _).Should().Be(RtpSendHistoryResult.Found);
    }

    [Fact]
    public void Refuses_a_packet_that_has_aged_out_even_before_it_is_trimmed()
    {
        var clock = new TestTimeProvider();
        var history = new RtpSendHistory(
            1200,
            new RtpSendHistoryOptions { Capacity = 64, Retention = TimeSpan.FromMilliseconds(200) },
            clock);

        history.Store(7, Packet(7));
        clock.Advance(TimeSpan.FromMilliseconds(500));

        history.TryCopy(7, TimeSpan.Zero, new byte[1200], out _).Should().Be(RtpSendHistoryResult.Missing);
    }

    [Fact]
    public void Evicts_by_byte_budget_before_the_ring_or_the_clock_bind()
    {
        // 20 slots of room and a full second of retention, but only enough bytes for three packets.
        var packetLength = RtpHeader.FixedLength + 100;
        var history = new RtpSendHistory(
            1200,
            new RtpSendHistoryOptions { Capacity = 32, MaxBytes = 3 * packetLength });

        for (ushort seq = 1; seq <= 10; seq++)
        {
            history.Store(seq, Packet(seq, 100));
        }

        history.Count.Should().Be(3);
        history.ByteCount.Should().Be(3 * packetLength);
        history.TryCopy(7, TimeSpan.Zero, new byte[1200], out _).Should().Be(RtpSendHistoryResult.Missing);
        history.TryCopy(8, TimeSpan.Zero, new byte[1200], out _).Should().Be(RtpSendHistoryResult.Found);
        history.TryCopy(10, TimeSpan.Zero, new byte[1200], out _).Should().Be(RtpSendHistoryResult.Found);
    }

    [Fact]
    public void Handles_the_sequence_number_wrapping_from_sixty_five_thousand_five_hundred_and_thirty_five_to_zero()
    {
        // RFC 3550 §5.1: sequence numbers wrap at 2^16, so the ring must stay coherent across the seam.
        var history = new RtpSendHistory(1200, new RtpSendHistoryOptions { Capacity = 8 });
        ushort seq = 65533;
        for (var i = 0; i < 6; i++)
        {
            history.Store(seq, Packet(seq));
            seq++;
        }

        history.Count.Should().Be(6);
        var destination = new byte[1200];
        foreach (var wanted in new ushort[] { 65533, 65534, 65535, 0, 1, 2 })
        {
            history.TryCopy(wanted, TimeSpan.Zero, destination, out var length)
                .Should().Be(RtpSendHistoryResult.Found);
            RtpPacket.TryParse(destination.AsSpan(0, length), out var packet).Should().BeTrue();
            packet.Header.SequenceNumber.Should().Be(wanted);
        }
    }

    [Fact]
    public void Suppresses_a_second_resend_inside_the_minimum_interval_but_serves_the_first_immediately()
    {
        var clock = new TestTimeProvider();
        var history = new RtpSendHistory(1200, new RtpSendHistoryOptions { Capacity = 8 }, clock);
        history.Store(5, Packet(5));

        // The first NACK is served however soon it arrives: a short round trip must not be penalised.
        clock.Advance(TimeSpan.FromMilliseconds(1));
        history.TryCopy(5, TimeSpan.FromMilliseconds(50), new byte[1200], out _)
            .Should().Be(RtpSendHistoryResult.Found);

        clock.Advance(TimeSpan.FromMilliseconds(20));
        history.TryCopy(5, TimeSpan.FromMilliseconds(50), new byte[1200], out _)
            .Should().Be(RtpSendHistoryResult.Suppressed);

        clock.Advance(TimeSpan.FromMilliseconds(40));
        history.TryCopy(5, TimeSpan.FromMilliseconds(50), new byte[1200], out _)
            .Should().Be(RtpSendHistoryResult.Found);
    }

    [Fact]
    public void Refuses_a_packet_larger_than_the_slot_size_rather_than_truncating_it()
    {
        var history = new RtpSendHistory(64, new RtpSendHistoryOptions { Capacity = 4 });

        history.Store(1, new byte[65]).Should().BeFalse();
        history.Store(1, []).Should().BeFalse();
        history.Count.Should().Be(0);
    }

    [Fact]
    public void Throws_when_the_destination_cannot_hold_the_retained_packet()
    {
        var history = new RtpSendHistory(1200, new RtpSendHistoryOptions { Capacity = 4 });
        history.Store(1, Packet(1, 100));

        var act = () => history.TryCopy(1, TimeSpan.Zero, new byte[10], out _);
        act.Should().Throw<ByteBufferException>();
    }

    [Fact]
    public void Clear_drops_everything()
    {
        var history = new RtpSendHistory(1200, new RtpSendHistoryOptions { Capacity = 8 });
        history.Store(1, Packet(1));
        history.Store(2, Packet(2));

        history.Clear();

        history.Count.Should().Be(0);
        history.ByteCount.Should().Be(0);
        history.TryCopy(1, TimeSpan.Zero, new byte[1200], out _).Should().Be(RtpSendHistoryResult.Missing);
    }

    [Fact]
    public void Rejects_a_capacity_that_could_alias_across_the_sequence_number_space()
    {
        var act = () => new RtpSendHistory(1200, new RtpSendHistoryOptions { Capacity = 65536 });
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public async Task Survives_concurrent_stores_and_lookups()
    {
        // NACKs are read on the RTCP receive loop while frames are written from the send thread.
        var history = new RtpSendHistory(1200, new RtpSendHistoryOptions { Capacity = 256 });
        var stop = false;
        var failures = 0;

        var reader = Task.Run(() =>
        {
            var destination = new byte[1200];
            while (!Volatile.Read(ref stop))
            {
                for (ushort seq = 0; seq < 1000; seq++)
                {
                    if (history.TryCopy(seq, TimeSpan.Zero, destination, out var length)
                        == RtpSendHistoryResult.Found
                        && (length < RtpHeader.FixedLength
                            || !RtpPacket.TryParse(destination.AsSpan(0, length), out _)))
                    {
                        Interlocked.Increment(ref failures);
                    }
                }
            }
        });

        for (ushort seq = 0; seq < 20_000; seq++)
        {
            history.Store(seq, Packet(seq, 40 + (seq % 200)));
        }

        Volatile.Write(ref stop, true);
        await reader.WaitAsync(TimeSpan.FromSeconds(10));
        failures.Should().Be(0);
    }
}
