using FluentAssertions;
using Keryx.Rtp;
using Xunit;

namespace Keryx.Rtp.Tests;

/// <summary>
/// Coverage for <see cref="RtpSendHistory.Remove"/>, which lets a barge-in cut purge the history for
/// sequence numbers it is about to reuse so a NACK can never resurrect the cut audio.
/// </summary>
public class RtpSendHistoryRemoveTests
{
    private static byte[] Packet(ushort sequenceNumber, int payloadLength = 8)
    {
        var sender = new RtpStreamSender(0x1234_5678, 96, 90_000, sequenceNumber, initialTimestamp: 1000);
        var buffer = new byte[RtpHeader.FixedLength + payloadLength];
        var length = sender.WritePacket(new byte[payloadLength], marker: false, buffer);
        return buffer[..length];
    }

    [Fact]
    public void Removes_a_retained_packet_and_reports_the_new_count_and_byte_total()
    {
        var history = new RtpSendHistory(1200, new RtpSendHistoryOptions { Capacity = 8 });
        var ten = Packet(10);
        var eleven = Packet(11);
        var twelve = Packet(12);
        history.Store(10, ten);
        history.Store(11, eleven);
        history.Store(12, twelve);

        history.Count.Should().Be(3);
        history.ByteCount.Should().Be(ten.Length + eleven.Length + twelve.Length);

        history.Remove(11).Should().BeTrue();

        history.Count.Should().Be(2);
        history.ByteCount.Should().Be(ten.Length + twelve.Length);
        history.TryCopy(11, TimeSpan.Zero, new byte[1200], out _)
            .Should().Be(RtpSendHistoryResult.Missing);
        history.TryCopy(10, TimeSpan.Zero, new byte[1200], out _)
            .Should().Be(RtpSendHistoryResult.Found);
        history.TryCopy(12, TimeSpan.Zero, new byte[1200], out _)
            .Should().Be(RtpSendHistoryResult.Found);
    }

    [Fact]
    public void Removing_a_sequence_number_that_was_never_stored_returns_false()
    {
        var history = new RtpSendHistory(1200, new RtpSendHistoryOptions { Capacity = 8 });
        history.Store(10, Packet(10));

        history.Remove(99).Should().BeFalse();
        history.Count.Should().Be(1);
    }

    [Fact]
    public void Storing_again_after_a_remove_hands_back_the_new_bytes()
    {
        var history = new RtpSendHistory(1200, new RtpSendHistoryOptions { Capacity = 8 });
        history.Store(11, Packet(11, payloadLength: 8));
        history.Remove(11).Should().BeTrue();

        var replacement = Packet(11, payloadLength: 32);
        history.Store(11, replacement).Should().BeTrue();

        var destination = new byte[1200];
        history.TryCopy(11, TimeSpan.Zero, destination, out var length)
            .Should().Be(RtpSendHistoryResult.Found);
        destination[..length].Should().Equal(replacement);
    }
}
