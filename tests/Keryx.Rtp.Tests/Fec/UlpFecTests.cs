using FluentAssertions;
using Keryx.Rtp.Fec;
using Xunit;

namespace Keryx.Rtp.Tests.Fec;

/// <summary>
/// Coverage for the RFC 5109 level-0 ULPFEC generator and single-loss recovery path.
/// </summary>
public class UlpFecTests
{
    private const uint MediaSsrc = 0x0A0B_0C0D;
    private const byte MediaPayloadType = 96;

    private static byte[] Media(ushort sequenceNumber, uint timestamp, bool marker, int payloadLength)
    {
        var sender = new RtpStreamSender(MediaSsrc, MediaPayloadType, 90_000, sequenceNumber, timestamp);
        var payload = new byte[payloadLength];
        for (var i = 0; i < payloadLength; i++)
        {
            // A per-sequence pattern so a mis-recovery of any octet is caught.
            payload[i] = (byte)((sequenceNumber * 31 + i) & 0xFF);
        }

        var buffer = new byte[RtpHeader.FixedLength + payloadLength];
        var length = sender.WritePacket(payload, marker, buffer);
        return buffer[..length];
    }

    private static byte[] ProduceFec(int maxProtected, params byte[][] group)
    {
        var generator = new UlpFecGenerator(maxProtected);
        foreach (var packet in group)
        {
            generator.TryAdd(packet).Should().BeTrue();
        }

        var fec = new byte[generator.MaxFecPayloadSize];
        generator.TryProduce(fec, out var length).Should().BeTrue();
        return fec[..length];
    }

    // ------------------------------------------------------------------ FEC packet shape (RFC 5109 §7.3)

    [Fact]
    public void The_fec_header_names_the_sequence_number_base_the_mask_and_the_protection_length()
    {
        var group = new[]
        {
            Media(1000, 90_000, marker: false, payloadLength: 20),
            Media(1001, 90_000, marker: false, payloadLength: 40),
            Media(1002, 90_000, marker: true, payloadLength: 30),
        };
        var fec = ProduceFec(200, group);

        UlpFecPacket.TryParse(fec, out var header).Should().BeTrue();
        header.SequenceNumberBase.Should().Be(1000);
        header.ProtectedCount.Should().Be(3);
        header.ProtectionLength.Should().Be(40); // the largest post-header region in the group
        header.Protects(1000).Should().BeTrue();
        header.Protects(1001).Should().BeTrue();
        header.Protects(1002).Should().BeTrue();
        header.Protects(1003).Should().BeFalse();
        // Three contiguous packets from the base: the top three mask bits.
        header.Mask.Should().Be(0b1110_0000_0000_0000);
    }

    // ------------------------------------------------------------------ single-loss recovery (RFC 5109 §7.4.2)

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void One_dropped_packet_in_a_group_is_recovered_exactly(int dropIndex)
    {
        var group = new[]
        {
            Media(2000, 111_000, marker: false, payloadLength: 25),
            Media(2001, 111_000, marker: false, payloadLength: 100),
            Media(2002, 111_000, marker: false, payloadLength: 60),
            Media(2003, 111_000, marker: true, payloadLength: 10),
        };
        var fec = ProduceFec(200, group);

        var receiver = new UlpFecReceiver(MediaSsrc);
        for (var i = 0; i < group.Length; i++)
        {
            if (i != dropIndex)
            {
                receiver.OnMediaPacket(group[i]);
            }
        }

        receiver.OnFecPacket(fec).Should().BeTrue();

        var recovered = new byte[1500];
        receiver.TryDequeueRecovered(recovered, out var length, out var seq).Should().BeTrue();
        seq.Should().Be((ushort)(2000 + dropIndex));
        recovered[..length].Should().Equal(group[dropIndex], "the recovered packet is byte-identical to the original");
        receiver.GetStats().PacketsRecovered.Should().Be(1);
    }

    [Fact]
    public void A_group_with_two_losses_cannot_be_recovered()
    {
        var group = new[]
        {
            Media(3000, 5000, marker: false, payloadLength: 50),
            Media(3001, 5000, marker: false, payloadLength: 50),
            Media(3002, 5000, marker: false, payloadLength: 50),
            Media(3003, 5000, marker: true, payloadLength: 50),
        };
        var fec = ProduceFec(64, group);

        var receiver = new UlpFecReceiver(MediaSsrc);
        // Two survivors, two losses (3001 and 3003 dropped).
        receiver.OnMediaPacket(group[0]);
        receiver.OnMediaPacket(group[2]);

        receiver.OnFecPacket(fec).Should().BeFalse();
        receiver.TryDequeueRecovered(new byte[1500], out _, out _).Should().BeFalse();
        receiver.GetStats().PacketsRecovered.Should().Be(0);
    }

    [Fact]
    public void A_late_survivor_after_a_second_loss_lets_the_group_recover()
    {
        // The FEC arrives while two packets are still missing (unrecoverable), then one of them arrives
        // by another path (a retransmission or a reordered packet), dropping the group to a single loss.
        var group = new[]
        {
            Media(4000, 7000, marker: false, payloadLength: 30),
            Media(4001, 7000, marker: false, payloadLength: 30),
            Media(4002, 7000, marker: true, payloadLength: 30),
        };
        var fec = ProduceFec(64, group);

        var receiver = new UlpFecReceiver(MediaSsrc);
        receiver.OnMediaPacket(group[0]); // 4001 and 4002 missing
        receiver.OnFecPacket(fec).Should().BeFalse();

        receiver.OnMediaPacket(group[2]); // now only 4001 missing → recover on this arrival

        var recovered = new byte[1500];
        receiver.TryDequeueRecovered(recovered, out var length, out var seq).Should().BeTrue();
        seq.Should().Be(4001);
        recovered[..length].Should().Equal(group[1]);
    }

    [Fact]
    public void An_intact_group_recovers_nothing()
    {
        var group = new[]
        {
            Media(5000, 9000, marker: false, payloadLength: 40),
            Media(5001, 9000, marker: true, payloadLength: 40),
        };
        var fec = ProduceFec(64, group);

        var receiver = new UlpFecReceiver(MediaSsrc);
        receiver.OnMediaPacket(group[0]);
        receiver.OnMediaPacket(group[1]);

        receiver.OnFecPacket(fec).Should().BeFalse();
        receiver.GetStats().PacketsRecovered.Should().Be(0);
    }

    [Fact]
    public void A_recovered_packet_is_not_recovered_a_second_time_by_an_overlapping_group()
    {
        // Two FEC packets protect overlapping groups; the first recovers the loss, and the second must
        // treat it as already present rather than recovering it again.
        var media = new[]
        {
            Media(6000, 1000, marker: false, payloadLength: 20),
            Media(6001, 1000, marker: false, payloadLength: 20),
            Media(6002, 1000, marker: false, payloadLength: 20),
        };
        var fecA = ProduceFec(64, media[0], media[1]);          // protects 6000,6001
        var fecB = ProduceFec(64, media[1], media[2]);          // protects 6001,6002

        var receiver = new UlpFecReceiver(MediaSsrc);
        receiver.OnMediaPacket(media[0]);
        receiver.OnMediaPacket(media[2]);       // 6001 missing

        receiver.OnFecPacket(fecA).Should().BeTrue();   // recovers 6001
        receiver.OnFecPacket(fecB).Should().BeFalse();  // 6001 already present, nothing to do

        receiver.GetStats().PacketsRecovered.Should().Be(1);
    }

    [Fact]
    public void The_generator_refuses_a_packet_outside_the_sixteen_packet_window()
    {
        var generator = new UlpFecGenerator(64);
        generator.TryAdd(Media(100, 0, false, 10)).Should().BeTrue();
        generator.TryAdd(Media(116, 0, false, 10)).Should().BeFalse(); // delta 16, past the short mask
        generator.Count.Should().Be(1);
    }

    [Fact]
    public void The_generator_refuses_a_packet_larger_than_it_was_sized_for()
    {
        var generator = new UlpFecGenerator(20);
        generator.TryAdd(Media(1, 0, false, 30)).Should().BeFalse();
        generator.Count.Should().Be(0);
    }
}
