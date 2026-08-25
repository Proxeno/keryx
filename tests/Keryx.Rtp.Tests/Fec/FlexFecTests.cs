using FluentAssertions;
using Keryx.Rtp.Fec;
using Xunit;

namespace Keryx.Rtp.Tests.Fec;

/// <summary>
/// Coverage for the FlexFEC (flexfec-03 / RFC 8627) flexible-mask generator, the packet round-trip for
/// each of the three mask widths, and the single-loss recovery path.
/// </summary>
public class FlexFecTests
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

    private static byte[] ProduceFec(uint protectedSsrc, int maxProtected, params byte[][] group)
    {
        var generator = new FlexFecGenerator(protectedSsrc, maxProtected);
        foreach (var packet in group)
        {
            generator.TryAdd(packet).Should().BeTrue();
        }

        var fec = new byte[generator.MaxFecPayloadSize];
        generator.TryProduce(fec, out var length).Should().BeTrue();
        return fec[..length];
    }

    // ------------------------------------------------------------------ header shape (RFC 8627 §4.2.2.1)

    [Fact]
    public void The_header_names_the_protected_ssrc_the_sequence_number_base_and_the_mask()
    {
        var group = new[]
        {
            Media(1000, 90_000, marker: false, payloadLength: 20),
            Media(1001, 90_000, marker: false, payloadLength: 40),
            Media(1002, 90_000, marker: true, payloadLength: 30),
        };
        var fec = ProduceFec(MediaSsrc, 200, group);

        FlexFecPacket.TryParse(fec, out var header).Should().BeTrue();
        header.IsRetransmission.Should().BeFalse();
        header.IsFixedBlock.Should().BeFalse();
        header.SsrcCount.Should().Be(1);
        header.ProtectedSsrc.Should().Be(MediaSsrc);
        header.SequenceNumberBase.Should().Be(1000);
        header.ProtectedCount.Should().Be(3);
        header.MaskBitCount.Should().Be(FlexFecPacket.ShortMaskBits);
        header.Protects(1000).Should().BeTrue();
        header.Protects(1001).Should().BeTrue();
        header.Protects(1002).Should().BeTrue();
        header.Protects(1003).Should().BeFalse();
        header.FecPayload.Length.Should().Be(40); // the largest post-header region in the group
    }

    // ------------------------------------------------------------------ mask-width round-trip

    [Theory]
    [InlineData(14, FlexFecPacket.ShortMaskBits)]   // max delta 14 -> 15-bit mask
    [InlineData(45, FlexFecPacket.MediumMaskBits)]  // a packet at delta 45 -> 46-bit mask
    [InlineData(109, FlexFecPacket.LongMaskBits)]   // a packet at delta 109 -> 110-bit mask
    public void The_mask_widens_to_cover_the_farthest_protected_packet(int farDelta, int expectedWidth)
    {
        const ushort baseSeq = 5000;
        // Base packet, a middle packet, and the farthest packet: a non-contiguous protected set.
        var group = new[]
        {
            Media(baseSeq, 3000, marker: false, payloadLength: 32),
            Media((ushort)(baseSeq + 7), 3000, marker: false, payloadLength: 48),
            Media((ushort)(baseSeq + farDelta), 3000, marker: true, payloadLength: 16),
        };
        var fec = ProduceFec(MediaSsrc, 200, group);

        FlexFecPacket.TryParse(fec, out var header).Should().BeTrue();
        header.MaskBitCount.Should().Be(expectedWidth);
        header.ProtectedCount.Should().Be(3);
        header.Protects(baseSeq).Should().BeTrue();
        header.Protects((ushort)(baseSeq + 7)).Should().BeTrue();
        header.Protects((ushort)(baseSeq + farDelta)).Should().BeTrue();
        // A packet inside the mask window but not in the protected set is not marked.
        header.Protects((ushort)(baseSeq + 1)).Should().BeFalse();
    }

    // ------------------------------------------------------------------ single-loss recovery (RFC 8627 §6.3)

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
        var fec = ProduceFec(MediaSsrc, 200, group);

        var receiver = new FlexFecReceiver(MediaSsrc);
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
    public void A_loss_is_recovered_across_a_non_contiguous_medium_mask()
    {
        // A protected set spread across a 46-bit mask, with the loss in the middle of the run.
        var group = new[]
        {
            Media(4000, 7000, marker: false, payloadLength: 40),
            Media(4020, 7000, marker: false, payloadLength: 55),
            Media(4045, 7000, marker: true, payloadLength: 30),
        };
        var fec = ProduceFec(MediaSsrc, 200, group);
        FlexFecPacket.TryParse(fec, out var header).Should().BeTrue();
        header.MaskBitCount.Should().Be(FlexFecPacket.MediumMaskBits);

        var receiver = new FlexFecReceiver(MediaSsrc);
        receiver.OnMediaPacket(group[0]);
        receiver.OnMediaPacket(group[2]); // 4020 missing

        receiver.OnFecPacket(fec).Should().BeTrue();
        var recovered = new byte[1500];
        receiver.TryDequeueRecovered(recovered, out var length, out var seq).Should().BeTrue();
        seq.Should().Be(4020);
        recovered[..length].Should().Equal(group[1]);
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
        var fec = ProduceFec(MediaSsrc, 64, group);

        var receiver = new FlexFecReceiver(MediaSsrc);
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
        var group = new[]
        {
            Media(4000, 7000, marker: false, payloadLength: 30),
            Media(4001, 7000, marker: false, payloadLength: 30),
            Media(4002, 7000, marker: true, payloadLength: 30),
        };
        var fec = ProduceFec(MediaSsrc, 64, group);

        var receiver = new FlexFecReceiver(MediaSsrc);
        receiver.OnMediaPacket(group[0]); // 4001 and 4002 missing
        receiver.OnFecPacket(fec).Should().BeFalse();

        receiver.OnMediaPacket(group[2]); // now only 4001 missing -> recover on this arrival

        var recovered = new byte[1500];
        receiver.TryDequeueRecovered(recovered, out var length, out var seq).Should().BeTrue();
        seq.Should().Be(4001);
        recovered[..length].Should().Equal(group[1]);
    }

    [Fact]
    public void A_single_bit_mask_recovers_the_one_protected_packet_a_retransmission_in_effect()
    {
        // FlexFEC expresses a retransmission as a one-packet protected set: the repair payload is that
        // packet's own post-header bytes, so recovery yields it exactly.
        var only = Media(9000, 1234, marker: true, payloadLength: 44);
        var fec = ProduceFec(MediaSsrc, 64, only);

        FlexFecPacket.TryParse(fec, out var header).Should().BeTrue();
        header.ProtectedCount.Should().Be(1);
        header.MaskBitCount.Should().Be(FlexFecPacket.ShortMaskBits);

        var receiver = new FlexFecReceiver(MediaSsrc);
        receiver.OnFecPacket(fec).Should().BeTrue(); // no survivors needed: the group is a single packet

        var recovered = new byte[1500];
        receiver.TryDequeueRecovered(recovered, out var length, out var seq).Should().BeTrue();
        seq.Should().Be(9000);
        recovered[..length].Should().Equal(only);
    }

    [Fact]
    public void A_fec_packet_for_a_different_source_ssrc_is_declined()
    {
        var group = new[]
        {
            Media(6000, 1000, marker: false, payloadLength: 20),
            Media(6001, 1000, marker: true, payloadLength: 20),
        };
        // The FEC protects MediaSsrc, but the receiver is bound to a different stream.
        var fec = ProduceFec(MediaSsrc, 64, group);
        var receiver = new FlexFecReceiver(0xDEAD_BEEF);
        receiver.OnMediaPacket(group[0]);

        receiver.OnFecPacket(fec).Should().BeFalse();
        receiver.GetStats().PacketsRecovered.Should().Be(0);
    }

    [Fact]
    public void A_recovered_packet_is_not_recovered_a_second_time_by_an_overlapping_group()
    {
        var media = new[]
        {
            Media(6000, 1000, marker: false, payloadLength: 20),
            Media(6001, 1000, marker: false, payloadLength: 20),
            Media(6002, 1000, marker: false, payloadLength: 20),
        };
        var fecA = ProduceFec(MediaSsrc, 64, media[0], media[1]);  // protects 6000,6001
        var fecB = ProduceFec(MediaSsrc, 64, media[1], media[2]);  // protects 6001,6002

        var receiver = new FlexFecReceiver(MediaSsrc);
        receiver.OnMediaPacket(media[0]);
        receiver.OnMediaPacket(media[2]);       // 6001 missing

        receiver.OnFecPacket(fecA).Should().BeTrue();   // recovers 6001
        receiver.OnFecPacket(fecB).Should().BeFalse();  // 6001 already present, nothing to do

        receiver.GetStats().PacketsRecovered.Should().Be(1);
    }

    [Fact]
    public void The_generator_refuses_a_packet_outside_the_hundred_ten_packet_window()
    {
        var generator = new FlexFecGenerator(MediaSsrc, 64);
        generator.TryAdd(Media(100, 0, false, 10)).Should().BeTrue();
        generator.TryAdd(Media(210, 0, false, 10)).Should().BeFalse(); // delta 110, past the widest mask
        generator.Count.Should().Be(1);
    }

    [Fact]
    public void The_generator_refuses_a_packet_larger_than_it_was_sized_for()
    {
        var generator = new FlexFecGenerator(MediaSsrc, 20);
        generator.TryAdd(Media(1, 0, false, 30)).Should().BeFalse();
        generator.Count.Should().Be(0);
    }
}
