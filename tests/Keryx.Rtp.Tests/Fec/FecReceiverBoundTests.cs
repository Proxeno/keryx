using FluentAssertions;
using Keryx.Rtp.Fec;
using Xunit;

namespace Keryx.Rtp.Tests.Fec;

/// <summary>
/// The FEC receivers hold a bounded list of repair packets they cannot yet resolve (a group missing two
/// or more media packets is kept in case a survivor still arrives). A flood of such unrecoverable repair
/// packets must not grow memory without limit: once the cap is reached the oldest pending repair packet
/// is evicted, so a repair whose survivors arrive only after it was evicted no longer recovers anything.
/// </summary>
public class FecReceiverBoundTests
{
    private const uint MediaSsrc = 0x0A0B_0C0D;
    private const byte MediaPayloadType = 96;
    private const int MaxPending = 4;
    private const int GroupSize = 3;
    private const int Groups = 32;
    private const ushort Base = 1000;

    [Fact]
    public void Ulpfec_pending_repair_list_is_bounded_and_evicts_the_oldest()
    {
        var receiver = new UlpFecReceiver(MediaSsrc, capacity: 256, maxPendingFec: MaxPending);

        // Flood the receiver with unrecoverable repair packets — each group's every member is missing, so
        // no repair can resolve — far past the cap. If the pending list were unbounded this would retain
        // all of them; the cap keeps only the most recent MaxPending.
        for (var g = 0; g < Groups; g++)
        {
            receiver.OnFecPacket(BuildUlpfecPayload(g)).Should().BeFalse();
        }

        receiver.GetStats().FecPacketsObserved.Should().Be(Groups);
        receiver.GetStats().PacketsRecovered.Should().Be(0);

        // The oldest group (0) was evicted long ago: supplying two of its three survivors cannot recover
        // its missing member, because its repair packet is no longer held.
        FeedSurvivors(receiver, group: 0, missingWithinGroup: 2);
        receiver.GetStats().PacketsRecovered.Should().Be(0, "the oldest repair packet was evicted by the bound");

        // The newest group is still within the retained window: supplying two of its three survivors leaves
        // exactly one loss, which its retained repair packet rebuilds.
        FeedSurvivors(receiver, group: Groups - 1, missingWithinGroup: 2);
        receiver.GetStats().PacketsRecovered.Should().Be(1, "a repair still inside the bound recovers its one loss");
    }

    [Fact]
    public void Flexfec_pending_repair_list_is_bounded_and_evicts_the_oldest()
    {
        var receiver = new FlexFecReceiver(MediaSsrc, capacity: 256, maxPendingFec: MaxPending);

        for (var g = 0; g < Groups; g++)
        {
            receiver.OnFecPacket(BuildFlexfecPayload(g)).Should().BeFalse();
        }

        receiver.GetStats().FecPacketsObserved.Should().Be(Groups);
        receiver.GetStats().PacketsRecovered.Should().Be(0);

        FeedFlexSurvivors(receiver, group: 0, missingWithinGroup: 2);
        receiver.GetStats().PacketsRecovered.Should().Be(0, "the oldest repair packet was evicted by the bound");

        FeedFlexSurvivors(receiver, group: Groups - 1, missingWithinGroup: 2);
        receiver.GetStats().PacketsRecovered.Should().Be(1, "a repair still inside the bound recovers its one loss");
    }

    private static byte[] BuildUlpfecPayload(int group)
    {
        var generator = new UlpFecGenerator(1200);
        foreach (var packet in GroupPackets(group))
        {
            generator.TryAdd(packet).Should().BeTrue();
        }

        var payload = new byte[generator.MaxFecPayloadSize];
        generator.TryProduce(payload, out var length).Should().BeTrue();
        return payload[..length];
    }

    private static byte[] BuildFlexfecPayload(int group)
    {
        var generator = new FlexFecGenerator(MediaSsrc, 1200);
        foreach (var packet in GroupPackets(group))
        {
            generator.TryAdd(packet).Should().BeTrue();
        }

        var payload = new byte[generator.MaxFecPayloadSize];
        generator.TryProduce(payload, out var length).Should().BeTrue();
        return payload[..length];
    }

    private static void FeedSurvivors(UlpFecReceiver receiver, int group, int missingWithinGroup)
    {
        var index = 0;
        foreach (var packet in GroupPackets(group))
        {
            if (index++ != missingWithinGroup)
            {
                receiver.OnMediaPacket(packet);
            }
        }
    }

    private static void FeedFlexSurvivors(FlexFecReceiver receiver, int group, int missingWithinGroup)
    {
        var index = 0;
        foreach (var packet in GroupPackets(group))
        {
            if (index++ != missingWithinGroup)
            {
                receiver.OnMediaPacket(packet);
            }
        }
    }

    // Three consecutive media packets for one group, each with a distinct sequence number and payload.
    private static IEnumerable<byte[]> GroupPackets(int group)
    {
        var sender = new RtpStreamSender(
            MediaSsrc,
            MediaPayloadType,
            90_000,
            initialSequenceNumber: (ushort)(Base + (group * GroupSize)),
            initialTimestamp: (uint)(group * 3000));

        for (var i = 0; i < GroupSize; i++)
        {
            var payload = new byte[24 + i];
            for (var b = 0; b < payload.Length; b++)
            {
                payload[b] = (byte)((group * 5 + i * 11 + b) & 0xFF);
            }

            var buffer = new byte[RtpHeader.FixedLength + payload.Length];
            var length = sender.WritePacket(payload, marker: i == GroupSize - 1, buffer);
            yield return buffer[..length];
        }
    }
}
