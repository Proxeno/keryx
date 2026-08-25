using FluentAssertions;
using Keryx.Rtp.Fec;
using Xunit;

namespace Keryx.Rtp.Tests.Fec;

/// <summary>
/// An end-to-end loopback over the real FlexFEC send and receive components: a media stream is
/// protected in fixed groups, exactly one packet per group is dropped in flight, and the receiver must
/// still deliver every media packet — the missing one rebuilt from the group's FlexFEC repair packet,
/// which rides its own SSRC and sequence space (no RED wrapping, unlike ULPFEC).
/// </summary>
public class FlexFecLoopbackTests
{
    private const uint MediaSsrc = 0x1111_2222;
    private const uint FlexFecSsrc = 0x3333_4444;
    private const byte MediaPayloadType = 96;
    private const byte FlexFecPayloadType = 118;
    private const int GroupSize = 4;

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void Every_media_packet_arrives_despite_one_drop_per_group(int dropWithinGroup)
    {
        const int groups = 6;
        var mediaSender = new RtpStreamSender(MediaSsrc, MediaPayloadType, 90_000, initialSequenceNumber: 1000);
        var fecSender = new RtpStreamSender(FlexFecSsrc, FlexFecPayloadType, 90_000, initialSequenceNumber: 40_000);
        var generator = new FlexFecGenerator(MediaSsrc, 1200);
        var receiver = new FlexFecReceiver(MediaSsrc);

        var sent = new Dictionary<ushort, byte[]>();
        var delivered = new HashSet<ushort>();

        for (var g = 0; g < groups; g++)
        {
            generator.Reset();
            var groupPackets = new List<byte[]>();

            for (var i = 0; i < GroupSize; i++)
            {
                var payload = new byte[16 + (i * 20)]; // varied lengths across the group
                for (var b = 0; b < payload.Length; b++)
                {
                    payload[b] = (byte)((g * 7 + i * 13 + b) & 0xFF);
                }

                var buffer = new byte[RtpHeader.FixedLength + payload.Length];
                var length = mediaSender.WritePacket(payload, marker: i == GroupSize - 1, buffer);
                mediaSender.AdvanceTimestamp(3000);
                var packet = buffer[..length];

                var seq = ReadSeq(packet);
                sent[seq] = packet;
                groupPackets.Add(packet);
                generator.TryAdd(packet).Should().BeTrue();
            }

            // Emit the FlexFEC repair packet for the group: an ordinary RTP packet on the FEC SSRC whose
            // payload is the FlexFEC repair payload verbatim.
            var fecPayload = new byte[generator.MaxFecPayloadSize];
            generator.TryProduce(fecPayload, out var fecLength).Should().BeTrue();

            var fecRtp = new byte[RtpHeader.FixedLength + fecLength];
            var fecRtpLength = fecSender.WritePacket(fecPayload.AsSpan(0, fecLength), marker: false, fecRtp);

            // The lossy channel: drop one chosen media packet, deliver the rest and the FEC packet.
            for (var i = 0; i < GroupSize; i++)
            {
                if (i == dropWithinGroup)
                {
                    continue;
                }

                DeliverMedia(receiver, groupPackets[i], delivered);
            }

            DeliverFec(receiver, fecRtp.AsSpan(0, fecRtpLength), delivered);
        }

        delivered.Should().BeEquivalentTo(sent.Keys, "every sent media packet is delivered, recovered ones included");
        receiver.GetStats().PacketsRecovered.Should().Be(groups, "one packet per group was recovered");
    }

    private static void DeliverMedia(FlexFecReceiver receiver, byte[] mediaRtp, HashSet<ushort> delivered)
    {
        RtpPacket.TryParse(mediaRtp, out var packet).Should().BeTrue();
        packet.Header.PayloadType.Should().Be(MediaPayloadType);
        packet.Header.Ssrc.Should().Be(MediaSsrc);
        delivered.Add(packet.Header.SequenceNumber);
        receiver.OnMediaPacket(mediaRtp);
        DrainRecovered(receiver, delivered);
    }

    private static void DeliverFec(FlexFecReceiver receiver, ReadOnlySpan<byte> fecRtp, HashSet<ushort> delivered)
    {
        RtpPacket.TryParse(fecRtp, out var packet).Should().BeTrue();
        packet.Header.PayloadType.Should().Be(FlexFecPayloadType);
        packet.Header.Ssrc.Should().Be(FlexFecSsrc); // the FEC rides its own SSRC

        // No RED decode: the FlexFEC repair payload is the RTP payload directly.
        receiver.OnFecPacket(packet.Payload);
        DrainRecovered(receiver, delivered);
    }

    private static void DrainRecovered(FlexFecReceiver receiver, HashSet<ushort> delivered)
    {
        var buffer = new byte[1500];
        while (receiver.TryDequeueRecovered(buffer, out var length, out var seq))
        {
            // A recovered packet is a well-formed media RTP packet on the media SSRC.
            RtpPacket.TryParse(buffer.AsSpan(0, length), out var packet).Should().BeTrue();
            packet.Header.Ssrc.Should().Be(MediaSsrc);
            packet.Header.SequenceNumber.Should().Be(seq);
            delivered.Add(seq);
        }
    }

    private static ushort ReadSeq(ReadOnlySpan<byte> packet) =>
        (ushort)((packet[2] << 8) | packet[3]);
}
