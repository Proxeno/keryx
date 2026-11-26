using System.Buffers.Binary;
using FluentAssertions;
using Keryx.Core;
using Keryx.Rtp;
using Keryx.Rtp.Fec;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// Unit-level coverage of <see cref="PeerConnection.FecEmitter"/>: the transport-wide-cc stamping added
/// to FEC repair packets, the MTU reserve that keeps a repair inside the datagram budget, the adaptive
/// group size and the repair counters. No network is involved; the emitter is driven directly with a
/// capturing send delegate.
/// </summary>
public sealed class FecEmitterTests
{
    private const byte TransportCcExtensionId = 3;

    public enum Scheme
    {
        Ulpfec,
        FlexFec,
    }

    [Theory]
    [InlineData(Scheme.Ulpfec)]
    [InlineData(Scheme.FlexFec)]
    public void A_repair_packet_carries_transport_wide_cc_when_negotiated(Scheme scheme)
    {
        var harness = new Harness(scheme, TransportCcExtensionId);

        for (var i = 0; i < harness.Controller.GroupSize; i++)
        {
            harness.AddMedia(payloadLength: 40, timestamp: (uint)(i * 3000));
        }

        harness.Sent.Should().HaveCount(1, "one repair packet closes one full group");
        var repair = harness.Sent[0];
        RtpPacket.TryParse(repair, out var packet).Should().BeTrue();
        packet.Header.HasExtension.Should().BeTrue("the repair carries a transport-cc extension");

        PeerConnection.TryLocateTransportCc(repair.AsSpan(), TransportCcExtensionId, out var offset)
            .Should().BeTrue();
        BinaryPrimitives.ReadUInt16BigEndian(repair.AsSpan(offset, 2))
            .Should().Be(harness.FirstTransportSequence);

        harness.TransportSentEvents.Should().ContainSingle();
        harness.TransportSentEvents[0].Should().Be((harness.FirstTransportSequence, repair.Length));
        harness.DrawnSequences.Should().ContainSingle();

        harness.Order.Should().HaveCount(2);
        harness.Order[0].Should().Be("record", "the send history is fed before the packet is sent");
        harness.Order[1].Should().Be("send");
    }

    [Theory]
    [InlineData(Scheme.Ulpfec)]
    [InlineData(Scheme.FlexFec)]
    public void Without_transport_cc_the_repair_is_byte_identical_to_the_previous_encoding(Scheme scheme)
    {
        const int payloadLength = 40;
        var first = new Harness(scheme, transportCcExtensionId: null);
        var second = new Harness(scheme, transportCcExtensionId: null);

        for (var i = 0; i < first.Controller.GroupSize; i++)
        {
            first.AddMedia(payloadLength, timestamp: (uint)(i * 3000));
            second.AddMedia(payloadLength, timestamp: (uint)(i * 3000));
        }

        first.Sent.Should().HaveCount(1);
        second.Sent.Should().HaveCount(1);
        first.Sent[0].Should().Equal(second.Sent[0], "independent emitters produce identical bytes");

        RtpPacket.TryParse(first.Sent[0], out var packet).Should().BeTrue();
        packet.Header.HasExtension.Should().BeFalse("without TWCC the repair carries no extension");

        first.DrawnSequences.Should().BeEmpty();
        first.TransportSentEvents.Should().BeEmpty();

        // Repair = fixed RTP header + FEC framing (+ RED's primary header for ULPFEC) + the protected
        // post-header region, which here is exactly the media payload.
        var expected = scheme == Scheme.Ulpfec
            ? RtpHeader.FixedLength + RedPacket.PrimaryHeaderLength + UlpFecPacket.HeaderLength + payloadLength
            : RtpHeader.FixedLength + FlexFecPacket.MinHeaderLength + payloadLength;
        first.Sent[0].Length.Should().Be(expected);
    }

    [Theory]
    [InlineData(Scheme.Ulpfec)]
    [InlineData(Scheme.FlexFec)]
    public void No_transport_sequence_number_is_drawn_for_an_empty_group(Scheme scheme)
    {
        var harness = new Harness(scheme, TransportCcExtensionId);

        harness.Emitter.EmitPending(timestamp: 1234);

        harness.Sent.Should().BeEmpty();
        harness.DrawnSequences.Should().BeEmpty("a repair that is not produced must not burn a sequence number");
        harness.TransportSentEvents.Should().BeEmpty();
    }

    [Theory]
    [InlineData(Scheme.Ulpfec)]
    [InlineData(Scheme.FlexFec)]
    public void Recovery_still_works_with_the_transport_cc_extension_present(Scheme scheme)
    {
        var harness = new Harness(scheme, TransportCcExtensionId);
        const int droppedIndex = 3;

        for (var i = 0; i < harness.Controller.GroupSize; i++)
        {
            harness.AddMedia(payloadLength: 60, timestamp: (uint)(i * 3000));
        }

        harness.Sent.Should().HaveCount(1);
        RtpPacket.TryParse(harness.Sent[0], out var repair).Should().BeTrue();

        var recovered = new List<byte[]>();
        if (scheme == Scheme.Ulpfec)
        {
            var receiver = new UlpFecReceiver(Harness.MediaSsrc);
            for (var i = 0; i < harness.MediaPackets.Count; i++)
            {
                if (i != droppedIndex)
                {
                    receiver.OnMediaPacket(harness.MediaPackets[i]);
                }
            }

            RedPacket.TryReadPrimary(repair.Payload, out var innerPayloadType, out var innerData).Should().BeTrue();
            innerPayloadType.Should().Be(Harness.UlpfecPayloadType);
            receiver.OnFecPacket(innerData);
            Drain(receiver.TryDequeueRecovered, recovered);
        }
        else
        {
            var receiver = new FlexFecReceiver(Harness.MediaSsrc);
            for (var i = 0; i < harness.MediaPackets.Count; i++)
            {
                if (i != droppedIndex)
                {
                    receiver.OnMediaPacket(harness.MediaPackets[i]);
                }
            }

            receiver.OnFecPacket(repair.Payload);
            Drain(receiver.TryDequeueRecovered, recovered);
        }

        recovered.Should().HaveCount(1);
        recovered[0].Should().Equal(harness.MediaPackets[droppedIndex], "the recovered packet is byte-identical");
    }

    [Theory]
    [InlineData(Scheme.Ulpfec)]
    [InlineData(Scheme.FlexFec)]
    public void Group_size_follows_reported_loss(Scheme scheme)
    {
        var harness = new Harness(scheme, TransportCcExtensionId);

        harness.Emitter.OnReportedLoss(0.30).Should().BeTrue();
        harness.Emitter.GroupSize.Should().Be(3);

        harness.AddMedia(40, timestamp: 0);
        harness.AddMedia(40, timestamp: 3000);
        harness.Sent.Should().BeEmpty("the new group needs three media packets");

        harness.AddMedia(40, timestamp: 6000);
        harness.Sent.Should().HaveCount(1, "the next repair is emitted after three media packets");
    }

    [Theory]
    [InlineData(Scheme.Ulpfec)]
    [InlineData(Scheme.FlexFec)]
    public void A_group_holding_more_than_the_new_size_closes_on_the_next_media_packet(Scheme scheme)
    {
        var harness = new Harness(scheme, TransportCcExtensionId);

        for (var i = 0; i < 6; i++)
        {
            harness.AddMedia(40, timestamp: (uint)(i * 3000));
        }

        harness.Sent.Should().BeEmpty("six packets do not fill a group of ten");

        harness.Emitter.OnReportedLoss(0.30).Should().BeTrue();
        harness.Emitter.GroupSize.Should().Be(3);
        harness.Sent.Should().BeEmpty("shrinking the size alone does not emit a repair");

        harness.AddMedia(40, timestamp: 18_000);
        harness.Sent.Should().HaveCount(1, "the group already holds at least three packets");
    }

    [Theory]
    [InlineData(Scheme.Ulpfec, null)]
    [InlineData(Scheme.Ulpfec, (byte)3)]
    [InlineData(Scheme.FlexFec, null)]
    [InlineData(Scheme.FlexFec, (byte)3)]
    public void Media_payload_reserve_covers_the_repair_headers(Scheme scheme, byte? transportCcExtensionId)
    {
        var harness = new Harness(scheme, transportCcExtensionId);
        const int payloadLength = 100;

        for (var i = 0; i < harness.Controller.GroupSize; i++)
        {
            harness.AddMedia(payloadLength, timestamp: (uint)(i * 3000));
        }

        harness.Sent.Should().HaveCount(1);
        var repairLength = harness.Sent[0].Length;
        var mediaLength = harness.MediaPackets[0].Length;
        var reserve = PeerConnection.FecEmitter.MediaPayloadReserve(
            flexFec: scheme == Scheme.FlexFec,
            transportCcExtensionId);

        (repairLength - mediaLength).Should().BeLessThanOrEqualTo(
            reserve,
            "reserving this many bytes from the media payload keeps the repair inside the same MTU");
    }

    [Theory]
    [InlineData(Scheme.Ulpfec)]
    [InlineData(Scheme.FlexFec)]
    public void Repair_counters_track_emitted_packets(Scheme scheme)
    {
        var harness = new Harness(scheme, TransportCcExtensionId);
        for (var i = 0; i < 2 * harness.Controller.GroupSize; i++)
        {
            harness.AddMedia(40, timestamp: (uint)(i * 3000));
        }

        harness.Sent.Should().HaveCount(2);
        harness.Emitter.RepairPacketsSent.Should().Be(2);
        harness.Emitter.RepairBytesSent.Should().Be(harness.Sent.Sum(packet => packet.Length));
    }

    private static void Drain(
        TryDequeueRecoveredDelegate tryDequeue,
        List<byte[]> recovered)
    {
        var buffer = new byte[1500];
        while (tryDequeue(buffer, out var length, out _))
        {
            recovered.Add(buffer.AsSpan(0, length).ToArray());
        }
    }

    /// <summary>The receiver's dequeue signature, shared by both FEC receivers.</summary>
    private delegate bool TryDequeueRecoveredDelegate(Span<byte> destination, out int length, out ushort sequenceNumber);

    /// <summary>One emitter plus the media and repair senders feeding it, with captured output.</summary>
    private sealed class Harness
    {
        internal const uint MediaSsrc = 0x1111_2222;
        internal const byte UlpfecPayloadType = 118;
        private const uint FecSsrc = 0x3333_4444;
        private const byte MediaPayloadType = 96;
        private const byte RedPayloadType = 116;
        private const byte FlexFecPayloadType = 118;
        private const ushort InitialTransportSequence = 5000;

        private readonly RtpStreamSender _media;

        internal Harness(Scheme scheme, byte? transportCcExtensionId)
        {
            _media = new RtpStreamSender(MediaSsrc, MediaPayloadType, 90_000, initialSequenceNumber: 1000);
            if (scheme == Scheme.Ulpfec)
            {
                var fecStream = new RtpStreamSender(FecSsrc, RedPayloadType, 90_000, initialSequenceNumber: 40_000);
                Emitter = PeerConnection.FecEmitter.ForUlpfec(
                    new UlpFecGenerator(1200),
                    UlpfecPayloadType,
                    fecStream,
                    Controller,
                    srtpOverhead: 0,
                    Capture,
                    NullLogger.Instance,
                    transportCcExtensionId,
                    NextTransportSequence,
                    OnTransportSent);
            }
            else
            {
                var fecStream = new RtpStreamSender(FecSsrc, FlexFecPayloadType, 90_000, initialSequenceNumber: 40_000);
                Emitter = PeerConnection.FecEmitter.ForFlexFec(
                    new FlexFecGenerator(MediaSsrc, 1200),
                    fecStream,
                    Controller,
                    srtpOverhead: 0,
                    Capture,
                    NullLogger.Instance,
                    transportCcExtensionId,
                    NextTransportSequence,
                    OnTransportSent);
            }
        }

        internal FecProtectionController Controller { get; } = new();

        internal PeerConnection.FecEmitter Emitter { get; }

        internal List<byte[]> Sent { get; } = [];

        internal List<byte[]> MediaPackets { get; } = [];

        internal List<string> Order { get; } = [];

        internal List<ushort> DrawnSequences { get; } = [];

        internal List<(ushort Sequence, int Length)> TransportSentEvents { get; } = [];

        internal ushort FirstTransportSequence => InitialTransportSequence;

        private ushort _nextTransportSequence = InitialTransportSequence;

        internal bool AddMedia(int payloadLength, uint timestamp)
        {
            var payload = new byte[payloadLength];
            for (var i = 0; i < payload.Length; i++)
            {
                payload[i] = (byte)((timestamp + (i * 31)) & 0xFF);
            }

            var buffer = new byte[1500];
            var length = _media.WritePacket(payload, marker: false, timestamp, buffer);
            var packet = buffer.AsSpan(0, length).ToArray();
            MediaPackets.Add(packet);

            var ready = Emitter.AddMediaPacket(packet, timestamp);
            if (ready)
            {
                Emitter.EmitPending(timestamp);
            }

            return ready;
        }

        private ushort NextTransportSequence()
        {
            var sequence = _nextTransportSequence;
            _nextTransportSequence = unchecked((ushort)(sequence + 1));
            DrawnSequences.Add(sequence);
            return sequence;
        }

        private void OnTransportSent(ushort sequenceNumber, int length)
        {
            Order.Add("record");
            TransportSentEvents.Add((sequenceNumber, length));
        }

        private void Capture(byte[] buffer, int length)
        {
            Order.Add("send");
            Sent.Add(buffer.AsSpan(0, length).ToArray());
        }
    }
}
