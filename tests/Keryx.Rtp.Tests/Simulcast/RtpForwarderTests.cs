using FluentAssertions;
using Keryx.Rtp;
using Keryx.Rtp.Simulcast;
using Xunit;

namespace Keryx.Rtp.Tests.Simulcast;

public class RtpForwarderTests
{
    private const uint OutboundSsrc = 0xF00D;

    private static RtpForwardResult Offer(
        RtpForwarder forwarder,
        SimulcastLayerId layer,
        uint upstreamSsrc,
        ushort seq,
        uint ts,
        bool canStartLayer,
        out RtpHeader outHeader,
        out int length)
    {
        var classification = new RtpLayerClassification(layer, upstreamSsrc, IsRepair: false, RtpLayerClassificationSource.RidExtension);
        RtpHeader.TryParse(SimulcastTestPackets.Plain(upstreamSsrc, seq, ts), out var header).Should().BeTrue();
        var payload = new byte[] { 0x0A, 0x0B, 0x0C, 0x0D };
        var destination = new byte[256];
        var result = forwarder.TryForward(classification, header, payload, canStartLayer, destination, out length);
        outHeader = default;
        if (result == RtpForwardResult.Forwarded)
        {
            RtpHeader.TryParse(destination.AsSpan(0, length), out outHeader).Should().BeTrue();
        }

        return result;
    }

    [Fact]
    public void TryForward_DropsPacketsUntilALayerIsSelectedAndKeyframeArrives()
    {
        var forwarder = new RtpForwarder(OutboundSsrc);
        var hi = SimulcastLayerId.Parse("hi");

        // Nothing selected yet.
        Offer(forwarder, hi, 0x1, 1, 90, canStartLayer: true, out _, out _).Should().Be(RtpForwardResult.Dropped);

        forwarder.SelectLayer(hi);
        forwarder.IsSwitchPending.Should().BeTrue();

        // Selected, but a mid-GOP packet is not a safe switch point.
        Offer(forwarder, hi, 0x1, 2, 180, canStartLayer: false, out _, out _).Should().Be(RtpForwardResult.Dropped);

        // Keyframe boundary: the switch lands and the packet is forwarded and rewritten.
        Offer(forwarder, hi, 0x1, 3, 270, canStartLayer: true, out var header, out var length)
            .Should().Be(RtpForwardResult.Forwarded);
        length.Should().BeGreaterThan(RtpHeader.FixedLength);
        header.Ssrc.Should().Be(OutboundSsrc);
        forwarder.ActiveLayer.Should().Be(hi);
        forwarder.IsSwitchPending.Should().BeFalse();
    }

    [Fact]
    public void TryForward_KeepsSequenceNumbersContiguousAcrossALayerSwitch()
    {
        var forwarder = new RtpForwarder(OutboundSsrc);
        var hi = SimulcastLayerId.Parse("hi");
        var lo = SimulcastLayerId.Parse("lo");
        forwarder.SelectLayer(hi);

        Offer(forwarder, hi, 0x1, 1000, 90, canStartLayer: true, out var h1, out _).Should().Be(RtpForwardResult.Forwarded);
        Offer(forwarder, hi, 0x1, 1001, 180, canStartLayer: false, out var h2, out _).Should().Be(RtpForwardResult.Forwarded);
        h2.SequenceNumber.Should().Be((ushort)(h1.SequenceNumber + 1));

        // Switch to the low layer, whose own sequence numbering is unrelated.
        forwarder.SelectLayer(lo);
        Offer(forwarder, hi, 0x1, 1002, 270, canStartLayer: false, out var h3, out _).Should().Be(RtpForwardResult.Forwarded);
        Offer(forwarder, lo, 0x2, 40, 260, canStartLayer: true, out var h4, out _).Should().Be(RtpForwardResult.Forwarded);

        // Egress stays contiguous even though the low layer restarted at seq 40.
        h4.SequenceNumber.Should().Be((ushort)(h3.SequenceNumber + 1));
        h4.Ssrc.Should().Be(OutboundSsrc);
    }

    [Fact]
    public void TryForward_DropsRepairPackets()
    {
        var forwarder = new RtpForwarder(OutboundSsrc);
        var hi = SimulcastLayerId.Parse("hi");
        forwarder.SelectLayer(hi);

        var classification = new RtpLayerClassification(hi, 0x9, IsRepair: true, RtpLayerClassificationSource.RepairedRidExtension);
        RtpHeader.TryParse(SimulcastTestPackets.Plain(0x9, 1, 90), out var header).Should().BeTrue();
        forwarder.TryForward(classification, header, [0x1], canStartLayer: true, new byte[128], out _)
            .Should().Be(RtpForwardResult.Dropped);
    }

    [Fact]
    public void TryForward_ReportsBufferTooSmall()
    {
        var forwarder = new RtpForwarder(OutboundSsrc);
        var hi = SimulcastLayerId.Parse("hi");
        forwarder.SelectLayer(hi);

        var classification = new RtpLayerClassification(hi, 0x1, IsRepair: false, RtpLayerClassificationSource.RidExtension);
        RtpHeader.TryParse(SimulcastTestPackets.Plain(0x1, 1, 90), out var header).Should().BeTrue();
        forwarder.TryForward(classification, header, new byte[100], canStartLayer: true, new byte[8], out var written)
            .Should().Be(RtpForwardResult.BufferTooSmall);
        written.Should().Be(0);
    }

    // ------------------------------------------------------------------ RFC 4588 forward RTX

    private const uint RepairSsrc = 0xBEEF;
    private const byte RtxPayloadType = 97;

    private static RtpForwarder NewRtxForwarder() => new(
        OutboundSsrc,
        rtx: new RtpForwarderRtx(
            RepairSsrc,
            RtxPayloadType,
            InitialSequenceNumber: 40_000,
            RetransmitOptions: new RtxRetransmitOptions
            {
                MinimumResendInterval = TimeSpan.Zero,
                MaxBytesPerSecond = 0,
            }));

    [Fact]
    public void A_forwarder_without_rtx_answers_a_nack_with_a_history_miss()
    {
        var forwarder = new RtpForwarder(OutboundSsrc);
        forwarder.RtxEnabled.Should().BeFalse();
        forwarder.RtxSsrc.Should().BeNull();

        forwarder.TryRetransmit(1000, new byte[1500], out var length).Should().Be(RtxRetransmitResult.HistoryMiss);
        length.Should().Be(0);
    }

    [Fact]
    public void A_forwarded_packet_is_answered_as_an_rtx_repair_on_the_repair_stream()
    {
        var forwarder = NewRtxForwarder();
        var hi = SimulcastLayerId.Parse("hi");
        forwarder.SelectLayer(hi);

        forwarder.RtxEnabled.Should().BeTrue();
        forwarder.RtxSsrc.Should().Be(RepairSsrc);
        forwarder.RtxPayloadType.Should().Be(RtxPayloadType);

        // Forward a keyframe: the first forwarded packet keeps the upstream numbering (offset 0), so the
        // subscriber sees seq 1000 — the sequence number a downstream NACK would name.
        var mediaPayload = new byte[] { 0x0A, 0x0B, 0x0C, 0x0D };
        var classification = new RtpLayerClassification(hi, 0x1, IsRepair: false, RtpLayerClassificationSource.RidExtension);
        RtpHeader.TryParse(SimulcastTestPackets.Plain(0x1, 1000, 90, payload: mediaPayload), out var header).Should().BeTrue();
        forwarder.TryForward(classification, header, mediaPayload, canStartLayer: true, new byte[256], out _)
            .Should().Be(RtpForwardResult.Forwarded);

        // Answer the NACK for the forwarded sequence number.
        var repair = new byte[forwarder.MaxRtxPacketSize];
        forwarder.TryRetransmit(1000, repair, out var length).Should().Be(RtxRetransmitResult.Retransmitted);

        // The repair rides the repair stream's own SSRC and payload type (RFC 4588 §4).
        RtpPacket.TryParse(repair.AsSpan(0, length), out var repairPacket).Should().BeTrue();
        repairPacket.Header.Ssrc.Should().Be(RepairSsrc);
        repairPacket.Header.PayloadType.Should().Be(RtxPayloadType);

        // Decapsulating with the forwarded stream's SSRC and payload type restores the forwarded packet:
        // the OSN is the forwarded sequence number, and the payload is the forwarded media verbatim.
        var recovered = new byte[256];
        RtxPacket.TryDecapsulate(repair.AsSpan(0, length), OutboundSsrc, 96, recovered, out var recoveredLength, out var osn)
            .Should().BeTrue();
        osn.Should().Be(1000);
        RtpPacket.TryParse(recovered.AsSpan(0, recoveredLength), out var recoveredMedia).Should().BeTrue();
        recoveredMedia.Header.Ssrc.Should().Be(OutboundSsrc);
        recoveredMedia.Header.SequenceNumber.Should().Be((ushort)1000);
        recoveredMedia.Payload.ToArray().Should().Equal(mediaPayload);
    }

    [Fact]
    public void A_relayed_layers_rtx_is_reassembled_and_forwarded_as_media()
    {
        var forwarder = NewRtxForwarder();
        var hi = SimulcastLayerId.Parse("hi");
        forwarder.SelectLayer(hi);

        // Establish the active layer on a keyframe so the recovered packet has a segment to ride.
        var classification = new RtpLayerClassification(hi, 0x1, IsRepair: false, RtpLayerClassificationSource.RidExtension);
        RtpHeader.TryParse(SimulcastTestPackets.Plain(0x1, 1000, 90), out var header).Should().BeTrue();
        forwarder.TryForward(classification, header, new byte[] { 0x1 }, canStartLayer: true, new byte[256], out _)
            .Should().Be(RtpForwardResult.Forwarded);

        // Build an inbound RTX packet repairing seq 1001 of the hi layer's media stream (upstream SSRC 0x1).
        var recoveredPayload = new byte[] { 0x11, 0x22, 0x33, 0x44 };
        var rtxPayload = new byte[RtxPacket.OriginalSequenceNumberLength + recoveredPayload.Length];
        RtxPacket.WritePayload(1001, recoveredPayload, rtxPayload);
        var rtxStream = new RtpStreamSender(0x9, RtxPayloadType, 90_000, 5, 90);
        var rtxBuffer = new byte[256];
        var rtxLength = rtxStream.WritePacket(rtxPayload, marker: false, 180, rtxBuffer);

        // Reassemble it: the OSN restores seq 1001, and the recovered media packet forwards on the
        // outbound stream contiguously after the keyframe (out seq 1000 -> 1001).
        var repairClassification = new RtpLayerClassification(hi, 0x9, IsRepair: true, RtpLayerClassificationSource.RepairedRidExtension);
        var destination = new byte[256];
        forwarder.TryForwardRtx(repairClassification, rtxBuffer.AsSpan(0, rtxLength), originalMediaSsrc: 0x1, originalPayloadType: 96, canStartLayer: false, destination, out var length)
            .Should().Be(RtpForwardResult.Forwarded);

        RtpPacket.TryParse(destination.AsSpan(0, length), out var forwarded).Should().BeTrue();
        forwarded.Header.Ssrc.Should().Be(OutboundSsrc);
        forwarded.Header.SequenceNumber.Should().Be((ushort)1001);
        forwarded.Payload.ToArray().Should().Equal(recoveredPayload);
    }

    [Fact]
    public void A_reassembled_relayed_repair_is_itself_answerable_as_a_forwarded_rtx()
    {
        var forwarder = NewRtxForwarder();
        var hi = SimulcastLayerId.Parse("hi");
        forwarder.SelectLayer(hi);

        var classification = new RtpLayerClassification(hi, 0x1, IsRepair: false, RtpLayerClassificationSource.RidExtension);
        RtpHeader.TryParse(SimulcastTestPackets.Plain(0x1, 1000, 90), out var header).Should().BeTrue();
        forwarder.TryForward(classification, header, new byte[] { 0x1 }, canStartLayer: true, new byte[256], out _)
            .Should().Be(RtpForwardResult.Forwarded);

        var recoveredPayload = new byte[] { 0x55, 0x66 };
        var rtxPayload = new byte[RtxPacket.OriginalSequenceNumberLength + recoveredPayload.Length];
        RtxPacket.WritePayload(1001, recoveredPayload, rtxPayload);
        var rtxStream = new RtpStreamSender(0x9, RtxPayloadType, 90_000, 5, 90);
        var rtxBuffer = new byte[256];
        var rtxLength = rtxStream.WritePacket(rtxPayload, marker: false, 180, rtxBuffer);

        var repairClassification = new RtpLayerClassification(hi, 0x9, IsRepair: true, RtpLayerClassificationSource.RepairedRidExtension);
        forwarder.TryForwardRtx(repairClassification, rtxBuffer.AsSpan(0, rtxLength), originalMediaSsrc: 0x1, originalPayloadType: 96, canStartLayer: false, new byte[256], out _)
            .Should().Be(RtpForwardResult.Forwarded);

        // The recovered-then-forwarded packet entered the send history under its forwarded seq, so a
        // downstream NACK for it is served like any other forwarded packet — RTX is end-to-end.
        var repair = new byte[forwarder.MaxRtxPacketSize];
        forwarder.TryRetransmit(1001, repair, out var length).Should().Be(RtxRetransmitResult.Retransmitted);
        RtxPacket.TryDecapsulate(repair.AsSpan(0, length), OutboundSsrc, 96, new byte[256], out _, out var osn)
            .Should().BeTrue();
        osn.Should().Be(1001);
    }
}
