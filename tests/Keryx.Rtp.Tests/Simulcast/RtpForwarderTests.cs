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
}
