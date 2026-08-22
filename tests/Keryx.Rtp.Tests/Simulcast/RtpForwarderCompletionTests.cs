using FluentAssertions;
using Keryx.Rtp;
using Keryx.Rtp.Simulcast;
using Xunit;

namespace Keryx.Rtp.Tests.Simulcast;

/// <summary>
/// Covers the forwarder's step-4 completions: cross-layer timestamp alignment from the RTCP
/// sender-report wall-clock mapping, and egress RID stripping / MID rewrite.
/// </summary>
public class RtpForwarderCompletionTests
{
    private const uint OutboundSsrc = 0xF00D;
    private static readonly SimulcastLayerId Hi = SimulcastLayerId.Parse("hi");
    private static readonly SimulcastLayerId Lo = SimulcastLayerId.Parse("lo");

    private static RtpForwardResult Forward(
        RtpForwarder forwarder,
        SimulcastLayerId layer,
        byte[] packet,
        bool canStartLayer,
        out RtpHeader outHeader,
        out int length)
    {
        RtpHeader.TryParse(packet, out var header).Should().BeTrue();
        var classification = new RtpLayerClassification(layer, header.Ssrc, IsRepair: false, RtpLayerClassificationSource.RidExtension);
        var payload = new byte[] { 0x0A, 0x0B, 0x0C, 0x0D };
        var destination = new byte[512];
        var result = forwarder.TryForward(classification, header, payload, canStartLayer, destination, out length);
        outHeader = default;
        if (result == RtpForwardResult.Forwarded)
        {
            RtpHeader.TryParse(destination.AsSpan(0, length), out outHeader).Should().BeTrue();
        }

        return result;
    }

    private static ulong Ntp(uint seconds, double fraction) =>
        ((ulong)seconds << 32) | (uint)(fraction * 4294967296.0);

    [Fact]
    public void TryForward_AlignsTimestampAcrossLayersFromSenderReports()
    {
        var forwarder = new RtpForwarder(OutboundSsrc, clockRate: 90000);

        // hi's clock: wall second 1000 corresponds to RTP 100000.
        forwarder.RecordSenderReport(Hi, Ntp(1000, 0.0), rtpTimestamp: 100000);
        // lo's clock: wall second 1000.5 corresponds to RTP 500000 (an unrelated random offset).
        forwarder.RecordSenderReport(Lo, Ntp(1000, 0.5), rtpTimestamp: 500000);

        forwarder.SelectLayer(Hi);
        Forward(forwarder, Hi, SimulcastTestPackets.Plain(0x1, 1000, 100000), canStartLayer: true, out var first, out _)
            .Should().Be(RtpForwardResult.Forwarded);
        first.Timestamp.Should().Be(100000u);

        // Switch to lo, landing on its keyframe. The outbound timestamp must advance from the last
        // emitted (100000) by the real time between the two layers' reference points: 0.5 s at 90 kHz
        // = 45000 ticks, independent of lo's random RTP offset.
        forwarder.SelectLayer(Lo);
        Forward(forwarder, Lo, SimulcastTestPackets.Plain(0x2, 40, 500000), canStartLayer: true, out var switched, out _)
            .Should().Be(RtpForwardResult.Forwarded);
        switched.Timestamp.Should().Be(145000u);

        // Within the new layer, inter-frame timestamp deltas are preserved.
        Forward(forwarder, Lo, SimulcastTestPackets.Plain(0x2, 41, 503000), canStartLayer: false, out var next, out _)
            .Should().Be(RtpForwardResult.Forwarded);
        next.Timestamp.Should().Be(148000u);
    }

    [Fact]
    public void TryForward_KeepsTimestampsMonotonicAcrossASwitchWithoutSenderReports()
    {
        var forwarder = new RtpForwarder(OutboundSsrc);

        forwarder.SelectLayer(Hi);
        Forward(forwarder, Hi, SimulcastTestPackets.Plain(0x1, 1000, 100000), canStartLayer: true, out var first, out _)
            .Should().Be(RtpForwardResult.Forwarded);

        forwarder.SelectLayer(Lo);
        Forward(forwarder, Lo, SimulcastTestPackets.Plain(0x2, 40, 500000), canStartLayer: true, out var switched, out _)
            .Should().Be(RtpForwardResult.Forwarded);

        // No sender report: fall back to a single-tick advance so egress never stalls or goes backwards.
        switched.Timestamp.Should().Be(unchecked(first.Timestamp + 1));

        Forward(forwarder, Lo, SimulcastTestPackets.Plain(0x2, 41, 503000), canStartLayer: false, out var next, out _)
            .Should().Be(RtpForwardResult.Forwarded);
        next.Timestamp.Should().Be(unchecked(switched.Timestamp + 3000));
    }

    [Fact]
    public void TryForward_StripsRidAndRewritesMidOnEgress()
    {
        var egress = new RtpEgressExtensions(RidElementId: 2, RepairedRidElementId: 3, MidElementId: 1, OutboundMid: "7");
        var forwarder = new RtpForwarder(OutboundSsrc, egressExtensions: egress);
        forwarder.SelectLayer(Hi);

        // Source carries MID (id 1 = "0"), RID (id 2 = "hi"), and abs-send-time (id 5).
        var packet = SimulcastTestPackets.WithExtensions(
            0x1, 1000, 90000, payloadType: 96, payload: null,
            (1, "0"), (2, "hi"), (5, "abc"));

        Forward(forwarder, Hi, packet, canStartLayer: true, out var header, out _)
            .Should().Be(RtpForwardResult.Forwarded);

        // RID is stripped on egress...
        header.TryGetExtension(2, out _).Should().BeFalse();

        // ...MID is rewritten to the subscriber's value...
        header.TryGetExtension(1, out var mid).Should().BeTrue();
        System.Text.Encoding.ASCII.GetString(mid).Should().Be("7");

        // ...and unrelated extensions are preserved untouched.
        header.TryGetExtension(5, out var abs).Should().BeTrue();
        System.Text.Encoding.ASCII.GetString(abs).Should().Be("abc");
    }

    [Fact]
    public void TryForward_DropsTheExtensionBlockWhenOnlyStrippedElementsRemain()
    {
        var egress = new RtpEgressExtensions(RidElementId: 2);
        var forwarder = new RtpForwarder(OutboundSsrc, egressExtensions: egress);
        forwarder.SelectLayer(Hi);

        var packet = SimulcastTestPackets.WithRid("hi", 0x1, 1000, 90000);

        Forward(forwarder, Hi, packet, canStartLayer: true, out var header, out _)
            .Should().Be(RtpForwardResult.Forwarded);

        header.HasExtension.Should().BeFalse();
        header.TryGetExtension(2, out _).Should().BeFalse();
    }
}
