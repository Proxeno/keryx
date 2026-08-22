using FluentAssertions;
using Keryx.Rtp;
using Keryx.Rtp.Simulcast;
using Xunit;

namespace Keryx.Rtp.Tests.Simulcast;

public class RtpStreamIdentifierTests
{
    [Fact]
    public void TryGetRid_ReadsTheRidElement()
    {
        var packet = SimulcastTestPackets.WithRid("hi", ssrc: 0x1111, seq: 10, ts: 1000);
        RtpHeader.TryParse(packet, out var header).Should().BeTrue();

        RtpStreamIdentifier.TryGetRid(header, SimulcastTestPackets.RidId, out var layer).Should().BeTrue();
        layer.ToString().Should().Be("hi");
    }

    [Fact]
    public void TryGetRepairedRid_ReadsTheRepairedRidElement()
    {
        var packet = SimulcastTestPackets.WithRepairedRid("lo", ssrc: 0x2222, seq: 5, ts: 500);
        RtpHeader.TryParse(packet, out var header).Should().BeTrue();

        RtpStreamIdentifier.TryGetRepairedRid(header, SimulcastTestPackets.RepairedRidId, out var layer).Should().BeTrue();
        layer.ToString().Should().Be("lo");
    }

    [Fact]
    public void TryGetRid_ReturnsFalseWhenExtensionAbsent()
    {
        var packet = SimulcastTestPackets.Plain(ssrc: 0x3333, seq: 1, ts: 90);
        RtpHeader.TryParse(packet, out var header).Should().BeTrue();

        RtpStreamIdentifier.TryGetRid(header, SimulcastTestPackets.RidId, out _).Should().BeFalse();
    }

    [Fact]
    public void TryGetRid_ReturnsFalseWhenExtensionNotNegotiated()
    {
        var packet = SimulcastTestPackets.WithRid("hi", ssrc: 0x4444, seq: 1, ts: 90);
        RtpHeader.TryParse(packet, out var header).Should().BeTrue();

        // Element id 0 means the RID extension was not negotiated.
        RtpStreamIdentifier.TryGetRid(header, 0, out _).Should().BeFalse();
    }
}
