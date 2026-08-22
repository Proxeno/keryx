using FluentAssertions;
using Keryx.Rtp.Simulcast;
using Xunit;

namespace Keryx.Rtp.Tests.Simulcast;

public class KeyframeRequestCoalescerTests
{
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void TryResolveUpstream_MapsOutboundSsrcToLearnedUpstreamSsrc()
    {
        var coalescer = new KeyframeRequestCoalescer(TimeSpan.FromMilliseconds(200));
        var hi = SimulcastLayerId.Parse("hi");
        coalescer.BindOutput(subscriberOutboundSsrc: 0xF00D, hi);
        coalescer.SetLayerUpstreamSsrc(hi, upstreamSsrc: 0xABCD);

        coalescer.TryResolveUpstream(0xF00D, T0, out var upstream).Should().BeTrue();
        upstream.Should().Be(0xABCDu);
    }

    [Fact]
    public void TryResolveUpstream_CoalescesRequestsWithinTheInterval()
    {
        var coalescer = new KeyframeRequestCoalescer(TimeSpan.FromMilliseconds(200));
        var hi = SimulcastLayerId.Parse("hi");
        coalescer.SetLayerUpstreamSsrc(hi, 0xABCD);
        coalescer.BindOutput(0x1, hi);
        coalescer.BindOutput(0x2, hi);

        coalescer.TryResolveUpstream(0x1, T0, out _).Should().BeTrue();

        // A second subscriber on the same layer inside the interval is coalesced away.
        coalescer.TryResolveUpstream(0x2, T0 + TimeSpan.FromMilliseconds(50), out _).Should().BeFalse();

        // After the interval, an upstream request is allowed again.
        coalescer.TryResolveUpstream(0x2, T0 + TimeSpan.FromMilliseconds(250), out var upstream).Should().BeTrue();
        upstream.Should().Be(0xABCDu);
    }

    [Fact]
    public void TryResolveUpstream_ReturnsFalseForUnknownOutputOrLayer()
    {
        var coalescer = new KeyframeRequestCoalescer(TimeSpan.FromMilliseconds(200));
        coalescer.TryResolveUpstream(0xDEAD, T0, out _).Should().BeFalse();

        // Output bound, but the layer's upstream SSRC has not been learned yet.
        coalescer.BindOutput(0xF00D, SimulcastLayerId.Parse("lo"));
        coalescer.TryResolveUpstream(0xF00D, T0, out _).Should().BeFalse();
    }
}
