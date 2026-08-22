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

    [Fact]
    public void TryTakeDeferred_FiresTheSuppressedRequestOnceWhenTheIntervalElapses()
    {
        var coalescer = new KeyframeRequestCoalescer(TimeSpan.FromMilliseconds(200));
        var hi = SimulcastLayerId.Parse("hi");
        coalescer.SetLayerUpstreamSsrc(hi, 0xABCD);
        coalescer.BindOutput(0x1, hi);
        coalescer.BindOutput(0x2, hi);

        coalescer.TryResolveUpstream(0x1, T0, out _).Should().BeTrue();

        // A second subscriber asks inside the interval: coalesced away, but remembered as deferred.
        coalescer.TryResolveUpstream(0x2, T0 + TimeSpan.FromMilliseconds(50), out _).Should().BeFalse();

        // Still inside the interval: nothing is due yet.
        coalescer.TryTakeDeferred(T0 + TimeSpan.FromMilliseconds(100), out _).Should().BeFalse();

        // The interval has elapsed: the deferred ask becomes due exactly once.
        coalescer.TryTakeDeferred(T0 + TimeSpan.FromMilliseconds(250), out var upstream).Should().BeTrue();
        upstream.Should().Be(0xABCDu);
        coalescer.TryTakeDeferred(T0 + TimeSpan.FromMilliseconds(300), out _).Should().BeFalse();
    }

    [Fact]
    public void TryTakeDeferred_ReturnsFalseWhenNothingWasCoalesced()
    {
        var coalescer = new KeyframeRequestCoalescer(TimeSpan.FromMilliseconds(200));
        var hi = SimulcastLayerId.Parse("hi");
        coalescer.SetLayerUpstreamSsrc(hi, 0xABCD);
        coalescer.BindOutput(0x1, hi);

        coalescer.TryResolveUpstream(0x1, T0, out _).Should().BeTrue();

        // The only request was granted, not suppressed, so nothing is deferred.
        coalescer.TryTakeDeferred(T0 + TimeSpan.FromSeconds(5), out _).Should().BeFalse();
    }

    [Fact]
    public void NextFirCommandSequence_IncrementsPerUpstreamIndependently()
    {
        var coalescer = new KeyframeRequestCoalescer(TimeSpan.FromMilliseconds(200));

        coalescer.NextFirCommandSequence(0xABCD).Should().Be(0);
        coalescer.NextFirCommandSequence(0xABCD).Should().Be(1);
        coalescer.NextFirCommandSequence(0xABCD).Should().Be(2);

        // A different upstream SSRC has its own independent command-sequence counter.
        coalescer.NextFirCommandSequence(0xBEEF).Should().Be(0);
        coalescer.NextFirCommandSequence(0xABCD).Should().Be(3);
    }
}
