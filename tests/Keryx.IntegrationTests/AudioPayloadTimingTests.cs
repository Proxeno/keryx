using FluentAssertions;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// Unit coverage for <see cref="AudioPayloadTiming"/> (the codec-to-duration rules) and the additive
/// <see cref="OutboundCutResult"/> members that report a cut's sample rate, duration and generation.
/// </summary>
public sealed class AudioPayloadTimingTests
{
    [Theory]
    [InlineData("opus")]
    [InlineData("OPUS")]
    public void OpusReadsItsDurationFromTheTocAt48k(string encodingName)
    {
        var timing = AudioPayloadTiming.FromCodec(encodingName, 48_000);

        timing.IsKnown.Should().BeTrue();
        timing.SampleRate.Should().Be(48_000);
        timing.GetSamples(OpusTone()).Should().Be(960);
        timing.TryGetRtpTicks(OpusTone(), out var ticks).Should().BeTrue();
        ticks.Should().Be(960);
    }

    [Theory]
    [InlineData("PCMU")]
    [InlineData("PCMA")]
    public void G711CountsOneSamplePerPayloadByte(string encodingName)
    {
        var payload = new byte[160];
        var timing = AudioPayloadTiming.FromCodec(encodingName, 8_000);

        timing.IsKnown.Should().BeTrue();
        timing.SampleRate.Should().Be(8_000);
        timing.GetSamples(payload).Should().Be(160);
        timing.TryGetRtpTicks(payload, out var ticks).Should().BeTrue();
        ticks.Should().Be(160);
    }

    [Fact]
    public void G722CountsTwoSamplesPerByteButOneRtpTickPerByte()
    {
        var payload = new byte[160];
        var timing = AudioPayloadTiming.FromCodec("G722", 8_000);

        timing.IsKnown.Should().BeTrue();
        timing.SampleRate.Should().Be(16_000, "G.722 samples at 16 kHz on an 8 kHz RTP clock");
        timing.GetSamples(payload).Should().Be(320);
        timing.TryGetRtpTicks(payload, out var ticks).Should().BeTrue();
        ticks.Should().Be(160);
    }

    [Fact]
    public void AnUnknownCodecReportsNoGuess()
    {
        var payload = new byte[160];
        foreach (var encodingName in new string?[] { "L16", null })
        {
            var timing = AudioPayloadTiming.FromCodec(encodingName, 16_000);

            timing.IsKnown.Should().BeFalse();
            timing.SampleRate.Should().Be(0);
            timing.GetSamples(payload).Should().Be(OutboundCutResult.UnknownSamples);
            timing.TryGetRtpTicks(payload, out var ticks).Should().BeFalse();
            ticks.Should().Be(0);
        }
    }

    [Fact]
    public void DefaultIsUnknown()
    {
        var timing = default(AudioPayloadTiming);

        timing.IsKnown.Should().BeFalse();
        timing.SampleRate.Should().Be(0);
        timing.GetSamples(new byte[160]).Should().Be(OutboundCutResult.UnknownSamples);
        timing.TryGetRtpTicks(new byte[160], out var ticks).Should().BeFalse();
        ticks.Should().Be(0);
    }

    [Theory]
    [InlineData(1600, 8000)]
    [InlineData(3200, 16000)]
    [InlineData(9600, 48000)]
    public void DurationDiscardedConvertsSamplesAtTheReportedRate(long samples, int sampleRate)
    {
        var result = new OutboundCutResult(10, samples) { SampleRate = sampleRate };

        result.DurationDiscarded.Should().Be(TimeSpan.FromMilliseconds(200));
    }

    [Fact]
    public void DurationDiscardedIsNullWhenTheCodecIsUnknown()
    {
        var result = new OutboundCutResult(10, OutboundCutResult.UnknownSamples);

        result.SampleRate.Should().Be(0);
        result.DurationDiscarded.Should().BeNull();
    }

    [Fact]
    public void AnEmptyOrDefaultCutHasZeroDuration()
    {
        default(OutboundCutResult).DurationDiscarded.Should().Be(TimeSpan.Zero);
        new OutboundCutResult(0, 0).DurationDiscarded.Should().Be(TimeSpan.Zero);
    }

    [Fact]
    public void ThePositionalConstructorAndDeconstructionStillWork()
    {
        var result = new OutboundCutResult(10, 1600) { SampleRate = 8000 };

        var (packets, samples) = result;
        packets.Should().Be(10);
        samples.Should().Be(1600);
        result.PacketsDiscarded.Should().Be(10);
        result.SamplesDiscarded.Should().Be(1600);
    }

    /// <summary>One 20 ms CELT Opus packet, shaped like <c>Tone()</c> in the cut tests.</summary>
    private static byte[] OpusTone()
    {
        var packet = new byte[80];
        packet[0] = 0xFC; // Opus TOC: CELT, one 20 ms frame
        return packet;
    }
}
