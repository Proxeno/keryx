using FluentAssertions;
using Keryx.Rtp;
using Keryx.Rtp.Simulcast;
using Xunit;

namespace Keryx.Rtp.Tests.Simulcast;

public class SimulcastClassifierTests
{
    private static SimulcastClassifier NewClassifier() => new(new RtpStreamIdentifierExtensions(
        SimulcastTestPackets.MidId, SimulcastTestPackets.RidId, SimulcastTestPackets.RepairedRidId));

    [Fact]
    public void TryClassify_UsesRidExtensionAndLearnsSsrc()
    {
        var classifier = NewClassifier();
        RtpHeader.TryParse(SimulcastTestPackets.WithRid("hi", ssrc: 0xAAA, seq: 1, ts: 90), out var tagged).Should().BeTrue();

        classifier.TryClassify(tagged, out var first).Should().BeTrue();
        first.LayerId.Should().Be(SimulcastLayerId.Parse("hi"));
        first.IsRepair.Should().BeFalse();
        first.Source.Should().Be(RtpLayerClassificationSource.RidExtension);
        classifier.GetMediaSsrc(SimulcastLayerId.Parse("hi")).Should().Be(0xAAAu);
    }

    [Fact]
    public void TryClassify_FallsBackToLearnedSsrcWhenRidStops()
    {
        var classifier = NewClassifier();
        RtpHeader.TryParse(SimulcastTestPackets.WithRid("mid", ssrc: 0xBBB, seq: 1, ts: 90), out var tagged).Should().BeTrue();
        classifier.TryClassify(tagged, out _).Should().BeTrue();

        RtpHeader.TryParse(SimulcastTestPackets.Plain(ssrc: 0xBBB, seq: 2, ts: 180), out var untagged).Should().BeTrue();
        classifier.TryClassify(untagged, out var second).Should().BeTrue();
        second.LayerId.Should().Be(SimulcastLayerId.Parse("mid"));
        second.Source.Should().Be(RtpLayerClassificationSource.LearnedSsrc);
    }

    [Fact]
    public void TryClassify_MarksRepairPacketsFromRepairedRid()
    {
        var classifier = NewClassifier();
        RtpHeader.TryParse(SimulcastTestPackets.WithRepairedRid("hi", ssrc: 0xCCC, seq: 1, ts: 90), out var repair).Should().BeTrue();

        classifier.TryClassify(repair, out var result).Should().BeTrue();
        result.IsRepair.Should().BeTrue();
        result.LayerId.Should().Be(SimulcastLayerId.Parse("hi"));
        result.Source.Should().Be(RtpLayerClassificationSource.RepairedRidExtension);
    }

    [Fact]
    public void TryClassify_ReturnsFalseForUnknownUntaggedSsrc()
    {
        var classifier = NewClassifier();
        RtpHeader.TryParse(SimulcastTestPackets.Plain(ssrc: 0xDDD, seq: 1, ts: 90), out var untagged).Should().BeTrue();

        classifier.TryClassify(untagged, out var result).Should().BeFalse();
        result.Should().Be(default(RtpLayerClassification));
    }

    [Fact]
    public void TryClassify_DoesNotLearnSsrcBindingsWithoutBoundUnderAFlood()
    {
        var classifier = NewClassifier();

        // A peer stamps a RID on a flood of freshly invented SSRCs. Every packet still classifies from
        // the RID on the wire, but the SSRC->layer bindings retained for later untagged lookup must stay
        // bounded — otherwise the learned table grows without limit.
        const int flood = 500;
        const uint baseSsrc = 0x0001_0000u;
        for (var i = 0; i < flood; i++)
        {
            RtpHeader.TryParse(SimulcastTestPackets.WithRid("hi", baseSsrc + (uint)i, seq: 1, ts: 90), out var tagged)
                .Should().BeTrue();
            classifier.TryClassify(tagged, out var classification).Should().BeTrue();
            classification.Source.Should().Be(RtpLayerClassificationSource.RidExtension);
        }

        // The first SSRC was learned and still resolves an untagged packet by its learned binding.
        RtpHeader.TryParse(SimulcastTestPackets.Plain(baseSsrc, seq: 2, ts: 180), out var early).Should().BeTrue();
        classifier.TryClassify(early, out var earlyResult).Should().BeTrue();
        earlyResult.Source.Should().Be(RtpLayerClassificationSource.LearnedSsrc);

        // A late SSRC, past the learned-binding cap, was never retained: an untagged packet on it is
        // unknown, exactly as any un-learned source is — so the flood cannot grow the table without bound.
        RtpHeader.TryParse(SimulcastTestPackets.Plain(baseSsrc + flood - 1, seq: 2, ts: 180), out var late)
            .Should().BeTrue();
        classifier.TryClassify(late, out var lateResult).Should().BeFalse();
        lateResult.Should().Be(default(RtpLayerClassification));
    }

    [Fact]
    public void Reset_ForgetsLearnedBindings()
    {
        var classifier = NewClassifier();
        RtpHeader.TryParse(SimulcastTestPackets.WithRid("lo", ssrc: 0xEEE, seq: 1, ts: 90), out var tagged).Should().BeTrue();
        classifier.TryClassify(tagged, out _).Should().BeTrue();

        classifier.Reset();
        classifier.GetMediaSsrc(SimulcastLayerId.Parse("lo")).Should().BeNull();
    }
}
