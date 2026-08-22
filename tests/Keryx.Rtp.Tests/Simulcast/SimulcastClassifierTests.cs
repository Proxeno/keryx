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
    public void Reset_ForgetsLearnedBindings()
    {
        var classifier = NewClassifier();
        RtpHeader.TryParse(SimulcastTestPackets.WithRid("lo", ssrc: 0xEEE, seq: 1, ts: 90), out var tagged).Should().BeTrue();
        classifier.TryClassify(tagged, out _).Should().BeTrue();

        classifier.Reset();
        classifier.GetMediaSsrc(SimulcastLayerId.Parse("lo")).Should().BeNull();
    }
}
