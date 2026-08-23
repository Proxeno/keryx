using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace Keryx.IntegrationTests;

/// <summary>
/// The quantified case for sender-side repair: a seeded lossy link under a Keryx sender's SRTP, a
/// Keryx receiver that detects gaps and asks for them back with RFC 4585 generic NACKs, and RFC 4588
/// RTX either on or off. With RTX on the detectable window comes back whole; with RTX off the same
/// seed leaves exactly the holes the link punched.
/// </summary>
public sealed class RtxLossSweepTests
{
    private readonly ITestOutputHelper _output;

    /// <summary>Captures the xunit output sink.</summary>
    /// <param name="output">Where each run's measurements are written.</param>
    public RtxLossSweepTests(ITestOutputHelper output) => _output = output;

    private static CancellationToken TestTimeout(int seconds = 120) =>
        new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    [Theory]
    [InlineData(0.01, 1.0)]
    [InlineData(0.05, 1.0)]
    [InlineData(0.15, 0.995)]
    public async Task RetransmissionRepairsUniformLoss(double lossRate, double requiredCompleteness)
    {
        var report = await LossRecoveryHarness.RunAsync(
            new LossScenario
            {
                Name = $"uniform {lossRate:P0} loss, RTX on",
                Seed = 0x10551 + (int)(lossRate * 1000),
                DropProbability = lossRate,
            },
            _output,
            TestTimeout());

        report.PacketsOffered.Should().BeGreaterThan(500, "the sweep must push enough media to be meaningful");
        report.PacketsDropped.Should().BeGreaterThan(0, "the injector must actually have dropped packets");
        report.InjectedLossRate.Should().BeApproximately(lossRate, lossRate * 0.4);
        report.StillConnected.Should().BeTrue();

        // RFC 4588 §1: retransmission is only useful if the repair arrives in time to be used, which
        // is what the send history's retention window buys. Everything the receiver could detect as
        // missing must therefore come back.
        report.Completeness.Should().BeGreaterThanOrEqualTo(requiredCompleteness);
        report.RecoveredByRtx.Should().BeGreaterThan(0);
        report.MalformedRepairs.Should().Be(0, "every RTX packet must decapsulate per RFC 4588 §4");

        var rtx = report.Retransmission!.Value;
        rtx.NacksReceived.Should().BeGreaterThan(0);
        rtx.PacketsRetransmitted.Should().BeGreaterThanOrEqualTo(report.RecoveredByRtx);
        rtx.NackRequestedPackets.Should().BeGreaterThanOrEqualTo(rtx.PacketsRetransmitted);
        rtx.BytesRetransmitted.Should().BeGreaterThan(0);

        // Every request is either served, missed, or suppressed; nothing may vanish unaccounted for.
        (rtx.PacketsRetransmitted + rtx.HistoryMisses + rtx.Suppressed)
            .Should().Be(rtx.NackRequestedPackets);
    }

    [Theory]
    [InlineData(0.01)]
    [InlineData(0.05)]
    [InlineData(0.15)]
    public async Task WithoutRetransmissionTheSameLossIsPermanent(double lossRate)
    {
        var report = await LossRecoveryHarness.RunAsync(
            new LossScenario
            {
                Name = $"uniform {lossRate:P0} loss, RTX off",
                Seed = 0x10551 + (int)(lossRate * 1000),
                EnableRetransmission = false,
                DropProbability = lossRate,

                // Nothing will ever fill these gaps, so there is no tail worth waiting on.
                SettleMilliseconds = 750,
            },
            _output,
            TestTimeout());

        report.Retransmission.Should().BeNull("no repair stream was negotiated");
        report.RecoveredByRtx.Should().Be(0);
        report.PacketsDropped.Should().BeGreaterThan(0);
        report.StillConnected.Should().BeTrue();

        // Without a repair stream a NACK is a congestion signal and nothing more: every packet the
        // link swallowed inside the detectable window stays lost.
        report.Holes.Should().BeGreaterThan(0);
        report.Holes.Should().Be(
            report.WindowSize - report.ArrivedDirectly,
            "with no repair stream, a hole is exactly a packet the link dropped");
        report.Completeness.Should().BeLessThan(1.0);
        _output.WriteLine(
            $"RTX off at {lossRate:P0}: {report.Holes} permanent holes in a {report.WindowSize}-packet window "
            + $"({1 - report.Completeness:P2} of the stream lost).");
    }

    [Fact]
    public async Task RetransmissionTurnsPermanentLossIntoACompleteStream()
    {
        const double lossRate = 0.05;
        const int seed = 0xB0554;

        var without = await LossRecoveryHarness.RunAsync(
            new LossScenario
            {
                Name = "A/B 5% loss, RTX off",
                Seed = seed,
                EnableRetransmission = false,
                DropProbability = lossRate,
                Frames = 400,
            },
            _output,
            TestTimeout());

        var with = await LossRecoveryHarness.RunAsync(
            new LossScenario
            {
                Name = "A/B 5% loss, RTX on",
                Seed = seed,
                DropProbability = lossRate,
                Frames = 400,
            },
            _output,
            TestTimeout());

        _output.WriteLine(
            $"A/B at {lossRate:P0} loss, seed {seed}: holes {without.Holes} -> {with.Holes}; "
            + $"completeness {without.Completeness:P2} -> {with.Completeness:P2}.");

        without.Holes.Should().BeGreaterThan(0);
        with.Holes.Should().Be(0);
        with.RecoveredByRtx.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task RetransmissionRepairsBurstLoss()
    {
        var report = await LossRecoveryHarness.RunAsync(
            new LossScenario
            {
                Name = "10-packet bursts, RTX on",
                Seed = 0xB0757,
                BurstEvery = 60,
                BurstLength = 10,
            },
            _output,
            TestTimeout());

        report.PacketsDropped.Should().BeGreaterThan(50, "several bursts must have fired");
        report.MalformedRepairs.Should().Be(0);
        report.StillConnected.Should().BeTrue();

        // A burst is the hard case for a rate limit: ten consecutive sequence numbers arrive in one
        // NACK, and RFC 4585 §6.2.1's BLP covers sixteen, so a single feedback packet asks for all of
        // them and the send history has to answer in one pass.
        report.Completeness.Should().Be(1.0);
        report.RecoveredByRtx.Should().BeGreaterThan(50);
    }

    [Fact]
    public async Task ReorderingAndDuplicationDoNotConfuseTheRepairPath()
    {
        var report = await LossRecoveryHarness.RunAsync(
            new LossScenario
            {
                Name = "reorder + duplicate + jitter, RTX on",
                Seed = 0x2E07D,
                DuplicateProbability = 0.03,
                ReorderProbability = 0.05,
                ReorderDistance = 5,
                MinDelay = TimeSpan.FromMilliseconds(1),
                MaxDelay = TimeSpan.FromMilliseconds(12),
                Frames = 400,
            },
            _output,
            TestTimeout());

        report.PacketsDuplicated.Should().BeGreaterThan(0);
        report.PacketsReordered.Should().BeGreaterThan(0);
        report.PacketsDropped.Should().Be(0, "this scenario impairs order, not delivery");
        report.StillConnected.Should().BeTrue();
        report.Completeness.Should().Be(1.0);
        report.MalformedRepairs.Should().Be(0);

        // Nothing was dropped, so nothing was truly lost: every packet arrived directly.
        report.RecoveredByRtx.Should().Be(0);
        report.ArrivedDirectly.Should().Be(report.WindowSize);

        // RFC 3711 §3.3.2 makes the receiver's replay list refuse a link-level duplicate before it can
        // reach the media path, so ReceiverSrtpRejections is not a no-op counter here. But exactly how
        // many rejections that produces is not a count worth asserting: the injector queues each of a
        // duplicate's two copies through its own independently-jittered delay and hands them to a real
        // pump thread, so which copy the SRTP layer sees first — and therefore whether the second is
        // caught as "already seen" or as "too old, the window already slid past it" while the first is
        // still in flight — depends on real wall-clock scheduling that a fixed seed cannot pin down.
        // Under full-suite CPU contention that has put the observed count one off from PacketsDuplicated
        // in either direction with the repair path never actually confused, so a tight bound on it was
        // testing scheduling luck, not correctness. What the replay list exists to guarantee — and what
        // does not depend on scheduling — is the end state below: no link-level duplicate ever reaches
        // the consumer as a second media delivery. The only duplicate deliveries allowed here are
        // decapsulated RTX repairs the receiver served into the media path for packets a NACK asked for
        // during their reorder delay and that then also arrived directly — at most one per retransmitted
        // packet, and never a link-level replay slipping through.
        report.DuplicateArrivals.Should().BeLessThanOrEqualTo(
            (int)report.Retransmission!.Value.PacketsRetransmitted);
    }
}
