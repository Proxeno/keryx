using System.Globalization;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace Keryx.IntegrationTests;

/// <summary>
/// A long, lossy, continuously repairing session: five minutes of 30 fps H.264 across a link that
/// drops 5% of the video stream, reorders some of the rest and jitters everything, with the receiver
/// NACKing throughout. It exists to catch what a short test cannot — a send history that grows, a
/// delay queue that never drains, a counter that runs away, a session that quietly drops out.
/// </summary>
/// <remarks>
/// Excluded from the default run (<c>Category=Soak</c>); run it with
/// <c>--filter "Category=Soak"</c>. <c>KERYX_SOAK_SECONDS</c> overrides the duration.
/// </remarks>
public sealed class RtxSoakTests
{
    private readonly ITestOutputHelper _output;

    /// <summary>Captures the xunit output sink.</summary>
    /// <param name="output">Where the soak's summary table is written.</param>
    public RtxSoakTests(ITestOutputHelper output) => _output = output;

    [Fact]
    [Trait("Category", "Soak")]
    public async Task FiveMinutesOfLossyVideoRepairsWithoutDrifting()
    {
        var seconds = int.TryParse(
            Environment.GetEnvironmentVariable("KERYX_SOAK_SECONDS"),
            CultureInfo.InvariantCulture,
            out var configured) && configured > 0
            ? configured
            : 300;

        // 30 fps is what a real encoder hands a sender; the asset's access units average a little
        // over three RTP packets each, so this is roughly a 1 Mbit/s stream.
        const int paceMilliseconds = 33;
        var frames = seconds * 1000 / paceMilliseconds;

        var samples = new List<Sample>();
        var connectedThroughout = true;
        var nextSample = TimeSpan.FromSeconds(30);
        var progressLock = new object();

        void OnProgress(LossProgress progress)
        {
            lock (progressLock)
            {
                connectedThroughout &= progress.Connected;
                if (progress.Elapsed < nextSample)
                {
                    return;
                }

                nextSample = progress.Elapsed + TimeSpan.FromSeconds(30);
                samples.Add(new Sample(progress, SettledHeapBytes()));
            }
        }

        var report = await LossRecoveryHarness.RunAsync(
            new LossScenario
            {
                Name = $"soak: {seconds}s at 5% loss + reorder",
                Seed = 0x50A4,
                DropProbability = 0.05,
                ReorderProbability = 0.02,
                ReorderDistance = 4,
                MinDelay = TimeSpan.FromMilliseconds(1),
                MaxDelay = TimeSpan.FromMilliseconds(10),
                Frames = frames,
                FramePaceMilliseconds = paceMilliseconds,
                NackIntervalMilliseconds = 80,
                SettleMilliseconds = 3000,
                OnProgress = OnProgress,
            },
            _output,
            new CancellationTokenSource(TimeSpan.FromSeconds(seconds + 120)).Token);

        // ------------------------------------------------------------------ the summary table
        var culture = CultureInfo.InvariantCulture;
        _output.WriteLine(string.Empty);
        _output.WriteLine("  elapsed   sent   dropped  arrived  recovered  managed heap  connected");
        foreach (var sample in samples)
        {
            _output.WriteLine(string.Format(
                culture,
                "  {0,6:F0}s {1,6} {2,9} {3,8} {4,10} {5,12:N0}  {6}",
                sample.Progress.Elapsed.TotalSeconds,
                sample.Progress.PacketsSent,
                sample.Progress.Dropped,
                sample.Progress.Arrived,
                sample.Progress.Recovered,
                sample.HeapBytes,
                sample.Progress.Connected));
        }

        samples.Should().HaveCountGreaterThan(2, "the soak must run long enough to sample a trend");

        var baseline = samples[0].HeapBytes;
        var final = samples[^1].HeapBytes;
        var peak = samples.Max(s => s.HeapBytes);
        _output.WriteLine(string.Empty);
        _output.WriteLine(string.Format(
            culture,
            "  managed heap: baseline {0:N0} B at {1:F0}s, final {2:N0} B, peak {3:N0} B, drift {4:+#,##0;-#,##0;0} B ({5:P1})",
            baseline,
            samples[0].Progress.Elapsed.TotalSeconds,
            final,
            peak,
            final - baseline,
            (final - baseline) / (double)baseline));

        // ------------------------------------------------------------------ stability
        connectedThroughout.Should().BeTrue("the session must stay connected for the whole soak");
        report.StillConnected.Should().BeTrue();

        // The send history is a fixed arena and the retransmitter reuses one scratch buffer, so a
        // steady-state sender must not accumulate heap. 4 MB of slack absorbs the runtime's own
        // fragmentation and the test host's logging.
        final.Should().BeLessThan(
            baseline + (4L * 1024 * 1024),
            "a send history that grew would show up as monotonic managed-heap growth");
        peak.Should().BeLessThan(baseline + (8L * 1024 * 1024));

        // ------------------------------------------------------------------ counters
        var rtx = report.Retransmission!.Value;
        rtx.PacketsRetransmitted.Should().BeGreaterThan(0);
        (rtx.PacketsRetransmitted + rtx.HistoryMisses + rtx.Suppressed).Should().Be(rtx.NackRequestedPackets);
        rtx.HistoryMisses.Should().BeLessThan(
            rtx.NackRequestedPackets / 10,
            "at 30 fps the one-second send history covers a NACK round trip many times over");
        report.MalformedRepairs.Should().Be(0);
        report.Completeness.Should().BeGreaterThan(0.999);

        // The injector's delay machinery is bounded by construction; a soak is where an unbounded one
        // would show.
        report.DelayQueueOverflows.Should().Be(0);
        report.DelayQueueHighWater.Should().BeLessThan(64);
    }

    private static long SettledHeapBytes()
    {
        GC.Collect(2, GCCollectionMode.Forced, blocking: true);
        GC.WaitForPendingFinalizers();
        GC.Collect(2, GCCollectionMode.Forced, blocking: true);
        return GC.GetTotalMemory(forceFullCollection: true);
    }

    private readonly record struct Sample(LossProgress Progress, long HeapBytes);
}
