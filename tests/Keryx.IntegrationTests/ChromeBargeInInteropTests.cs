using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using FluentAssertions;
using Keryx.Rtp;
using Keryx.Sctp;
using Keryx.Sdp;
using Xunit;
using Xunit.Abstractions;

namespace Keryx.IntegrationTests;

/// <summary>
/// End-to-end barge-in measurement against a real browser. Keryx sends a 440 Hz tone as the "old"
/// generation, then a barge-in cut followed by an 880 Hz "new" generation. The fixture classifies every
/// AudioWorklet render quantum by frequency, so the test can measure, from the browser's point of view,
/// how long the cut audio stayed audible, how much jitter-buffer residue there was, and how much the
/// decoder concealed after the new generation arrived.
/// </summary>
/// <remarks>
/// Excluded from CI (<c>Category=ChromeInterop</c>): it needs Google Chrome on the machine. The browser
/// path can be overridden with <c>KERYX_CHROME_PATH</c>.
/// </remarks>
public sealed class ChromeBargeInInteropTests
{
    private const int HttpPort = 7993;
    private const int FrameIncrement = 960; // 20 ms of Opus at 48 kHz
    private const string MeasurementPrefix = "BARGEIN-MEASURE ";

    private readonly ITestOutputHelper _output;

    /// <summary>Captures the xunit output sink.</summary>
    /// <param name="output">Where the measurement line lands.</param>
    public ChromeBargeInInteropTests(ITestOutputHelper output) => _output = output;

    [Fact]
    [Trait("Category", "ChromeInterop")]
    public async Task BargeInCutStopsOldAudioAndStartsAContiguousNewGeneration()
    {
        var chromePath = ChromeBrowser.Require();
        if (chromePath is null)
        {
            _output.WriteLine("SKIPPED: Google Chrome not found (set KERYX_CHROME_PATH to enable).");
            return;
        }

        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        var cancellationToken = shutdown.Token;

        var config = TestSupport.NewConfig();
        config.EnableCongestionControl = true;
        await using var peer = new PeerConnection(config);

        var oldPackets = OggOpusReader.ReadPackets(Path.Combine(AppContext.BaseDirectory, "assets", "tone-440.ogg"));
        var newPackets = OggOpusReader.ReadPackets(Path.Combine(AppContext.BaseDirectory, "assets", "tone-880.ogg"));
        oldPackets.Should().NotBeEmpty();
        newPackets.Should().NotBeEmpty();

        var audioSsrc = peer.GetLocalSsrc(MediaKind.Audio);

        // Generation 0 = old (440 Hz), 1 = new (880 Hz). The observer tags each wire packet with whichever
        // generation was current when it was sent, so the measurement can find the last old-gen send.
        var generation = 0;
        var wire = new ConcurrentQueue<WireRecord>();
        peer.RtpWireObserverForTest = (ReadOnlySpan<byte> rtp, long ticks) =>
        {
            var copy = rtp.ToArray();
            if (RtpPacket.TryParse(copy, out var packet) && packet.Header.Ssrc == audioSsrc)
            {
                wire.Enqueue(new WireRecord(
                    packet.Header.SequenceNumber,
                    packet.Header.Timestamp,
                    packet.Header.Marker,
                    ticks,
                    Volatile.Read(ref generation)));
            }
        };

        var controlTask = peer.CreateDataChannel("control");
        var offerSdp = await peer.CreateOfferAsync(cancellationToken);

        var latestReport = new object();
        string? latestReportJson = null;
        using var host = new InteropSignalingHost(HttpPort, _output)
        {
            PageAsset = "chrome-bargein.html",
        };
        host.OnGetOffer = () => Task.FromResult(offerSdp);
        host.OnAnswer = async sdp => await peer.SetRemoteDescriptionAsync(sdp, SdpType.Answer, cancellationToken);
        host.OnReport = json =>
        {
            lock (latestReport)
            {
                latestReportJson = json;
            }
        };
        host.Start(cancellationToken);

        var userDataDir = Path.Combine(Path.GetTempPath(), $"keryx-bargein-{Guid.NewGuid():N}");
        var chrome = ChromeBrowser.Launch(chromePath, $"http://127.0.0.1:{HttpPort}/", userDataDir);

        try
        {
            (await peer.WaitForConnectedAsync(TimeSpan.FromSeconds(20), cancellationToken))
                .Should().BeTrue("ICE + DTLS should complete against Chrome");

            string? SnapshotJson()
            {
                lock (latestReport)
                {
                    return latestReportJson;
                }
            }

            bool ReportSatisfies(Func<JsonElement, bool> predicate)
            {
                var snapshot = SnapshotJson();
                if (snapshot is null)
                {
                    return false;
                }

                using var document = JsonDocument.Parse(snapshot);
                return predicate(document.RootElement);
            }

            var control = await controlTask.WaitAsync(TimeSpan.FromSeconds(20), cancellationToken);
            (await TestSupport.WaitForAsync(() => control.State == DataChannelState.Open))
                .Should().BeTrue("the control channel should open");

            // Shared send cursor so the burst and both pumps keep one continuous application timeline.
            var audioGate = new object();
            long frames = 0;
            var stopPump = false;

            void SendPacket(byte[] packet)
            {
                lock (audioGate)
                {
                    if (stopPump)
                    {
                        return;
                    }

                    var timestamp = unchecked((uint)(frames * FrameIncrement));
                    frames++;
                    peer.SendAudioFrame(packet, timestamp);
                }
            }

            async Task PumpAsync(List<byte[]> packets, int milliseconds, CancellationToken token)
            {
                var clock = Stopwatch.StartNew();
                var next = TimeSpan.Zero;
                var index = 0;
                try
                {
                    while (!token.IsCancellationRequested && clock.Elapsed < TimeSpan.FromMilliseconds(milliseconds))
                    {
                        SendPacket(packets[index % packets.Count]);
                        index++;
                        next += TimeSpan.FromMilliseconds(20);
                        var wait = next - clock.Elapsed;
                        if (wait > TimeSpan.Zero)
                        {
                            await Task.Delay(wait, token).ConfigureAwait(false);
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    // stopped at the cut
                }
            }

            using var oldPumpCts = new CancellationTokenSource();
            var oldPump = PumpAsync(oldPackets, milliseconds: 60_000, oldPumpCts.Token);

            (await TestSupport.WaitForAsync(
                () => ReportSatisfies(IsPlaying),
                timeoutMilliseconds: 30_000)).Should().BeTrue(
                $"the browser should report phase=playing once the old tone is steady; last report: {SnapshotJson() ?? "(none)"}");

            // Simulate TTS running ahead of playout with a tight 10-packet burst, then cut. Holding the
            // pacer for this instant guarantees the burst is still queued when the cut runs, so the
            // measurement sees discarded packets rather than a drain that beat the cut.
            var paced = peer.PacedSenderForTest;
            paced.Should().NotBeNull();
            paced!.HoldDrainForTest = true;
            for (var i = 0; i < 10; i++)
            {
                SendPacket(oldPackets[i % oldPackets.Count]);
            }

            long cutStart;
            long cutEnd;
            double serverCutEpoch;
            OutboundCutResult cut;
            lock (audioGate)
            {
                // Under the same gate the pump sends through: guarantees no old-generation packet is
                // emitted between the cut and the pump actually stopping.
                stopPump = true;
                cutStart = Stopwatch.GetTimestamp();
                serverCutEpoch = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                cut = peer.CutOutboundAudio();
                cutEnd = Stopwatch.GetTimestamp();
            }

            paced.HoldDrainForTest = false;
            oldPumpCts.Cancel();
            await oldPump;

            control.SendText($"cut:{serverCutEpoch.ToString("F0", CultureInfo.InvariantCulture)}");
            Volatile.Write(ref generation, 1);

            await Task.Delay(400, cancellationToken);

            lock (audioGate)
            {
                stopPump = false;
            }

            await PumpAsync(newPackets, milliseconds: 1500, cancellationToken);

            (await TestSupport.WaitForAsync(
                () => ReportSatisfies(HasNewGeneration),
                timeoutMilliseconds: 10_000)).Should().BeTrue(
                "the browser should report firstNewEpoch and statsAfter");

            var finalJson = SnapshotJson();
            finalJson.Should().NotBeNull();
            using var final = JsonDocument.Parse(finalJson!);
            var root = final.RootElement;

            var records = wire.ToArray();
            var lastOld = records.Where(r => r.Generation == 0).ToArray();
            WireRecord? firstNew = records.Where(r => r.Generation == 1).Cast<WireRecord?>().FirstOrDefault();
            lastOld.Should().NotBeEmpty("the old generation must have reached the wire");
            firstNew.Should().NotBeNull("the new generation must have reached the wire");

            var lastOldWire = lastOld[^1];
            var cutToLastOldWireMs = Math.Max(
                0, (lastOldWire.Ticks - cutStart) * 1000.0 / Stopwatch.Frequency);
            var cutCallUs = (cutEnd - cutStart) * 1_000_000.0 / Stopwatch.Frequency;

            var lifetimeMs = ReadNullableDouble(root, "jb", "lifetimeMs");
            var recentMs = ReadNullableDouble(root, "jb", "recentMs");
            var lastOldEpoch = ReadNullableDouble(root, "lastOldEpoch");
            var firstNewEpoch = ReadNullableDouble(root, "firstNewEpoch");
            var cutSignalEpoch = ReadNullableDouble(root, "cutSignalEpoch");
            var audibleStopMs = lastOldEpoch - serverCutEpoch;
            var staleAfterSignalMs = lastOldEpoch - cutSignalEpoch;
            var oldAfterNew = root.TryGetProperty("oldAfterNew", out var oan) && oan.ValueKind == JsonValueKind.True;
            var concealedDelta = ReadNullableDouble(root, "newGenConcealedDelta");
            var lostDelta = ReadStatsDouble(root, "statsAfter", "packetsLost")
                - ReadStatsDouble(root, "statsAtCut", "packetsLost");

            var measurement =
                MeasurementPrefix
                + $"cutCallUs={cutCallUs.ToString("F0", CultureInfo.InvariantCulture)}"
                + $" cutToLastOldWireMs={cutToLastOldWireMs.ToString("F1", CultureInfo.InvariantCulture)}"
                + $" discardedPackets={cut.PacketsDiscarded.ToString(CultureInfo.InvariantCulture)}"
                + $" discardedSamples={cut.SamplesDiscarded.ToString(CultureInfo.InvariantCulture)}"
                + $" jitterResidueLifetimeMs={Format(lifetimeMs)}"
                + $" jitterResidueRecentMs={Format(recentMs)}"
                + $" audibleStopMs={Format(audibleStopMs)}"
                + $" staleAfterSignalMs={Format(staleAfterSignalMs)}"
                + $" oldAfterNew={oldAfterNew.ToString().ToLowerInvariant()}"
                + $" newGenConcealedDelta={Format(concealedDelta)}"
                + $" packetsLostDelta={Format(lostDelta)}";
            _output.WriteLine(measurement);
            Console.WriteLine(measurement);

            firstNewEpoch.Should().NotBeNull("the new generation must be audible at the browser");
            cutToLastOldWireMs.Should().BeLessThan(50, "a cut must stop old packets reaching the wire almost at once");
            oldAfterNew.Should().BeFalse("stale audio must never be counted after the new generation starts");

            firstNew!.Value.Marker.Should().BeTrue("the first packet of the new generation marks a talkspurt");
            firstNew.Value.SequenceNumber.Should().Be(
                unchecked((ushort)(lastOldWire.SequenceNumber + 1)),
                "the sequence space is rewound to the first discarded number");
            unchecked((int)(firstNew.Value.Timestamp - (lastOldWire.Timestamp + FrameIncrement)))
                .Should().BeGreaterThanOrEqualTo(0, "the new timestamp must be ahead of where the old audio ended");
        }
        finally
        {
            ChromeBrowser.Cleanup(chrome, userDataDir);
        }
    }

    private static bool IsPlaying(JsonElement root) =>
        root.TryGetProperty("phase", out var phase)
        && string.Equals(phase.GetString(), "playing", StringComparison.Ordinal);

    private static bool HasNewGeneration(JsonElement root) =>
        root.TryGetProperty("firstNewEpoch", out var epoch) && epoch.ValueKind == JsonValueKind.Number
        && root.TryGetProperty("statsAfter", out var after) && after.ValueKind == JsonValueKind.Object;

    private static double? ReadNullableDouble(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Number)
        {
            return null;
        }

        return value.GetDouble();
    }

    private static double? ReadNullableDouble(JsonElement root, string parent, string name)
    {
        if (!root.TryGetProperty(parent, out var parentElement) || parentElement.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        return ReadNullableDouble(parentElement, name);
    }

    private static double ReadStatsDouble(JsonElement root, string statsName, string field)
    {
        if (!root.TryGetProperty(statsName, out var stats) || stats.ValueKind != JsonValueKind.Object)
        {
            return 0;
        }

        return stats.TryGetProperty(field, out var value) && value.ValueKind == JsonValueKind.Number
            ? value.GetDouble()
            : 0;
    }

    private static string Format(double? value) =>
        value is { } number ? number.ToString("F1", CultureInfo.InvariantCulture) : "null";

    private readonly record struct WireRecord(
        ushort SequenceNumber,
        uint Timestamp,
        bool Marker,
        long Ticks,
        int Generation);
}
