using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace Keryx.IntegrationTests;

/// <summary>
/// The claim that matters, checked against the only receiver that counts: a real browser. Keryx
/// offers RFC 4588 retransmission, Chrome's answer keeps the <c>rtx</c> codec, and a seeded 5% of
/// the video stream is then thrown away below Keryx's SRTP. The same session is run twice — once
/// with retransmission and once without — so Chrome's own <c>getStats()</c> says what the repair
/// stream is worth.
/// </summary>
/// <remarks>
/// Excluded from CI (<c>Category=ChromeInterop</c>): it needs Google Chrome on the machine, whose
/// path can be overridden with <c>KERYX_CHROME_PATH</c>.
/// </remarks>
public sealed class ChromeLossInteropTests
{
    private const int HttpPort = 7981;
    private const double InjectedLossRate = 0.05;
    private const int MediaSeconds = 15;

    private readonly ITestOutputHelper _output;

    /// <summary>Captures the xunit output sink.</summary>
    /// <param name="output">Where the measured browser-side numbers land.</param>
    public ChromeLossInteropTests(ITestOutputHelper output) => _output = output;

    [Fact]
    [Trait("Category", "ChromeInterop")]
    public async Task ChromeNacksAndKeryxRepairsWhatTheLinkDestroyed()
    {
        var chromePath = ChromeBrowser.Require();
        if (chromePath is null)
        {
            _output.WriteLine("SKIPPED: Google Chrome not found (set KERYX_CHROME_PATH to enable).");
            return;
        }

        var withRtx = await RunSessionAsync(chromePath, enableRetransmission: true);
        var withoutRtx = await RunSessionAsync(chromePath, enableRetransmission: false);

        _output.WriteLine(string.Empty);
        _output.WriteLine(Describe("RTX on ", withRtx));
        _output.WriteLine(Describe("RTX off", withoutRtx));

        // ------------------------------------------------------------------ the link really was lossy
        withRtx.Dropped.Should().BeGreaterThan(20);
        withoutRtx.Dropped.Should().BeGreaterThan(20);

        // ------------------------------------------------------------------ Chrome asked (RFC 4585 §6.2.1)
        withRtx.NackCount.Should().BeGreaterThan(0, "Chrome must NACK the packets the link swallowed");

        // ------------------------------------------------------------------ Keryx served (RFC 4588 §4)
        var rtx = withRtx.Retransmission!.Value;
        rtx.NacksReceived.Should().BeGreaterThan(0);
        rtx.PacketsRetransmitted.Should().BeGreaterThan(0);
        rtx.BytesRetransmitted.Should().BeGreaterThan(0);
        (rtx.PacketsRetransmitted + rtx.HistoryMisses + rtx.Suppressed).Should().Be(rtx.NackRequestedPackets);

        // ------------------------------------------------------------------ Chrome received the repairs
        // retransmittedPacketsReceived is the browser's own count of RFC 4588 repairs it accepted, so
        // this is Chrome confirming, from the far side of the link, what Keryx's counters claim.
        withRtx.RetransmittedPacketsReceived.Should().BeGreaterThan(0);
        withRtx.RetransmittedPacketsReceived.Should().BeGreaterThanOrEqualTo(
            (long)(withRtx.Dropped * 0.8),
            "nearly everything the link destroyed should come back as a repair");
        withRtx.RetransmittedPacketsReceived.Should().BeLessThanOrEqualTo(rtx.PacketsRetransmitted);

        // Without the repair codec there is no repair stream, so nothing comes back however much
        // Chrome asks: RFC 4585 bare nack on its own is a congestion signal, not a repair mechanism.
        withoutRtx.Retransmission.Should().BeNull();
        withoutRtx.RetransmittedPacketsReceived.Should().Be(0);

        // ------------------------------------------------------------------ what the viewer sees
        // Chrome's packetsLost counts gaps in the *media* stream's sequence numbers and is not walked
        // back when the repair stream fills them, so it tracks injected loss in both runs. The
        // difference shows up where it matters: in frames that decode.
        withRtx.PacketsLost.Should().BeGreaterThan(0);
        withRtx.FramesDecoded.Should().BeGreaterThan(
            withoutRtx.FramesDecoded,
            "repaired packets complete frames that would otherwise be discarded");
        withRtx.FreezeCount.Should().BeLessThanOrEqualTo(withoutRtx.FreezeCount);
        withRtx.KeyFramesDecoded.Should().BeGreaterThan(0);

        // Decoding kept up throughout, not just at the end.
        withRtx.DecodedSeries.Should().BeInAscendingOrder().And.HaveCountGreaterThan(10);
        withRtx.DecodedSeries[^1].Should().BeGreaterThan(withRtx.DecodedSeries[0]);
        withRtx.ConnectionState.Should().Be("connected");
        withRtx.FramesPerSecond.Should().BeGreaterThan(20, "a repaired 30 fps stream should decode at 30 fps");

        _output.WriteLine(string.Empty);
        _output.WriteLine(string.Format(
            CultureInfo.InvariantCulture,
            "  repair delta: framesDecoded {0:N0} -> {1:N0} (+{2:N0}), freezes {3} -> {4}, "
                + "repairs accepted by Chrome {5:N0} of {6:N0} dropped",
            withoutRtx.FramesDecoded,
            withRtx.FramesDecoded,
            withRtx.FramesDecoded - withoutRtx.FramesDecoded,
            withoutRtx.FreezeCount,
            withRtx.FreezeCount,
            withRtx.RetransmittedPacketsReceived,
            withRtx.Dropped));
    }

    private static string Describe(string label, ChromeRun run) => string.Format(
        CultureInfo.InvariantCulture,
        "  {0}: injected {1:N0}/{2:N0} dropped ({3:P2}) | keryx nacks={4:N0} retransmitted={5:N0} "
            + "misses={6:N0} suppressed={7:N0} | chrome recv={8:N0} lost={9:N0} nack={10:N0} repairs={11:N0} "
            + "| decoded={12:N0} keyframes={13:N0} fps={14} freezes={15}",
        label,
        run.Dropped,
        run.Offered,
        run.Offered == 0 ? 0 : run.Dropped / (double)run.Offered,
        run.Retransmission?.NacksReceived ?? 0,
        run.Retransmission?.PacketsRetransmitted ?? 0,
        run.Retransmission?.HistoryMisses ?? 0,
        run.Retransmission?.Suppressed ?? 0,
        run.PacketsReceived,
        run.PacketsLost,
        run.NackCount,
        run.RetransmittedPacketsReceived,
        run.FramesDecoded,
        run.KeyFramesDecoded,
        run.FramesPerSecond,
        run.FreezeCount);

    private async Task<ChromeRun> RunSessionAsync(string chromePath, bool enableRetransmission)
    {
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(120));
        var cancellationToken = shutdown.Token;

        uint mediaSsrc = 0;
        var offeredPackets = 0;
        var droppedPackets = 0;
        FaultInjectingDatagramTransport? injector = null;

        var config = TestSupport.NewConfig();
        config.EnableRetransmission = enableRetransmission;
        var profile = new FaultProfile
        {
            DropProbability = InjectedLossRate,
            Selector = datagram => DatagramClassifier.IsSrtpMedia(datagram)
                && DatagramClassifier.ReadSsrc(datagram) == Volatile.Read(ref mediaSsrc),
            Observer = (fault, _) =>
            {
                Interlocked.Increment(ref offeredPackets);
                if (fault is DatagramFault.Dropped or DatagramFault.BurstDropped)
                {
                    Interlocked.Increment(ref droppedPackets);
                }
            },
        };

        config.TransportInterceptor = inner =>
            injector = new FaultInjectingDatagramTransport(inner, profile, seed: 0xC4B0);

        await using var peer = new PeerConnection(config);
        Volatile.Write(ref mediaSsrc, peer.VideoSsrc);

        var offerSdp = await peer.CreateOfferAsync(cancellationToken);
        if (enableRetransmission)
        {
            // RFC 4588 §8.6 and RFC 5576 §4.2: without the rtx codec, its apt, and the FID group,
            // Chrome has nothing to answer with and no repair stream to expect.
            offerSdp.Should().Contain("rtx/90000").And.Contain("apt=96").And.Contain("a=ssrc-group:FID");
            offerSdp.Should().Contain("a=rtcp-fb:96 nack");
        }

        var reportLock = new object();
        string? latestReportJson = null;
        var answerApplied = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        using var listener = new HttpListener();
        listener.Prefixes.Add($"http://127.0.0.1:{HttpPort}/");
        listener.Start();
        var serverTask = Task.Run(async () =>
        {
            while (listener.IsListening)
            {
                HttpListenerContext context;
                try
                {
                    context = await listener.GetContextAsync().ConfigureAwait(false);
                }
                catch (Exception) when (!listener.IsListening || cancellationToken.IsCancellationRequested)
                {
                    return;
                }

                try
                {
                    await HandleAsync(context).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _output.WriteLine($"signaling host error: {ex.Message}");
                }
            }
        });

        async Task HandleAsync(HttpListenerContext context)
        {
            var response = context.Response;
            switch (context.Request.Url?.AbsolutePath)
            {
                case "/":
                    var html = await File.ReadAllBytesAsync(
                        Path.Combine(AppContext.BaseDirectory, "assets", "chrome-client.html"));
                    response.ContentType = "text/html";
                    await response.OutputStream.WriteAsync(html);
                    break;
                case "/offer":
                    var offerJson = JsonSerializer.SerializeToUtf8Bytes(new { type = "offer", sdp = offerSdp });
                    response.ContentType = "application/json";
                    await response.OutputStream.WriteAsync(offerJson);
                    break;
                case "/answer":
                    using (var reader = new StreamReader(context.Request.InputStream, Encoding.UTF8))
                    {
                        using var doc = JsonDocument.Parse(await reader.ReadToEndAsync());
                        var sdp = doc.RootElement.GetProperty("sdp").GetString()!;
                        await peer.SetRemoteDescriptionAsync(sdp, SdpType.Answer, cancellationToken);
                        answerApplied.TrySetResult();
                    }

                    break;
                case "/report":
                    using (var reader = new StreamReader(context.Request.InputStream, Encoding.UTF8))
                    {
                        var body = await reader.ReadToEndAsync();
                        lock (reportLock)
                        {
                            latestReportJson = body;
                        }
                    }

                    break;
                default:
                    response.StatusCode = 404;
                    break;
            }

            response.Close();
        }

        var userDataDir = Path.Combine(Path.GetTempPath(), $"keryx-chrome-rtx-{Guid.NewGuid():N}");
        Process? chrome = null;

        try
        {
            chrome = ChromeBrowser.Launch(chromePath, $"http://127.0.0.1:{HttpPort}/", userDataDir);

            (await Task.WhenAny(answerApplied.Task, Task.Delay(TimeSpan.FromSeconds(30), cancellationToken)))
                .Should().Be(answerApplied.Task, "Chrome should fetch the offer and post an answer");

            // Chrome keeps the rtx codec whenever the offer is well formed, so this is the assertion
            // that the negotiation Keryx writes is the one browsers actually accept.
            if (enableRetransmission)
            {
                peer.NegotiatedVideoRtxPayloadType.Should().NotBeNull(
                    "Chrome's answer must keep the RFC 4588 rtx codec");
            }
            else
            {
                peer.NegotiatedVideoRtxPayloadType.Should().BeNull();
            }

            (await peer.WaitForConnectedAsync(TimeSpan.FromSeconds(30), cancellationToken))
                .Should().BeTrue("ICE + DTLS should complete against Chrome");
            _output.WriteLine(
                $"connected (rtx={enableRetransmission}): pt={peer.NegotiatedVideoRtxPayloadType} "
                + $"mediaSsrc=0x{peer.VideoSsrc:x8} rtxSsrc=0x{peer.VideoRtxSsrc:x8} "
                + $"srtp={peer.NegotiatedSrtpProfile}");

            var accessUnits = H264TestStream.ReadAccessUnits(maxAccessUnits: 90);
            var restartFromIdr = 0;
            peer.OnPictureLossIndication += (_, _) => Interlocked.Exchange(ref restartFromIdr, 1);

            var pump = Task.Run(async () =>
            {
                uint timestamp = 0;
                var index = 0;
                while (!cancellationToken.IsCancellationRequested)
                {
                    if (Interlocked.Exchange(ref restartFromIdr, 0) == 1)
                    {
                        index = 0; // the asset opens with SPS/PPS + IDR, so looping restarts clean
                    }

                    peer.SendVideoFrame(accessUnits[index], timestamp);
                    index = (index + 1) % accessUnits.Count;
                    timestamp += 3000;
                    try
                    {
                        await Task.Delay(33, cancellationToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        return;
                    }
                }
            });

            // Both runs get exactly the same wall-clock budget, so their browser-side counters compare.
            await Task.Delay(TimeSpan.FromSeconds(MediaSeconds), cancellationToken).ConfigureAwait(false);
            (await TestSupport.WaitForAsync(
                    () =>
                    {
                        lock (reportLock)
                        {
                            return latestReportJson is not null;
                        }
                    },
                    timeoutMilliseconds: 20_000))
                .Should().BeTrue("Chrome must have posted at least one getStats() snapshot");

            string finalJson;
            lock (reportLock)
            {
                finalJson = latestReportJson!;
            }

            await shutdown.CancelAsync();
            await pump;

            using var report = JsonDocument.Parse(finalJson);
            var root = report.RootElement;
            var stats = root.GetProperty("stats");

            static long Number(JsonElement stats, string name) =>
                stats.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.Number
                    ? (long)el.GetDouble()
                    : 0;

            return new ChromeRun(
                Offered: Volatile.Read(ref offeredPackets),
                Dropped: Volatile.Read(ref droppedPackets),
                Retransmission: peer.GetStats().Video?.Retransmission,
                PacketsReceived: Number(stats, "packetsReceived"),
                PacketsLost: Number(stats, "packetsLost"),
                NackCount: Number(stats, "nackCount"),
                RetransmittedPacketsReceived: Number(stats, "retransmittedPacketsReceived"),
                FramesDecoded: Number(stats, "framesDecoded"),
                KeyFramesDecoded: Number(stats, "keyFramesDecoded"),
                FramesPerSecond: Number(stats, "framesPerSecond"),
                FreezeCount: Number(stats, "freezeCount"),
                PliCount: Number(stats, "pliCount"),
                ConnectionState: root.GetProperty("connectionState").GetString() ?? string.Empty,
                DecodedSeries: [.. root.GetProperty("samples").EnumerateArray()
                    .Select(s => s.GetProperty("framesDecoded").GetInt64())]);
        }
        finally
        {
            ChromeBrowser.Cleanup(chrome, userDataDir);
            listener.Stop();
            await Task.WhenAny(serverTask, Task.Delay(2000));
            await peer.CloseAsync();
            injector?.Dispose();
        }
    }

    /// <summary>What one browser session measured, on both sides of the link.</summary>
    private sealed record ChromeRun(
        int Offered,
        int Dropped,
        RetransmissionStats? Retransmission,
        long PacketsReceived,
        long PacketsLost,
        long NackCount,
        long RetransmittedPacketsReceived,
        long FramesDecoded,
        long KeyFramesDecoded,
        long FramesPerSecond,
        long FreezeCount,
        long PliCount,
        string ConnectionState,
        long[] DecodedSeries);
}
