using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace Keryx.IntegrationTests;

/// <summary>
/// The end goal of the stack, proven against a real browser: headless Chrome fetches an offer from
/// a Keryx <see cref="PeerConnection"/> over HTTP signaling, answers it, ICE connects, DTLS
/// completes, Chrome decodes and renders the H.264 video Keryx sends, and both data channels
/// round-trip messages. Chrome reports progress by POSTing <c>getStats()</c> snapshots back to the
/// test host (see <c>assets/chrome-client.html</c>).
/// </summary>
/// <remarks>
/// Excluded from CI (<c>Category=ChromeInterop</c>): it needs Google Chrome on the machine. The
/// browser path can be overridden with <c>KERYX_CHROME_PATH</c>.
/// </remarks>
public sealed class ChromeInteropTests
{
    private const int HttpPort = 7980;

    private readonly ITestOutputHelper _output;

    /// <summary>Captures the xunit output sink.</summary>
    /// <param name="output">Where progress and the final report land.</param>
    public ChromeInteropTests(ITestOutputHelper output) => _output = output;

    [Fact]
    [Trait("Category", "ChromeInterop")]
    public async Task ChromeDecodesKeryxVideoAndDataChannelsRoundTrip()
    {
        var chromePath = ChromeBrowser.Find();
        if (chromePath is null)
        {
            _output.WriteLine("SKIPPED: Google Chrome not found (set KERYX_CHROME_PATH to enable).");
            return;
        }

        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        var cancellationToken = shutdown.Token;

        var logPath = Environment.GetEnvironmentVariable("KERYX_INTEROP_LOG");
        using var logWriter = logPath is null ? null : new StreamWriter(logPath, append: false);
        var logger = logWriter is null
            ? (Keryx.Core.IKeryxLogger?)null
            : new Keryx.Core.TextWriterLogger(logWriter, Keryx.Core.KeryxLogLevel.Trace, "interop");
        await using var peer = new PeerConnection(TestSupport.NewConfig(logger));
        var controllerTask = peer.CreateDataChannel("controller", ordered: false, maxRetransmits: 0);
        var telemetryTask = peer.CreateDataChannel("telemetry");

        var offerSdp = await peer.CreateOfferAsync(cancellationToken);

        // ------------------------------------------------------------------ HTTP signaling host
        var latestReport = new object();
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
            var request = context.Request;
            var response = context.Response;
            switch (request.Url?.AbsolutePath)
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
                    using (var reader = new StreamReader(request.InputStream, Encoding.UTF8))
                    {
                        var body = await reader.ReadToEndAsync();
                        using var doc = JsonDocument.Parse(body);
                        var sdp = doc.RootElement.GetProperty("sdp").GetString()!;
                        await peer.SetRemoteDescriptionAsync(sdp, SdpType.Answer, cancellationToken);
                        answerApplied.TrySetResult();
                    }

                    break;
                case "/report":
                    using (var reader = new StreamReader(request.InputStream, Encoding.UTF8))
                    {
                        var body = await reader.ReadToEndAsync();
                        lock (latestReport)
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

        // ------------------------------------------------------------------ headless Chrome
        var userDataDir = Path.Combine(Path.GetTempPath(), $"keryx-chrome-{Guid.NewGuid():N}");
        using var chrome = new Process();
        chrome.StartInfo = new ProcessStartInfo
        {
            FileName = chromePath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        chrome.StartInfo.ArgumentList.Add("--headless=new");
        chrome.StartInfo.ArgumentList.Add("--disable-gpu");
        chrome.StartInfo.ArgumentList.Add("--mute-audio");
        chrome.StartInfo.ArgumentList.Add("--no-first-run");
        chrome.StartInfo.ArgumentList.Add("--no-default-browser-check");
        chrome.StartInfo.ArgumentList.Add("--autoplay-policy=no-user-gesture-required");
        chrome.StartInfo.ArgumentList.Add($"--user-data-dir={userDataDir}");
        chrome.StartInfo.ArgumentList.Add($"http://127.0.0.1:{HttpPort}/");

        try
        {
            chrome.Start().Should().BeTrue();

            (await Task.WhenAny(answerApplied.Task, Task.Delay(TimeSpan.FromSeconds(20), cancellationToken)))
                .Should().Be(answerApplied.Task, "Chrome should fetch the offer and post an answer");

            (await peer.WaitForConnectedAsync(TimeSpan.FromSeconds(20), cancellationToken))
                .Should().BeTrue("ICE + DTLS should complete against Chrome");
            _output.WriteLine(
                $"connected: dtlsRole={peer.LocalDtlsRole} srtp={peer.NegotiatedSrtpProfile} " +
                $"remoteFp={peer.RemoteFingerprint?[..23]}...");

            // -------------------------------------------------------------- media + ping pumps
            var accessUnits = H264TestStream.ReadAccessUnits(maxAccessUnits: 90); // the full 3 s asset
            var restartFromIdr = 0;
            peer.OnPictureLossIndication += (_, _) => Interlocked.Exchange(ref restartFromIdr, 1);

            var pumps = Task.Run(async () =>
            {
                var controller = await controllerTask;
                var telemetry = await telemetryTask;
                uint timestamp = 0;
                var index = 0;
                var ping = 0;
                var ticks = 0;
                while (!cancellationToken.IsCancellationRequested)
                {
                    if (Interlocked.Exchange(ref restartFromIdr, 0) == 1)
                    {
                        index = 0; // the asset opens with SPS/PPS + IDR, so looping restarts clean
                    }

                    peer.SendVideoFrame(accessUnits[index], timestamp);
                    index = (index + 1) % accessUnits.Count;
                    timestamp += 3000;

                    if (++ticks % 12 == 0
                        && controller.State == Keryx.Sctp.DataChannelState.Open
                        && telemetry.State == Keryx.Sctp.DataChannelState.Open)
                    {
                        ping++;
                        controller.SendText($"ping:{ping}");
                        telemetry.SendText($"ping:{ping}");
                    }

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

            // -------------------------------------------------------------- assert on Chrome's view
            static long ReadStat(JsonElement root, string name) =>
                root.GetProperty("stats").TryGetProperty(name, out var el) ? el.GetInt64() : 0;

            JsonDocument? final = null;
            var healthy = await TestSupport.WaitForAsync(
                () =>
                {
                    string? json;
                    lock (latestReport)
                    {
                        json = latestReportJson;
                    }

                    if (json is null)
                    {
                        return false;
                    }

                    var doc = JsonDocument.Parse(json);
                    var root = doc.RootElement;
                    var channels = root.GetProperty("channels");
                    var done = ReadStat(root, "framesDecoded") >= 60
                        && ReadStat(root, "frameWidth") == 640
                        && channels.TryGetProperty("controller", out var c) && c.GetProperty("echoed").GetInt64() >= 3
                        && channels.TryGetProperty("telemetry", out var t) && t.GetProperty("echoed").GetInt64() >= 3;
                    if (done)
                    {
                        final?.Dispose();
                        final = doc;
                        return true;
                    }

                    doc.Dispose();
                    return false;
                },
                timeoutMilliseconds: 45_000);

            string? lastJson;
            lock (latestReport)
            {
                lastJson = latestReportJson;
            }

            _output.WriteLine($"final report: {lastJson ?? "(none)"}");
            healthy.Should().BeTrue(
                $"Chrome should decode Keryx video and echo on both channels; last report: {lastJson}");

            using (final)
            {
                var root = final!.RootElement;
                root.GetProperty("connectionState").GetString().Should().Be("connected");
                ReadStat(root, "keyFramesDecoded").Should().BeGreaterThan(0);
                ReadStat(root, "packetsReceived").Should().BeGreaterThan(60);
                root.GetProperty("track").GetProperty("video").GetBoolean().Should().BeTrue();
            }

            var stats = peer.GetStats();
            stats.Video.Should().NotBeNull();
            var video = stats.Video!.Value;
            video.PacketsSent.Should().BeGreaterThan(60);
            _output.WriteLine(
                $"keryx stats: videoPkts={video.PacketsSent} videoBytes={video.BytesSent} " +
                $"pli={stats.Feedback.PictureLossIndications} rr={stats.Feedback.ReceiverReports}");

            shutdown.Cancel();
            await pumps;
        }
        finally
        {
            try
            {
                if (!chrome.HasExited)
                {
                    chrome.Kill(entireProcessTree: true);
                }
            }
            catch
            {
                // best effort
            }

            listener.Stop();
            await Task.WhenAny(serverTask, Task.Delay(2000));
            try
            {
                Directory.Delete(userDataDir, recursive: true);
            }
            catch
            {
                // best effort
            }
        }
    }
}
