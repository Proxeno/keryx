using System.Diagnostics;
using System.Net;
using System.Text.Json;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace Keryx.IntegrationTests;

/// <summary>
/// The end goal of the stack, proven against a second real browser engine: headless Firefox fetches
/// an offer from a Keryx <see cref="PeerConnection"/> over HTTP signaling, answers it, ICE connects on
/// a pure 127.0.0.1 loopback, DTLS completes, Firefox decodes the H.264 video Keryx sends, and both
/// data channels round-trip. It mirrors <see cref="ChromeInteropTests"/> and drives the identical
/// role-flexible fixture (<c>assets/chrome-client.html</c>) through the same
/// <see cref="BrowserLauncher"/> seam — the value is that Firefox exercises paths Chrome does not
/// (two-byte header extensions negotiated more readily, its own codec/PT preferences and <c>a=setup</c>
/// role choices, and — decisively — H.264 via the OpenH264 GMP rather than a built-in decoder).
/// </summary>
/// <remarks>
/// Excluded from the default suite (<c>Category=FirefoxInterop</c>): it needs Firefox on the machine.
/// Its absence skips locally and — when the CI job sets <c>KERYX_REQUIRE_FIREFOX=1</c> — fails. The
/// browser path can be overridden with <c>KERYX_FIREFOX_PATH</c>.
/// </remarks>
public sealed class FirefoxInteropTests
{
    private const int HttpPort = 7986;

    private readonly ITestOutputHelper _output;

    /// <summary>Captures the xunit output sink.</summary>
    /// <param name="output">Where progress and the final report land.</param>
    public FirefoxInteropTests(ITestOutputHelper output) => _output = output;

    /// <summary>
    /// Keryx offers H.264 video plus two data channels; Firefox answers, connects, decodes the video,
    /// and echoes on both channels — the media-server shape proven against Firefox end to end.
    /// </summary>
    [Fact]
    [Trait("Category", "FirefoxInterop")]
    public async Task FirefoxDecodesKeryxVideoAndDataChannelsRoundTrip()
    {
        var firefoxPath = BrowserLauncher.Require(BrowserKind.Firefox);
        if (firefoxPath is null)
        {
            _output.WriteLine("SKIPPED: Firefox not found (set KERYX_FIREFOX_PATH to enable).");
            return;
        }

        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        var cancellationToken = shutdown.Token;

        var logPath = Environment.GetEnvironmentVariable("KERYX_INTEROP_LOG");
        using var logWriter = logPath is null ? null : new StreamWriter(logPath, append: false);
        var logger = logWriter is null
            ? (Keryx.Core.IKeryxLogger?)null
            : new Keryx.Core.TextWriterLogger(logWriter, Keryx.Core.KeryxLogLevel.Trace, "interop");
        await using var peer = new PeerConnection(TestSupport.NewConfig(logger, IPAddress.Any));
        var controllerTask = peer.CreateDataChannel("controller", ordered: false, maxRetransmits: 0);
        var telemetryTask = peer.CreateDataChannel("telemetry");

        var offerSdp = await peer.CreateOfferAsync(cancellationToken);

        var reportLock = new object();
        string? latestReportJson = null;
        var answerApplied = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        using var host = new InteropSignalingHost(HttpPort, _output)
        {
            OnGetOffer = () => Task.FromResult(offerSdp),
            OnAnswer = async sdp =>
            {
                await peer.SetRemoteDescriptionAsync(sdp, SdpType.Answer, cancellationToken);
                answerApplied.TrySetResult();
            },
            OnReport = body =>
            {
                lock (reportLock)
                {
                    latestReportJson = body;
                }
            },
        };
        host.Start(cancellationToken);

        var profileDir = Path.Combine(Path.GetTempPath(), $"keryx-firefox-{Guid.NewGuid():N}");
        Process? firefox = null;
        try
        {
            firefox = BrowserLauncher.Launch(
                BrowserKind.Firefox, firefoxPath, $"http://127.0.0.1:{HttpPort}/?role=answer", profileDir);

            (await Task.WhenAny(answerApplied.Task, Task.Delay(TimeSpan.FromSeconds(30), cancellationToken)))
                .Should().Be(answerApplied.Task, "Firefox should fetch the offer and post an answer");

            (await peer.WaitForConnectedAsync(TimeSpan.FromSeconds(30), cancellationToken))
                .Should().BeTrue("ICE + DTLS should complete against Firefox");
            _output.WriteLine(
                $"connected: dtlsRole={peer.LocalDtlsRole} srtp={peer.NegotiatedSrtpProfile} "
                + $"remoteFp={peer.RemoteFingerprint?[..23]}...");

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

            // -------------------------------------------------------------- assert on Firefox's view
            static long ReadStat(JsonElement root, string name) =>
                root.GetProperty("stats").TryGetProperty(name, out var el) ? el.GetInt64() : 0;

            JsonDocument? final = null;
            var healthy = await TestSupport.WaitForAsync(
                () =>
                {
                    string? json;
                    lock (reportLock)
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
            lock (reportLock)
            {
                lastJson = latestReportJson;
            }

            _output.WriteLine($"final report: {lastJson ?? "(none)"}");
            healthy.Should().BeTrue(
                $"Firefox should decode Keryx video and echo on both channels; last report: {lastJson}");

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
                $"keryx stats: videoPkts={video.PacketsSent} videoBytes={video.BytesSent} "
                + $"pli={stats.Feedback.PictureLossIndications} rr={stats.Feedback.ReceiverReports}");

            shutdown.Cancel();
            await pumps;
        }
        finally
        {
            BrowserLauncher.Cleanup(firefox, profileDir);
            if (!shutdown.IsCancellationRequested)
            {
                shutdown.Cancel();
            }
        }
    }
}
