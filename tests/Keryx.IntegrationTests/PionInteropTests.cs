using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace Keryx.IntegrationTests;

/// <summary>
/// Keryx proven against a second, non-browser peer implementation — Go/pion — so bugs a single
/// peer would mask surface. Keryx offers (the media-server shape); the pion peer answers, decodes
/// the H.264 track Keryx sends, and echoes on the data channels Keryx opens. One handshake exercises
/// media and data in both directions: Keryx -> pion video, and a Keryx -> pion -> Keryx data
/// round-trip. The peer reports progress by POSTing JSON snapshots to the test host (see
/// <c>tests/interop/pion/main.go</c>), the same HTTP signaling shape the Chrome fixture uses.
/// </summary>
/// <remarks>
/// Excluded from the default CI filter (<c>Category=PionInterop</c>): it needs the Go toolchain to
/// build the peer. Its absence skips locally and — when the CI job sets <c>KERYX_REQUIRE_PION=1</c>
/// — fails. A prebuilt peer can be supplied with <c>KERYX_PION_PEER</c>.
/// </remarks>
public sealed class PionInteropTests
{
    private const int HttpPort = 7984;
    private const int PionPortMin = 7800;
    private const int PionPortMax = 7899;

    private readonly ITestOutputHelper _output;

    /// <summary>Captures the xunit output sink.</summary>
    /// <param name="output">Where progress and the final report land.</param>
    public PionInteropTests(ITestOutputHelper output) => _output = output;

    [Fact]
    [Trait("Category", "PionInterop")]
    public async Task PionAnswersKeryxVideoAndDataChannelsRoundTrip()
    {
        var peerPath = PionPeer.Require(_output.WriteLine);
        if (peerPath is null)
        {
            _output.WriteLine("SKIPPED: Go toolchain / pion peer not available (set KERYX_PION_PEER or install Go to enable).");
            return;
        }

        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        var cancellationToken = shutdown.Token;

        await using var peer = new PeerConnection(TestSupport.NewConfig());
        var controllerTask = peer.CreateDataChannel("controller", ordered: false, maxRetransmits: 0);
        var telemetryTask = peer.CreateDataChannel("telemetry");

        // Count the "echo:" replies pion sends back on each channel: this is the round-trip
        // assertion from Keryx's own side, proving the SCTP/DTLS data path both directions.
        var controllerEchoes = 0;
        var telemetryEchoes = 0;
        void CountEcho(bool isBinary, ReadOnlySpan<byte> payload, ref int counter)
        {
            if (isBinary)
            {
                return;
            }

            if (Encoding.UTF8.GetString(payload).StartsWith("echo:", StringComparison.Ordinal))
            {
                Interlocked.Increment(ref counter);
            }
        }

        var controller = await controllerTask;
        var telemetry = await telemetryTask;
        controller.OnMessage += (bool b, ReadOnlySpan<byte> p) => CountEcho(b, p, ref controllerEchoes);
        telemetry.OnMessage += (bool b, ReadOnlySpan<byte> p) => CountEcho(b, p, ref telemetryEchoes);

        var offerSdp = await peer.CreateOfferAsync(cancellationToken);

        // ------------------------------------------------------------------ HTTP signaling host
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
            var request = context.Request;
            var response = context.Response;
            switch (request.Url?.AbsolutePath)
            {
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

        // ------------------------------------------------------------------ pion peer
        var pionOutput = new StringBuilder();
        Process? pion = null;
        try
        {
            pion = PionPeer.Launch(peerPath, $"http://127.0.0.1:{HttpPort}", PionPortMin, PionPortMax);
            pion.OutputDataReceived += (_, e) => { if (e.Data is not null) { lock (pionOutput) { pionOutput.AppendLine(e.Data); } } };
            pion.ErrorDataReceived += (_, e) => { if (e.Data is not null) { lock (pionOutput) { pionOutput.AppendLine(e.Data); } } };
            pion.BeginOutputReadLine();
            pion.BeginErrorReadLine();

            (await Task.WhenAny(answerApplied.Task, Task.Delay(TimeSpan.FromSeconds(30), cancellationToken)))
                .Should().Be(answerApplied.Task, "the pion peer should fetch the offer and post an answer");

            (await peer.WaitForConnectedAsync(TimeSpan.FromSeconds(30), cancellationToken))
                .Should().BeTrue("ICE + DTLS should complete against pion");
            _output.WriteLine(
                $"connected: dtlsRole={peer.LocalDtlsRole} srtp={peer.NegotiatedSrtpProfile} "
                + $"remoteFp={peer.RemoteFingerprint?[..Math.Min(23, peer.RemoteFingerprint!.Length)]}...");

            // -------------------------------------------------------------- media + ping pumps
            var accessUnits = H264TestStream.ReadAccessUnits(maxAccessUnits: 90); // the full 3 s asset
            var restartFromIdr = 0;
            peer.OnPictureLossIndication += (_, _) => Interlocked.Exchange(ref restartFromIdr, 1);

            var pumps = Task.Run(async () =>
            {
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

            // -------------------------------------------------------------- assert on pion's view
            static long ReadStat(JsonElement video, string name) =>
                video.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.Number
                    ? el.GetInt64()
                    : 0;

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

                    using var doc = JsonDocument.Parse(json);
                    var root = doc.RootElement;
                    if (root.GetProperty("connectionState").GetString() != "connected")
                    {
                        return false;
                    }

                    var video = root.GetProperty("video");
                    var packets = ReadStat(video, "packetsReceived") >= 60;
                    var frames = ReadStat(video, "framesReceived") >= 5;
                    var echoes = Volatile.Read(ref controllerEchoes) >= 3 && Volatile.Read(ref telemetryEchoes) >= 3;
                    return packets && frames && echoes;
                },
                timeoutMilliseconds: 45_000);

            string? lastJson;
            lock (reportLock)
            {
                lastJson = latestReportJson;
            }

            _output.WriteLine($"final pion report: {lastJson ?? "(none)"}");
            _output.WriteLine($"keryx echoes: controller={Volatile.Read(ref controllerEchoes)} telemetry={Volatile.Read(ref telemetryEchoes)}");

            healthy.Should().BeTrue(
                $"pion should decode Keryx video and echo on both channels; last report: {lastJson}");

            using (var final = JsonDocument.Parse(lastJson!))
            {
                var root = final.RootElement;
                root.GetProperty("connectionState").GetString().Should().Be("connected");
                root.GetProperty("track").GetProperty("video").GetBoolean().Should().BeTrue();
                ReadStat(root.GetProperty("video"), "packetsReceived").Should().BeGreaterThan(60);
            }

            var stats = peer.GetStats();
            stats.Video.Should().NotBeNull();
            var video = stats.Video!.Value;
            video.PacketsSent.Should().BeGreaterThan(60);
            Volatile.Read(ref controllerEchoes).Should().BeGreaterThan(2, "the controller channel must round-trip");
            Volatile.Read(ref telemetryEchoes).Should().BeGreaterThan(2, "the telemetry channel must round-trip");
            _output.WriteLine(
                $"keryx stats: videoPkts={video.PacketsSent} videoBytes={video.BytesSent} "
                + $"pli={stats.Feedback.PictureLossIndications} rr={stats.Feedback.ReceiverReports}");

            shutdown.Cancel();
            await pumps;
        }
        finally
        {
            lock (pionOutput)
            {
                if (pionOutput.Length > 0)
                {
                    _output.WriteLine($"pion peer output:\n{pionOutput}");
                }
            }

            PionPeer.Cleanup(pion);
            listener.Stop();
            await Task.WhenAny(serverTask, Task.Delay(2000));
        }
    }
}
