using System.Diagnostics;
using System.Text.Json;
using FluentAssertions;
using Keryx.Broadcast;
using Keryx.Rtp;
using Keryx.Rtp.Simulcast;
using Keryx.Sdp;
using Keryx.Srtp;
using Xunit;
using Xunit.Abstractions;

namespace Keryx.IntegrationTests;

/// <summary>
/// A stock browser connects to the shared broadcast port (<see cref="BroadcastEndpoint"/> — a 2-socket
/// <c>SO_REUSEPORT</c> pool on Linux) alongside another Keryx viewer and receives media, on both the
/// per-connection path (<see cref="PeerConnection.TryForwardRtp"/>) and the bridged fan-out path
/// (<see cref="ViewerBroadcastBridge"/> + <c>SendBatch</c>). The browser offers <c>recvonly</c> through
/// the same role-flexible fixture the SFU lanes use; first-contact demux binds its 5-tuple on the shared
/// port.
/// </summary>
/// <remarks>
/// <c>Category=SharedPortChromeInterop</c> / <c>SharedPortFirefoxInterop</c>: need a browser. Absence
/// skips locally and — when the CI job sets <c>KERYX_REQUIRE_CHROME=1</c> / <c>KERYX_REQUIRE_FIREFOX=1</c>
/// — fails.
/// </remarks>
public sealed class SharedPortBrowserInteropTests
{
    private const int ChromeHttpPort = 7983;
    private const int FirefoxHttpPort = 7989;
    private const uint IngestSsrc = 0x0BAD_F00Du;
    private static readonly SimulcastLayerId Hi = SimulcastLayerId.Parse("hi");

    private readonly ITestOutputHelper _output;

    /// <summary>Captures the xunit output sink.</summary>
    /// <param name="output">Where progress and the final report land.</param>
    public SharedPortBrowserInteropTests(ITestOutputHelper output) => _output = output;

    /// <summary>Chrome on the shared port, per-connection forwarding.</summary>
    /// <returns>A task.</returns>
    [Fact]
    [Trait("Category", "SharedPortChromeInterop")]
    public Task Chrome_ConnectsToSharedBroadcastPort_AndReceivesForwardedRtp() =>
        RunAsync(BrowserKind.Chrome, ChromeHttpPort, bridged: false);

    /// <summary>Chrome on the shared port, bridged fan-out.</summary>
    /// <returns>A task.</returns>
    [Fact]
    [Trait("Category", "SharedPortChromeInterop")]
    public Task Chrome_OnSharedBroadcastPort_ReceivesBridgedFanoutMedia() =>
        RunAsync(BrowserKind.Chrome, ChromeHttpPort, bridged: true);

    /// <summary>Firefox on the shared port, per-connection forwarding.</summary>
    /// <returns>A task.</returns>
    [Fact]
    [Trait("Category", "SharedPortFirefoxInterop")]
    public Task Firefox_ConnectsToSharedBroadcastPort_AndReceivesForwardedRtp() =>
        RunAsync(BrowserKind.Firefox, FirefoxHttpPort, bridged: false);

    /// <summary>Firefox on the shared port, bridged fan-out.</summary>
    /// <returns>A task.</returns>
    [Fact]
    [Trait("Category", "SharedPortFirefoxInterop")]
    public Task Firefox_OnSharedBroadcastPort_ReceivesBridgedFanoutMedia() =>
        RunAsync(BrowserKind.Firefox, FirefoxHttpPort, bridged: true);

    private static long ReadStat(JsonElement root, string name) =>
        root.GetProperty("stats").TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.Number
            ? (long)el.GetDouble()
            : 0;

    private static byte[] BuildIngestPacket(ushort sequenceNumber, uint timestamp, bool marker, byte[] payload)
    {
        var header = new RtpHeader
        {
            Version = 2,
            PayloadType = 96,
            Ssrc = IngestSsrc,
            SequenceNumber = sequenceNumber,
            Timestamp = timestamp,
            Marker = marker,
        };

        var buffer = new byte[header.HeaderLength + payload.Length];
        var written = header.WriteTo(buffer);
        payload.CopyTo(buffer.AsSpan(written));
        return buffer;
    }

    private async Task RunAsync(BrowserKind kind, int httpPort, bool bridged)
    {
        var browserPath = BrowserLauncher.Require(kind);
        if (browserPath is null)
        {
            _output.WriteLine($"SKIPPED: {kind} not found (set {BrowserLauncher.PathEnvVar(kind)} to enable).");
            return;
        }

        var wildcard = kind == BrowserKind.Firefox;
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        var cancellationToken = shutdown.Token;

        await using var endpoint = SharedPortInteropSupport.CreateEndpoint(wildcard);
        SharedPortInteropSupport.AssertPoolShape(endpoint);
        _output.WriteLine(
            $"endpoint={endpoint.LocalEndPoint} poolSize={endpoint.SocketPoolSize} wildcard={wildcard} bridged={bridged}");

        SharedPortInteropSupport.Companion? companion = null;
        var profileDir = Path.Combine(Path.GetTempPath(), $"keryx-shared-port-{kind.ToString().ToLowerInvariant()}-{Guid.NewGuid():N}");
        Process? browser = null;
        try
        {
            companion = await SharedPortInteropSupport.ConnectCompanionAsync(endpoint, wildcard, cancellationToken);

            var session = endpoint.AddViewer(TestSupport.NewConfig());
            var peer = session.Connection;

            var reportLock = new object();
            string? latestReportJson = null;
            var answered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var sharedPort = endpoint.LocalEndPoint.Port;

            using var host = new InteropSignalingHost(httpPort, _output)
            {
                OnPostOffer = async offerSdp =>
                {
                    await peer.SetRemoteDescriptionAsync(offerSdp, SdpType.Offer, cancellationToken);
                    var answer = await peer.CreateAnswerAsync(cancellationToken);
                    answer.Should().Contain("a=sendonly", "a recvonly offer must be answered sendonly");

                    var candidateLines = answer.Split('\n')
                        .Select(l => l.TrimEnd('\r'))
                        .Where(l => l.StartsWith("a=candidate:", StringComparison.Ordinal))
                        .ToList();
                    candidateLines.Should().NotBeEmpty("the answer must advertise the shared port's host candidate");
                    candidateLines.Should().OnlyContain(
                        l => l.Contains(" " + sharedPort + " typ host", StringComparison.Ordinal),
                        "every advertised candidate must be the endpoint's shared port");

                    answered.TrySetResult();
                    return answer;
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

            browser = BrowserLauncher.Launch(kind, browserPath, $"http://127.0.0.1:{httpPort}/?role=offer-recv", profileDir);

            (await Task.WhenAny(answered.Task, Task.Delay(TimeSpan.FromSeconds(30), cancellationToken)))
                .Should().Be(answered.Task, $"{kind} should offer recvonly and Keryx should answer sendonly");

            (await peer.WaitForConnectedAsync(TimeSpan.FromSeconds(30), cancellationToken))
                .Should().BeTrue($"ICE + DTLS should complete against {kind} on the shared port");

            endpoint.ViewerCount.Should().Be(2, "the companion and the browser share the endpoint");
            (await TestSupport.WaitForAsync(() => session.BoundEndPoints.Count >= 1, 10_000)).Should().BeTrue(
                "the browser's 5-tuple must bind on the shared port through first-contact demux");

            var payloadType = peer.GetNegotiatedPayloadType(MediaKind.Video);
            payloadType.Should().NotBeNull("the answerer negotiated a video send track against the recvonly offer");
            _output.WriteLine(
                $"connected: sendPt={payloadType} sendSsrc=0x{peer.VideoSsrc:x8} bound={string.Join(",", session.BoundEndPoints)}");

            var forwarded = 0;
            using var pumpStop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var pumpToken = pumpStop.Token;
            BroadcastSubscriber? subscriber = null;
            Task pump;
            if (bridged)
            {
                var forwarder = new RtpForwarder(peer.GetLocalSsrc(MediaKind.Video), outboundPayloadType: payloadType);
                forwarder.SelectLayer(Hi);
                subscriber = ViewerBroadcastBridge.CreateFanoutSubscriber(session, forwarder);
                var bridgedSubscriber = subscriber;
                pump = Task.Run(async () =>
                {
                    var fanout = new BroadcastFanout();
                    var subscribers = new[] { bridgedSubscriber };
                    var datagrams = new List<BroadcastDatagram>();
                    var classification = new RtpLayerClassification(
                        Hi, IngestSsrc, IsRepair: false, RtpLayerClassificationSource.RidExtension);
                    uint timestamp = 1_000_000;
                    var seq = 0;
                    while (!pumpToken.IsCancellationRequested)
                    {
                        var payload = new byte[200];
                        Random.Shared.NextBytes(payload);
                        var ingest = BuildIngestPacket((ushort)seq, timestamp, seq % 30 == 29, payload);
                        fanout.Forward(in classification, ingest, canStartLayer: seq == 0, subscribers, datagrams);
                        Interlocked.Add(ref forwarded, endpoint.SendBatch(datagrams));

                        seq++;
                        timestamp += 3000;
                        try
                        {
                            await Task.Delay(20, pumpToken).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException)
                        {
                            return;
                        }
                    }
                });
            }
            else
            {
                pump = Task.Run(async () =>
                {
                    uint timestamp = 1_000_000;
                    var seq = 0;
                    while (!pumpToken.IsCancellationRequested)
                    {
                        var payload = new byte[200];
                        Random.Shared.NextBytes(payload);
                        var marker = seq % 30 == 29; // a frame boundary every ~30 packets
                        if (peer.TryForwardRtp(MediaKind.Video, payload, timestamp, marker, payloadType!.Value))
                        {
                            Interlocked.Increment(ref forwarded);
                        }

                        seq++;
                        timestamp += 3000;
                        try
                        {
                            await Task.Delay(20, pumpToken).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException)
                        {
                            return;
                        }
                    }
                });
            }

            try
            {
                var browserReceived = await TestSupport.WaitForAsync(
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
                        return ReadStat(doc.RootElement, "packetsReceived") >= 20;
                    },
                    timeoutMilliseconds: 45_000);

                pumpStop.Cancel();
                await pump;

                string? lastJson;
                lock (reportLock)
                {
                    lastJson = latestReportJson;
                }

                _output.WriteLine(
                    $"poolSize={endpoint.SocketPoolSize} dropped={endpoint.DroppedDatagrams} "
                    + $"forwarded={Volatile.Read(ref forwarded)} final browser report: {lastJson ?? "(none)"}");
                browserReceived.Should().BeTrue(
                    $"{kind} must receive the media Keryx sent on the shared port; last report: {lastJson}");
                Volatile.Read(ref forwarded).Should().BeGreaterThan(0, "a connected, negotiated egress track must accept sends (the browser-side packetsReceived wait above is the volume bar; the pump stops as soon as it is met, so the forwarded count can equal it)");
                if (bridged)
                {
                    endpoint.DroppedDatagrams.Should().Be(0, "the bridged fan-out must not shed datagrams on loopback");
                }
            }
            finally
            {
                pumpStop.Cancel();
                await pump;
                subscriber?.Dispose();
            }

            await SharedPortInteropSupport.AssertCompanionStillReceivesAsync(companion, 20, cancellationToken);
        }
        finally
        {
            BrowserLauncher.Cleanup(browser, profileDir);
            if (companion is not null)
            {
                await companion.DisposeAsync();
            }

            if (!shutdown.IsCancellationRequested)
            {
                shutdown.Cancel();
            }
        }
    }
}
