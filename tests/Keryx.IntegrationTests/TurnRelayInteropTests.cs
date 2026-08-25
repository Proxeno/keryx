using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Keryx.Stun;
using Keryx.Turn;
using Xunit;
using Xunit.Abstractions;

namespace Keryx.IntegrationTests;

/// <summary>
/// The relay path, proven end to end against a real peer: a real coturn server, a pion peer
/// restricted to that TURN relay only (<c>webrtc.ICETransportPolicyRelay</c>, pion's equivalent
/// of a browser's <c>iceTransportPolicy: "relay"</c>), and a Keryx <see cref="PeerConnection"/>
/// restricted the same way (<see cref="PeerConnectionConfig.RelayOnly"/>). Every other interop
/// lane (<see cref="PionInteropTests"/>, <c>ChromeInteropTests</c>, <c>FirefoxInteropTests</c>)
/// runs host-candidate-only loopback - no STUN, TURN or mDNS - so none of them ever exercises a
/// relayed candidate pair against a real second implementation. <see cref="Keryx.Turn.Tests.CoturnInteropTests"/>
/// proves Keryx's own TURN *client* against coturn at the ICE-agent level; this test proves the
/// full <see cref="PeerConnection"/> media + data-channel session traverses the relay when it is
/// the only path available on both sides, and asserts the pair Keryx actually selected is a
/// relayed one.
/// </summary>
/// <remarks>
/// Excluded from the default CI filter (<c>Category=TurnRelayInterop</c>): it needs both the
/// <c>turnserver</c> binary and the Go toolchain (to build the pion peer). Locally, either
/// missing piece prints a SKIPPED line and returns. The CI job that installs coturn and Go sets
/// <c>KERYX_REQUIRE_TURN_RELAY=1</c>, which turns a missing coturn binary, unusable relay ports,
/// or an unbuildable pion peer into a failure instead of a graceful skip - the same fail-not-skip
/// contract <see cref="PionPeer.PionRequired"/> already applies to plain pion interop.
///
/// <para>The whole handshake is bounded by a single deadline, exactly like
/// <see cref="PionInteropTests"/>: every await either takes the deadline token or has its own
/// shorter timeout, so a peer that never connects through the relay fails the test with a
/// diagnostic instead of hanging CI.</para>
/// </remarks>
public sealed class TurnRelayInteropTests
{
    private const string Realm = "keryx.test";
    private const string TurnUsername = "keryx";
    private const string TurnPassword = "keryxpass";

    /// <summary>coturn's control port; the relay ports are the range right above it.</summary>
    private const int CoturnListeningPort = 7970;

    private const int CoturnMinRelayPort = 7971;
    private const int CoturnMaxRelayPort = 7974;

    /// <summary>Keryx's own socket range - distinct from coturn's ports and pion's, above.</summary>
    private const int KeryxMinPort = 7975;
    private const int KeryxMaxPort = 7979;

    /// <summary>pion's ephemeral range for the socket it reaches the TURN server on.</summary>
    private const int PionPortMin = 7980;
    private const int PionPortMax = 7989;

    private const int HttpPort = 7990;

    // One hard budget for the whole handshake, matching PionInteropTests: kept well under CI's
    // default six-hour ceiling so a stall fails fast rather than burning the job.
    private const int DeadlineSeconds = 75;

    private readonly ITestOutputHelper _output;

    /// <summary>Captures the xunit output sink.</summary>
    /// <param name="output">Where progress and the final report land.</param>
    public TurnRelayInteropTests(ITestOutputHelper output) => _output = output;

    [Fact]
    [Trait("Category", "TurnRelayInterop")]
    public async Task PionAnswersKeryxThroughCoturnRelayOnly()
    {
        using var coturn = Coturn.TryStart(_output);
        if (coturn is null)
        {
            return;
        }

        var peerPath = PionPeer.Require(_output.WriteLine);
        if (peerPath is null)
        {
            _output.WriteLine("SKIPPED: Go toolchain / pion peer not available (set KERYX_PION_PEER or install Go to enable).");
            return;
        }

        var stopwatch = Stopwatch.StartNew();
        void Log(string message) => _output.WriteLine($"[{stopwatch.Elapsed:mm\\:ss\\.f}] {message}");

        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(DeadlineSeconds));
        var cancellationToken = shutdown.Token;

        var config = TestSupport.NewConfig();
        config.MinPort = KeryxMinPort;
        config.MaxPort = KeryxMaxPort;
        config.TurnServers.Add(new TurnServerOptions(coturn.EndPoint, TurnUsername, TurnPassword));

        // The knob under test: force every path but the coturn allocation closed, mirroring the
        // browser's iceTransportPolicy: "relay" applied to pion below.
        config.RelayOnly = true;

        await using var peer = new PeerConnection(config);

        peer.OnConnectionStateChanged += (_, state) =>
            Log($"keryx connection state -> {state} (ice={peer.IceState} dtls={peer.DtlsState})");

        var controllerTask = peer.CreateDataChannel("controller", ordered: false, maxRetransmits: 0);
        var telemetryTask = peer.CreateDataChannel("telemetry");

        var controllerEchoes = 0;
        var telemetryEchoes = 0;
        var controllerFirstEcho = 0;
        var telemetryFirstEcho = 0;
        void CountEcho(bool isBinary, ReadOnlySpan<byte> payload, ref int counter, ref int firstSeen, string label)
        {
            if (isBinary)
            {
                return;
            }

            if (Encoding.UTF8.GetString(payload).StartsWith("echo:", StringComparison.Ordinal))
            {
                Interlocked.Increment(ref counter);
                if (Interlocked.Exchange(ref firstSeen, 1) == 0)
                {
                    Log($"first echo on '{label}' channel");
                }
            }
        }

        // ------------------------------------------------------------------ signaling host state
        var reportLock = new object();
        string? latestReportJson = null;
        var answerApplied = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        Log("creating offer");
        var offerSdp = await peer.CreateOfferAsync(cancellationToken);
        Log("offer created; starting signaling host");

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
                    Log($"signaling host error: {ex.Message}");
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
                        Log("answer received from pion; applying remote description");
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

        string? Report()
        {
            lock (reportLock)
            {
                return latestReportJson;
            }
        }

        // ------------------------------------------------------------------ pion peer
        var pionOutput = new StringBuilder();
        Process? pion = null;

        using var progressStop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var progressTask = Task.Run(async () =>
        {
            while (!progressStop.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(3000, progressStop.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }

                Log($"progress: keryx state={peer.State} ice={peer.IceState} dtls={peer.DtlsState} "
                    + $"ctrlEcho={Volatile.Read(ref controllerEchoes)} telEcho={Volatile.Read(ref telemetryEchoes)}; "
                    + $"pion report={Report() ?? "(none yet)"}");
            }
        });

        try
        {
            var turnUrl = $"turn:{coturn.EndPoint}";
            Log($"launching pion peer, relay-only against {turnUrl}");
            pion = PionPeer.Launch(
                peerPath,
                $"http://127.0.0.1:{HttpPort}",
                PionPortMin,
                PionPortMax,
                turnUrl,
                TurnUsername,
                TurnPassword);
            pion.OutputDataReceived += (_, e) => { if (e.Data is not null) { lock (pionOutput) { pionOutput.AppendLine(e.Data); } } };
            pion.ErrorDataReceived += (_, e) => { if (e.Data is not null) { lock (pionOutput) { pionOutput.AppendLine(e.Data); } } };
            pion.BeginOutputReadLine();
            pion.BeginErrorReadLine();

            (await Task.WhenAny(answerApplied.Task, Task.Delay(TimeSpan.FromSeconds(30), cancellationToken)))
                .Should().Be(answerApplied.Task, $"the pion peer should fetch the offer and post an answer; last report: {Report()}");

            (await peer.WaitForConnectedAsync(TimeSpan.FromSeconds(30), cancellationToken))
                .Should().BeTrue($"ICE + DTLS should complete through the coturn relay; last report: {Report()}");
            Log($"connected: dtlsRole={peer.LocalDtlsRole} srtp={peer.NegotiatedSrtpProfile} "
                + $"remoteFp={peer.RemoteFingerprint?[..Math.Min(23, peer.RemoteFingerprint!.Length)]}...");

            // The core assertion this lane exists for: with RelayOnly set, the only pair that
            // could ever succeed is a relayed one (see IceAgent.RebuildPairsLocked), but assert
            // it directly off the public stats surface too, so a future regression that weakens
            // the pairing restriction is caught even if the handshake still happens to connect.
            var report = peer.GetStatsReport();
            var transport = report.OfType<RtcTransportStats>().Single();
            transport.SelectedCandidatePairId.Should().NotBeNull("a connected session must have a selected pair");
            var pair = (RtcCandidatePairStats)report[transport.SelectedCandidatePairId!];
            var localCandidate = (RtcIceCandidateStats)report[pair.LocalCandidateId];
            localCandidate.CandidateType.Should().Be("relay", "RelayOnly must force the selected pair through the coturn allocation");
            Log($"selected pair: local {localCandidate.Address}:{localCandidate.Port} (type={localCandidate.CandidateType})");

            var controller = await controllerTask.WaitAsync(TimeSpan.FromSeconds(15), cancellationToken);
            var telemetry = await telemetryTask.WaitAsync(TimeSpan.FromSeconds(15), cancellationToken);
            Log($"data channels resolved (controller={controller.State} telemetry={telemetry.State})");
            controller.OnMessage += (bool b, ReadOnlySpan<byte> p) => CountEcho(b, p, ref controllerEchoes, ref controllerFirstEcho, "controller");
            telemetry.OnMessage += (bool b, ReadOnlySpan<byte> p) => CountEcho(b, p, ref telemetryEchoes, ref telemetryFirstEcho, "telemetry");

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
                    var json = Report();
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

            var lastJson = Report();
            Log($"final pion report: {lastJson ?? "(none)"}");
            Log($"keryx echoes: controller={Volatile.Read(ref controllerEchoes)} telemetry={Volatile.Read(ref telemetryEchoes)}");

            healthy.Should().BeTrue(
                $"pion should decode Keryx video and echo on both channels through the relay; last report: {lastJson}");

            using (var final = JsonDocument.Parse(lastJson!))
            {
                var root = final.RootElement;
                root.GetProperty("connectionState").GetString().Should().Be("connected");
                root.GetProperty("track").GetProperty("video").GetBoolean().Should().BeTrue();
                ReadStat(root.GetProperty("video"), "packetsReceived").Should().BeGreaterThan(60);
            }

            var stats = peer.GetStats();
            stats.Video.Should().NotBeNull();
            var videoStats = stats.Video!.Value;
            videoStats.PacketsSent.Should().BeGreaterThan(60);
            Volatile.Read(ref controllerEchoes).Should().BeGreaterThan(2, "the controller channel must round-trip through the relay");
            Volatile.Read(ref telemetryEchoes).Should().BeGreaterThan(2, "the telemetry channel must round-trip through the relay");
            Log($"keryx stats: videoPkts={videoStats.PacketsSent} videoBytes={videoStats.BytesSent} "
                + $"pli={stats.Feedback.PictureLossIndications} rr={stats.Feedback.ReceiverReports}");

            shutdown.Cancel();
            await pumps;
        }
        finally
        {
            progressStop.Cancel();
            await Task.WhenAny(progressTask, Task.Delay(2000));

            lock (pionOutput)
            {
                if (pionOutput.Length > 0)
                {
                    _output.WriteLine($"pion peer output:\n{pionOutput}");
                }
            }

            _output.WriteLine($"last pion report: {Report() ?? "(none)"}");
            PionPeer.Cleanup(pion);
            listener.Stop();
            await Task.WhenAny(serverTask, Task.Delay(2000));
        }
    }

    /// <summary>
    /// True when the environment demands this lane actually run: the CI job that installs coturn
    /// and Go sets <c>KERYX_REQUIRE_TURN_RELAY=1</c>. In that mode a missing coturn binary, taken
    /// relay ports, or an unbuildable pion peer is a test failure, not a graceful skip - the same
    /// fail-not-skip contract <see cref="PionPeer.PionRequired"/> already applies.
    /// </summary>
    private static bool TurnRelayRequired =>
        string.Equals(
            Environment.GetEnvironmentVariable("KERYX_REQUIRE_TURN_RELAY"),
            "1",
            StringComparison.Ordinal);

    /// <summary>A coturn process started for the duration of one test.</summary>
    /// <remarks>
    /// A trimmed copy of <see cref="Keryx.Turn.Tests.CoturnInteropTests"/>'s private launcher,
    /// pinned to this class's own port range so the two lanes never contend even though they
    /// happen to both spin up coturn: they run in separate test assemblies (separate CI jobs, and
    /// separate local test-host processes), so nothing but the source is shared.
    /// </remarks>
    private sealed class Coturn : IDisposable
    {
        private readonly Process _process;
        private readonly string _directory;
        private readonly ITestOutputHelper _output;

        private Coturn(Process process, string directory, ITestOutputHelper output)
        {
            _process = process;
            _directory = directory;
            _output = output;
        }

        public IPEndPoint EndPoint { get; } = new(IPAddress.Loopback, CoturnListeningPort);

        /// <summary>
        /// Starts coturn, or returns null after printing why the test is being skipped - unless
        /// <see cref="TurnRelayRequired"/>, in which case it throws so the CI job fails instead of
        /// silently passing.
        /// </summary>
        public static Coturn? TryStart(ITestOutputHelper output)
        {
            var binary = FindTurnServer();
            if (binary is null)
            {
                return Unavailable(output, "no turnserver binary found (set KERYX_TURNSERVER_PATH, or `brew install coturn` / `apt-get install coturn`).");
            }

            for (var port = CoturnListeningPort; port <= CoturnMaxRelayPort; port++)
            {
                if (!IsUdpPortFree(port))
                {
                    return Unavailable(output, $"UDP port {port} is already in use, so coturn cannot be started on {CoturnListeningPort}-{CoturnMaxRelayPort}.");
                }
            }

            var directory = Path.Combine(Path.GetTempPath(), "keryx-coturn-relay-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            var configPath = Path.Combine(directory, "turnserver.conf");
            File.WriteAllText(
                configPath,
                $"""
                 listening-ip=127.0.0.1
                 listening-port={CoturnListeningPort}
                 relay-ip=127.0.0.1
                 min-port={CoturnMinRelayPort}
                 max-port={CoturnMaxRelayPort}
                 realm={Realm}
                 lt-cred-mech
                 user={TurnUsername}:{TurnPassword}
                 allow-loopback-peers
                 no-tls
                 no-dtls
                 no-cli
                 pidfile={Path.Combine(directory, "turnserver.pid")}
                 log-file=stdout
                 simple-log

                 """);

            var process = new Process
            {
                StartInfo =
                {
                    FileName = binary,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                },
            };
            process.StartInfo.ArgumentList.Add("-c");
            process.StartInfo.ArgumentList.Add(configPath);

            var log = new List<string>();
            process.OutputDataReceived += (_, e) => Capture(log, e.Data);
            process.ErrorDataReceived += (_, e) => Capture(log, e.Data);

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            var coturn = new Coturn(process, directory, output);
            if (!coturn.WaitUntilListening())
            {
                coturn.Dispose();
                return Unavailable(output, "coturn did not come up: " + string.Join(" | ", Snapshot(log).TakeLast(20)));
            }

            output.WriteLine($"coturn {binary} listening on {coturn.EndPoint}, relay ports {CoturnMinRelayPort}-{CoturnMaxRelayPort}.");
            return coturn;
        }

        private static Coturn? Unavailable(ITestOutputHelper output, string reason)
        {
            if (TurnRelayRequired)
            {
                throw new InvalidOperationException(
                    $"KERYX_REQUIRE_TURN_RELAY=1 but coturn could not be started: {reason} The TurnRelayInterop CI "
                    + "job installs coturn, so its absence is a failure, not a skip.");
            }

            output.WriteLine($"SKIPPED: {reason}");
            return null;
        }

        public void Dispose()
        {
            try
            {
                if (!_process.HasExited)
                {
                    _process.Kill(entireProcessTree: true);
                    _process.WaitForExit(5000);
                }
            }
            catch (Exception ex)
            {
                _output.WriteLine("Could not stop coturn: " + ex.Message);
            }

            _process.Dispose();

            try
            {
                Directory.Delete(_directory, recursive: true);
            }
            catch (Exception)
            {
                // Best effort.
            }
        }

        private static void Capture(List<string> log, string? line)
        {
            if (line is null)
            {
                return;
            }

            lock (log)
            {
                log.Add(line);
            }
        }

        private static List<string> Snapshot(List<string> log)
        {
            lock (log)
            {
                return [.. log];
            }
        }

        private static string? FindTurnServer()
        {
            var overridePath = Environment.GetEnvironmentVariable("KERYX_TURNSERVER_PATH");
            string[] candidates =
            [
                overridePath ?? string.Empty,
                "/opt/homebrew/bin/turnserver",
                "/usr/local/bin/turnserver",
                "/usr/bin/turnserver",
                "/usr/sbin/turnserver",
            ];

            return candidates.FirstOrDefault(static p => p.Length > 0 && File.Exists(p));
        }

        private static bool IsUdpPortFree(int port)
        {
            try
            {
                using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                probe.Bind(new IPEndPoint(IPAddress.Loopback, port));
                return true;
            }
            catch (SocketException)
            {
                return false;
            }
        }

        /// <summary>
        /// Waits until coturn answers a STUN Binding on its listening port, which is the only
        /// readiness signal that does not depend on the wording of its log lines.
        /// </summary>
        private bool WaitUntilListening()
        {
            var deadline = Environment.TickCount64 + 15_000;
            using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            probe.ReceiveTimeout = 250;

            var buffer = new byte[512];
            while (Environment.TickCount64 < deadline)
            {
                if (_process.HasExited)
                {
                    return false;
                }

                var request = StunMessage.CreateBindingRequest();
                try
                {
                    probe.SendTo(request.Encode(appendFingerprint: true), SocketFlags.None, EndPoint);
                    EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                    var received = probe.ReceiveFrom(buffer, ref from);
                    if (StunMessage.TryDecode(buffer.AsSpan(0, received), out var response)
                        && response.TransactionId.Equals(request.TransactionId))
                    {
                        return true;
                    }
                }
                catch (SocketException)
                {
                    // Not up yet.
                }
            }

            return false;
        }
    }
}
