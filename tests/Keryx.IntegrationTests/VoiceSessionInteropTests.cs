using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Text.Json;
using FluentAssertions;
using Keryx.Sctp;
using Keryx.Sdp;
using Xunit;
using Xunit.Abstractions;

namespace Keryx.IntegrationTests;

/// <summary>
/// A long voice call against a real browser: the browser offers one <c>sendrecv</c> Opus audio m-line
/// (microphone, or a WebAudio oscillator when capture is unavailable) plus a reliable, ordered
/// "control" data channel; Keryx answers, receives the browser's Opus, and sends Opus back every 20 ms
/// while pinging the control channel once a second. Every five seconds the test proves the call is
/// still making progress, and at the end it checks the audio and echo totals and the browser's loss and
/// concealment counters.
/// <para>
/// The soak duration comes from <c>KERYX_VOICE_SOAK_SECONDS</c> (default 60, clamped to 10..3600).
/// PR CI leaves it unset so each browser lane stays at one minute; the scheduled
/// <c>voice-soak.yml</c> workflow sets twenty minutes.
/// </para>
/// </summary>
public sealed class VoiceSessionInteropTests
{
    private const int ChromeHttpPort = 7992;
    private const int FirefoxHttpPort = 7993;

    private readonly ITestOutputHelper _output;

    /// <summary>Captures the xunit output sink.</summary>
    /// <param name="output">Where progress and the final report land.</param>
    public VoiceSessionInteropTests(ITestOutputHelper output) => _output = output;

    /// <summary>Chrome as the voice client: sendrecv Opus plus the control channel, stable for the soak.</summary>
    [Fact]
    [Trait("Category", "ChromeInterop")]
    public async Task ChromeVoiceSession_SendRecvOpusPlusControlChannel_StaysStable()
    {
        await RunVoiceCallAsync(BrowserKind.Chrome, ChromeHttpPort);
    }

    /// <summary>Firefox as the voice client, bound to every interface exactly like the other Firefox lanes.</summary>
    [Fact]
    [Trait("Category", "FirefoxInterop")]
    public async Task FirefoxVoiceSession_SendRecvOpusPlusControlChannel_StaysStable()
    {
        await RunVoiceCallAsync(BrowserKind.Firefox, FirefoxHttpPort);
    }

    /// <summary>Runs the voice soak against one engine, skipping with a printed reason when it is absent.</summary>
    private async Task RunVoiceCallAsync(BrowserKind kind, int httpPort)
    {
        var browserPath = BrowserLauncher.Require(kind);
        if (browserPath is null)
        {
            _output.WriteLine($"SKIPPED: {kind} not found (set {BrowserLauncher.PathEnvVar(kind)} to enable).");
            return;
        }

        var duration = SoakSeconds();
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(duration + 120));
        var cancellationToken = shutdown.Token;

        // The Firefox lane binds every interface (see TestSupport.NewConfig); Chrome collapses onto
        // loopback. The receive jitter buffer is the voice path's playout surface.
        var config = VoiceTestSupport.NewVoiceConfig(
            kind == BrowserKind.Firefox ? IPAddress.Any : null);
        config.EnableReceiveJitterBuffer = true;
        await using var peer = new PeerConnection(config);

        // Keryx-side receipts: inbound audio count, the loss the jitter buffer declares, the longest
        // arrival gap, and the browser's echoed pings parsed back out of the control channel.
        var statsGate = new object();
        var inboundAudio = 0;
        var lostBeforeSum = 0L;
        var longestArrivalGap = 0L;
        var lastArrivalTimestamp = -1L;
        var echoes = new List<int>();

        peer.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            _ = payload;
            if (info.Kind != MediaKind.Audio)
            {
                return;
            }

            lock (statsGate)
            {
                inboundAudio++;
                lostBeforeSum += info.LostBefore;
                if (lastArrivalTimestamp >= 0)
                {
                    longestArrivalGap = Math.Max(longestArrivalGap, info.ArrivalTimestamp - lastArrivalTimestamp);
                }

                lastArrivalTimestamp = info.ArrivalTimestamp;
            }
        };

        DataChannel? control = null;
        peer.OnDataChannel += (_, channel) =>
        {
            if (channel.Label != "control")
            {
                return;
            }

            control = channel;
            channel.OnMessage += (binary, payload) =>
            {
                if (binary)
                {
                    return;
                }

                var text = System.Text.Encoding.UTF8.GetString(payload);
                if (text.StartsWith("echo:", StringComparison.Ordinal)
                    && int.TryParse(text.AsSpan(5), NumberStyles.None, CultureInfo.InvariantCulture, out var n))
                {
                    lock (statsGate)
                    {
                        echoes.Add(n);
                    }
                }
            };
        };

        var answerGate = new object();
        string? answerSdp = null;
        var answered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var reportGate = new object();
        string? latestReportJson = null;

        using var host = new InteropSignalingHost(httpPort, _output)
        {
            OnPostOffer = async offerSdp =>
            {
                await peer.SetRemoteDescriptionAsync(offerSdp, SdpType.Offer, cancellationToken);

                // Binding the legacy audio transceiver to the browser's offer resets it to recvonly;
                // make it bidirectional again before answering.
                VoiceTestSupport.MakeAudioSendRecv(peer);
                var answer = await peer.CreateAnswerAsync(cancellationToken);
                lock (answerGate)
                {
                    answerSdp = answer;
                }

                answered.TrySetResult();
                return answer;
            },
            OnReport = body =>
            {
                lock (reportGate)
                {
                    latestReportJson = body;
                }
            },
        };
        host.Start(cancellationToken);

        var profileDir = Path.Combine(Path.GetTempPath(), $"keryx-voice-{kind}-{Guid.NewGuid():N}");
        Process? browser = null;
        try
        {
            browser = BrowserLauncher.Launch(
                kind, browserPath, $"http://127.0.0.1:{httpPort}/?role=voice", profileDir);

            var answeredOrTimeout = await Task.WhenAny(
                answered.Task, Task.Delay(TimeSpan.FromSeconds(45), cancellationToken));
            if (answeredOrTimeout != answered.Task)
            {
                await Task.Delay(500, cancellationToken);
                _output.WriteLine(
                    $"browser never offered; last report: {SnapshotReportJson(latestReportJson, reportGate) ?? "(none)"}");
            }

            answeredOrTimeout.Should().Be(
                answered.Task, "the browser should offer audio plus a control channel and Keryx should answer");

            string answeredSdp;
            lock (answerGate)
            {
                answeredSdp = answerSdp!;
            }

            answeredSdp.Should().NotContain("m=video", "a voice answer carries no video m-line");
            var answer = SessionDescription.Parse(answeredSdp);
            answer.MediaDescriptions.Count(m => m.Media == "audio" && m.DirectionOrDefault == MediaDirection.SendRecv)
                .Should().Be(1, "the voice answer is one sendrecv audio section");

            (await peer.WaitForConnectedAsync(TimeSpan.FromSeconds(45), cancellationToken))
                .Should().BeTrue("ICE + DTLS should complete against the browser");
            _output.WriteLine(
                $"connected: engine={kind} dtlsRole={peer.LocalDtlsRole} srtp={peer.NegotiatedSrtpProfile} "
                + $"soak={duration}s");

            (await TestSupport.WaitForAsync(
                () => control is { State: DataChannelState.Open },
                timeoutMilliseconds: 30_000))
                .Should().BeTrue("the browser-created 'control' channel must open");
            var channel = control!;

            (await TestSupport.WaitForAsync(
                () => { lock (reportGate) { return latestReportJson is not null; } },
                timeoutMilliseconds: 30_000))
                .Should().BeTrue("the browser must post its first status report");

            // ---------------------------------------------------------------- media + ping pump
            var start = Stopwatch.StartNew();
            var ping = 0;
            var nextPingMilliseconds = 0.0;
            var pump = Task.Run(async () =>
            {
                using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(20));
                while (await timer.WaitForNextTickAsync(cancellationToken))
                {
                    var elapsedMilliseconds = start.Elapsed.TotalMilliseconds;

                    // Advance the RTP clock from wall time and quantize to a 20 ms frame, so timer slip
                    // never drifts the timestamp off the audio clock.
                    var frameIndex = (long)Math.Round(elapsedMilliseconds * 48.0 / 960.0);
                    peer.SendAudioFrame(VoiceTestSupport.OpusSilence, (uint)(frameIndex * 960));

                    if (elapsedMilliseconds >= nextPingMilliseconds)
                    {
                        nextPingMilliseconds = elapsedMilliseconds + 1000.0;
                        ping++;
                        try
                        {
                            channel.SendText($"ping:{ping}");
                        }
                        catch (InvalidOperationException)
                        {
                            // The channel closed underneath the pump; the final assertions will say so.
                        }
                    }
                }
            });

            // ---------------------------------------------------------------- stability, every 5 s
            var previousKeryxInbound = 0;
            var previousBrowserReceived = 0L;
            var previousEchoCount = 0;
            var check = 0;
            var elapsedSeconds = 0;
            while (elapsedSeconds + 5 <= duration)
            {
                await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);
                elapsedSeconds += 5;
                check++;

                var report = ReadBrowserReport(SnapshotReportJson(latestReportJson, reportGate));
                int keryxInbound;
                int echoCount;
                lock (statsGate)
                {
                    keryxInbound = inboundAudio;
                    echoCount = echoes.Count;
                }

                peer.State.Should().Be(PeerConnectionState.Connected, $"check {check}: Keryx must stay connected");
                report.ConnectionState.Should().Be("connected", $"check {check}: the browser must stay connected");
                report.AudioPacketsReceived.Should().BeGreaterThan(
                    previousBrowserReceived,
                    $"check {check}: the browser must keep receiving audio");
                keryxInbound.Should().BeGreaterThan(
                    previousKeryxInbound,
                    $"check {check}: Keryx must keep receiving the browser's audio");
                if (check >= 2)
                {
                    echoCount.Should().BeGreaterThan(
                        previousEchoCount,
                        $"check {check}: the control channel must keep carrying echoes");
                }

                _output.WriteLine(
                    $"check {check} t={elapsedSeconds}s: keryxInbound={keryxInbound} "
                    + $"browserReceived={report.AudioPacketsReceived} browserLost={report.AudioPacketsLost} "
                    + $"concealed={report.ConcealedSamples}/{report.TotalSamplesReceived} echoes={echoCount} "
                    + $"pingsSent={ping} source={report.AudioSource}");

                previousKeryxInbound = keryxInbound;
                previousBrowserReceived = report.AudioPacketsReceived;
                previousEchoCount = echoCount;
            }

            if (elapsedSeconds < duration)
            {
                await Task.Delay(TimeSpan.FromSeconds(duration - elapsedSeconds), cancellationToken);
            }

            await shutdown.CancelAsync();
            try
            {
                await pump;
            }
            catch (OperationCanceledException)
            {
                // Expected: the pump ends when the soak does.
            }

            // ---------------------------------------------------------------- final assertions
            var finalReport = ReadBrowserReport(SnapshotReportJson(latestReportJson, reportGate));
            int finalKeryxInbound;
            long finalLostBefore;
            long finalArrivalGap;
            List<int> finalEchoes;
            lock (statsGate)
            {
                finalKeryxInbound = inboundAudio;
                finalLostBefore = lostBeforeSum;
                finalArrivalGap = longestArrivalGap;
                finalEchoes = [.. echoes];
            }

            finalEchoes.Should().Equal(
                Enumerable.Range(1, finalEchoes.Count),
                "echoes must arrive strictly increasing with no gaps");

            finalKeryxInbound.Should().BeGreaterThanOrEqualTo(
                (int)(0.9 * duration * 50), "Keryx must receive the browser's audio for the whole soak");
            finalReport.AudioPacketsReceived.Should().BeGreaterThanOrEqualTo(
                (long)(0.9 * duration * 50), "the browser must receive Keryx's audio for the whole soak");
            finalReport.AudioPacketsLost.Should().BeLessThanOrEqualTo(
                (long)(0.01 * Math.Max(1, finalReport.AudioPacketsReceived)), "the browser's loss must stay under 1%");
            finalEchoes.Count.Should().BeGreaterThanOrEqualTo(duration - 3, "the control channel must keep echoing");
            finalLostBefore.Should().BeLessThanOrEqualTo(
                (long)(0.01 * Math.Max(1, finalKeryxInbound)), "Keryx's declared loss must stay under 1%");

            if (finalReport.TotalSamplesReceived > 0)
            {
                (finalReport.ConcealedSamples / (double)finalReport.TotalSamplesReceived).Should().BeLessThan(
                    0.05, "the browser must conceal under 5% of received audio samples");
            }
            else
            {
                _output.WriteLine("browser reported no playout samples (headless); concealment check skipped.");
            }

            _output.WriteLine(
                $"summary: engine={kind} soak={duration}s source={finalReport.AudioSource} "
                + $"keryxInbound={finalKeryxInbound} browserReceived={finalReport.AudioPacketsReceived} "
                + $"browserLost={finalReport.AudioPacketsLost} browserJitter={finalReport.Jitter} "
                + $"concealed={finalReport.ConcealedSamples}/{finalReport.TotalSamplesReceived} "
                + $"concealmentEvents={finalReport.ConcealmentEvents} outboundAudio={finalReport.OutboundAudioPackets} "
                + $"lostBeforeSum={finalLostBefore} longestArrivalGapTicks={finalArrivalGap} "
                + $"echoes={finalEchoes.Count} connected={peer.State}");
        }
        finally
        {
            BrowserLauncher.Cleanup(browser, profileDir);
            if (!shutdown.IsCancellationRequested)
            {
                await shutdown.CancelAsync();
            }
        }
    }

    /// <summary>Reads the soak duration from the environment, defaulting to 60 s and clamping to 10..3600.</summary>
    private static int SoakSeconds()
    {
        var raw = Environment.GetEnvironmentVariable("KERYX_VOICE_SOAK_SECONDS");
        var seconds = int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : 60;
        return Math.Clamp(seconds, 10, 3600);
    }

    /// <summary>Takes a copy of the latest browser report under its lock.</summary>
    private static string? SnapshotReportJson(string? latestReportJson, object reportGate)
    {
        lock (reportGate)
        {
            return latestReportJson;
        }
    }

    /// <summary>Parses one browser status snapshot into the counters the soak asserts on.</summary>
    private static BrowserReport ReadBrowserReport(string? json)
    {
        if (json is null)
        {
            return default;
        }

        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        var stats = root.GetProperty("stats");

        long Read(string name) =>
            stats.TryGetProperty(name, out var element) && element.ValueKind == JsonValueKind.Number
                ? (long)element.GetDouble()
                : 0;

        return new BrowserReport(
            root.TryGetProperty("connectionState", out var state) ? state.GetString() ?? string.Empty : string.Empty,
            Read("audioPacketsReceived"),
            Read("audioPacketsLost"),
            Read("totalSamplesReceived"),
            Read("concealedSamples"),
            Read("concealmentEvents"),
            Read("audioJitter"),
            Read("audioPacketsSent"),
            root.TryGetProperty("audioSource", out var source) ? source.GetString() ?? string.Empty : string.Empty);
    }

    /// <summary>A browser status snapshot reduced to the voice-soak counters.</summary>
    private readonly record struct BrowserReport(
        string ConnectionState,
        long AudioPacketsReceived,
        long AudioPacketsLost,
        long TotalSamplesReceived,
        long ConcealedSamples,
        long ConcealmentEvents,
        double Jitter,
        long OutboundAudioPackets,
        string AudioSource);
}
