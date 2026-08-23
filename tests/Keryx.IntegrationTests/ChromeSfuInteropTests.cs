using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Keryx.Rtp;
using Xunit;
using Xunit.Abstractions;

namespace Keryx.IntegrationTests;

/// <summary>
/// The SFU shapes, proven against a real browser with the browser as the offerer and Keryx as the
/// answerer — the reverse of <see cref="ChromeInteropTests"/> (Keryx offers). Two directions run
/// against the one role-flexible fixture (<c>assets/chrome-client.html</c>):
/// <list type="bullet">
/// <item>the browser offers <c>sendonly</c> and Keryx receives its RTP (the ingest shape), and</item>
/// <item>the browser offers <c>recvonly</c>, Keryx answers <c>sendonly</c> and forwards RTP with
/// <see cref="PeerConnection.TryForwardRtp"/>, and the browser reports what it received (the
/// subscriber-egress shape, and a regression for the 0.2.0 answerer-send path).</item>
/// </list>
/// </summary>
/// <remarks>
/// <c>Category=ChromeInterop</c>: needs a browser. Its absence skips locally and — when the CI job
/// sets <c>KERYX_REQUIRE_CHROME=1</c> — fails. The browser path can be overridden with
/// <c>KERYX_CHROME_PATH</c>.
/// </remarks>
public sealed class ChromeSfuInteropTests
{
    private const int HttpPort = 7982;

    private readonly ITestOutputHelper _output;

    /// <summary>Captures the xunit output sink.</summary>
    /// <param name="output">Where progress and the final report land.</param>
    public ChromeSfuInteropTests(ITestOutputHelper output) => _output = output;

    /// <summary>
    /// Browser offers <c>sendonly</c> video (a synthetic canvas stream); Keryx answers, connects, and
    /// its inbound RTP counter climbs — the media-server ingest path, but with the browser driving the
    /// offer.
    /// </summary>
    [Fact]
    [Trait("Category", "ChromeInterop")]
    public async Task BrowserOffersSendonlyAndKeryxReceivesInboundRtp()
    {
        var chromePath = ChromeBrowser.Require();
        if (chromePath is null)
        {
            _output.WriteLine("SKIPPED: Google Chrome not found (set KERYX_CHROME_PATH to enable).");
            return;
        }

        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        var cancellationToken = shutdown.Token;

        await using var peer = new PeerConnection(TestSupport.NewConfig());

        // Count the inbound video RTP Keryx routes, alongside the transport-level receive counter, so
        // the assertion is "Keryx saw the browser's media", not merely "some datagram decrypted".
        var videoPacketsSeen = 0;
        peer.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            _ = payload;
            if (info.Kind == MediaKind.Video)
            {
                Interlocked.Increment(ref videoPacketsSeen);
            }
        };

        var reportLock = new object();
        string? latestReportJson = null;
        var answered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        using var host = new SignalingHost(HttpPort);
        host.OnOffer = async offerSdp =>
        {
            await peer.SetRemoteDescriptionAsync(offerSdp, SdpType.Offer, cancellationToken);
            var answer = await peer.CreateAnswerAsync(cancellationToken);
            answer.Should().Contain("a=recvonly", "a sendonly offer must be answered recvonly");
            answered.TrySetResult();
            return answer;
        };
        host.OnReport = body =>
        {
            lock (reportLock)
            {
                latestReportJson = body;
            }
        };
        host.Start(cancellationToken, _output);

        var userDataDir = Path.Combine(Path.GetTempPath(), $"keryx-chrome-sfu-send-{Guid.NewGuid():N}");
        Process? chrome = null;
        try
        {
            chrome = ChromeBrowser.Launch(chromePath, $"http://127.0.0.1:{HttpPort}/?role=offer-send", userDataDir);

            (await Task.WhenAny(answered.Task, Task.Delay(TimeSpan.FromSeconds(30), cancellationToken)))
                .Should().Be(answered.Task, "Chrome should offer and Keryx should answer it");

            (await peer.WaitForConnectedAsync(TimeSpan.FromSeconds(30), cancellationToken))
                .Should().BeTrue("ICE + DTLS should complete against Chrome");
            _output.WriteLine(
                $"connected: dtlsRole={peer.LocalDtlsRole} srtp={peer.NegotiatedSrtpProfile}");

            var received = await TestSupport.WaitForAsync(
                () => peer.GetStats().RtpPacketsReceived >= 60 && Volatile.Read(ref videoPacketsSeen) >= 60,
                timeoutMilliseconds: 45_000);

            var stats = peer.GetStats();
            string? lastJson;
            lock (reportLock)
            {
                lastJson = latestReportJson;
            }

            _output.WriteLine(
                $"keryx inbound: rtpPackets={stats.RtpPacketsReceived} videoPackets={Volatile.Read(ref videoPacketsSeen)} "
                + $"srtpFailures={stats.SrtpAuthenticationFailures} beforeReady={stats.MediaDroppedBeforeReady}");
            _output.WriteLine($"final browser report: {lastJson ?? "(none)"}");

            received.Should().BeTrue(
                $"Keryx must see the browser's inbound RTP; last report: {lastJson}");
            stats.RtpPacketsReceived.Should().BeGreaterThan(30);
            Volatile.Read(ref videoPacketsSeen).Should().BeGreaterThan(30, "inbound video must route to the video track");
        }
        finally
        {
            ChromeBrowser.Cleanup(chrome, userDataDir);
            shutdown.Cancel();
        }
    }

    /// <summary>
    /// Browser offers <c>recvonly</c> video; Keryx answers <c>sendonly</c> and forwards synthetic RTP
    /// packets with <see cref="PeerConnection.TryForwardRtp"/> on the SSRC and payload type it owns.
    /// The browser reports the packets it received — the subscriber-egress path, proven end to end
    /// against a real receiver.
    /// </summary>
    [Fact]
    [Trait("Category", "ChromeInterop")]
    public async Task BrowserOffersRecvonlyAndReceivesKeryxForwardedRtp()
    {
        var chromePath = ChromeBrowser.Require();
        if (chromePath is null)
        {
            _output.WriteLine("SKIPPED: Google Chrome not found (set KERYX_CHROME_PATH to enable).");
            return;
        }

        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        var cancellationToken = shutdown.Token;

        await using var peer = new PeerConnection(TestSupport.NewConfig());

        var reportLock = new object();
        string? latestReportJson = null;
        var answered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        using var host = new SignalingHost(HttpPort);
        host.OnOffer = async offerSdp =>
        {
            await peer.SetRemoteDescriptionAsync(offerSdp, SdpType.Offer, cancellationToken);
            var answer = await peer.CreateAnswerAsync(cancellationToken);
            answer.Should().Contain("a=sendonly", "a recvonly offer must be answered sendonly");
            answered.TrySetResult();
            return answer;
        };
        host.OnReport = body =>
        {
            lock (reportLock)
            {
                latestReportJson = body;
            }
        };
        host.Start(cancellationToken, _output);

        var userDataDir = Path.Combine(Path.GetTempPath(), $"keryx-chrome-sfu-recv-{Guid.NewGuid():N}");
        Process? chrome = null;
        try
        {
            chrome = ChromeBrowser.Launch(chromePath, $"http://127.0.0.1:{HttpPort}/?role=offer-recv", userDataDir);

            (await Task.WhenAny(answered.Task, Task.Delay(TimeSpan.FromSeconds(30), cancellationToken)))
                .Should().Be(answered.Task, "Chrome should offer recvonly and Keryx should answer sendonly");

            (await peer.WaitForConnectedAsync(TimeSpan.FromSeconds(30), cancellationToken))
                .Should().BeTrue("ICE + DTLS should complete against Chrome");

            // Answering a recvonly offer wired a real send track: the send SSRC and negotiated PT — the
            // shape an SFU consumer polls before forwarding — light up on the answerer.
            var payloadType = peer.GetNegotiatedPayloadType(MediaKind.Video);
            payloadType.Should().NotBeNull("the answerer negotiated a video send track against the recvonly offer");
            peer.GetLocalSsrc(MediaKind.Video).Should().Be(peer.VideoSsrc).And.NotBe(0u);
            _output.WriteLine(
                $"connected: sendPt={payloadType} sendSsrc=0x{peer.VideoSsrc:x8} srtp={peer.NegotiatedSrtpProfile}");

            // Forward synthetic RTP verbatim on the owned SSRC/seq space until the browser confirms
            // reception. TryForwardRtp is the SFU egress entry point; here the receiver is a browser.
            var forwarded = 0;
            var pump = Task.Run(async () =>
            {
                uint timestamp = 1_000_000;
                var seq = 0;
                while (!cancellationToken.IsCancellationRequested)
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
                        await Task.Delay(20, cancellationToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        return;
                    }
                }
            });

            static long ReadStat(JsonElement root, string name) =>
                root.GetProperty("stats").TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.Number
                    ? (long)el.GetDouble()
                    : 0;

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

            shutdown.Cancel();
            await pump;

            string? lastJson;
            lock (reportLock)
            {
                lastJson = latestReportJson;
            }

            _output.WriteLine($"forwarded={Volatile.Read(ref forwarded)} final browser report: {lastJson ?? "(none)"}");
            browserReceived.Should().BeTrue(
                $"the browser must receive the RTP Keryx forwarded; last report: {lastJson}");
            Volatile.Read(ref forwarded).Should().BeGreaterThan(20, "a connected, negotiated egress track must accept forwards");
        }
        finally
        {
            ChromeBrowser.Cleanup(chrome, userDataDir);
            if (!shutdown.IsCancellationRequested)
            {
                shutdown.Cancel();
            }
        }
    }

    /// <summary>
    /// A tiny HTTP signaling host for the browser-offerer flow: serves the shared fixture on <c>/</c>,
    /// takes the browser's offer on <c>POST /offer</c> and returns Keryx's answer in the response, and
    /// collects <c>POST /report</c> snapshots. One host, so both SFU directions share the same wiring.
    /// </summary>
    private sealed class SignalingHost : IDisposable
    {
        private readonly HttpListener _listener = new();

        internal SignalingHost(int port) => _listener.Prefixes.Add($"http://127.0.0.1:{port}/");

        /// <summary>Handles <c>POST /offer</c>: takes the browser offer SDP, returns Keryx's answer SDP.</summary>
        internal Func<string, Task<string>> OnOffer { get; set; } = _ => Task.FromResult(string.Empty);

        /// <summary>Handles <c>POST /report</c>: receives one browser status snapshot as JSON.</summary>
        internal Action<string> OnReport { get; set; } = _ => { };

        internal void Start(CancellationToken cancellationToken, ITestOutputHelper output)
        {
            _listener.Start();
            _ = Task.Run(async () =>
            {
                while (_listener.IsListening)
                {
                    HttpListenerContext context;
                    try
                    {
                        context = await _listener.GetContextAsync().ConfigureAwait(false);
                    }
                    catch (Exception) when (!_listener.IsListening || cancellationToken.IsCancellationRequested)
                    {
                        return;
                    }

                    try
                    {
                        await HandleAsync(context).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        output.WriteLine($"signaling host error: {ex.Message}");
                    }
                }
            });
        }

        private async Task HandleAsync(HttpListenerContext context)
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
                    using (var reader = new StreamReader(request.InputStream, Encoding.UTF8))
                    {
                        var body = await reader.ReadToEndAsync();
                        using var doc = JsonDocument.Parse(body);
                        var offerSdp = doc.RootElement.GetProperty("sdp").GetString()!;
                        var answerSdp = await OnOffer(offerSdp);
                        var answerJson = JsonSerializer.SerializeToUtf8Bytes(new { type = "answer", sdp = answerSdp });
                        response.ContentType = "application/json";
                        await response.OutputStream.WriteAsync(answerJson);
                    }

                    break;
                case "/report":
                    using (var reader = new StreamReader(request.InputStream, Encoding.UTF8))
                    {
                        OnReport(await reader.ReadToEndAsync());
                    }

                    break;
                default:
                    response.StatusCode = 404;
                    break;
            }

            response.Close();
        }

        public void Dispose()
        {
            try
            {
                _listener.Stop();
                _listener.Close();
            }
            catch (Exception)
            {
                // best effort
            }
        }
    }
}
