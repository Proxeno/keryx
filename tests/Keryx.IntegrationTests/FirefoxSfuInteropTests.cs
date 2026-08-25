using System.Diagnostics;
using System.Net;
using System.Text.Json;
using FluentAssertions;
using Keryx.Rtp;
using Xunit;
using Xunit.Abstractions;

namespace Keryx.IntegrationTests;

/// <summary>
/// The SFU egress shape, proven against Firefox as the offerer and Keryx as the answerer — the mirror
/// of <see cref="ChromeSfuInteropTests"/> on a second real engine. Firefox offers <c>recvonly</c>,
/// Keryx answers <c>sendonly</c> and forwards RTP with <see cref="PeerConnection.TryForwardRtp"/>, and
/// Firefox reports what it received. It runs against the one role-flexible fixture
/// (<c>assets/chrome-client.html</c>) through the shared <see cref="BrowserLauncher"/> seam. Firefox's
/// codec/PT preferences and <c>a=setup</c> role differ from Chrome's, so it exercises the answerer's
/// codec-matching and DTLS-role paths against inputs Chrome does not produce.
/// <para>
/// The complementary ingest shape (browser offers <c>sendonly</c>, Keryx receives the browser's RTP)
/// that the Chrome lane proves is deliberately absent here because headless Firefox's H.264 encoder is
/// not portable: with the GMP sandbox disabled it encodes on Linux (where CI runs) but a headless macOS
/// Firefox produces zero encoded frames (it has no working headless H.264 encoder), so a Firefox
/// <c>sendonly</c> offer would carry media on CI but none on a developer's Mac — an inconsistency that
/// would fail the lane locally. Keeping the browser-sends-H.264 direction on the Chrome lane, whose
/// H.264 encoder works headless everywhere, keeps this lane green on both. H.264 <em>decode</em> (the
/// keryx-offers and egress flows) is portable once the GMP is registered and its sandbox disabled.
/// </para>
/// </summary>
/// <remarks>
/// <c>Category=FirefoxInterop</c>: needs a browser. Its absence skips locally and — when the CI job
/// sets <c>KERYX_REQUIRE_FIREFOX=1</c> — fails. The browser path can be overridden with
/// <c>KERYX_FIREFOX_PATH</c>.
/// </remarks>
public sealed class FirefoxSfuInteropTests
{
    private const int HttpPort = 7988;

    private readonly ITestOutputHelper _output;

    /// <summary>Captures the xunit output sink.</summary>
    /// <param name="output">Where progress and the final report land.</param>
    public FirefoxSfuInteropTests(ITestOutputHelper output) => _output = output;

    /// <summary>
    /// Firefox offers <c>recvonly</c> video; Keryx answers <c>sendonly</c> and forwards synthetic RTP
    /// packets with <see cref="PeerConnection.TryForwardRtp"/> on the SSRC and payload type it owns.
    /// Firefox reports the packets it received — the subscriber-egress path against a second receiver.
    /// </summary>
    [Fact]
    [Trait("Category", "FirefoxInterop")]
    public async Task BrowserOffersRecvonlyAndReceivesKeryxForwardedRtp()
    {
        var firefoxPath = BrowserLauncher.Require(BrowserKind.Firefox);
        if (firefoxPath is null)
        {
            _output.WriteLine("SKIPPED: Firefox not found (set KERYX_FIREFOX_PATH to enable).");
            return;
        }

        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        var cancellationToken = shutdown.Token;

        await using var peer = new PeerConnection(TestSupport.NewConfig(bindAddress: IPAddress.Any));

        var reportLock = new object();
        string? latestReportJson = null;
        var answered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        using var host = new InteropSignalingHost(HttpPort, _output)
        {
            OnPostOffer = async offerSdp =>
            {
                await peer.SetRemoteDescriptionAsync(offerSdp, SdpType.Offer, cancellationToken);
                var answer = await peer.CreateAnswerAsync(cancellationToken);
                answer.Should().Contain("a=sendonly", "a recvonly offer must be answered sendonly");
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

        var profileDir = Path.Combine(Path.GetTempPath(), $"keryx-firefox-sfu-recv-{Guid.NewGuid():N}");
        Process? firefox = null;
        try
        {
            firefox = BrowserLauncher.Launch(
                BrowserKind.Firefox, firefoxPath, $"http://127.0.0.1:{HttpPort}/?role=offer-recv", profileDir);

            (await Task.WhenAny(answered.Task, Task.Delay(TimeSpan.FromSeconds(30), cancellationToken)))
                .Should().Be(answered.Task, "Firefox should offer recvonly and Keryx should answer sendonly");

            (await peer.WaitForConnectedAsync(TimeSpan.FromSeconds(30), cancellationToken))
                .Should().BeTrue("ICE + DTLS should complete against Firefox");

            // Answering a recvonly offer wired a real send track: the send SSRC and negotiated PT — the
            // shape an SFU consumer polls before forwarding — light up on the answerer.
            var payloadType = peer.GetNegotiatedPayloadType(MediaKind.Video);
            payloadType.Should().NotBeNull("the answerer negotiated a video send track against the recvonly offer");
            peer.GetLocalSsrc(MediaKind.Video).Should().Be(peer.VideoSsrc).And.NotBe(0u);
            _output.WriteLine(
                $"connected: sendPt={payloadType} sendSsrc=0x{peer.VideoSsrc:x8} srtp={peer.NegotiatedSrtpProfile}");

            // Forward synthetic RTP verbatim on the owned SSRC/seq space until Firefox confirms
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
                $"Firefox must receive the RTP Keryx forwarded; last report: {lastJson}");
            Volatile.Read(ref forwarded).Should().BeGreaterThan(20, "a connected, negotiated egress track must accept forwards");
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
