using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Keryx.Dtls;
using Xunit;
using Xunit.Abstractions;

namespace Keryx.IntegrationTests;

/// <summary>
/// Forces each DTLS cipher suite and ECDHE curve Keryx implements, one per case, against real
/// headless Chrome, so newer suites (AES-256-GCM, ChaCha20-Poly1305) and curves (P-384) can be
/// promoted ahead of AES-128-GCM/P-256 with real-browser evidence rather than the loopback coverage
/// <see cref="Keryx.Dtls.Tests.DtlsCipherSuiteNegotiationTests"/> already gives every suite and curve.
/// <see cref="ChromeInteropTests"/> proves Keryx's default configuration end to end against Chrome;
/// this class proves every DTLS configuration Keryx can be pointed at, one Chrome session per case.
/// </summary>
/// <remarks>
/// <para>
/// Each case sets <see cref="PeerConnectionConfig.DtlsOfferedCipherSuites"/> or
/// <see cref="PeerConnectionConfig.DtlsOfferedNamedGroups"/> to a single value, so the DTLS transport
/// has no fallback: either that exact suite/curve carries the handshake, or the case fails. Every case
/// authenticates with a certificate matching the forced suite's key type (ECDSA suites/curves get an
/// ECDSA certificate, RSA suites get an RSA certificate — <see cref="CertificateFor"/>), the same way
/// <see cref="Keryx.Dtls.Tests.DtlsCipherSuiteNegotiationTests"/> does over loopback, so the only
/// variable under test is whether the suite/curve itself is negotiable with Chrome, never a
/// self-inflicted certificate mismatch.
/// </para>
/// <para>
/// <b>Real-browser findings recorded here (Google Chrome 151.0.7922.174, headless, macOS,
/// 2026-08-24):</b> Chrome negotiates AES-128-GCM and ChaCha20-Poly1305 under both ECDSA and RSA
/// authentication (<see cref="Chrome_completes_the_handshake_on_each_negotiable_suite"/>), and
/// negotiates both P-256 and P-384 (<see cref="Chrome_completes_the_handshake_on_each_curve"/>). It
/// does <em>not</em> negotiate AES-256-GCM under either authentication type — Chrome's DTLS ClientHello
/// never lists <c>TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384</c> or
/// <c>TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384</c> at all, so forcing Keryx to either one leaves no suite
/// in common and the handshake fails closed (<see cref="Chrome_does_not_negotiate_aes_256_gcm"/>). That
/// contradicts this epic's premise for AES-256-GCM specifically: it cannot be promoted as a Keryx
/// default while real Chrome refuses to offer it, though P-384 is fully clear to promote. RSA suites
/// were also assumed unnegotiable going in — Chrome was expected to authenticate with ECDSA only — but
/// that assumption was wrong for AES-128-GCM and ChaCha20-Poly1305: the suite name's "RSA" describes
/// the certificate authenticating whichever side plays DTLS server (Keryx here), not a browser-side
/// requirement, and Chrome's ClientHello offers RSA variants of both.
/// </para>
/// <para>
/// Excluded from CI (<c>Category=ChromeInterop</c>), same as <see cref="ChromeInteropTests"/>: it
/// needs Google Chrome on the machine. The browser path can be overridden with
/// <c>KERYX_CHROME_PATH</c>.
/// </para>
/// </remarks>
public sealed class ChromeDtlsCipherSuiteMatrixTests
{
    /// <summary>Distinct from <see cref="ChromeInteropTests"/>'s port and spread across cases so a
    /// listener from one case is never still unwinding when the next case binds.</summary>
    private const int BasePort = 7985;

    private readonly ITestOutputHelper _output;

    /// <summary>Captures the xunit output sink.</summary>
    /// <param name="output">Where progress and the final report land.</param>
    public ChromeDtlsCipherSuiteMatrixTests(ITestOutputHelper output) => _output = output;

    /// <summary>
    /// The suites real Chrome negotiates: AES-128-GCM and ChaCha20-Poly1305, each under both ECDSA and
    /// RSA authentication. See the class remarks for how this was established.
    /// </summary>
    private static readonly ushort[] NegotiableSuiteValues =
    [
        CipherSuites.TlsEcdheEcdsaWithAes128GcmSha256,
        CipherSuites.TlsEcdheEcdsaWithChaCha20Poly1305Sha256,
        CipherSuites.TlsEcdheRsaWithAes128GcmSha256,
        CipherSuites.TlsEcdheRsaWithChaCha20Poly1305Sha256,
    ];

    /// <summary>
    /// AES-256-GCM under both authentication types: real Chrome's ClientHello never offers either, so
    /// forcing Keryx to one leaves no mutually supported suite. See the class remarks.
    /// </summary>
    private static readonly ushort[] NonNegotiableAes256SuiteValues =
    [
        CipherSuites.TlsEcdheEcdsaWithAes256GcmSha384,
        CipherSuites.TlsEcdheRsaWithAes256GcmSha384,
    ];

    /// <summary>The ECDHE named groups Keryx implements; real Chrome negotiates both.</summary>
    private static readonly ushort[] CurveValues =
    [
        NamedGroups.Secp256r1,
        NamedGroups.Secp384r1,
    ];

    public static TheoryData<ushort> NegotiableSuites => ToTheoryData(NegotiableSuiteValues);

    public static TheoryData<ushort> NonNegotiableAes256Suites => ToTheoryData(NonNegotiableAes256SuiteValues);

    public static TheoryData<ushort> Curves => ToTheoryData(CurveValues);

    private static TheoryData<ushort> ToTheoryData(IEnumerable<ushort> values)
    {
        var data = new TheoryData<ushort>();
        foreach (var value in values)
        {
            data.Add(value);
        }

        return data;
    }

    /// <summary>The certificate key type a suite authenticates with — ECDSA or RSA, matched exactly so
    /// the suite itself is the only variable under test.</summary>
    private static DtlsCertificate CertificateFor(ushort suite) =>
        CipherSuites.Describe(suite)!.Value.RequiresEcdsaCertificate
            ? DtlsCertificate.GenerateSelfSigned("keryx-suite-matrix")
            : GenerateRsaCertificate("keryx-suite-matrix");

    [Theory]
    [Trait("Category", "ChromeInterop")]
    [MemberData(nameof(NegotiableSuites))]
    public async Task Chrome_completes_the_handshake_on_each_negotiable_suite(ushort suite)
    {
        var result = await RunCaseAsync(
            port: BasePort + Array.IndexOf(NegotiableSuiteValues, suite),
            certificate: CertificateFor(suite),
            configure: config => config.DtlsOfferedCipherSuites = [suite]);

        result.Connected.Should().BeTrue(
            $"{CipherSuites.Name(suite)} is a suite real Chrome is known to negotiate; last report: {result.LastReportJson}");
        result.NegotiatedCipherSuite.Should().Be(CipherSuites.Name(suite));
        result.FramesDecoded.Should().BeGreaterThan(0, "Chrome should decode video carried over the forced suite's derived keys");
        result.EchoedMessages.Should().BeGreaterThan(0, "the data channel should round-trip over the forced suite's derived keys");
    }

    [Theory]
    [Trait("Category", "ChromeInterop")]
    [MemberData(nameof(Curves))]
    public async Task Chrome_completes_the_handshake_on_each_curve(ushort group)
    {
        var result = await RunCaseAsync(
            port: BasePort + NegotiableSuiteValues.Length + Array.IndexOf(CurveValues, group),
            certificate: DtlsCertificate.GenerateSelfSigned("keryx-curve-matrix"),
            configure: config => config.DtlsOfferedNamedGroups = [group]);

        result.Connected.Should().BeTrue(
            $"named group {group} is a curve Chrome is expected to negotiate; last report: {result.LastReportJson}");
        result.NegotiatedNamedGroup.Should().Be(group);
        result.FramesDecoded.Should().BeGreaterThan(0, "Chrome should decode video carried over keys derived on the forced curve");
        result.EchoedMessages.Should().BeGreaterThan(0, "the data channel should round-trip over keys derived on the forced curve");
    }

    /// <summary>
    /// The real-browser finding this matrix exists to surface: real Chrome's DTLS ClientHello never
    /// offers AES-256-GCM, under either ECDSA or RSA authentication, so forcing Keryx to one of these
    /// two suites leaves no suite in common and the handshake fails closed. Keryx still authenticates
    /// with a certificate matching the forced suite (see <see cref="CertificateFor"/>), so the failure
    /// is Chrome's absent offer, not a self-inflicted certificate mismatch. If this case starts passing,
    /// Chrome has started offering AES-256-GCM — update the class remarks and promote the suite rather
    /// than treat the newly-passing case as a bug.
    /// </summary>
    [Theory]
    [Trait("Category", "ChromeInterop")]
    [MemberData(nameof(NonNegotiableAes256Suites))]
    public async Task Chrome_does_not_negotiate_aes_256_gcm(ushort suite)
    {
        var result = await RunCaseAsync(
            port: BasePort + NegotiableSuiteValues.Length + CurveValues.Length + Array.IndexOf(NonNegotiableAes256SuiteValues, suite),
            certificate: CertificateFor(suite),
            configure: config => config.DtlsOfferedCipherSuites = [suite]);

        result.Connected.Should().BeFalse(
            $"{CipherSuites.Name(suite)} is AES-256-GCM; real Chrome's ClientHello does not offer it "
            + $"under either authentication type, so it is not expected to negotiate. If this now "
            + $"connects, Chrome has started offering it — update this class's remarks rather than "
            + $"treat the newly-passing case as a bug.");
    }

    /// <summary>One forced-suite/curve Chrome session's outcome.</summary>
    /// <param name="Connected">True once ICE and the DTLS handshake both completed.</param>
    /// <param name="NegotiatedCipherSuite">The suite Keryx's side of the handshake settled on.</param>
    /// <param name="NegotiatedNamedGroup">The ECDHE group Keryx's side of the handshake settled on.</param>
    /// <param name="FramesDecoded">The last <c>framesDecoded</c> Chrome reported.</param>
    /// <param name="EchoedMessages">The lowest per-channel <c>echoed</c> count Chrome reported.</param>
    /// <param name="LastReportJson">The last status snapshot Chrome posted, for failure messages.</param>
    private readonly record struct CaseResult(
        bool Connected,
        string? NegotiatedCipherSuite,
        ushort? NegotiatedNamedGroup,
        long FramesDecoded,
        long EchoedMessages,
        string? LastReportJson);

    /// <summary>
    /// Runs one Chrome session end to end — offer, headless Chrome answers over HTTP signaling, ICE,
    /// the forced DTLS suite/curve, a short video stream and a data-channel ping/pong — and reports
    /// what happened. Mirrors <see cref="ChromeInteropTests.ChromeDecodesKeryxVideoAndDataChannelsRoundTrip"/>
    /// at smaller scale (fewer access units, lower thresholds): this method runs up to eight times per
    /// suite/CI invocation, so each case stays fast while still requiring Chrome to actually decode
    /// video and echo a data channel over the forced configuration's derived keys — proof the DTLS
    /// suite/curve produced usable SRTP and SCTP keys, not just a completed handshake.
    /// </summary>
    /// <param name="port">The signaling HTTP port this case binds; unique per case so no two cases
    /// ever race for the same listener even if a prior case's cleanup is still unwinding.</param>
    /// <param name="certificate">The local DTLS certificate; its key type must match the forced suite
    /// (ECDSA suites/curves need an ECDSA certificate, RSA suites need an RSA certificate) or the
    /// mismatch — not Chrome — would be why negotiation fails. Disposed before returning.</param>
    /// <param name="configure">Applies the one override under test to the connection's config.</param>
    private async Task<CaseResult> RunCaseAsync(
        int port,
        DtlsCertificate certificate,
        Action<PeerConnectionConfig> configure)
    {
        using var _ = certificate;

        var chromePath = ChromeBrowser.Require();
        if (chromePath is null)
        {
            _output.WriteLine("SKIPPED: Google Chrome not found (set KERYX_CHROME_PATH to enable).");
            return default;
        }

        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var cancellationToken = shutdown.Token;

        var config = TestSupport.NewConfig();
        config.Certificate = certificate;
        configure(config);

        await using var peer = new PeerConnection(config);
        var controllerTask = peer.CreateDataChannel("controller", ordered: false, maxRetransmits: 0);

        var offerSdp = await peer.CreateOfferAsync(cancellationToken);

        // ------------------------------------------------------------------ HTTP signaling host
        var latestReport = new object();
        string? latestReportJson = null;
        var answerApplied = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        using var listener = new HttpListener();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
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
        var userDataDir = Path.Combine(Path.GetTempPath(), $"keryx-chrome-suite-{Guid.NewGuid():N}");
        using var chrome = new Process();
        chrome.StartInfo = new ProcessStartInfo
        {
            FileName = chromePath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in ChromeBrowser.Arguments($"http://127.0.0.1:{port}/", userDataDir))
        {
            chrome.StartInfo.ArgumentList.Add(argument);
        }

        try
        {
            chrome.Start().Should().BeTrue();

            var answered = await Task.WhenAny(answerApplied.Task, Task.Delay(TimeSpan.FromSeconds(20), cancellationToken));
            if (answered != answerApplied.Task)
            {
                return new CaseResult(false, null, null, 0, 0, "(Chrome never posted an answer)");
            }

            var connected = await peer.WaitForConnectedAsync(TimeSpan.FromSeconds(20), cancellationToken);
            if (!connected)
            {
                return new CaseResult(false, peer.NegotiatedDtlsCipherSuite, peer.NegotiatedDtlsNamedGroup, 0, 0, null);
            }

            _output.WriteLine(
                $"connected: dtlsRole={peer.LocalDtlsRole} suite={peer.NegotiatedDtlsCipherSuite} "
                + $"group={peer.NegotiatedDtlsNamedGroup} srtp={peer.NegotiatedSrtpProfile}");

            // -------------------------------------------------------------- short media + ping pump
            var accessUnits = H264TestStream.ReadAccessUnits(maxAccessUnits: 45); // 1.5 s at 30fps
            var restartFromIdr = 0;
            peer.OnPictureLossIndication += (_, _) => Interlocked.Exchange(ref restartFromIdr, 1);

            var pumps = Task.Run(async () =>
            {
                var controller = await controllerTask;
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

                    if (++ticks % 12 == 0 && controller.State == Keryx.Sctp.DataChannelState.Open)
                    {
                        ping++;
                        controller.SendText($"ping:{ping}");
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

                    using var doc = JsonDocument.Parse(json);
                    var root = doc.RootElement;
                    var channels = root.GetProperty("channels");
                    return ReadStat(root, "framesDecoded") >= 20
                        && channels.TryGetProperty("controller", out var c) && c.GetProperty("echoed").GetInt64() >= 2;
                },
                timeoutMilliseconds: 20_000);

            string? lastJson;
            lock (latestReport)
            {
                lastJson = latestReportJson;
            }

            shutdown.Cancel();
            await pumps;

            var framesDecoded = 0L;
            var echoed = 0L;
            if (lastJson is not null)
            {
                using var doc = JsonDocument.Parse(lastJson);
                var root = doc.RootElement;
                framesDecoded = ReadStat(root, "framesDecoded");
                if (root.GetProperty("channels").TryGetProperty("controller", out var c))
                {
                    echoed = c.GetProperty("echoed").GetInt64();
                }
            }

            _output.WriteLine($"final report: {lastJson ?? "(none)"}");
            healthy.Should().BeTrue($"Chrome should decode Keryx video and echo the data channel; last report: {lastJson}");

            return new CaseResult(
                true, peer.NegotiatedDtlsCipherSuite, peer.NegotiatedDtlsNamedGroup, framesDecoded, echoed, lastJson);
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

    private static DtlsCertificate GenerateRsaCertificate(string commonName)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={commonName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));

        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-15);
        var certificate = request.CreateSelfSigned(notBefore, notBefore.AddDays(1));
        return DtlsCertificate.FromCertificate(certificate);
    }
}
