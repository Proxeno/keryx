using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Keryx.Stun;
using Xunit.Abstractions;

namespace Keryx.Turn.Tests;

/// <summary>The ports one coturn instance uses. TlsPort null = started with no-tls.</summary>
internal sealed record CoturnLayout(int ListeningPort, int? TlsPort, int MinRelayPort, int MaxRelayPort)
{
    /// <summary>UDP cases: exactly today's layout and config (no-tls).</summary>
    public static CoturnLayout Udp { get; } = new(7995, null, 7996, 7999);

    /// <summary>
    /// TCP/TLS cases: distinct from 7995-7999 (UDP cases) and from 7970-7990
    /// (<c>Keryx.IntegrationTests TurnRelayInteropTests</c>, which may run in parallel in another
    /// test process).
    /// </summary>
    public static CoturnLayout Stream { get; } = new(7960, 7961, 7962, 7965);
}

/// <summary>
/// A real coturn (<c>turnserver</c>) process started for the duration of one test, on loopback.
/// </summary>
/// <remarks>
/// The TURN interop tests prove the wire against an independent implementation rather than only
/// the in-repo fake. Locally, a missing binary or a taken port prints a SKIPPED line and returns
/// null; the CI build-test job sets <c>KERYX_REQUIRE_COTURN=1</c>, which turns either into a
/// failure so the coverage cannot silently disappear.
/// </remarks>
internal sealed class CoturnServer : IDisposable
{
    /// <summary>The realm coturn serves, and the TLS server name the client validates against.</summary>
    public const string Realm = "keryx.test";

    /// <summary>The long-term credential username.</summary>
    public const string Username = "keryx";

    /// <summary>The long-term credential password.</summary>
    public const string Password = "keryxpass";

    private readonly Process _process;
    private readonly string _directory;
    private readonly ITestOutputHelper _output;

    private CoturnServer(
        Process process,
        string directory,
        ITestOutputHelper output,
        CoturnLayout layout,
        X509Certificate2? certificate)
    {
        _process = process;
        _directory = directory;
        _output = output;
        Layout = layout;
        EndPoint = new IPEndPoint(IPAddress.Loopback, layout.ListeningPort);
        TlsEndPoint = layout.TlsPort is int tlsPort ? new IPEndPoint(IPAddress.Loopback, tlsPort) : null;
        Certificate = certificate;
    }

    /// <summary>The ports this instance was started on.</summary>
    public CoturnLayout Layout { get; }

    /// <summary>127.0.0.1:ListeningPort - UDP and plain TCP.</summary>
    public IPEndPoint EndPoint { get; }

    /// <summary>127.0.0.1:TlsPort, or null when the instance was started with no-tls.</summary>
    public IPEndPoint? TlsEndPoint { get; }

    /// <summary>The certificate coturn presents (public part only), or null when no TLS.</summary>
    public X509Certificate2? Certificate { get; }

    /// <summary>
    /// Starts coturn, or returns null after printing why the test is being skipped - unless
    /// <c>KERYX_REQUIRE_COTURN=1</c>, in which case it throws so the CI job fails instead.
    /// </summary>
    public static CoturnServer? TryStart(ITestOutputHelper output, CoturnLayout layout)
    {
        var binary = FindTurnServer();
        if (binary is null)
        {
            return Skip(output, "no turnserver binary found (set KERYX_TURNSERVER_PATH, or `brew install coturn` / `apt-get install coturn`).");
        }

        for (var port = layout.ListeningPort; port <= layout.MaxRelayPort; port++)
        {
            if (!IsUdpPortFree(port))
            {
                return Skip(
                    output,
                    $"UDP port {port} is already in use, so coturn cannot be started on {layout.ListeningPort}-{layout.MaxRelayPort}.");
            }
        }

        if (layout.TlsPort is int tlsPort)
        {
            // Only a successful connect means something is listening. A bind probe would fail
            // spuriously on the second test in a row: a just-killed coturn's port sits in
            // TIME_WAIT, while coturn itself (SO_REUSEADDR) starts fine on it.
            foreach (var port in new[] { layout.ListeningPort, tlsPort })
            {
                if (IsTcpPortInUse(port))
                {
                    return Skip(
                        output,
                        $"TCP port {port} is already in use, so coturn cannot be started on {layout.ListeningPort}/{tlsPort}.");
                }
            }
        }

        var directory = Path.Combine(Path.GetTempPath(), "keryx-coturn-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);

        X509Certificate2? certificate = null;
        if (layout.TlsPort is not null)
        {
            var generated = CreateSelfSignedCertificate();
            certificate = generated.Public;
            File.WriteAllText(Path.Combine(directory, "cert.pem"), generated.CertificatePem);
            File.WriteAllText(Path.Combine(directory, "key.pem"), generated.KeyPem);
        }

        var configPath = Path.Combine(directory, "turnserver.conf");
        File.WriteAllText(configPath, BuildConfig(layout, directory));

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

        var coturn = new CoturnServer(process, directory, output, layout, certificate);
        if (!coturn.WaitUntilListening(log))
        {
            var tail = Snapshot(log).TakeLast(20).ToList();
            foreach (var line in tail)
            {
                output.WriteLine("  coturn: " + line);
            }

            var reason = tail.Count == 0
                ? "coturn did not come up."
                : "coturn did not come up: " + string.Join(" | ", tail);

            // Never leak the process on the failure path, whichever way Skip reports it.
            coturn.Dispose();
            return Skip(output, reason);
        }

        output.WriteLine(
            $"coturn {binary} listening on {coturn.EndPoint}{(coturn.TlsEndPoint is { } tls ? $" and TLS on {tls}" : string.Empty)}, "
            + $"relay ports {layout.MinRelayPort}-{layout.MaxRelayPort}.");
        return coturn;
    }

    /// <summary>
    /// The server address for <paramref name="transport"/>: the plain endpoint for UDP/TCP, the
    /// TLS endpoint for TLS. Throws when TLS is requested from an instance started with no-tls.
    /// </summary>
    public IPEndPoint EndPointFor(TurnClientTransport transport) => transport switch
    {
        TurnClientTransport.Udp or TurnClientTransport.Tcp => EndPoint,
        TurnClientTransport.Tls => TlsEndPoint
            ?? throw new InvalidOperationException("This coturn instance was started with no-tls, so it has no TLS endpoint."),
        _ => throw new InvalidOperationException($"Unknown TURN client transport {transport}."),
    };

    /// <summary>The <see cref="TurnServerOptions"/> an <see cref="Keryx.Ice.IceAgent"/> uses for this server.</summary>
    public TurnServerOptions ToOptions(TurnClientTransport transport = TurnClientTransport.Udp) =>
        new(EndPointFor(transport), Username, Password)
        {
            ClientTransport = transport,
            TlsServerName = transport == TurnClientTransport.Tls ? Realm : null,
        };

    /// <summary>
    /// A validation callback that accepts exactly the certificate this instance presents - pinned
    /// by thumbprint - and nothing else. It never trusts unconditionally.
    /// </summary>
    public RemoteCertificateValidationCallback PinCertificate()
    {
        var pinned = Certificate
            ?? throw new InvalidOperationException("This coturn instance was started with no-tls, so it presents no certificate to pin.");
        return (_, presented, _, _) =>
            presented is not null
            && string.Equals(presented.GetCertHashString(), pinned.Thumbprint, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>True when the environment demands coturn actually run (the CI build-test job).</summary>
    private static bool CoturnRequired =>
        string.Equals(Environment.GetEnvironmentVariable("KERYX_REQUIRE_COTURN"), "1", StringComparison.Ordinal);

    private static CoturnServer? Skip(ITestOutputHelper output, string reason)
    {
        if (CoturnRequired)
        {
            throw new InvalidOperationException(
                $"KERYX_REQUIRE_COTURN=1 but coturn could not be started: {reason} The build-test CI job "
                + "installs coturn, so its absence is a failure, not a skip.");
        }

        output.WriteLine($"SKIPPED: {reason}");
        return null;
    }

    private static string BuildConfig(CoturnLayout layout, string directory)
    {
        // Built line by line so the UDP form stays byte-for-byte what it always was.
        var lines = new List<string>
        {
            "listening-ip=127.0.0.1",
            $"listening-port={layout.ListeningPort}",
        };

        if (layout.TlsPort is int tlsPort)
        {
            lines.Add($"tls-listening-port={tlsPort}");
        }

        lines.Add("relay-ip=127.0.0.1");
        lines.Add($"min-port={layout.MinRelayPort}");
        lines.Add($"max-port={layout.MaxRelayPort}");
        lines.Add($"realm={Realm}");
        lines.Add("lt-cred-mech");
        lines.Add($"user={Username}:{Password}");
        lines.Add("allow-loopback-peers");

        if (layout.TlsPort is null)
        {
            lines.Add("no-tls");
        }
        else
        {
            lines.Add($"cert={Path.Combine(directory, "cert.pem")}");
            lines.Add($"pkey={Path.Combine(directory, "key.pem")}");
        }

        lines.Add("no-dtls");
        lines.Add("no-cli");
        lines.Add($"pidfile={Path.Combine(directory, "turnserver.pid")}");
        lines.Add("log-file=stdout");
        lines.Add("simple-log");

        return string.Join('\n', lines) + "\n";
    }

    private static (X509Certificate2 Public, string CertificatePem, string KeyPem) CreateSelfSignedCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest($"CN={Realm}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var subjectAlternativeName = new SubjectAlternativeNameBuilder();
        subjectAlternativeName.AddDnsName(Realm);
        subjectAlternativeName.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(subjectAlternativeName.Build());

        var now = DateTimeOffset.UtcNow;
        using var certificate = request.CreateSelfSigned(now.AddDays(-1), now.AddDays(1));

        // A public-only copy for thumbprint pinning; the private key never leaves the temp
        // directory, and its PKCS#8 PEM is what coturn is configured with.
        return (
            X509CertificateLoader.LoadCertificate(certificate.RawData),
            certificate.ExportCertificatePem(),
            rsa.ExportPkcs8PrivateKeyPem());
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
        Certificate?.Dispose();

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
    /// True when something is already accepting TCP connections on the port. A refused or timed
    /// out connect means the port is free to coturn.
    /// </summary>
    private static bool IsTcpPortInUse(int port)
    {
        using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            var connect = probe.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port), CancellationToken.None).AsTask();
            return connect.Wait(TimeSpan.FromMilliseconds(200)) && probe.Connected;
        }
        catch (Exception)
        {
            // Connection refused (or the wait faulted): nothing is listening.
            return false;
        }
    }

    /// <summary>
    /// Waits until coturn answers a STUN Binding on its listening port, which is the only
    /// readiness signal that does not depend on the wording of its log lines. For a TLS instance
    /// it then waits for a TCP connect to both the plain and the TLS port to succeed.
    /// </summary>
    private bool WaitUntilListening(List<string> log)
    {
        var deadline = Environment.TickCount64 + 15_000;
        if (!WaitForUdpBinding(deadline))
        {
            _ = Snapshot(log);
            return false;
        }

        if (TlsEndPoint is not null)
        {
            return WaitForTcpConnect(EndPoint, deadline) && WaitForTcpConnect(TlsEndPoint, deadline);
        }

        return true;
    }

    private bool WaitForUdpBinding(long deadline)
    {
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

    private bool WaitForTcpConnect(IPEndPoint endPoint, long deadline)
    {
        while (Environment.TickCount64 < deadline)
        {
            if (_process.HasExited)
            {
                return false;
            }

            using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                var connect = probe.ConnectAsync(endPoint, CancellationToken.None).AsTask();
                if (connect.Wait(TimeSpan.FromMilliseconds(250)) && probe.Connected)
                {
                    return true;
                }
            }
            catch (Exception)
            {
                // Not accepting yet.
            }

            Thread.Sleep(50);
        }

        return false;
    }
}
