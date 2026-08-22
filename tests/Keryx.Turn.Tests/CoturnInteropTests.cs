using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using FluentAssertions;
using Keryx.Ice;
using Keryx.Stun;
using Xunit;
using Xunit.Abstractions;

namespace Keryx.Turn.Tests;

/// <summary>
/// Interop against a real coturn server. These are the measurements that matter: the in-test relay
/// proves the state machine, coturn proves the wire.
/// </summary>
/// <remarks>
/// Excluded from CI (<c>Category=TurnInterop</c>): it needs the <c>turnserver</c> binary on the
/// machine. The path can be overridden with <c>KERYX_TURNSERVER_PATH</c>. When the binary is not
/// found, or when the UDP ports the server needs are already taken, each test prints a SKIPPED line
/// and returns rather than failing.
/// </remarks>
public sealed class CoturnInteropTests(ITestOutputHelper output)
{
    private const string Realm = "keryx.test";
    private const string Username = "keryx";
    private const string Password = "keryxpass";

    /// <summary>The control port coturn listens on. The relay ports are the four above it.</summary>
    private const int ListeningPort = 7995;

    private const int MinRelayPort = 7996;
    private const int MaxRelayPort = 7999;

    private readonly ITestOutputHelper _output = output;

    [Fact]
    [Trait("Category", "TurnInterop")]
    public async Task CoturnAllocatesARelayedAddressAndRelaysDatagramsBothWays()
    {
        using var coturn = Coturn.TryStart(_output);
        if (coturn is null)
        {
            return;
        }

        using var harness = new TurnClientHarness(coturn.EndPoint, Username, Password);
        using var peer = new TestPeer();

        var relayed = await harness.Client.AllocateAsync(TestTimeout.Token);
        _output.WriteLine($"coturn allocated {relayed}, reflexive {harness.Client.MappedEndPoint}, lifetime {harness.Client.GrantedLifetime}.");

        // coturn hands out a port from the configured relay range, on a socket it owns.
        relayed.Address.Should().Be(IPAddress.Loopback);
        relayed.Port.Should().BeInRange(MinRelayPort, MaxRelayPort);
        relayed.Should().NotBe(harness.LocalEndPoint);

        // RFC 8656 section 7.2: the Allocate response carries the client's reflexive address, which
        // over loopback is the client's own socket.
        harness.Client.MappedEndPoint.Should().Be(harness.LocalEndPoint);

        // RFC 8656 section 7.2: the granted lifetime is at least the 600 s default.
        harness.Client.GrantedLifetime.Should().BeGreaterThanOrEqualTo(TimeSpan.FromSeconds(600));

        await harness.Client.CreatePermissionAsync(peer.EndPoint, TestTimeout.Token);

        byte[] outbound = [0xC0, 0xFF, 0xEE, 0x11, 0x22];
        var inbound = peer.ReceiveAsync(TestTimeout.Token);
        harness.Client.SendTo(outbound, peer.EndPoint);
        var (data, from) = await inbound;

        data.Should().Equal(outbound);
        from.Should().Be(relayed, "the datagram must reach the peer from coturn's relayed address, not from the client's socket");

        byte[] reply = [1, 2, 3, 4, 5, 6, 7, 8];
        peer.SendTo(reply, relayed);
        (await TestTimeout.WaitForAsync(() => harness.Received.Count > 0)).Should().BeTrue();
        harness.Received[0].Data.Should().Equal(reply);
        harness.Received[0].Peer.Should().Be(peer.EndPoint);
    }

    [Fact]
    [Trait("Category", "TurnInterop")]
    public async Task CoturnAcceptsAChannelBindAndCarriesChannelData()
    {
        using var coturn = Coturn.TryStart(_output);
        if (coturn is null)
        {
            return;
        }

        using var harness = new TurnClientHarness(coturn.EndPoint, Username, Password);
        using var peer = new TestPeer();

        var relayed = await harness.Client.AllocateAsync(TestTimeout.Token);
        var channel = await harness.Client.BindChannelAsync(peer.EndPoint, TestTimeout.Token);

        // coturn only accepts RFC 8656's 0x4000-0x4FFF unless started with --rfc5766-channel-numbers.
        channel.Should().BeInRange(StunChannelNumberAttribute.MinChannelNumber, StunChannelNumberAttribute.MaxChannelNumber);
        _output.WriteLine($"coturn bound channel 0x{channel:X4} to {peer.EndPoint}.");

        byte[] outbound = [0x41, 0x42, 0x43];
        var inbound = peer.ReceiveAsync(TestTimeout.Token);
        harness.Client.SendTo(outbound, peer.EndPoint);
        var (data, from) = await inbound;

        data.Should().Equal(outbound);
        from.Should().Be(relayed);

        // Inbound now comes back as ChannelData, which the client unwraps to the same payload.
        byte[] reply = [0x51, 0x52];
        peer.SendTo(reply, relayed);
        (await TestTimeout.WaitForAsync(() => harness.Received.Count > 0)).Should().BeTrue();
        harness.Received[0].Data.Should().Equal(reply);
    }

    [Fact]
    [Trait("Category", "TurnInterop")]
    public async Task CoturnRefusesAWrongCredentialWithoutTheClientLooping()
    {
        using var coturn = Coturn.TryStart(_output);
        if (coturn is null)
        {
            return;
        }

        using var harness = new TurnClientHarness(coturn.EndPoint, Username, "wrong-password");

        var allocate = async () => await harness.Client.AllocateAsync(TestTimeout.Token);

        var thrown = await allocate.Should().ThrowAsync<StunErrorResponseException>();
        thrown.Which.Code.Should().Be(StunErrorCodeAttribute.Unauthorized);
        _output.WriteLine($"coturn refused the bad credential with {thrown.Which.Code} {thrown.Which.Reason}.");
    }

    [Fact]
    [Trait("Category", "TurnInterop")]
    public async Task CoturnReleasesTheAllocationOnRefreshWithLifetimeZero()
    {
        using var coturn = Coturn.TryStart(_output);
        if (coturn is null)
        {
            return;
        }

        using var harness = new TurnClientHarness(coturn.EndPoint, Username, Password);
        using var peer = new TestPeer();

        var relayed = await harness.Client.AllocateAsync(TestTimeout.Token);
        await harness.Client.CreatePermissionAsync(peer.EndPoint, TestTimeout.Token);
        await harness.Client.ReleaseAsync(TestTimeout.Token);

        harness.Client.IsAllocated.Should().BeFalse();

        // The allocation is gone on coturn's side too: nothing sent to the relayed address reaches
        // the client any more.
        peer.SendTo([1, 2, 3], relayed);
        await Task.Delay(500);
        harness.Received.Should().BeEmpty();
    }

    [Fact]
    [Trait("Category", "TurnInterop")]
    public async Task IceAgentGathersATypRelayCandidateFromCoturn()
    {
        using var coturn = Coturn.TryStart(_output);
        if (coturn is null)
        {
            return;
        }

        using var agent = new IceAgent(AgentOptions(coturn));
        await agent.StartGatheringAsync(TestTimeout.Token);

        var relay = agent.LocalCandidates.SingleOrDefault(c => c.Type == IceCandidateType.Relayed);
        relay.Should().NotBeNull();
        _output.WriteLine($"gathered {relay!.ToAttributeString()}");

        relay.EndPoint.Port.Should().BeInRange(MinRelayPort, MaxRelayPort, "the relayed port must be one coturn owns");
        relay.ToAttributeString().Should().Contain("typ relay");

        // RFC 8445 section 4: raddr/rport are the mapped address from the Allocate response.
        relay.RelatedAddress.Should().Be(agent.LocalEndPoint!.Address);
        relay.RelatedPort.Should().Be(agent.LocalEndPoint.Port);
    }

    [Fact]
    [Trait("Category", "TurnInterop")]
    public async Task IceAgentConnectsThroughCoturnWhenOnlyTheRelayedPathIsAnswered()
    {
        using var coturn = Coturn.TryStart(_output);
        if (coturn is null)
        {
            return;
        }

        using var agent = new IceAgent(AgentOptions(coturn));
        using var peer = new TestIcePeer("peerpassword0123456789");

        await agent.StartGatheringAsync(TestTimeout.Token);
        var relay = agent.LocalCandidates.Single(c => c.Type == IceCandidateType.Relayed);

        // The symmetric-NAT case this whole feature exists for: the peer answers only what arrives
        // from coturn's relayed address and drops the direct check.
        peer.AcceptOnlyFrom = relay.EndPoint;

        agent.SetRemoteCredentials("peer", "peerpassword0123456789");
        agent.AddRemoteCandidate(new IceCandidate(
            "1", 1, IceCandidate.UdpTransport, 1000, peer.EndPoint.Address, peer.EndPoint.Port, IceCandidateType.Host));

        (await agent.WaitForConnectedAsync(TimeSpan.FromSeconds(25), TestTimeout.Token)).Should().BeTrue();

        agent.SelectedPair!.Local.Type.Should().Be(IceCandidateType.Relayed);
        peer.Dropped.Should().BeGreaterThan(0, "the direct check must have been refused");
        peer.CheckSources.Should().Contain(relay.EndPoint);

        byte[] payload = [0x17, 0xFE, 0xFD, 0xAA, 0xBB];
        agent.Transport.Send(payload);

        (await TestTimeout.WaitForAsync(() => peer.Media.Count > 0)).Should().BeTrue();
        peer.Media[0].Should().Equal(payload);
        _output.WriteLine($"media traversed coturn's allocation at {relay.EndPoint}.");
    }

    private static IceAgentOptions AgentOptions(Coturn coturn)
    {
        var options = new IceAgentOptions
        {
            BindAddress = IPAddress.Loopback,
            CheckRetransmissionTimeout = TimeSpan.FromMilliseconds(250),
            MaxCheckTransmissions = 12,
            TurnClientOptions = new TurnClientOptions
            {
                StunClientOptions = new StunClientOptions
                {
                    InitialRetransmissionTimeout = TimeSpan.FromMilliseconds(250),
                    MaxTransmissions = 5,
                    FinalWaitMultiplier = 2,
                },
            },
        };

        options.TurnServers.Add(coturn.ToOptions());
        return options;
    }

    /// <summary>A coturn process started for the duration of one test.</summary>
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

        public IPEndPoint EndPoint { get; } = new(IPAddress.Loopback, ListeningPort);

        /// <summary>
        /// Starts coturn, or returns null after printing why the test is being skipped: the binary
        /// is missing, the ports are taken, or the process died on startup.
        /// </summary>
        public static Coturn? TryStart(ITestOutputHelper output)
        {
            var binary = FindTurnServer();
            if (binary is null)
            {
                output.WriteLine("SKIPPED: no turnserver binary found (set KERYX_TURNSERVER_PATH, or `brew install coturn`).");
                return null;
            }

            for (var port = ListeningPort; port <= MaxRelayPort; port++)
            {
                if (!IsUdpPortFree(port))
                {
                    output.WriteLine($"SKIPPED: UDP port {port} is already in use, so coturn cannot be started on {ListeningPort}-{MaxRelayPort}.");
                    return null;
                }
            }

            var directory = Path.Combine(Path.GetTempPath(), "keryx-coturn-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            var configPath = Path.Combine(directory, "turnserver.conf");
            File.WriteAllText(
                configPath,
                $"""
                 listening-ip=127.0.0.1
                 listening-port={ListeningPort}
                 relay-ip=127.0.0.1
                 min-port={MinRelayPort}
                 max-port={MaxRelayPort}
                 realm={Realm}
                 lt-cred-mech
                 user={Username}:{Password}
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
            if (!coturn.WaitUntilListening(log))
            {
                output.WriteLine("SKIPPED: coturn did not come up.");
                foreach (var line in Snapshot(log).TakeLast(20))
                {
                    output.WriteLine("  coturn: " + line);
                }

                coturn.Dispose();
                return null;
            }

            output.WriteLine($"coturn {binary} listening on {coturn.EndPoint}, relay ports {MinRelayPort}-{MaxRelayPort}.");
            return coturn;
        }

        public TurnServerOptions ToOptions() => new(EndPoint, Username, Password);

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
        private bool WaitUntilListening(List<string> log)
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

            _ = Snapshot(log);
            return false;
        }
    }
}
