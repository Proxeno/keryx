using System.Net;
using System.Security.Authentication;
using FluentAssertions;
using Keryx.Ice;
using Keryx.Stun;
using Xunit;
using Xunit.Abstractions;

namespace Keryx.Turn.Tests;

/// <summary>
/// Interop of the TCP and TLS client-to-server leg (RFC 5766 section 2.1 / RFC 8656 section 3.1)
/// against a real coturn: the relayed leg is still UDP, only the way the client reaches the server
/// changes. TLS trust is by pinning the test-time self-signed certificate - validation is never
/// disabled.
/// </summary>
public sealed class CoturnStreamInteropTests(ITestOutputHelper output)
{
    private readonly ITestOutputHelper _output = output;

    [Theory]
    [InlineData(TurnClientTransport.Tcp)]
    [InlineData(TurnClientTransport.Tls)]
    [Trait("Category", "TurnInterop")]
    public async Task CoturnAllocatesOverAStreamAndRelaysDatagramsBothWays(TurnClientTransport transport)
    {
        using var coturn = CoturnServer.TryStart(_output, CoturnLayout.Stream);
        if (coturn is null)
        {
            return;
        }

        using var client = await ConnectAsync(coturn, transport);
        using var peer = new TestPeer();

        var received = new List<(byte[] Data, IPEndPoint Peer)>();
        client.OnRelayedData += (data, from) =>
        {
            lock (received)
            {
                received.Add((data.ToArray(), from));
            }
        };

        var relayed = await client.AllocateAsync(TestTimeout.Token);
        _output.WriteLine($"{transport} client mapped as {client.MappedEndPoint}, relayed at {relayed}.");

        // coturn hands out a port from the configured relay range, on a socket it owns.
        relayed.Address.Should().Be(IPAddress.Loopback);
        relayed.Port.Should().BeInRange(coturn.Layout.MinRelayPort, coturn.Layout.MaxRelayPort);

        // Over a stream the XOR-MAPPED-ADDRESS is the TCP connection's ephemeral source port, not
        // a listening port and not the relayed one; the client does not expose its local endpoint,
        // so that is all that can be asserted about it.
        var mapped = client.MappedEndPoint;
        mapped.Should().NotBeNull();
        mapped!.Address.Should().Be(IPAddress.Loopback);
        mapped.Port.Should().NotBe(coturn.Layout.ListeningPort);
        if (coturn.Layout.TlsPort is int tlsPort)
        {
            mapped.Port.Should().NotBe(tlsPort);
        }

        mapped.Port.Should().NotBe(relayed.Port);

        client.GrantedLifetime.Should().BeGreaterThanOrEqualTo(TimeSpan.FromSeconds(600));

        await client.CreatePermissionAsync(peer.EndPoint, TestTimeout.Token);

        byte[] outbound = [0xC0, 0xFF, 0xEE, 0x11, 0x22];
        var inbound = peer.ReceiveAsync(TestTimeout.Token);
        client.SendTo(outbound, peer.EndPoint);
        var (toPeer, from) = await inbound;

        toPeer.Should().Equal(outbound);
        from.Should().Be(relayed, "the datagram must reach the peer from coturn's relayed address");

        byte[] reply = [1, 2, 3, 4, 5, 6, 7, 8];
        peer.SendTo(reply, relayed);
        (await TestTimeout.WaitForAsync(() =>
        {
            lock (received)
            {
                return received.Count > 0;
            }
        })).Should().BeTrue();

        lock (received)
        {
            received[0].Data.Should().Equal(reply);
            received[0].Peer.Should().Be(peer.EndPoint);
        }
    }

    [Theory]
    [InlineData(TurnClientTransport.Tcp)]
    [InlineData(TurnClientTransport.Tls)]
    [Trait("Category", "TurnInterop")]
    public async Task CoturnCarriesChannelDataOfEveryPaddingLengthOverAStream(TurnClientTransport transport)
    {
        // This is the test that catches a padding/reassembly desync: ChannelData over TCP/TLS is
        // padded to a four-byte boundary (RFC 8656 section 12.5), and if the client or coturn ever
        // miscounts that padding the stream desynchronises and every later datagram is lost.
        using var coturn = CoturnServer.TryStart(_output, CoturnLayout.Stream);
        if (coturn is null)
        {
            return;
        }

        using var client = await ConnectAsync(coturn, transport);
        using var peer = new TestPeer();

        var received = new List<(byte[] Data, IPEndPoint Peer)>();
        client.OnRelayedData += (data, from) =>
        {
            lock (received)
            {
                received.Add((data.ToArray(), from));
            }
        };

        var relayed = await client.AllocateAsync(TestTimeout.Token);
        var channel = await client.BindChannelAsync(peer.EndPoint, TestTimeout.Token);
        channel.Should().BeInRange(StunChannelNumberAttribute.MinChannelNumber, StunChannelNumberAttribute.MaxChannelNumber);

        // Client -> peer: every payload length, so each one needs a different amount of stream
        // padding.
        var expectedClientToPeer = new List<byte[]>();
        for (var length = 1; length <= 8; length++)
        {
            var datagram = new byte[length];
            for (var i = 0; i < length; i++)
            {
                datagram[i] = (byte)(0x10 * length + i);
            }

            client.SendTo(datagram, peer.EndPoint);
            expectedClientToPeer.Add(datagram);
        }

        var actualClientToPeer = new List<byte[]>();
        for (var i = 0; i < expectedClientToPeer.Count; i++)
        {
            var (data, from) = await peer.ReceiveAsync(TestTimeout.Token);
            from.Should().Be(relayed);
            actualClientToPeer.Add(data);
        }

        // Order by length, not arrival: the relayed leg is UDP and arrival order is not what is
        // under test here.
        AssertSameSetByLength(expectedClientToPeer, actualClientToPeer);

        // Peer -> client: the same lengths back, now travelling as ChannelData over the stream.
        var expectedPeerToClient = new List<byte[]>();
        for (var length = 1; length <= 8; length++)
        {
            var datagram = new byte[length];
            for (var i = 0; i < length; i++)
            {
                datagram[i] = (byte)(0xA0 + length + i);
            }

            peer.SendTo(datagram, relayed);
            expectedPeerToClient.Add(datagram);
        }

        (await TestTimeout.WaitForAsync(() =>
        {
            lock (received)
            {
                return received.Count >= expectedPeerToClient.Count;
            }
        })).Should().BeTrue();

        List<(byte[] Data, IPEndPoint Peer)> actualPeerToClient;
        lock (received)
        {
            actualPeerToClient = [.. received];
        }

        actualPeerToClient.Should().OnlyContain(entry => entry.Peer.Equals(peer.EndPoint));
        AssertSameSetByLength(expectedPeerToClient, actualPeerToClient.Select(entry => entry.Data).ToList());
    }

    [Theory]
    [InlineData(TurnClientTransport.Tcp)]
    [InlineData(TurnClientTransport.Tls)]
    [Trait("Category", "TurnInterop")]
    public async Task CoturnRefusesAWrongCredentialOverAStream(TurnClientTransport transport)
    {
        using var coturn = CoturnServer.TryStart(_output, CoturnLayout.Stream);
        if (coturn is null)
        {
            return;
        }

        using var client = await ConnectAsync(coturn, transport, "wrong-password");

        var allocate = async () => await client.AllocateAsync(TestTimeout.Token);

        var thrown = await allocate.Should().ThrowAsync<StunErrorResponseException>();
        thrown.Which.Code.Should().Be(StunErrorCodeAttribute.Unauthorized);
        _output.WriteLine($"coturn refused the bad {transport} credential with {thrown.Which.Code} {thrown.Which.Reason}.");
    }

    [Fact]
    [Trait("Category", "TurnInterop")]
    public async Task CoturnTlsIsRefusedWhenTheCertificateIsNotThePinnedOne()
    {
        using var coturn = CoturnServer.TryStart(_output, CoturnLayout.Stream);
        if (coturn is null)
        {
            return;
        }

        var invoked = false;
        var options = FastOptions();
        options.TlsCertificateValidationCallback = (_, presented, _, _) =>
        {
            invoked = true;

            // A fixed bogus thumbprint: correct shape, certainly not the certificate coturn
            // generated for this test.
            const string bogusThumbprint = "00112233445566778899AABBCCDDEEFF00112233";
            return presented is not null
                && string.Equals(presented.GetCertHashString(), bogusThumbprint, StringComparison.OrdinalIgnoreCase);
        };

        var connect = async () => await TurnClient.ConnectAsync(
            coturn.EndPointFor(TurnClientTransport.Tls),
            CoturnServer.Username,
            CoturnServer.Password,
            TurnClientTransport.Tls,
            options,
            tlsServerName: CoturnServer.Realm,
            cancellationToken: TestTimeout.Token);

        await connect.Should().ThrowAsync<AuthenticationException>();

        // The handshake reached certificate validation, so coturn really spoke TLS and the refusal
        // came from the pin rather than from no TLS at all.
        invoked.Should().BeTrue();
    }

    [Fact]
    [Trait("Category", "TurnInterop")]
    public async Task CoturnTlsIsRefusedByDefaultPlatformValidation()
    {
        using var coturn = CoturnServer.TryStart(_output, CoturnLayout.Stream);
        if (coturn is null)
        {
            return;
        }

        // No callback: the platform's chain-and-name validation runs, and the test-time
        // self-signed certificate cannot satisfy it. Proves Keryx does not silently trust.
        var connect = async () => await TurnClient.ConnectAsync(
            coturn.EndPointFor(TurnClientTransport.Tls),
            CoturnServer.Username,
            CoturnServer.Password,
            TurnClientTransport.Tls,
            FastOptions(),
            tlsServerName: CoturnServer.Realm,
            cancellationToken: TestTimeout.Token);

        await connect.Should().ThrowAsync<AuthenticationException>();
    }

    [Theory]
    [InlineData(TurnClientTransport.Tcp)]
    [InlineData(TurnClientTransport.Tls)]
    [Trait("Category", "TurnInterop")]
    public async Task IceAgentGathersATypRelayCandidateFromCoturnOverAStream(TurnClientTransport transport)
    {
        using var coturn = CoturnServer.TryStart(_output, CoturnLayout.Stream);
        if (coturn is null)
        {
            return;
        }

        using var agent = new IceAgent(AgentOptions(coturn, transport));
        await agent.StartGatheringAsync(TestTimeout.Token);

        var relays = agent.LocalCandidates.Where(c => c.Type == IceCandidateType.Relayed).ToList();
        relays.Should().HaveCount(1);
        var relay = relays[0];
        _output.WriteLine($"gathered {relay.ToAttributeString()}");

        relay.EndPoint.Port.Should().BeInRange(coturn.Layout.MinRelayPort, coturn.Layout.MaxRelayPort, "the relayed port must be one coturn owns");
        relay.ToAttributeString().Should().Contain("typ relay");

        // The relayed candidate is a UDP address whatever transport the client used to reach the
        // server, and its related address is the loopback control connection's.
        relay.IsUdp.Should().BeTrue();
        relay.RelatedAddress.Should().Be(IPAddress.Loopback);

        // The TCP/TLS control connection's mapped address must not be harvested as a UDP srflx.
        agent.LocalCandidates.Should().NotContain(c => c.Type == IceCandidateType.ServerReflexive);
    }

    [Theory]
    [InlineData(TurnClientTransport.Tcp)]
    [InlineData(TurnClientTransport.Tls)]
    [Trait("Category", "TurnInterop")]
    public async Task IceAgentConnectsThroughCoturnOverAStreamWhenOnlyTheRelayedPathIsAnswered(TurnClientTransport transport)
    {
        using var coturn = CoturnServer.TryStart(_output, CoturnLayout.Stream);
        if (coturn is null)
        {
            return;
        }

        using var agent = new IceAgent(AgentOptions(coturn, transport));
        using var peer = new TestIcePeer("peerpassword0123456789");

        await agent.StartGatheringAsync(TestTimeout.Token);
        var relay = agent.LocalCandidates.Single(c => c.Type == IceCandidateType.Relayed);

        // The symmetric-NAT case: the peer answers only what arrives from coturn's relayed address
        // and drops the direct check.
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

        // Inbound: the peer sends to the relayed address and the datagram surfaces at the agent's
        // transport seam.
        var received = new List<byte[]>();
        agent.Transport.OnReceived += datagram =>
        {
            lock (received)
            {
                received.Add(datagram.ToArray());
            }
        };

        byte[] inbound = [0x16, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x09];
        peer.SendMediaTo(inbound, relay.EndPoint);

        (await TestTimeout.WaitForAsync(() =>
        {
            lock (received)
            {
                return received.Count > 0;
            }
        })).Should().BeTrue();

        lock (received)
        {
            received[0].Should().Equal(inbound);
        }
    }

    private static async Task<TurnClient> ConnectAsync(
        CoturnServer coturn,
        TurnClientTransport transport,
        string password = CoturnServer.Password)
    {
        var options = FastOptions();
        if (transport == TurnClientTransport.Tls)
        {
            options.TlsCertificateValidationCallback = coturn.PinCertificate();
        }

        return await TurnClient.ConnectAsync(
            coturn.EndPointFor(transport),
            CoturnServer.Username,
            password,
            transport,
            options,
            tlsServerName: transport == TurnClientTransport.Tls ? CoturnServer.Realm : null,
            cancellationToken: TestTimeout.Token);
    }

    private static TurnClientOptions FastOptions()
    {
        var options = TurnClientHarness.FastOptions();
        options.StunClientOptions!.InitialRetransmissionTimeout = TimeSpan.FromMilliseconds(250);
        options.StunClientOptions.MaxTransmissions = 5;
        return options;
    }

    private static IceAgentOptions AgentOptions(CoturnServer coturn, TurnClientTransport transport)
    {
        var turnOptions = new TurnClientOptions
        {
            StunClientOptions = new StunClientOptions
            {
                InitialRetransmissionTimeout = TimeSpan.FromMilliseconds(250),
                MaxTransmissions = 5,
                FinalWaitMultiplier = 2,
            },
        };

        if (transport == TurnClientTransport.Tls)
        {
            turnOptions.TlsCertificateValidationCallback = coturn.PinCertificate();
        }

        var options = new IceAgentOptions
        {
            BindAddress = IPAddress.Loopback,
            CheckRetransmissionTimeout = TimeSpan.FromMilliseconds(250),
            MaxCheckTransmissions = 12,
            TurnClientOptions = turnOptions,
        };

        options.TurnServers.Add(coturn.ToOptions(transport));
        return options;
    }

    private static void AssertSameSetByLength(IReadOnlyList<byte[]> expected, IReadOnlyList<byte[]> actual)
    {
        var expectedByLength = expected.OrderBy(d => d.Length).Select(d => d.ToArray()).ToList();
        var actualByLength = actual.OrderBy(d => d.Length).Select(d => d.ToArray()).ToList();

        actualByLength.Should().HaveCount(expectedByLength.Count);
        for (var i = 0; i < expectedByLength.Count; i++)
        {
            actualByLength[i].Should().Equal(expectedByLength[i], "datagram of length {0} must round-trip unchanged", expectedByLength[i].Length);
        }
    }
}
