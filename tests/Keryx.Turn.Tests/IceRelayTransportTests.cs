using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using Keryx.Ice;
using Keryx.Stun;
using Xunit;

namespace Keryx.Turn.Tests;

/// <summary>
/// <see cref="IceAgent"/> reaching a TURN server over TCP or TLS (RFC 5766 section 2.1) rather than
/// UDP: the relayed candidate is gathered through the normal flow and, when only the relay works,
/// media traverses the allocation end to end - proving the client-to-server transport is opt-in
/// through ordinary ICE configuration, not just the raw <see cref="TurnClient"/>.
/// </summary>
public sealed class IceRelayTransportTests
{
    [Theory]
    [InlineData(TurnClientTransport.Tcp)]
    [InlineData(TurnClientTransport.Tls)]
    public async Task StartGathering_OverAStreamTransport_ProducesARelayCandidateAtTheServersAddress(
        TurnClientTransport transport)
    {
        using var server = new TestTurnServer(transport: transport);
        using var agent = new IceAgent(AgentOptions(server));

        await agent.StartGatheringAsync(TestTimeout.Token);

        // The relayed candidate is a UDP address the server owns, exactly as for a UDP allocation -
        // only the client-to-server leg differs, and the relayed candidate does not reveal it.
        var relay = agent.LocalCandidates.Single(c => c.Type == IceCandidateType.Relayed);
        relay.EndPoint.Should().Be(server.RelayedEndPoint);
        relay.EndPoint.Should().NotBe(agent.LocalEndPoint);
        relay.ToAttributeString().Should().Contain("typ relay");
        relay.IsUdp.Should().BeTrue();
    }

    [Theory]
    [InlineData(TurnClientTransport.Tcp)]
    [InlineData(TurnClientTransport.Tls)]
    public async Task StartGathering_OverAStreamTransport_DoesNotHarvestTheControlConnectionAsAnSrflxCandidate(
        TurnClientTransport transport)
    {
        using var server = new TestTurnServer(transport: transport);
        using var agent = new IceAgent(AgentOptions(server));

        await agent.StartGatheringAsync(TestTimeout.Token);

        // The Allocate response's XOR-MAPPED-ADDRESS is the reflexive of the TCP/TLS control
        // connection - a TCP port that is no use as a UDP srflx candidate - so, unlike the UDP path,
        // nothing srflx is added here.
        agent.LocalCandidates.Should().Contain(c => c.Type == IceCandidateType.Relayed);
        agent.LocalCandidates.Should().NotContain(c => c.Type == IceCandidateType.ServerReflexive);
    }

    [Theory]
    [InlineData(TurnClientTransport.Tcp)]
    [InlineData(TurnClientTransport.Tls)]
    public async Task WhenOnlyTheRelayedPathWorks_MediaTraversesTheStreamAllocationEndToEnd(
        TurnClientTransport transport)
    {
        using var server = new TestTurnServer(transport: transport);
        using var agent = new IceAgent(AgentOptions(server));
        using var peer = new TestIcePeer("peerpassword0123456789");

        await agent.StartGatheringAsync(TestTimeout.Token);
        var relayCandidate = agent.LocalCandidates.Single(c => c.Type == IceCandidateType.Relayed);
        var relayed = relayCandidate.EndPoint;

        // Symmetric-NAT simulation: the peer answers only what arrives from the relayed address, so
        // the direct check (from the agent's own socket) is dropped and only the relayed pair can win.
        peer.AcceptOnlyFrom = relayed;

        agent.SetRemoteCredentials("peer", "peerpassword0123456789");
        agent.AddRemoteCandidate(new IceCandidate(
            "1", 1, IceCandidate.UdpTransport, 1000, peer.EndPoint.Address, peer.EndPoint.Port, IceCandidateType.Host));

        (await agent.WaitForConnectedAsync(TimeSpan.FromSeconds(20), TestTimeout.Token)).Should().BeTrue();

        var selected = agent.SelectedPair;
        selected.Should().NotBeNull();
        selected!.Local.Type.Should().Be(IceCandidateType.Relayed);
        selected.Local.EndPoint.Should().Be(relayed);

        // Outbound media really left through the allocation: it went out of the relay to the peer,
        // carried to the server as ChannelData over the TCP/TLS control connection.
        var relayedToPeerBefore = server.RelayedToPeer;
        byte[] payload = [0x17, 0xFE, 0xFD, 0x00, 0x01, 0x02, 0x03];
        agent.Transport.Send(payload);

        (await TestTimeout.WaitForAsync(() => peer.Media.Count > 0)).Should().BeTrue();
        peer.Media[0].Should().Equal(payload);

        // The peer's receive only proves the socket send happened; RelayedToPeer is incremented
        // right after that send, so it can lag the peer's own receive by a scheduling hair. Wait
        // for it rather than assuming it already landed.
        (await TestTimeout.WaitForCountAsync(() => server.RelayedToPeer, relayedToPeerBefore + 1)).Should().BeTrue();
        server.RelayedToPeer.Should().BeGreaterThan(relayedToPeerBefore);
        server.ChannelDataFromClient.Should().BeGreaterThan(0);

        // Inbound relayed traffic comes back over the same stream and surfaces at the transport seam.
        var received = new List<byte[]>();
        agent.Transport.OnReceived += datagram =>
        {
            lock (received)
            {
                received.Add(datagram.ToArray());
            }
        };

        byte[] inbound = [0x16, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x09];
        peer.SendMediaTo(inbound, relayed);

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

        (await TestTimeout.WaitForCountAsync(() => server.RelayedToClient, 1)).Should().BeTrue();
        server.RelayedToClient.Should().BeGreaterThan(0);
    }

    private static StunClientOptions FastStun() => new()
    {
        InitialRetransmissionTimeout = TimeSpan.FromMilliseconds(150),
        MaxTransmissions = 4,
        FinalWaitMultiplier = 2,
    };

    private static IceAgentOptions AgentOptions(TestTurnServer server)
    {
        var turnOptions = new TurnClientOptions { StunClientOptions = FastStun() };
        if (server.Certificate is { } certificate)
        {
            // The self-signed test certificate is trusted by pinning its thumbprint, never by
            // switching validation off - exactly the hook a caller uses for a private CA.
            turnOptions.TlsCertificateValidationCallback = (_, presented, _, _) =>
                presented is X509Certificate2 leaf && leaf.Thumbprint == certificate.Thumbprint;
        }

        var options = new IceAgentOptions
        {
            BindAddress = IPAddress.Loopback,
            StunClientOptions = FastStun(),
            CheckRetransmissionTimeout = TimeSpan.FromMilliseconds(200),
            MaxCheckTransmissions = 12,
            TurnClientOptions = turnOptions,
        };

        options.TurnServers.Add(server.ToOptions());
        return options;
    }
}
