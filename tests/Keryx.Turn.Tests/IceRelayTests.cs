using System.Net;
using FluentAssertions;
using Keryx.Ice;
using Keryx.Stun;
using Xunit;

namespace Keryx.Turn.Tests;

/// <summary>
/// <see cref="IceAgent"/> with a TURN server configured: relayed candidate gathering, permissions
/// as remote candidates arrive, and traffic that is forced through the allocation and measured
/// there.
/// </summary>
public sealed class IceRelayTests
{
    [Fact]
    public async Task StartGathering_ProducesATypRelayCandidateAtTheAddressTheTurnServerOwns()
    {
        using var server = new TestTurnServer();
        using var agent = new IceAgent(AgentOptions(server));

        await agent.StartGatheringAsync(TestTimeout.Token);

        var relay = agent.LocalCandidates.Single(c => c.Type == IceCandidateType.Relayed);
        relay.EndPoint.Should().Be(server.RelayedEndPoint);
        relay.EndPoint.Should().NotBe(agent.LocalEndPoint);
        relay.ToAttributeString().Should().Contain("typ relay");
        relay.IsUdp.Should().BeTrue();
    }

    [Fact]
    public async Task RelayCandidate_CarriesTheReflexiveAddressAsRaddrAndRport()
    {
        using var server = new TestTurnServer();
        using var agent = new IceAgent(AgentOptions(server));

        await agent.StartGatheringAsync(TestTimeout.Token);

        // RFC 8445 section 4: "If the candidate is relayed, the related address and port are equal
        // to the mapped address in the Allocate response that provided the client with that relayed
        // candidate." The test server reports the client's own source address there.
        var relay = agent.LocalCandidates.Single(c => c.Type == IceCandidateType.Relayed);
        relay.RelatedAddress.Should().Be(agent.LocalEndPoint!.Address);
        relay.RelatedPort.Should().Be(agent.LocalEndPoint.Port);

        var reparsed = IceCandidate.Parse(relay.ToAttributeString());
        reparsed.Type.Should().Be(IceCandidateType.Relayed);
        reparsed.RelatedAddress.Should().Be(relay.RelatedAddress);
        reparsed.RelatedPort.Should().Be(relay.RelatedPort);
    }

    [Fact]
    public async Task RelayCandidate_UsesTheRfc8445RelayedTypePreference()
    {
        using var server = new TestTurnServer();
        using var agent = new IceAgent(AgentOptions(server));

        await agent.StartGatheringAsync(TestTimeout.Token);

        var relay = agent.LocalCandidates.Single(c => c.Type == IceCandidateType.Relayed);
        var host = agent.LocalCandidates.First(c => c.Type == IceCandidateType.Host);

        // RFC 8445 section 5.1.2.2 recommends type preference 0 for relayed candidates, which puts
        // the whole top byte of the priority at zero and sorts them below every direct candidate.
        (relay.Priority >> 24).Should().Be(IcePriority.RelayedTypePreference);
        relay.Priority.Should().BeLessThan(host.Priority);
    }

    [Fact]
    public async Task StartGathering_AlsoHarvestsTheServerReflexiveCandidateFromTheAllocateResponse()
    {
        using var server = new TestTurnServer();
        using var agent = new IceAgent(AgentOptions(server));

        await agent.StartGatheringAsync(TestTimeout.Token);

        // RFC 8656 section 7.2 puts XOR-MAPPED-ADDRESS in the Allocate response so a client running
        // ICE does not need an extra Binding transaction for its srflx candidate.
        var srflx = agent.LocalCandidates.SingleOrDefault(c => c.Type == IceCandidateType.ServerReflexive);
        srflx.Should().NotBeNull();
        srflx!.EndPoint.Should().Be(agent.LocalEndPoint);
    }

    [Fact]
    public async Task StartGathering_KeepsGoingWhenTheTurnServerIsUnreachable()
    {
        var options = new IceAgentOptions
        {
            BindAddress = IPAddress.Loopback,
            StunClientOptions = FastStun(),
            TurnClientOptions = new TurnClientOptions { StunClientOptions = FastStun() },
        };

        // A port nothing is listening on: the Allocate transaction must time out and be logged and
        // skipped, exactly like an unreachable STUN server, not take gathering down with it.
        using var dead = new TestTurnServer();
        var deadEndPoint = dead.EndPoint;
        dead.Dispose();
        options.TurnServers.Add(new TurnServerOptions(deadEndPoint, "keryx", "keryxpass"));

        using var agent = new IceAgent(options);
        await agent.StartGatheringAsync(TestTimeout.Token);

        agent.LocalCandidates.Should().NotBeEmpty();
        agent.LocalCandidates.Should().NotContain(c => c.Type == IceCandidateType.Relayed);
    }

    [Fact]
    public async Task RemoteCandidates_ArePermittedAndChannelBoundOnTheAllocationAsTheyArrive()
    {
        using var server = new TestTurnServer();
        using var agent = new IceAgent(AgentOptions(server));
        await agent.StartGatheringAsync(TestTimeout.Token);

        var peer = new IPEndPoint(IPAddress.Loopback, 45678);
        agent.AddRemoteCandidate(new IceCandidate(
            "1", 1, IceCandidate.UdpTransport, 1000, peer.Address, peer.Port, IceCandidateType.Host));

        // RFC 8656 section 9: without a permission the relay would not accept a single packet from
        // that address, so the agent installs one per remote candidate, then binds a channel.
        (await TestTimeout.WaitForAsync(() => server.CreatePermissionRequests >= 1)).Should().BeTrue();
        (await TestTimeout.WaitForAsync(() => server.ChannelBindRequests >= 1)).Should().BeTrue();
        server.Permissions.Should().Contain(peer.Address);
        server.Channels.Values.Should().Contain(peer);
    }

    [Fact]
    public async Task PairsAreFormedForBothTheDirectPathAndEveryAllocation()
    {
        using var server = new TestTurnServer();
        using var agent = new IceAgent(AgentOptions(server));
        await agent.StartGatheringAsync(TestTimeout.Token);
        agent.SetRemoteCredentials("peer", "peerpassword0123456789");

        var peer = new IPEndPoint(IPAddress.Loopback, 45679);
        agent.AddRemoteCandidate(new IceCandidate(
            "1", 1, IceCandidate.UdpTransport, 1000, peer.Address, peer.Port, IceCandidateType.Host));

        var pairs = agent.CheckList.Where(p => p.RemoteEndPoint.Equals(peer)).ToList();
        pairs.Should().HaveCount(2);
        pairs.Should().ContainSingle(p => p.Local.Type == IceCandidateType.Relayed);
        pairs.Should().ContainSingle(p => p.Local.Type != IceCandidateType.Relayed);

        // The direct pair outranks the relayed one, so the relay is only reached if it fails.
        pairs[0].Local.Type.Should().NotBe(IceCandidateType.Relayed);
    }

    [Fact]
    public async Task WhenOnlyTheRelayedPathWorks_TheAgentSelectsItAndMediaTraversesTheAllocation()
    {
        using var server = new TestTurnServer();
        using var agent = new IceAgent(AgentOptions(server));
        using var peer = new TestIcePeer("peerpassword0123456789");

        await agent.StartGatheringAsync(TestTimeout.Token);
        var relayCandidate = agent.LocalCandidates.Single(c => c.Type == IceCandidateType.Relayed);
        var relayed = relayCandidate.EndPoint;

        // The symmetric-NAT simulation: the peer answers only what arrives from the TURN server's
        // relayed address, so the direct check - which leaves from the agent's own socket - is
        // dropped exactly as a symmetric NAT would drop it.
        peer.AcceptOnlyFrom = relayed;

        agent.SetRemoteCredentials("peer", "peerpassword0123456789");
        agent.AddRemoteCandidate(new IceCandidate(
            "1", 1, IceCandidate.UdpTransport, 1000, peer.EndPoint.Address, peer.EndPoint.Port, IceCandidateType.Host));

        (await agent.WaitForConnectedAsync(TimeSpan.FromSeconds(20), TestTimeout.Token)).Should().BeTrue();

        var selected = agent.SelectedPair;
        selected.Should().NotBeNull();
        selected!.Local.Type.Should().Be(IceCandidateType.Relayed);
        selected.Local.EndPoint.Should().Be(relayed);

        // The direct check really was sent and really was refused: both source addresses show up at
        // the peer, and only the relayed one was answered.
        peer.CheckSources.Should().Contain(relayed);
        peer.CheckSources.Should().Contain(agent.LocalEndPoint!);
        peer.Dropped.Should().BeGreaterThan(0);

        var relayedToPeerBefore = server.RelayedToPeer;
        byte[] payload = [0x17, 0xFE, 0xFD, 0x00, 0x01, 0x02, 0x03];
        agent.Transport.Send(payload);

        (await TestTimeout.WaitForAsync(() => peer.Media.Count > 0)).Should().BeTrue();
        peer.Media[0].Should().Equal(payload);

        // Measured, not assumed: the TURN server counted the datagram going out of the allocation.
        server.RelayedToPeer.Should().BeGreaterThan(relayedToPeerBefore);
        server.ChannelDataFromClient.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task RelayedInboundTraffic_ReachesTheTransportSeamDtlsRidesOn()
    {
        using var server = new TestTurnServer();
        using var agent = new IceAgent(AgentOptions(server));
        using var peer = new TestPeer();

        var received = new List<byte[]>();
        agent.Transport.OnReceived += datagram =>
        {
            lock (received)
            {
                received.Add(datagram.ToArray());
            }
        };

        await agent.StartGatheringAsync(TestTimeout.Token);
        var relayed = agent.LocalCandidates.Single(c => c.Type == IceCandidateType.Relayed).EndPoint;

        agent.AddRemoteCandidate(new IceCandidate(
            "1", 1, IceCandidate.UdpTransport, 1000, peer.EndPoint.Address, peer.EndPoint.Port, IceCandidateType.Host));
        (await TestTimeout.WaitForAsync(() => server.Permissions.Contains(peer.EndPoint.Address))).Should().BeTrue();

        // A DTLS record, from the peer, into the relay. It must come out of IDatagramTransport
        // unwrapped, with nothing above ICE needing to know a relay was involved.
        byte[] dtlsRecord = [0x16, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00];
        peer.SendTo(dtlsRecord, relayed);

        bool Arrived()
        {
            lock (received)
            {
                return received.Count > 0;
            }
        }

        (await TestTimeout.WaitForAsync(Arrived)).Should().BeTrue();
        lock (received)
        {
            received[0].Should().Equal(dtlsRecord);
        }

        server.RelayedToClient.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task Close_ReleasesTheAllocationBeforeTheSocketGoes()
    {
        using var server = new TestTurnServer();
        var agent = new IceAgent(AgentOptions(server));
        try
        {
            await agent.StartGatheringAsync(TestTimeout.Token);
            server.RelayedEndPoint.Should().NotBeNull();

            agent.Close();

            // RFC 8656 section 7.5: LIFETIME 0 frees the relayed port immediately instead of
            // leaving the server holding it for the rest of the ten-minute lifetime.
            (await TestTimeout.WaitForAsync(() => server.Releases == 1)).Should().BeTrue();
            server.RelayedEndPoint.Should().BeNull();
        }
        finally
        {
            agent.Dispose();
        }
    }

    private static StunClientOptions FastStun() => new()
    {
        InitialRetransmissionTimeout = TimeSpan.FromMilliseconds(150),
        MaxTransmissions = 4,
        FinalWaitMultiplier = 2,
    };

    private static IceAgentOptions AgentOptions(TestTurnServer server)
    {
        var options = new IceAgentOptions
        {
            BindAddress = IPAddress.Loopback,
            StunClientOptions = FastStun(),
            CheckRetransmissionTimeout = TimeSpan.FromMilliseconds(200),
            MaxCheckTransmissions = 12,
            TurnClientOptions = new TurnClientOptions { StunClientOptions = FastStun() },
        };

        options.TurnServers.Add(server.ToOptions());
        return options;
    }
}
