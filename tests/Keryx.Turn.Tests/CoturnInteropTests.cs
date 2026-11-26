using System.Net;
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
/// These run in the CI build-test job, which installs coturn and sets <c>KERYX_REQUIRE_COTURN=1</c>
/// so a missing or unusable coturn fails instead of skipping. Locally, without the binary (or with
/// the ports the server needs already taken) each test prints a SKIPPED line and returns. The path
/// can be overridden with <c>KERYX_TURNSERVER_PATH</c>.
/// </remarks>
public sealed class CoturnInteropTests(ITestOutputHelper output)
{
    private readonly ITestOutputHelper _output = output;

    [Fact]
    [Trait("Category", "TurnInterop")]
    public async Task CoturnAllocatesARelayedAddressAndRelaysDatagramsBothWays()
    {
        using var coturn = CoturnServer.TryStart(_output, CoturnLayout.Udp);
        if (coturn is null)
        {
            return;
        }

        using var harness = new TurnClientHarness(coturn.EndPoint, CoturnServer.Username, CoturnServer.Password);
        using var peer = new TestPeer();

        var relayed = await harness.Client.AllocateAsync(TestTimeout.Token);
        _output.WriteLine($"coturn allocated {relayed}, reflexive {harness.Client.MappedEndPoint}, lifetime {harness.Client.GrantedLifetime}.");

        // coturn hands out a port from the configured relay range, on a socket it owns.
        relayed.Address.Should().Be(IPAddress.Loopback);
        relayed.Port.Should().BeInRange(CoturnLayout.Udp.MinRelayPort, CoturnLayout.Udp.MaxRelayPort);
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
        using var coturn = CoturnServer.TryStart(_output, CoturnLayout.Udp);
        if (coturn is null)
        {
            return;
        }

        using var harness = new TurnClientHarness(coturn.EndPoint, CoturnServer.Username, CoturnServer.Password);
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
        using var coturn = CoturnServer.TryStart(_output, CoturnLayout.Udp);
        if (coturn is null)
        {
            return;
        }

        using var harness = new TurnClientHarness(coturn.EndPoint, CoturnServer.Username, "wrong-password");

        var allocate = async () => await harness.Client.AllocateAsync(TestTimeout.Token);

        var thrown = await allocate.Should().ThrowAsync<StunErrorResponseException>();
        thrown.Which.Code.Should().Be(StunErrorCodeAttribute.Unauthorized);
        _output.WriteLine($"coturn refused the bad credential with {thrown.Which.Code} {thrown.Which.Reason}.");
    }

    [Fact]
    [Trait("Category", "TurnInterop")]
    public async Task CoturnReleasesTheAllocationOnRefreshWithLifetimeZero()
    {
        using var coturn = CoturnServer.TryStart(_output, CoturnLayout.Udp);
        if (coturn is null)
        {
            return;
        }

        using var harness = new TurnClientHarness(coturn.EndPoint, CoturnServer.Username, CoturnServer.Password);
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
        using var coturn = CoturnServer.TryStart(_output, CoturnLayout.Udp);
        if (coturn is null)
        {
            return;
        }

        using var agent = new IceAgent(AgentOptions(coturn));
        await agent.StartGatheringAsync(TestTimeout.Token);

        var relay = agent.LocalCandidates.SingleOrDefault(c => c.Type == IceCandidateType.Relayed);
        relay.Should().NotBeNull();
        _output.WriteLine($"gathered {relay!.ToAttributeString()}");

        relay.EndPoint.Port.Should().BeInRange(CoturnLayout.Udp.MinRelayPort, CoturnLayout.Udp.MaxRelayPort, "the relayed port must be one coturn owns");
        relay.ToAttributeString().Should().Contain("typ relay");

        // RFC 8445 section 4: raddr/rport are the mapped address from the Allocate response.
        relay.RelatedAddress.Should().Be(agent.LocalEndPoint!.Address);
        relay.RelatedPort.Should().Be(agent.LocalEndPoint.Port);
    }

    [Fact]
    [Trait("Category", "TurnInterop")]
    public async Task IceAgentConnectsThroughCoturnWhenOnlyTheRelayedPathIsAnswered()
    {
        using var coturn = CoturnServer.TryStart(_output, CoturnLayout.Udp);
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

    private static IceAgentOptions AgentOptions(CoturnServer coturn)
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
}
