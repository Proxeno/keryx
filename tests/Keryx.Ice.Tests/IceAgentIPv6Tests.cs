using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using FluentAssertions;
using Xunit;

namespace Keryx.Ice.Tests;

/// <summary>
/// IPv6 gathering and RFC 8445 pairing for <see cref="IceAgent"/>: an IPv6-only agent gathers an
/// IPv6 host candidate, two IPv6 agents complete checks and carry a datagram, and candidates are
/// only ever paired with a remote candidate of the same address family.
/// </summary>
/// <remarks>
/// Every test that needs a live IPv6 stack is guarded by <see cref="Socket.OSSupportsIPv6"/>, so a
/// runner without IPv6 skips them rather than failing. Loopback (<c>::1</c>) is used throughout, so
/// the tests do not depend on the host having a routable IPv6 address.
/// </remarks>
public sealed class IceAgentIPv6Tests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(8);
    private static readonly int ReceiveTimeoutMs = 5000;

    private static CancellationToken Timeout(int seconds = 30)
        => new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    private static IceAgentOptions IPv6LoopbackOptions(IceRole role) => new()
    {
        Role = role,
        BindAddress = IPAddress.IPv6Loopback,
        CheckInterval = TimeSpan.FromMilliseconds(20),
        CheckRetransmissionTimeout = TimeSpan.FromMilliseconds(150),
        KeepaliveInterval = TimeSpan.FromMilliseconds(500),
    };

    [Fact]
    public async Task GatheringOnIPv6Loopback_ProducesAnIPv6HostCandidate()
    {
        if (!Socket.OSSupportsIPv6)
        {
            return;
        }

        using var agent = new IceAgent(IPv6LoopbackOptions(IceRole.Controlling));

        await agent.StartGatheringAsync(Timeout());

        var host = agent.LocalCandidates.Single(c => c.Type == IceCandidateType.Host);
        host.Address.AddressFamily.Should().Be(AddressFamily.InterNetworkV6);
        host.Address.Should().Be(IPAddress.IPv6Loopback);
        agent.LocalEndPoint!.AddressFamily.Should().Be(AddressFamily.InterNetworkV6);
    }

    [Fact]
    public async Task RemoteCandidates_ArePairedOnlyWithLocalCandidatesOfTheSameFamily()
    {
        if (!Socket.OSSupportsIPv6)
        {
            return;
        }

        using var agent = new IceAgent(IPv6LoopbackOptions(IceRole.Controlling));
        await agent.StartGatheringAsync(Timeout());
        agent.SetRemoteCredentials("peer", "peerpassword0123456789");

        // The agent has only an IPv6 host candidate. RFC 8445 section 6.1.2.2 forbids pairing across
        // families, so the IPv4 remote must form no pair while the IPv6 remote forms exactly one.
        var v4Remote = new IPEndPoint(IPAddress.Loopback, 40001);
        var v6Remote = new IPEndPoint(IPAddress.IPv6Loopback, 40002);
        agent.AddRemoteCandidate(new IceCandidate(
            "1", 1, IceCandidate.UdpTransport, 1000, v4Remote.Address, v4Remote.Port, IceCandidateType.Host));
        agent.AddRemoteCandidate(new IceCandidate(
            "2", 1, IceCandidate.UdpTransport, 1000, v6Remote.Address, v6Remote.Port, IceCandidateType.Host));

        agent.CheckList.Should().NotContain(p => p.RemoteEndPoint.Equals(v4Remote));
        agent.CheckList.Should().ContainSingle(p => p.RemoteEndPoint.Equals(v6Remote))
            .Which.Local.Address.AddressFamily.Should().Be(AddressFamily.InterNetworkV6);
    }

    [Fact]
    public async Task TwoIPv6LoopbackAgents_ConnectAndCarryADatagram()
    {
        if (!Socket.OSSupportsIPv6)
        {
            return;
        }

        var cancellationToken = Timeout();
        using var offerer = new IceAgent(IPv6LoopbackOptions(IceRole.Controlling));
        using var answerer = new IceAgent(IPv6LoopbackOptions(IceRole.Controlled));

        var answererInbox = new BlockingCollection<byte[]>();
        answerer.Transport.OnReceived += datagram => answererInbox.Add(datagram.ToArray());

        offerer.OnLocalCandidate += (_, c) => answerer.AddRemoteCandidate(c.ToSdpLine());
        answerer.OnLocalCandidate += (_, c) => offerer.AddRemoteCandidate(c.ToSdpLine());

        offerer.SetRemoteCredentials(answerer.LocalUfrag, answerer.LocalPassword);
        answerer.SetRemoteCredentials(offerer.LocalUfrag, offerer.LocalPassword);

        await offerer.StartGatheringAsync(cancellationToken);
        await answerer.StartGatheringAsync(cancellationToken);

        (await offerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        // The selected pair really is IPv6 end to end, not an accidental v4-mapped fallback.
        offerer.SelectedPair!.Local.Address.AddressFamily.Should().Be(AddressFamily.InterNetworkV6);
        offerer.SelectedPair.RemoteEndPoint.Address.AddressFamily.Should().Be(AddressFamily.InterNetworkV6);
        offerer.SelectedPair.RemoteEndPoint.Should().Be(answerer.LocalEndPoint);

        var dtls = new byte[] { 22, 0xFE, 0xFD, 0x00, 0x00, 0x01, 0x02, 0x03 };
        offerer.Transport.Send(dtls);

        answererInbox.TryTake(out var received, ReceiveTimeoutMs).Should().BeTrue();
        received.Should().Equal(dtls);
    }
}
