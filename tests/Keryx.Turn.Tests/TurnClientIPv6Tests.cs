using System.Net;
using System.Net.Sockets;
using FluentAssertions;
using Keryx.Stun;
using Xunit;

namespace Keryx.Turn.Tests;

/// <summary>
/// RFC 8656 section 18.6 IPv6 relay allocation for <see cref="TurnClient"/>: requesting an IPv6
/// relayed address with REQUESTED-ADDRESS-FAMILY, accepting an IPv6 XOR-RELAYED-ADDRESS, and
/// carrying permissions, channel bindings and datagrams for an IPv6 peer.
/// </summary>
/// <remarks>
/// Every test that needs a live IPv6 stack is guarded by <see cref="Socket.OSSupportsIPv6"/>, so a
/// runner without IPv6 skips them rather than failing. Loopback (<c>::1</c>) is used throughout, so
/// the tests do not depend on the host having a routable IPv6 address; the control channel between
/// client and <see cref="TestTurnServer"/> stays on IPv4 loopback exactly as in the other TURN
/// tests - only the relay socket itself, and the peer traffic riding it, are IPv6.
/// </remarks>
public sealed class TurnClientIPv6Tests
{
    [Fact]
    public async Task Allocate_OmitsRequestedAddressFamilyByDefaultAndKeepsTheIPv4Relay()
    {
        // Backward compatibility: the default keeps today's wire behaviour - no
        // REQUESTED-ADDRESS-FAMILY attribute at all - and the server's own RFC 8656 section 6.1
        // default is an IPv4 relayed address.
        using var server = new TestTurnServer();
        using var harness = new TurnClientHarness(server);

        var relayed = await harness.Client.AllocateAsync(TestTimeout.Token);

        server.LastAllocateRequestedFamily.Should().BeNull();
        relayed.AddressFamily.Should().Be(AddressFamily.InterNetwork);
    }

    [Fact]
    public async Task Allocate_EncodesRequestedAddressFamilyAndAcceptsAnIPv6RelayedAddress()
    {
        if (!Socket.OSSupportsIPv6)
        {
            return;
        }

        using var server = new TestTurnServer();
        var options = TurnClientHarness.FastOptions();
        options.RequestedAddressFamily = AddressFamily.InterNetworkV6;
        using var harness = new TurnClientHarness(server, options);

        var relayed = await harness.Client.AllocateAsync(TestTimeout.Token);

        // RFC 8656 section 18.6: the Allocate request itself must carry REQUESTED-ADDRESS-FAMILY
        // set to IPv6, and the client must parse and accept the IPv6 XOR-RELAYED-ADDRESS the
        // server hands back rather than rejecting it as it used to.
        server.LastAllocateRequestedFamily.Should().Be(AddressFamily.InterNetworkV6);
        relayed.AddressFamily.Should().Be(AddressFamily.InterNetworkV6);
        relayed.Should().Be(server.RelayedEndPoint);
        harness.Client.RelayedEndPoint.Should().Be(relayed);
        harness.Client.IsAllocated.Should().BeTrue();
    }

    [Fact]
    public async Task Allocate_ThrowsWhenTheServerGrantsADifferentFamilyThanRequested()
    {
        // A server that ignores REQUESTED-ADDRESS-FAMILY and grants IPv4 anyway is misbehaving;
        // the client must not silently accept a family it did not ask for.
        using var server = new TestTurnServer { IgnoreRequestedAddressFamily = true };
        var options = TurnClientHarness.FastOptions();
        options.RequestedAddressFamily = AddressFamily.InterNetworkV6;
        using var harness = new TurnClientHarness(server, options);

        var allocate = async () => await harness.Client.AllocateAsync(TestTimeout.Token);

        (await allocate.Should().ThrowAsync<StunFormatException>())
            .WithMessage("*InterNetworkV6*");
        harness.Client.IsAllocated.Should().BeFalse();
    }

    [Fact]
    public async Task CreatePermissionAndBindChannel_AcceptAnIPv6PeerOnAnIPv6Relay()
    {
        if (!Socket.OSSupportsIPv6)
        {
            return;
        }

        using var server = new TestTurnServer();
        var options = TurnClientHarness.FastOptions();
        options.RequestedAddressFamily = AddressFamily.InterNetworkV6;
        using var harness = new TurnClientHarness(server, options);

        await harness.Client.AllocateAsync(TestTimeout.Token);

        var peer = new IPEndPoint(IPAddress.IPv6Loopback, 40010);
        await harness.Client.CreatePermissionAsync(peer, TestTimeout.Token);

        server.Permissions.Should().Contain(IPAddress.IPv6Loopback);
        harness.Client.Permissions.Should().Contain(IPAddress.IPv6Loopback);

        var channel = await harness.Client.BindChannelAsync(peer, TestTimeout.Token);

        channel.Should().BeInRange(StunChannelNumberAttribute.MinChannelNumber, StunChannelNumberAttribute.MaxChannelNumber);
        server.Channels.Should().Contain(new KeyValuePair<ushort, IPEndPoint>(channel, peer));
        harness.Client.BoundChannels.Should().Contain(new KeyValuePair<IPEndPoint, ushort>(peer, channel));
    }

    [Fact]
    public async Task DatagramToAnIPv6Peer_TraversesTheIPv6RelayInBothDirections()
    {
        if (!Socket.OSSupportsIPv6)
        {
            return;
        }

        using var server = new TestTurnServer();
        var options = TurnClientHarness.FastOptions();
        options.RequestedAddressFamily = AddressFamily.InterNetworkV6;
        using var harness = new TurnClientHarness(server, options);
        using var peer = new TestPeer(AddressFamily.InterNetworkV6);

        var relayed = await harness.Client.AllocateAsync(TestTimeout.Token);
        relayed.AddressFamily.Should().Be(AddressFamily.InterNetworkV6);
        await harness.Client.CreatePermissionAsync(peer.EndPoint, TestTimeout.Token);

        byte[] outbound = [0xC0, 0xFF, 0xEE, 0x06];
        var inbound = peer.ReceiveAsync(TestTimeout.Token);
        harness.Client.SendTo(outbound, peer.EndPoint);
        var (dataToPeer, from) = await inbound;

        dataToPeer.Should().Equal(outbound);

        // The proof that the IPv6 relay carried it: the peer sees the datagram arriving from the
        // relayed transport address the server owns, which is itself IPv6.
        from.Should().Be(relayed);
        from.AddressFamily.Should().Be(AddressFamily.InterNetworkV6);

        // The peer observing the datagram only proves the socket send happened; the server's
        // counter is incremented right after that send, so it can lag the peer's own receive by a
        // scheduling hair. Wait for it rather than assuming it already landed.
        (await TestTimeout.WaitForCountAsync(() => server.RelayedToPeer, 1)).Should().BeTrue();
        server.RelayedToPeer.Should().Be(1);

        byte[] reply = [1, 1, 2, 3, 5, 8, 13];
        peer.SendTo(reply, relayed);

        (await TestTimeout.WaitForAsync(() => harness.Received.Count > 0)).Should().BeTrue();
        var received = harness.Received.Single();
        received.Data.Should().Equal(reply);
        received.Peer.Should().Be(peer.EndPoint);
        (await TestTimeout.WaitForCountAsync(() => server.RelayedToClient, 1)).Should().BeTrue();
        server.RelayedToClient.Should().Be(1);
    }
}
