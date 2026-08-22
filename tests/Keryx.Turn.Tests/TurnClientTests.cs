using System.Net;
using FluentAssertions;
using Keryx.Stun;
using Xunit;

namespace Keryx.Turn.Tests;

/// <summary>
/// <see cref="TurnClient"/> against <see cref="TestTurnServer"/> over UDP loopback: the RFC 8656
/// allocation lifecycle, and datagrams that are shown to have gone through the relay rather than
/// around it.
/// </summary>
public sealed class TurnClientTests
{
    [Fact]
    public async Task Allocate_AnswersThe401ChallengeAndTakesTheRelayedAddressTheServerOwns()
    {
        using var server = new TestTurnServer();
        using var harness = new TurnClientHarness(server);

        var relayed = await harness.Client.AllocateAsync(TestTimeout.Token);

        // RFC 8489 section 9.2.3.1: the first Allocate goes out unauthenticated and is challenged;
        // the second carries USERNAME, REALM, NONCE and MESSAGE-INTEGRITY.
        server.UnauthenticatedAllocates.Should().Be(1);
        server.AuthenticatedAllocates.Should().Be(1);

        relayed.Should().Be(server.RelayedEndPoint);
        harness.Client.RelayedEndPoint.Should().Be(relayed);
        harness.Client.IsAllocated.Should().BeTrue();

        // The relayed address is a socket the server really owns, not the client's own socket.
        relayed.Should().NotBe(harness.LocalEndPoint);
        relayed.Port.Should().NotBe(server.EndPoint.Port);
    }

    [Fact]
    public async Task Allocate_ReportsTheReflexiveAddressTheServerObservedAndTheGrantedLifetime()
    {
        using var server = new TestTurnServer { GrantedLifetime = TimeSpan.FromSeconds(600) };
        using var harness = new TurnClientHarness(server);

        await harness.Client.AllocateAsync(TestTimeout.Token);

        // RFC 8656 section 7.2 puts the client's server-reflexive address in XOR-MAPPED-ADDRESS
        // precisely so an ICE agent does not need a separate Binding transaction; RFC 8445
        // section 5.1.1.2 then uses it as the relayed candidate's raddr/rport.
        harness.Client.MappedEndPoint.Should().Be(harness.LocalEndPoint);
        harness.Client.GrantedLifetime.Should().Be(TimeSpan.FromSeconds(600));
    }

    [Fact]
    public async Task Allocate_RetriesWithTheFreshNonceWhenTheServerAnswers438()
    {
        using var server = new TestTurnServer { StaleNonceOnRequest = 1 };
        using var harness = new TurnClientHarness(server);

        var relayed = await harness.Client.AllocateAsync(TestTimeout.Token);

        relayed.Should().Be(server.RelayedEndPoint);
        server.StaleNonceResponses.Should().Be(1);

        // One 401 challenge, one 438 challenge, then the request that actually allocated.
        server.UnauthenticatedAllocates.Should().Be(1);
        server.AuthenticatedAllocates.Should().Be(1);
    }

    [Fact]
    public async Task Allocate_FailsWithoutLoopingWhenTheCredentialIsWrong()
    {
        using var server = new TestTurnServer();
        using var harness = new TurnClientHarness(server, password: "not-the-password");

        var allocate = async () => await harness.Client.AllocateAsync(TestTimeout.Token);

        // RFC 8489 section 9.2.5: a 401 answering an already-authenticated request must not be
        // retried with the same credentials, so this fails fast instead of challenging forever.
        (await allocate.Should().ThrowAsync<StunErrorResponseException>())
            .Which.Code.Should().Be(StunErrorCodeAttribute.Unauthorized);
        harness.Client.IsAllocated.Should().BeFalse();
        server.AuthenticatedAllocates.Should().Be(0);
    }

    [Fact]
    public async Task Allocate_RejectsAServerThatDemandsRfc8489PasswordAlgorithms()
    {
        using var server = new TestTurnServer { AdvertisePasswordAlgorithms = true };
        using var harness = new TurnClientHarness(server);

        var allocate = async () => await harness.Client.AllocateAsync(TestTimeout.Token);

        (await allocate.Should().ThrowAsync<StunFormatException>())
            .WithMessage("*password-algorithm*");
    }

    [Fact]
    public async Task CreatePermission_InstallsThePermissionOnTheServerForTheAddressOnly()
    {
        using var server = new TestTurnServer();
        using var harness = new TurnClientHarness(server);
        await harness.Client.AllocateAsync(TestTimeout.Token);

        var peer = new IPEndPoint(IPAddress.Loopback, 40000);
        await harness.Client.CreatePermissionAsync(peer, TestTimeout.Token);

        server.CreatePermissionRequests.Should().Be(1);
        server.Permissions.Should().Contain(IPAddress.Loopback);
        harness.Client.Permissions.Should().Contain(IPAddress.Loopback);
    }

    [Fact]
    public async Task BindChannel_UsesTheRfc8656ChannelRangeAndAlsoInstallsThePermission()
    {
        using var server = new TestTurnServer();
        using var harness = new TurnClientHarness(server);
        await harness.Client.AllocateAsync(TestTimeout.Token);

        var peer = new IPEndPoint(IPAddress.Loopback, 40001);
        var channel = await harness.Client.BindChannelAsync(peer, TestTimeout.Token);

        channel.Should().BeInRange(StunChannelNumberAttribute.MinChannelNumber, StunChannelNumberAttribute.MaxChannelNumber);
        server.ChannelBindRequests.Should().Be(1);
        server.Channels.Should().Contain(new KeyValuePair<ushort, IPEndPoint>(channel, peer));

        // RFC 8656 section 11.2: a ChannelBind creates or refreshes the permission too.
        server.Permissions.Should().Contain(peer.Address);
        harness.Client.BoundChannels.Should().Contain(new KeyValuePair<IPEndPoint, ushort>(peer, channel));
    }

    [Fact]
    public async Task DatagramToAPermittedPeer_TraversesTheAllocationRatherThanTakingAHostShortcut()
    {
        using var server = new TestTurnServer();
        using var harness = new TurnClientHarness(server);
        using var peer = new TestPeer();

        var relayed = await harness.Client.AllocateAsync(TestTimeout.Token);
        await harness.Client.CreatePermissionAsync(peer.EndPoint, TestTimeout.Token);

        byte[] payload = [0xC0, 0xFF, 0xEE, 0x01, 0x02, 0x03];
        var inbound = peer.ReceiveAsync(TestTimeout.Token);
        harness.Client.SendTo(payload, peer.EndPoint);

        var (data, from) = await inbound;

        data.Should().Equal(payload);

        // The proof that the relay carried it: the peer sees the datagram arriving from the
        // relayed transport address the server owns, not from the client's socket.
        from.Should().Be(relayed);
        from.Should().NotBe(harness.LocalEndPoint);
        server.RelayedToPeer.Should().Be(1);
    }

    [Fact]
    public async Task DatagramFromAPermittedPeer_ComesBackThroughTheAllocationTaggedWithThePeer()
    {
        using var server = new TestTurnServer();
        using var harness = new TurnClientHarness(server);
        using var peer = new TestPeer();

        var relayed = await harness.Client.AllocateAsync(TestTimeout.Token);
        await harness.Client.CreatePermissionAsync(peer.EndPoint, TestTimeout.Token);

        byte[] payload = [1, 1, 2, 3, 5, 8, 13];
        peer.SendTo(payload, relayed);

        (await TestTimeout.WaitForAsync(() => harness.Received.Count > 0)).Should().BeTrue();
        var received = harness.Received.Single();
        received.Data.Should().Equal(payload);
        received.Peer.Should().Be(peer.EndPoint);
        server.RelayedToClient.Should().Be(1);
    }

    [Fact]
    public async Task PeerTraffic_IsDroppedByTheRelayUntilAPermissionExists()
    {
        using var server = new TestTurnServer();
        using var harness = new TurnClientHarness(server);
        using var peer = new TestPeer();

        var relayed = await harness.Client.AllocateAsync(TestTimeout.Token);

        // RFC 8656 section 9: with no permission the relay must not forward the peer's datagram.
        peer.SendTo([9, 9, 9], relayed);
        (await TestTimeout.WaitForAsync(() => server.DroppedUnpermitted > 0, 3000)).Should().BeTrue();
        harness.Received.Should().BeEmpty();

        await harness.Client.CreatePermissionAsync(peer.EndPoint, TestTimeout.Token);
        peer.SendTo([9, 9, 9], relayed);

        (await TestTimeout.WaitForAsync(() => harness.Received.Count > 0)).Should().BeTrue();
    }

    [Fact]
    public async Task Send_UsesASendIndicationBeforeAChannelIsBoundAndChannelDataAfterwards()
    {
        using var server = new TestTurnServer();
        using var harness = new TurnClientHarness(server);
        using var peer = new TestPeer();

        await harness.Client.AllocateAsync(TestTimeout.Token);
        await harness.Client.CreatePermissionAsync(peer.EndPoint, TestTimeout.Token);

        var first = peer.ReceiveAsync(TestTimeout.Token);
        harness.Client.SendTo([1], peer.EndPoint);
        await first;
        server.ChannelDataFromClient.Should().Be(0);
        server.RelayedToPeer.Should().Be(1);

        await harness.Client.BindChannelAsync(peer.EndPoint, TestTimeout.Token);

        var second = peer.ReceiveAsync(TestTimeout.Token);
        harness.Client.SendTo([2], peer.EndPoint);
        await second;

        // RFC 8656 section 12: once a channel exists the payload rides a four-byte ChannelData
        // header instead of a 36-byte Send indication.
        server.ChannelDataFromClient.Should().Be(1);
        server.RelayedToPeer.Should().Be(2);
    }

    [Fact]
    public async Task Send_StaysOnIndicationsWhenChannelDataIsTurnedOff()
    {
        using var server = new TestTurnServer();
        var options = TurnClientHarness.FastOptions();
        options.UseChannelData = false;
        using var harness = new TurnClientHarness(server, options);
        using var peer = new TestPeer();

        await harness.Client.AllocateAsync(TestTimeout.Token);
        await harness.Client.CreatePermissionAsync(peer.EndPoint, TestTimeout.Token);

        var inbound = peer.ReceiveAsync(TestTimeout.Token);
        harness.Client.SendTo([7], peer.EndPoint);
        await inbound;

        server.ChannelDataFromClient.Should().Be(0);
        harness.Client.BoundChannels.Should().BeEmpty();
    }

    [Fact]
    public async Task Refresh_ExtendsTheAllocationAndReportsTheGrantedLifetime()
    {
        using var server = new TestTurnServer { GrantedLifetime = TimeSpan.FromSeconds(600) };
        using var harness = new TurnClientHarness(server);
        await harness.Client.AllocateAsync(TestTimeout.Token);

        var granted = await harness.Client.RefreshAsync(cancellationToken: TestTimeout.Token);

        granted.Should().Be(TimeSpan.FromSeconds(600));
        server.RefreshRequests.Should().Be(1);
    }

    [Fact]
    public async Task Maintenance_RefreshesTheAllocationAtHalfTheGrantedLifetime()
    {
        using var server = new TestTurnServer { GrantedLifetime = TimeSpan.FromSeconds(2) };
        var options = TurnClientHarness.FastOptions();
        options.MaintenanceInterval = TimeSpan.FromMilliseconds(50);
        options.RefreshFraction = 0.5;
        using var harness = new TurnClientHarness(server, options);

        await harness.Client.AllocateAsync(TestTimeout.Token);

        // Half of a two-second lifetime is one second, so a refresh must have gone out well before
        // the allocation would have expired.
        (await TestTimeout.WaitForAsync(() => server.RefreshRequests >= 1, 5000)).Should().BeTrue();
        server.Releases.Should().Be(0);
    }

    [Fact]
    public async Task Release_DeletesTheAllocationWithALifetimeOfZero()
    {
        using var server = new TestTurnServer();
        using var harness = new TurnClientHarness(server);
        await harness.Client.AllocateAsync(TestTimeout.Token);

        await harness.Client.ReleaseAsync(TestTimeout.Token);

        server.Releases.Should().Be(1);
        harness.Client.IsAllocated.Should().BeFalse();
        harness.Client.Permissions.Should().BeEmpty();
        server.RelayedEndPoint.Should().BeNull();
    }

    [Fact]
    public async Task SendRelease_DeletesTheAllocationWithoutWaitingForTheResponse()
    {
        using var server = new TestTurnServer();
        using var harness = new TurnClientHarness(server);
        await harness.Client.AllocateAsync(TestTimeout.Token);

        harness.Client.SendRelease();

        harness.Client.IsAllocated.Should().BeFalse();
        (await TestTimeout.WaitForAsync(() => server.Releases == 1)).Should().BeTrue();
    }

    [Fact]
    public async Task Send_ThrowsBeforeAnAllocationExists()
    {
        using var server = new TestTurnServer();
        using var harness = new TurnClientHarness(server);

        var send = () => harness.Client.SendTo([1, 2, 3], new IPEndPoint(IPAddress.Loopback, 1234));

        send.Should().Throw<InvalidOperationException>();
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Allocate_SurfacesTheServersErrorCodeVerbatim()
    {
        using var server = new TestTurnServer { RefuseAllocationsWith = StunErrorCodeAttribute.AllocationQuotaReached };
        using var harness = new TurnClientHarness(server);

        var allocate = async () => await harness.Client.AllocateAsync(TestTimeout.Token);

        (await allocate.Should().ThrowAsync<StunErrorResponseException>())
            .Which.Code.Should().Be(StunErrorCodeAttribute.AllocationQuotaReached);
    }
}
