using System.Net;
using System.Net.Sockets;
using FluentAssertions;

using Xunit;

namespace Keryx.Stun.Tests;

/// <summary>
/// Tests for <see cref="StunClient"/>: the RFC 5389 section 7.2.1 retransmission schedule and the
/// send/receive seam that lets ICE run the client on its own socket.
/// </summary>
public sealed class StunClientTests
{
    private static readonly IPEndPoint Server = new(IPAddress.Parse("198.51.100.10"), 3478);
    private static readonly IPEndPoint Reflexive = new(IPAddress.Parse("203.0.113.42"), 51234);

    private static StunClientOptions FastOptions(int transmissions = 5) => new()
    {
        InitialRetransmissionTimeout = TimeSpan.FromMilliseconds(20),
        MaxTransmissions = transmissions,
        FinalWaitMultiplier = 2,
        Software = "Keryx tests",
    };

    [Fact]
    public async Task BindingRequestAsync_ReturnsTheXorMappedAddressFromTheSuccessResponse()
    {
        StunClient? client = null;
        var destinations = new List<IPEndPoint>();

        client = new StunClient((datagram, destination) =>
        {
            destinations.Add(destination);
            var request = StunMessage.Decode(datagram);
            var response = StunMessage.CreateSuccessResponse(request)
                .Add(new StunXorMappedAddressAttribute(Reflexive));
            client!.TryHandleDatagram(response.Encode(appendFingerprint: true));
        }, FastOptions());

        var mapped = await client.BindingRequestAsync(Server, TestTimeout.Token);

        mapped.Should().Be(Reflexive);
        destinations.Should().Equal(new[] { Server });
    }

    [Fact]
    public async Task BindingRequestAsync_RetransmitsUntilAResponseArrives()
    {
        StunClient? client = null;
        var attempts = 0;
        StunMessage? lastRequest = null;

        client = new StunClient((datagram, _) =>
        {
            attempts++;
            lastRequest = StunMessage.Decode(datagram);
            if (attempts < 3)
            {
                return;
            }

            var response = StunMessage.CreateSuccessResponse(lastRequest)
                .Add(new StunXorMappedAddressAttribute(Reflexive));
            client!.TryHandleDatagram(response.Encode(appendFingerprint: true));
        }, FastOptions());

        var mapped = await client.BindingRequestAsync(Server, TestTimeout.Token);

        mapped.Should().Be(Reflexive);
        attempts.Should().Be(3);

        // Every retransmission reuses the same transaction id (RFC 5389 section 7.2.1).
        lastRequest!.Class.Should().Be(StunClass.Request);
        lastRequest.GetAttribute<StunSoftwareAttribute>()!.Value.Should().Be("Keryx tests");
    }

    [Fact]
    public async Task BindingRequestAsync_ThrowsAfterTheConfiguredNumberOfTransmissions()
    {
        var attempts = 0;
        var client = new StunClient((_, _) => attempts++, FastOptions(transmissions: 3));

        var act = async () => await client.BindingRequestAsync(Server, TestTimeout.Token);

        await act.Should().ThrowAsync<StunTimeoutException>();
        attempts.Should().Be(3);
    }

    [Fact]
    public async Task BindingRequestAsync_SurfacesAnErrorResponse()
    {
        StunClient? client = null;
        client = new StunClient((datagram, _) =>
        {
            var request = StunMessage.Decode(datagram);
            client!.TryHandleDatagram(
                StunMessage.CreateErrorResponse(request, 401, "Unauthorized").Encode(appendFingerprint: true));
        }, FastOptions());

        var act = async () => await client.BindingRequestAsync(Server, TestTimeout.Token);

        (await act.Should().ThrowAsync<StunErrorResponseException>()).Which.Code.Should().Be(401);
    }

    [Fact]
    public void TryHandleDatagram_IgnoresNonStunAndForeignTransactions()
    {
        var client = new StunClient((_, _) => { }, FastOptions());

        client.TryHandleDatagram([0x16, 0xFE, 0xFD, 0x00]).Should().BeFalse();
        client.TryHandleDatagram(StunMessage.CreateBindingRequest().Encode()).Should().BeFalse();

        var strayResponse = StunMessage.CreateSuccessResponse(StunMessage.CreateBindingRequest());
        client.TryHandleDatagram(strayResponse.Encode()).Should().BeFalse();
    }

    [Fact]
    public async Task QueryAsync_TalksToARealUdpStunResponder()
    {
        using var server = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        server.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var serverEndPoint = (IPEndPoint)server.LocalEndPoint!;

        using var stop = CancellationTokenSource.CreateLinkedTokenSource(TestTimeout.Token);
        var responder = Task.Run(async () =>
        {
            var buffer = new byte[1500];
            EndPoint from = new IPEndPoint(IPAddress.Any, 0);
            var received = await server.ReceiveFromAsync(buffer, SocketFlags.None, from, stop.Token);
            var request = StunMessage.Decode(buffer.AsSpan(0, received.ReceivedBytes));
            var response = StunMessage.CreateSuccessResponse(request)
                .Add(new StunXorMappedAddressAttribute((IPEndPoint)received.RemoteEndPoint));
            server.SendTo(response.Encode(appendFingerprint: true), received.RemoteEndPoint);
        }, stop.Token);

        var mapped = await StunClient.QueryAsync(
            serverEndPoint, FastOptions(), cancellationToken: TestTimeout.Token);

        await responder;
        mapped.Address.Should().Be(IPAddress.Loopback);
        mapped.Port.Should().BeGreaterThan(0);
    }
}
