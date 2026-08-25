using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using FluentAssertions;
using Keryx.Stun;
using Xunit;

namespace Keryx.Ice.Tests;

/// <summary>
/// Tests for the two connectivity-tail features: STUN servers addressed by host name and port
/// (resolved via DNS, symmetric with TURN), and RFC 6544 passive TCP candidate gathering with
/// connectivity checks and the datagram transport carried over a TCP pair.
/// </summary>
public sealed class IceConnectivityTailTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(10);
    private static readonly int ReceiveTimeoutMs = 5000;

    private static CancellationToken Timeout(int seconds = 30)
        => new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    private static IceAgentOptions TcpLoopbackOptions(IceRole role, ulong tieBreaker) => new()
    {
        Role = role,
        BindAddress = IPAddress.Loopback,
        TieBreaker = tieBreaker,
        GatherTcpCandidates = true,
        CheckInterval = TimeSpan.FromMilliseconds(20),
        CheckRetransmissionTimeout = TimeSpan.FromMilliseconds(150),
        KeepaliveInterval = TimeSpan.FromMilliseconds(500),
    };

    private static BlockingCollection<byte[]> Capture(IceAgent agent)
    {
        var queue = new BlockingCollection<byte[]>();
        agent.Transport.OnReceived += datagram => queue.Add(datagram.ToArray());
        return queue;
    }

    // Trickle only TCP candidates, so no UDP pair can ever form: the session must connect over TCP.
    private static void TrickleTcp(IceAgent from, IceAgent to)
        => from.OnLocalCandidate += (_, candidate) =>
        {
            if (candidate.IsTcp)
            {
                to.AddRemoteCandidate(candidate.ToSdpLine());
            }
        };

    private static async Task<bool> WaitUntilAsync(Func<bool> condition, TimeSpan timeout)
    {
        var deadline = Environment.TickCount64 + (long)timeout.TotalMilliseconds;
        while (Environment.TickCount64 < deadline)
        {
            if (condition())
            {
                return true;
            }

            await Task.Delay(20);
        }

        return condition();
    }

    // ------------------------------------------------------------- STUN by host name (DNS)

    [Fact]
    public async Task StunServerOptions_ResolvesHostNameToEndpoint()
    {
        var resolved = await new StunServerOptions("localhost", 3478).ResolveAsync(Timeout());

        resolved.Port.Should().Be(3478);
        IPAddress.IsLoopback(resolved.Address).Should().BeTrue();
    }

    [Fact]
    public async Task StunServerOptions_PrefersExplicitEndpoint()
    {
        var endPoint = new IPEndPoint(IPAddress.Parse("203.0.113.9"), 3478);

        (await new StunServerOptions(endPoint).ResolveAsync(Timeout())).Should().Be(endPoint);
    }

    [Fact]
    public void StunServerOptions_WithoutHostOrEndpoint_FailsValidation()
    {
        var act = () => new StunServerOptions().Validate();

        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public async Task StartGathering_AddsSrflxFromHostConfiguredStunServer()
    {
        var cancellationToken = Timeout();
        var reflexive = new IPEndPoint(IPAddress.Parse("203.0.113.42"), 51234);

        using var stunServer = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        stunServer.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var stunPort = ((IPEndPoint)stunServer.LocalEndPoint!).Port;

        var responder = Task.Run(async () =>
        {
            var buffer = new byte[1500];
            EndPoint from = new IPEndPoint(IPAddress.Any, 0);
            var received = await stunServer.ReceiveFromAsync(buffer, SocketFlags.None, from, cancellationToken);
            var request = StunMessage.Decode(buffer.AsSpan(0, received.ReceivedBytes));
            var response = StunMessage.CreateSuccessResponse(request)
                .Add(new StunXorMappedAddressAttribute(reflexive));
            stunServer.SendTo(response.Encode(appendFingerprint: true), received.RemoteEndPoint);
        }, cancellationToken);

        var options = new IceAgentOptions
        {
            BindAddress = IPAddress.Loopback,
            StunClientOptions = new StunClientOptions
            {
                InitialRetransmissionTimeout = TimeSpan.FromMilliseconds(100),
                MaxTransmissions = 5,
                FinalWaitMultiplier = 4,
            },
        };

        // The STUN server is configured by host name and resolved when gathering starts, exactly as
        // a TURN server host is; "localhost" resolves to the loopback the UDP responder listens on.
        options.StunServerHosts.Add(new StunServerOptions("localhost", stunPort));

        using var agent = new IceAgent(options);
        await agent.StartGatheringAsync(cancellationToken);
        await responder;

        var srflx = agent.LocalCandidates.Single(c => c.Type == IceCandidateType.ServerReflexive);
        srflx.EndPoint.Should().Be(reflexive);
        srflx.RelatedAddress.Should().Be(IPAddress.Loopback);
        srflx.RelatedPort.Should().Be(agent.LocalEndPoint!.Port);
    }

    // ------------------------------------------------------------- TCP gathering (RFC 6544)

    [Fact]
    public async Task GatherTcpCandidates_Off_GathersNoTcpCandidate()
    {
        using var agent = new IceAgent(new IceAgentOptions { BindAddress = IPAddress.Loopback });
        await agent.StartGatheringAsync(Timeout());

        agent.LocalCandidates.Should().OnlyContain(c => c.IsUdp);
    }

    [Fact]
    public async Task GatherTcpCandidates_On_AdvertisesPassiveTcpHostCandidate()
    {
        using var agent = new IceAgent(TcpLoopbackOptions(IceRole.Controlling, tieBreaker: 1));
        await agent.StartGatheringAsync(Timeout());

        var tcp = agent.LocalCandidates.Single(c => c.IsTcp);
        tcp.Type.Should().Be(IceCandidateType.Host);
        tcp.TcpType.Should().Be("passive");
        tcp.ToAttributeString().Should().Contain(" tcp ").And.Contain("typ host tcptype passive");

        // RFC 6544 section 4.2: a TCP host candidate ranks below the UDP host candidate, so UDP wins
        // when both work.
        var udp = agent.LocalCandidates.Single(c => c.IsUdp && c.Type == IceCandidateType.Host);
        tcp.Priority.Should().BeLessThan(udp.Priority);
    }

    [Fact]
    public async Task TwoLoopbackAgents_ConnectOverTcpPair_AndCarryDatagramsBothWays()
    {
        var cancellationToken = Timeout();

        // Distinct tie-breakers so no role conflict flips who dials; the controlling agent dials the
        // controlled agent's passive candidate.
        using var offerer = new IceAgent(TcpLoopbackOptions(IceRole.Controlling, tieBreaker: 2));
        using var answerer = new IceAgent(TcpLoopbackOptions(IceRole.Controlled, tieBreaker: 1));

        var offererInbox = Capture(offerer);
        var answererInbox = Capture(answerer);

        TrickleTcp(offerer, answerer);
        TrickleTcp(answerer, offerer);

        offerer.SetRemoteCredentials(answerer.LocalUfrag, answerer.LocalPassword);
        answerer.SetRemoteCredentials(offerer.LocalUfrag, offerer.LocalPassword);

        await offerer.StartGatheringAsync(cancellationToken);
        await answerer.StartGatheringAsync(cancellationToken);

        (await offerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        (await WaitUntilAsync(() => offerer.SelectedPair is { Nominated: true }, ConnectTimeout))
            .Should().BeTrue();
        (await WaitUntilAsync(() => answerer.SelectedPair is not null, ConnectTimeout))
            .Should().BeTrue();

        // The selected pair really is TCP on both ends: local and remote candidates are TCP, not the
        // UDP host candidates that were gathered but never trickled.
        offerer.SelectedPair!.Local.IsTcp.Should().BeTrue();
        offerer.SelectedPair.Remote.IsTcp.Should().BeTrue();
        answerer.SelectedPair!.Local.IsTcp.Should().BeTrue();
        answerer.SelectedPair.Remote.IsTcp.Should().BeTrue();

        // A DTLS-shaped record (first byte 20-63) and an RTP-shaped packet (128-191) traverse the TCP
        // pair untouched, so DTLS/SRTP/data can ride it when UDP is blocked.
        var dtls = new byte[] { 22, 0xFE, 0xFD, 0x00, 0x00, 0x01, 0x02, 0x03 };
        var rtp = new byte[] { 128, 0x60, 0x00, 0x2A, 0xDE, 0xAD, 0xBE, 0xEF };

        offerer.Transport.Send(dtls);
        answerer.Transport.Send(rtp);

        answererInbox.TryTake(out var atAnswerer, ReceiveTimeoutMs).Should().BeTrue();
        atAnswerer.Should().Equal(dtls);

        offererInbox.TryTake(out var atOfferer, ReceiveTimeoutMs).Should().BeTrue();
        atOfferer.Should().Equal(rtp);
    }
}
