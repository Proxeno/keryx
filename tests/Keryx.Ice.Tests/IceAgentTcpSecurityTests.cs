using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using FluentAssertions;
using Xunit;

namespace Keryx.Ice.Tests;

/// <summary>
/// Adversarial tests for the RFC 6544 passive TCP listener. Connecting to the advertised passive
/// candidate needs no ICE credentials (only passing a connectivity check does), so an off-path party
/// who can reach the listener can open TCP connections at will. Each accepted connection is a socket,
/// a receive task and a growable reassembly buffer, none of them timed out, so the number held at
/// once must be capped (<see cref="IceAgentOptions.MaxTcpConnections"/>) or the accept path is a
/// denial-of-service amplifier. The cap must still leave a legitimate single-pair session working.
/// </summary>
public sealed class IceAgentTcpSecurityTests
{
    private static CancellationToken Timeout(int seconds = 30)
        => new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

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

    // True once the peer has closed its end: the socket becomes readable but no bytes are available.
    // A connection the agent is still holding stays not-readable because the agent never sends
    // anything unsolicited, so this cleanly separates "kept" from "dropped".
    private static bool ClosedByPeer(Socket socket)
    {
        try
        {
            return socket.Poll(0, SelectMode.SelectRead) && socket.Available == 0;
        }
        catch (SocketException)
        {
            return true;
        }
        catch (ObjectDisposedException)
        {
            return true;
        }
    }

    private static Socket ConnectRaw(IPEndPoint target)
    {
        var socket = new Socket(target.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        socket.Connect(target);
        return socket;
    }

    [Fact]
    public async Task AcceptFlood_IsCappedAtMaxTcpConnections()
    {
        const int cap = 4;
        const int flood = cap + 8;

        using var agent = new IceAgent(new IceAgentOptions
        {
            BindAddress = IPAddress.Loopback,
            GatherTcpCandidates = true,
            MaxTcpConnections = cap,
        });

        await agent.StartGatheringAsync(Timeout());
        var passive = agent.LocalCandidates.Single(c => c.IsTcp).EndPoint;

        var clients = new List<Socket>();
        try
        {
            for (var i = 0; i < flood; i++)
            {
                clients.Add(ConnectRaw(passive));
            }

            // The agent accepts every connection but keeps only the cap; the surplus it disposes,
            // which the client observes as the peer closing. The count settles at exactly the cap.
            (await WaitUntilAsync(() => clients.Count(c => !ClosedByPeer(c)) == cap, TimeSpan.FromSeconds(10)))
                .Should().BeTrue("the passive listener must hold at most MaxTcpConnections connections at once");

            // ... and stays there: kept connections are not later dropped, and the surplus does not
            // creep back in.
            await Task.Delay(300);
            clients.Count(c => !ClosedByPeer(c)).Should().Be(cap);

            // The flood did not fault the agent; it is still a healthy, still-gathering listener.
            agent.State.Should().NotBe(IceAgentState.Failed);
            agent.LocalCandidates.Should().Contain(c => c.IsTcp);
        }
        finally
        {
            foreach (var client in clients)
            {
                client.Dispose();
            }
        }
    }

    [Fact]
    public async Task AcceptCap_AdmitsAFreshConnectionOnceAHeldOneIsClosed()
    {
        const int cap = 2;

        using var agent = new IceAgent(new IceAgentOptions
        {
            BindAddress = IPAddress.Loopback,
            GatherTcpCandidates = true,
            MaxTcpConnections = cap,
        });

        await agent.StartGatheringAsync(Timeout());
        var passive = agent.LocalCandidates.Single(c => c.IsTcp).EndPoint;

        var held = new List<Socket> { ConnectRaw(passive), ConnectRaw(passive) };
        try
        {
            // Fill the cap, then a further connection is refused (closed by the agent).
            var overflow = ConnectRaw(passive);
            (await WaitUntilAsync(() => ClosedByPeer(overflow), TimeSpan.FromSeconds(10)))
                .Should().BeTrue("a connection beyond the cap must be refused");
            overflow.Dispose();

            // Free a slot: the agent's receive loop sees the close and forgets the connection.
            held[0].Dispose();
            held.RemoveAt(0);

            // A slot is now free, so a fresh connection is admitted (stays open) rather than refused.
            var admitted = ConnectRaw(passive);
            held.Add(admitted);
            (await WaitUntilAsync(
                () => !ClosedByPeer(admitted),
                TimeSpan.FromSeconds(2)))
                .Should().BeTrue();
            await Task.Delay(300);
            ClosedByPeer(admitted).Should().BeFalse("a connection admitted into a freed slot must be held, not dropped");
        }
        finally
        {
            foreach (var socket in held)
            {
                socket.Dispose();
            }
        }
    }

    [Fact]
    public async Task LegitimateTcpSession_ConnectsWithASmallConnectionCapInPlace()
    {
        var cancellationToken = Timeout();

        IceAgentOptions Options(IceRole role, ulong tieBreaker) => new()
        {
            Role = role,
            BindAddress = IPAddress.Loopback,
            TieBreaker = tieBreaker,
            GatherTcpCandidates = true,
            MaxTcpConnections = 2,
            CheckInterval = TimeSpan.FromMilliseconds(20),
            CheckRetransmissionTimeout = TimeSpan.FromMilliseconds(150),
            KeepaliveInterval = TimeSpan.FromMilliseconds(500),
        };

        using var offerer = new IceAgent(Options(IceRole.Controlling, tieBreaker: 2));
        using var answerer = new IceAgent(Options(IceRole.Controlled, tieBreaker: 1));

        var offererInbox = new BlockingCollection<byte[]>();
        var answererInbox = new BlockingCollection<byte[]>();
        offerer.Transport.OnReceived += d => offererInbox.Add(d.ToArray());
        answerer.Transport.OnReceived += d => answererInbox.Add(d.ToArray());

        void TrickleTcp(IceAgent from, IceAgent to)
            => from.OnLocalCandidate += (_, candidate) =>
            {
                if (candidate.IsTcp)
                {
                    to.AddRemoteCandidate(candidate.ToSdpLine());
                }
            };

        TrickleTcp(offerer, answerer);
        TrickleTcp(answerer, offerer);

        offerer.SetRemoteCredentials(answerer.LocalUfrag, answerer.LocalPassword);
        answerer.SetRemoteCredentials(offerer.LocalUfrag, offerer.LocalPassword);

        await offerer.StartGatheringAsync(cancellationToken);
        await answerer.StartGatheringAsync(cancellationToken);

        (await offerer.WaitForConnectedAsync(TimeSpan.FromSeconds(10), cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(TimeSpan.FromSeconds(10), cancellationToken)).Should().BeTrue();

        // A datagram still traverses the TCP pair, so the cap left the one legitimate connection intact.
        var payload = new byte[] { 22, 0xFE, 0xFD, 0x01, 0x02, 0x03, 0x04, 0x05 };
        offerer.Transport.Send(payload);
        answererInbox.TryTake(out var atAnswerer, 5000).Should().BeTrue();
        atAnswerer.Should().Equal(payload);
    }
}
