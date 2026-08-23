using System.Net;
using System.Net.Sockets;
using Keryx.Stun;
using Keryx.Turn;
using Xunit;

// Every test in this assembly binds real UDP sockets and, in the coturn tests, a fixed port range;
// running classes in parallel would let two of them race for the same ports and for the loopback
// interface.
[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace Keryx.Turn.Tests;

internal static class TestTimeout
{
    public static CancellationToken Token { get; } = new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;

    /// <summary>Polls <paramref name="condition"/> until it holds or the timeout elapses.</summary>
    public static async Task<bool> WaitForAsync(Func<bool> condition, int timeoutMilliseconds = 10_000)
    {
        var deadline = Environment.TickCount64 + timeoutMilliseconds;
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
}

/// <summary>
/// A <see cref="TurnClient"/> wired to a real loopback UDP socket, with a receive loop that feeds
/// the socket into <see cref="TurnClient.TryHandleDatagram"/> - the same seam
/// <see cref="Keryx.Ice.IceAgent"/> uses.
/// </summary>
internal sealed class TurnClientHarness : IDisposable
{
    private readonly Socket _socket;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _receiveLoop;
    private readonly List<(byte[] Data, IPEndPoint Peer)> _received = [];

    public TurnClientHarness(TestTurnServer server, TurnClientOptions? options = null, string? password = null)
        : this(server.EndPoint, server.Username, password ?? server.Password, options)
    {
    }

    public TurnClientHarness(IPEndPoint server, string username, string password, TurnClientOptions? options = null)
    {
        _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        _socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        LocalEndPoint = (IPEndPoint)_socket.LocalEndPoint!;

        options ??= FastOptions();
        Client = new TurnClient(
            server,
            username,
            password,
            (datagram, destination) => Send(datagram, destination),
            options);
        Client.OnRelayedData += (data, peer) =>
        {
            lock (_received)
            {
                _received.Add((data.ToArray(), peer));
            }
        };

        _receiveLoop = Task.Run(() => ReceiveLoopAsync(_cts.Token));
    }

    public TurnClient Client { get; }

    public IPEndPoint LocalEndPoint { get; }

    public IReadOnlyList<(byte[] Data, IPEndPoint Peer)> Received
    {
        get
        {
            lock (_received)
            {
                return [.. _received];
            }
        }
    }

    /// <summary>Retransmission settings that keep a failing transaction under a second.</summary>
    public static TurnClientOptions FastOptions() => new()
    {
        StunClientOptions = new StunClientOptions
        {
            InitialRetransmissionTimeout = TimeSpan.FromMilliseconds(100),
            MaxTransmissions = 3,
            FinalWaitMultiplier = 2,
        },
    };

    public void Dispose()
    {
        _cts.Cancel();
        Client.Dispose();
        _socket.Close();
        try
        {
            _receiveLoop.Wait(TimeSpan.FromSeconds(2));
        }
        catch (Exception)
        {
            // The loop only ever faults because the socket was closed above.
        }

        _socket.Dispose();
        _cts.Dispose();
    }

    private void Send(ReadOnlySpan<byte> datagram, IPEndPoint destination)
    {
        try
        {
            _socket.SendTo(datagram, SocketFlags.None, destination);
        }
        catch (Exception)
        {
            // The harness is shutting down.
        }
    }

    private async Task ReceiveLoopAsync(CancellationToken cancellationToken)
    {
        var buffer = new byte[4096];
        EndPoint any = new IPEndPoint(IPAddress.Any, 0);
        while (!cancellationToken.IsCancellationRequested)
        {
            SocketReceiveFromResult result;
            try
            {
                result = await _socket.ReceiveFromAsync(buffer, SocketFlags.None, any, cancellationToken);
            }
            catch (Exception)
            {
                return;
            }

            Client.TryHandleDatagram(buffer.AsSpan(0, result.ReceivedBytes), (IPEndPoint)result.RemoteEndPoint);
        }
    }
}

/// <summary>A bare UDP socket standing in for the far-end peer a relayed datagram travels to.</summary>
internal sealed class TestPeer : IDisposable
{
    private readonly Socket _socket;
    private readonly EndPoint _any;

    /// <param name="family">
    /// The peer's address family; defaults to IPv4. Pass <see cref="AddressFamily.InterNetworkV6"/>
    /// to stand in for a peer behind an IPv6 TURN relay.
    /// </param>
    public TestPeer(AddressFamily family = AddressFamily.InterNetwork)
    {
        var loopback = family == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;
        _socket = new Socket(family, SocketType.Dgram, ProtocolType.Udp);
        _socket.Bind(new IPEndPoint(loopback, 0));
        EndPoint = (IPEndPoint)_socket.LocalEndPoint!;
        _any = family == AddressFamily.InterNetworkV6 ? new IPEndPoint(IPAddress.IPv6Any, 0) : new IPEndPoint(IPAddress.Any, 0);
    }

    public IPEndPoint EndPoint { get; }

    public void SendTo(ReadOnlySpan<byte> datagram, IPEndPoint destination)
        => _socket.SendTo(datagram, SocketFlags.None, destination);

    /// <summary>Waits for one datagram and reports the payload and the address it came from.</summary>
    public async Task<(byte[] Data, IPEndPoint From)> ReceiveAsync(CancellationToken cancellationToken)
    {
        var buffer = new byte[4096];
        var result = await _socket.ReceiveFromAsync(buffer, SocketFlags.None, _any, cancellationToken);
        return (buffer.AsSpan(0, result.ReceivedBytes).ToArray(), (IPEndPoint)result.RemoteEndPoint);
    }

    public void Dispose() => _socket.Dispose();
}
