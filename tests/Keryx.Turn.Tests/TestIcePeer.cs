using System.Net;
using System.Net.Sockets;
using Keryx.Stun;

namespace Keryx.Turn.Tests;

/// <summary>
/// A remote ICE peer that behaves like one sitting behind a symmetric NAT: it answers connectivity
/// checks only when they arrive from the one source address it has been told to accept, and
/// silently drops everything else.
/// </summary>
/// <remarks>
/// That is what makes a relay test provable rather than plausible. Both a direct check and a
/// relayed check leave the agent for the same destination; only the relayed one arrives from the
/// TURN server's relayed transport address, so only it is answered, and any pair the agent then
/// selects must be the relayed one.
/// </remarks>
internal sealed class TestIcePeer : IDisposable
{
    private readonly Socket _socket;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;
    private readonly byte[] _key;
    private readonly object _lock = new();
    private readonly List<byte[]> _media = [];
    private readonly HashSet<IPEndPoint> _checkSources = [];

    private IPEndPoint? _acceptFrom;

    /// <summary>Creates the peer.</summary>
    /// <param name="password">The ICE password the agent will validate responses against.</param>
    public TestIcePeer(string password)
    {
        _key = StunCredentials.ShortTermKey(password);
        _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        _socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        EndPoint = (IPEndPoint)_socket.LocalEndPoint!;
        _loop = Task.Run(() => ReceiveLoopAsync(_cts.Token));
    }

    /// <summary>The peer's transport address, to be signalled to the agent as a remote candidate.</summary>
    public IPEndPoint EndPoint { get; }

    /// <summary>Datagrams dropped because they did not come from <see cref="AcceptOnlyFrom"/>.</summary>
    public int Dropped;

    /// <summary>Connectivity checks answered.</summary>
    public int ChecksAnswered;

    /// <summary>The source addresses checks have arrived from, whether answered or dropped.</summary>
    public IReadOnlyCollection<IPEndPoint> CheckSources
    {
        get
        {
            lock (_lock)
            {
                return [.. _checkSources];
            }
        }
    }

    /// <summary>Non-STUN datagrams received, in order.</summary>
    public IReadOnlyList<byte[]> Media
    {
        get
        {
            lock (_lock)
            {
                return [.. _media];
            }
        }
    }

    /// <summary>The only source address the peer will answer; null accepts everything.</summary>
    public IPEndPoint? AcceptOnlyFrom
    {
        get
        {
            lock (_lock)
            {
                return _acceptFrom;
            }
        }

        set
        {
            lock (_lock)
            {
                _acceptFrom = value;
            }
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _socket.Close();
        try
        {
            _loop.Wait(TimeSpan.FromSeconds(2));
        }
        catch (Exception)
        {
            // The loop only ever faults because the socket was closed above.
        }

        _socket.Dispose();
        _cts.Dispose();
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

            var datagram = buffer.AsSpan(0, result.ReceivedBytes);
            var from = (IPEndPoint)result.RemoteEndPoint;
            var isStun = StunMessage.LooksLikeStun(datagram);

            if (isStun)
            {
                lock (_lock)
                {
                    _checkSources.Add(from);
                }
            }

            IPEndPoint? accept;
            lock (_lock)
            {
                accept = _acceptFrom;
            }

            if (accept is not null && !accept.Equals(from))
            {
                Interlocked.Increment(ref Dropped);
                continue;
            }

            if (!isStun)
            {
                lock (_lock)
                {
                    _media.Add(datagram.ToArray());
                }

                continue;
            }

            if (!StunMessage.TryDecode(datagram, out var message)
                || message.Class != StunClass.Request
                || message.Method != StunMethod.Binding)
            {
                continue;
            }

            var response = StunMessage.CreateSuccessResponse(message)
                .Add(new StunXorMappedAddressAttribute(from));
            try
            {
                _socket.SendTo(response.Encode(_key, appendFingerprint: true), SocketFlags.None, from);
                Interlocked.Increment(ref ChecksAnswered);
            }
            catch (Exception)
            {
                // The peer is shutting down.
            }
        }
    }
}
