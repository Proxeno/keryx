using System.Net;
using System.Net.Sockets;
using Keryx.Core;
using Keryx.Ice;
using Keryx.Stun;

namespace Keryx.Broadcast;

/// <summary>
/// The shared-socket broadcast fan-out transport (<c>broadcast-scale.md</c> §2): one UDP socket
/// serving many viewers, instead of one socket per viewer. A single receive loop demultiplexes every
/// inbound datagram to the owning <see cref="ViewerSession"/> by its remote 5-tuple, learned from the
/// viewer's first STUN Binding request (matched by the local ICE ufrag in the USERNAME attribute);
/// outbound datagrams from every viewer leave through the same socket, tagged with that viewer's
/// remote address. Each viewer keeps its own ICE session, DTLS handshake and per-viewer SRTP keys —
/// only the file descriptor is shared.
/// </summary>
/// <remarks>
/// <para>
/// This is the transport foundation. Per ingest packet it puts N outbound datagrams on one socket, so
/// the high-volume media egress flushes them in one <c>sendmmsg</c> via <see cref="SendBatch"/> (§3):
/// a <see cref="BatchedDatagramSender"/> bound to the shared socket. The low-volume per-viewer control
/// plane — ICE checks/keepalives, the DTLS handshake, RTCP — still leaves through the per-datagram
/// send seam (<see cref="SendToViewer"/>, driven by each viewer's <c>IceAgent.SendRaw</c>).
/// </para>
/// <para>
/// <b>Socket send coordination.</b> Two producers now write the one shared socket: the media fan-out
/// (<see cref="SendBatch"/>, called from the ingest/fan-out thread) and per-viewer control traffic
/// (<see cref="SendToViewer"/>, called from the receive loop and ICE/DTLS timer threads). A
/// <see cref="BatchedDatagramSender"/> is <i>not</i> thread-safe — it reuses per-instance native
/// marshalling buffers — so every send on this endpoint, control and media alike, is serialised
/// through one <see cref="_sendLock"/>. That single lock is the endpoint's whole concurrency model for
/// egress: control and media never race the socket or the batch sender's reused buffers, yet because
/// the control plane is low-volume and each media flush is one bounded <c>sendmmsg</c>, the lock is
/// held only briefly and control-plane latency is unaffected. The inbound receive loop is lock-free
/// and independent of the send path (concurrent send + receive on one UDP socket is safe).
/// </para>
/// <para>
/// Baseline packaging is a single socket. <c>SO_REUSEPORT</c> shards (one socket per send worker, all
/// on one advertised port — §2/§4) are not reachable as a first-class, cross-platform managed socket
/// option in .NET, so a single receive loop is the correct and portable baseline; the demux and send
/// seams are shaped so a socket pool can be added behind them without changing viewer code.
/// </para>
/// </remarks>
public sealed class BroadcastEndpoint : IAsyncDisposable
{
    private const int ReceiveBufferSize = 2048;

    // A backpressured media flush retries its un-sent tail a few times, then drops the remainder rather
    // than stall the fan-out on one full socket buffer (broadcast-scale.md §3.1: one viewer's transient
    // ENOBUFS must never hold up the batch).
    private const int MaxFlushAttempts = 4;

    private readonly BroadcastEndpointOptions _options;
    private readonly IKeryxLogger _logger;
    private readonly Socket _socket;
    private readonly IPEndPoint _advertisedEndPoint;
    private readonly IceExternalSendHandler _send;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _receiveLoop;

    // The one send path for the shared socket. Both the media fan-out (SendBatch) and per-viewer
    // control traffic (SendToViewer) send under _sendLock: the batch sender reuses native marshalling
    // buffers and is single-sender-only, so serialising all egress here is what keeps control and media
    // from racing the socket or those buffers. _batchScratch is the reused BroadcastDatagram -> Datagram
    // staging array, touched only under the lock.
    private readonly object _sendLock = new();
    private readonly BatchedDatagramSender _batchSender;
    private Datagram[] _batchScratch = [];

    // Read-mostly demux state. _byEndPoint routes established 5-tuples (the hot path); _byUfrag is the
    // first-contact index a new viewer's STUN Binding request is matched against. Both are keyed so a
    // lookup is O(1) in viewer count.
    private readonly System.Collections.Concurrent.ConcurrentDictionary<IPEndPoint, ViewerSession> _byEndPoint = new();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, ViewerSession> _byUfrag = new(StringComparer.Ordinal);

    private readonly object _lifecycleLock = new();
    private int _viewerCount;
    private bool _disposed;

    /// <summary>Opens the shared socket and starts its receive loop.</summary>
    /// <param name="options">Configuration; defaults are used when null.</param>
    public BroadcastEndpoint(BroadcastEndpointOptions? options = null)
    {
        _options = (options ?? new BroadcastEndpointOptions()).Validate();
        _logger = _options.Logger;
        _socket = CreateSocket(_options.BindEndPoint);
        try
        {
            _socket.Bind(_options.BindEndPoint);
        }
        catch
        {
            _socket.Dispose();
            throw;
        }

        var bound = (IPEndPoint)_socket.LocalEndPoint!;
        LocalEndPoint = bound;
        _advertisedEndPoint = new IPEndPoint(_options.AdvertisedAddress ?? _options.BindEndPoint.Address, bound.Port);
        _batchSender = new BatchedDatagramSender(_socket);
        _send = SendToViewer;
        _receiveLoop = Task.Run(() => ReceiveLoopAsync(_cts.Token), CancellationToken.None);
        _logger.Log(
            KeryxLogLevel.Info,
            $"Broadcast endpoint listening on {bound}, advertising {_advertisedEndPoint} "
            + $"(batched send: {(_batchSender.UsesNativeBatchSend ? "native sendmmsg" : "managed fallback")}).");
    }

    /// <summary>The shared socket's bound transport address (with the OS-assigned port resolved).</summary>
    public IPEndPoint LocalEndPoint { get; }

    /// <summary>The number of viewer sessions currently held.</summary>
    public int ViewerCount => Volatile.Read(ref _viewerCount);

    /// <summary>
    /// Enrolls a new viewer: mints its local ICE credentials, points the supplied config's ICE agent
    /// at this endpoint's shared socket (endpoint-session mode), constructs the viewer's server-side
    /// <see cref="PeerConnection"/>, and registers it for first-contact demux. The caller then drives
    /// SDP negotiation and media on <see cref="ViewerSession.Connection"/>.
    /// </summary>
    /// <param name="config">
    /// The viewer connection's configuration. Its <see cref="PeerConnectionConfig.IceExternalTransport"/>,
    /// <see cref="PeerConnectionConfig.LocalIceUfrag"/> and <see cref="PeerConnectionConfig.LocalIcePassword"/>
    /// are set by this method — pass a fresh config per viewer. Codecs, tracks and everything else are
    /// the caller's to configure.
    /// </param>
    /// <returns>The new viewer session.</returns>
    /// <exception cref="InvalidOperationException">The endpoint is disposed or at its viewer cap.</exception>
    public ViewerSession AddViewer(PeerConnectionConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        var ufrag = ReserveUfrag();
        try
        {
            config.IceExternalTransport = new IceExternalTransportOptions(_send, [_advertisedEndPoint]);
            config.LocalIceUfrag = ufrag;
            config.LocalIcePassword = IceCredentials.NewPassword();

            var connection = new PeerConnection(config);
            var session = new ViewerSession("viewer-" + ufrag, connection, ufrag);
            _byUfrag[ufrag] = session;
            _logger.Log(KeryxLogLevel.Debug, $"Broadcast viewer {session.Id} enrolled ({ViewerCount} total).");
            return session;
        }
        catch
        {
            // Roll the reservation back so a failed construction does not leak a cap slot or ufrag.
            _byUfrag.TryRemove(ufrag, out _);
            Interlocked.Decrement(ref _viewerCount);
            throw;
        }
    }

    /// <summary>
    /// Removes a viewer: unbinds all its 5-tuples and its ufrag, then disposes its connection. Other
    /// viewers are undisturbed — a leaving viewer frees only its own session and demux entries.
    /// </summary>
    /// <param name="session">The session to remove.</param>
    /// <returns>True when the session was held by this endpoint and has now been removed.</returns>
    public async ValueTask<bool> RemoveViewerAsync(ViewerSession session)
    {
        ArgumentNullException.ThrowIfNull(session);

        if (!_byUfrag.TryRemove(session.LocalIceUfrag, out _))
        {
            return false;
        }

        foreach (var endPoint in session.DrainBoundEndPoints())
        {
            _byEndPoint.TryRemove(new KeyValuePair<IPEndPoint, ViewerSession>(endPoint, session));
        }

        Interlocked.Decrement(ref _viewerCount);
        await session.Connection.DisposeAsync().ConfigureAwait(false);
        _logger.Log(KeryxLogLevel.Debug, $"Broadcast viewer {session.Id} removed ({ViewerCount} remaining).");
        return true;
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        lock (_lifecycleLock)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
        }

        _cts.Cancel();
        _socket.Close();

        // Free the batch sender's native buffers, but only once no flush is mid-send: taking _sendLock
        // lets any in-flight SendBatch/SendToViewer complete first (the socket is already closed, so a
        // late send simply no-ops).
        lock (_sendLock)
        {
            _batchSender.Dispose();
        }

        try
        {
            await _receiveLoop.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // The loop only ever faults because the socket was closed above.
        }

        foreach (var session in _byUfrag.Values)
        {
            if (ReferenceEquals(session, PlaceholderSession))
            {
                continue;
            }

            _byUfrag.TryRemove(session.LocalIceUfrag, out _);
            await session.Connection.DisposeAsync().ConfigureAwait(false);
        }

        _byEndPoint.Clear();
        _cts.Dispose();
        _socket.Dispose();
    }

    private string ReserveUfrag()
    {
        lock (_lifecycleLock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (Volatile.Read(ref _viewerCount) >= _options.MaxViewers)
            {
                throw new InvalidOperationException(
                    $"The broadcast endpoint is at its viewer cap of {_options.MaxViewers}.");
            }

            string ufrag;
            do
            {
                ufrag = IceCredentials.NewUfrag();
            }
            while (!_byUfrag.TryAdd(ufrag, PlaceholderSession));

            Interlocked.Increment(ref _viewerCount);
            return ufrag;
        }
    }

    private async Task ReceiveLoopAsync(CancellationToken cancellationToken)
    {
        var buffer = new byte[ReceiveBufferSize];
        EndPoint any = new IPEndPoint(
            _socket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);

        while (!cancellationToken.IsCancellationRequested)
        {
            SocketReceiveFromResult result;
            try
            {
                result = await _socket.ReceiveFromAsync(buffer, SocketFlags.None, any, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException ex)
            {
                // A UDP send to a closed port can surface as a receive error; keep reading.
                _logger.Log(KeryxLogLevel.Trace, "Broadcast socket receive error; continuing.", ex);
                continue;
            }

            if (result.ReceivedBytes <= 0 || result.RemoteEndPoint is not IPEndPoint from)
            {
                continue;
            }

            Dispatch(buffer.AsSpan(0, result.ReceivedBytes), Normalize(from));
        }
    }

    private void Dispatch(ReadOnlySpan<byte> datagram, IPEndPoint from)
    {
        // Hot path: an established 5-tuple routes straight to its session.
        if (_byEndPoint.TryGetValue(from, out var session))
        {
            session.Inject(datagram, from);
            return;
        }

        // First contact: the only datagram accepted from an unknown source is a STUN Binding request
        // whose USERNAME names one of our viewers' local ufrags. It binds the 5-tuple, then routes as
        // any subsequent packet would. Everything else from an unknown source is dropped.
        if (TryBindFirstContact(datagram, from, out session))
        {
            session.Inject(datagram, from);
        }
    }

    private bool TryBindFirstContact(ReadOnlySpan<byte> datagram, IPEndPoint from, out ViewerSession session)
    {
        session = null!;
        if (!StunMessage.TryDecode(datagram, out var message)
            || message.Class != StunClass.Request
            || message.Method != StunMethod.Binding
            || message.Username is not { } username)
        {
            return false;
        }

        // RFC 8445: the USERNAME of an inbound check is "{our-ufrag}:{their-ufrag}". Match on the
        // local half — the ufrag we minted for this viewer's session.
        var colon = username.IndexOf(':', StringComparison.Ordinal);
        var localUfrag = colon < 0 ? username : username[..colon];
        if (!_byUfrag.TryGetValue(localUfrag, out var candidate) || ReferenceEquals(candidate, PlaceholderSession))
        {
            return false;
        }

        // First writer wins if two datagrams from the same new 5-tuple race in on one loop; either way
        // the mapping is stable afterwards. GetOrAdd returns the established binding.
        session = _byEndPoint.GetOrAdd(from, candidate);
        session.NoteBoundEndPoint(from);
        _logger.Log(KeryxLogLevel.Debug, $"Broadcast first-contact: {from} bound to {session.Id} via ufrag '{localUfrag}'.");
        return true;
    }

    /// <summary>True when the shared socket's batched send path uses the native <c>sendmmsg(2)</c> fast
    /// path; false when the managed one-syscall-per-datagram fallback is in use (non-Linux, or the
    /// native symbol was unavailable).</summary>
    public bool UsesNativeBatchSend => _batchSender.UsesNativeBatchSend;

    /// <summary>
    /// Flushes one fan-out batch — the per-viewer datagrams a <c>BroadcastFanout</c> pass produced for
    /// this ingest packet — out of the shared socket in as few syscalls as possible: one
    /// <c>sendmmsg(2)</c> on Linux, a managed <see cref="Socket.SendTo(System.ReadOnlySpan{byte},SocketFlags,EndPoint)"/>
    /// loop elsewhere. This is the high-volume media egress; it bypasses the per-datagram control seam
    /// (<see cref="SendToViewer"/>) precisely so the fan-out can batch.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Serialised against control traffic and other flushes through the endpoint's single send lock
    /// (see the type remarks): the batch sender is not thread-safe, so callers may invoke this from any
    /// thread, but each call takes the lock for the duration of its flush. Call it once per ingest
    /// packet with that packet's whole fan-out; it never throws for a per-datagram send error.
    /// </para>
    /// <para>
    /// Each datagram's <see cref="BroadcastDatagram.Payload"/> is read in place (a window into the
    /// owning subscriber's output buffer) and must stay valid for the duration of the call — do not
    /// begin the next fan-out pass for these subscribers until <see cref="SendBatch"/> returns.
    /// </para>
    /// </remarks>
    /// <param name="datagrams">The fan-out's produced datagrams: per-viewer payload plus destination.</param>
    /// <returns>The number of leading datagrams accepted by the kernel; a short count means the socket
    /// send buffer filled and the un-sent tail was dropped for this packet.</returns>
    public int SendBatch(IReadOnlyList<BroadcastDatagram> datagrams)
    {
        ArgumentNullException.ThrowIfNull(datagrams);

        var count = datagrams.Count;
        if (count == 0)
        {
            return 0;
        }

        lock (_sendLock)
        {
            if (_batchScratch.Length < count)
            {
                _batchScratch = new Datagram[count];
            }

            for (var i = 0; i < count; i++)
            {
                var datagram = datagrams[i];
                var destination = datagram.Destination is IPEndPoint ip
                    ? NormalizeOutbound(ip)
                    : datagram.Destination;
                _batchScratch[i] = new Datagram(datagram.Payload, destination);
            }

            return FlushLocked(count);
        }
    }

    // Drain the staged batch through the shared socket's sender. Held under _sendLock. A partial send
    // (backpressure) retries the un-sent tail a bounded number of times, then drops it: a fan-out must
    // never stall on one full socket buffer. Never throws for a send error.
    private int FlushLocked(int count)
    {
        var total = 0;
        var attempts = 0;
        try
        {
            while (total < count)
            {
                var sent = _batchSender.Send(_batchScratch.AsSpan(total, count - total));
                total += sent;
                if (total >= count || ++attempts >= MaxFlushAttempts)
                {
                    break;
                }
            }
        }
        catch (SocketException ex)
        {
            // A non-transient rejection (e.g. EMSGSIZE) of the datagram at the front of the window;
            // those ahead of it already went out. Drop the rest of this packet's batch and count it.
            _logger.Log(KeryxLogLevel.Warning, "A broadcast fan-out batch was truncated by a send error.", ex);
        }
        catch (ObjectDisposedException)
        {
            // The endpoint was disposed while a flush was in flight.
        }

        if (total < count)
        {
            _logger.Log(
                KeryxLogLevel.Trace,
                $"Broadcast fan-out flush sent {total}/{count} datagrams; the tail was dropped (send buffer full).");
        }

        return total;
    }

    private void SendToViewer(ReadOnlySpan<byte> datagram, IPEndPoint destination)
    {
        var to = NormalizeOutbound(destination);
        lock (_sendLock)
        {
            try
            {
                _socket.SendTo(datagram, SocketFlags.None, to);
            }
            catch (SocketException ex)
            {
                _logger.Log(KeryxLogLevel.Warning, $"Failed to send a broadcast datagram to {to}.", ex);
            }
            catch (ObjectDisposedException)
            {
                // The endpoint was disposed while a send was in flight.
            }
        }
    }

    // The mirror of Normalize on the way out: a dual-stack v6 socket cannot send to a native IPv4
    // endpoint, so map an IPv4 destination to its v4-mapped v6 form first.
    private IPEndPoint NormalizeOutbound(IPEndPoint destination)
        => _socket.AddressFamily == AddressFamily.InterNetworkV6
            && destination.AddressFamily == AddressFamily.InterNetwork
            ? new IPEndPoint(destination.Address.MapToIPv6(), destination.Port)
            : destination;

    // Test seam: drives the coordinated control-plane send path (the SendToViewer half of the send
    // lock) directly, so a stress test can pound control traffic concurrently with SendBatch media.
    internal void SendControlForTest(byte[] datagram, IPEndPoint destination)
        => SendToViewer(datagram, destination);

    private static Socket CreateSocket(IPEndPoint bind)
    {
        var socket = new Socket(bind.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        if (bind.AddressFamily == AddressFamily.InterNetworkV6 && bind.Address.Equals(IPAddress.IPv6Any))
        {
            // One dual-stack v6 socket then carries IPv4 too, as v4-mapped addresses that the receive
            // loop and SendToViewer normalise back to native IPv4.
            socket.DualMode = true;
        }

        return socket;
    }

    // A dual-stack socket reports IPv4 senders as v4-mapped IPv6 (::ffff:a.b.c.d); the demux maps and
    // the ICE agents work in native families, so an inbound address is unmapped here at the boundary.
    private static IPEndPoint Normalize(IPEndPoint endPoint)
        => endPoint.Address.IsIPv4MappedToIPv6
            ? new IPEndPoint(endPoint.Address.MapToIPv4(), endPoint.Port)
            : endPoint;

    // A sentinel that reserves a ufrag slot in _byUfrag between minting the ufrag and constructing the
    // session, so two concurrent AddViewer calls cannot mint the same ufrag. First-contact demux skips
    // it, so a viewer whose session is still being built is simply not yet routable.
    private static readonly ViewerSession PlaceholderSession = new("reserved", null!, string.Empty);
}
