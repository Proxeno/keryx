using System.Net;
using System.Net.Sockets;
using Keryx.Core;
using Keryx.Ice;
using Keryx.Stun;

namespace Keryx.Broadcast;

/// <summary>
/// The shared-socket broadcast fan-out transport (<c>broadcast-scale.md</c> §2/§4): a pool of UDP sockets
/// serving many viewers, instead of one socket per viewer. Inbound datagrams are demultiplexed to the
/// owning <see cref="ViewerSession"/> by their remote 5-tuple, learned from the viewer's first STUN
/// Binding request (matched by the local ICE ufrag in the USERNAME attribute); outbound datagrams from
/// every viewer leave through the pool, each viewer pinned to one shard so the fan-out sends spread across
/// cores. Each viewer keeps its own ICE session, DTLS handshake and per-viewer SRTP keys — only the file
/// descriptors are shared.
/// </summary>
/// <remarks>
/// <para>
/// <b>Socket pool (§2/§4).</b> With <see cref="BroadcastEndpointOptions.SocketPoolSize"/> &gt; 1 the endpoint
/// binds N UDP sockets to <b>one advertised port</b> via Linux <c>SO_REUSEPORT</c> (the kernel
/// 5-tuple-hashes inbound datagrams across them), and each socket is a <i>shard</i> owning its own receive
/// loop and its own <see cref="BatchedDatagramSender"/> + send worker. A viewer's egress (media and control)
/// is pinned to one shard by a stable hash of its destination 5-tuple, so N shards flush N <c>sendmmsg</c>
/// batches in parallel per ingest packet — the fan-out send syscall being the tightest wall. Where
/// <c>SO_REUSEPORT</c> is unavailable (macOS/Windows, or a kernel that rejects it) the endpoint falls back
/// to a single socket: correctness is identical on every platform, only the Linux scaling win is lost. Pool
/// size 1 (the default) is exactly the original single-socket, single-send-path behaviour.
/// </para>
/// <para>
/// <b>Inbound demux is global across shards.</b> The 5-tuple → session and ufrag → session maps are shared
/// by every shard's receive loop, so a viewer is routed correctly no matter which shard's socket the kernel
/// happened to deliver its packet on — the send-shard pinning and the kernel's receive-shard hash need not
/// agree for correctness (they usually do, since both hash the 5-tuple). Because every shard socket is bound
/// to the SAME port, an outbound datagram leaves with the same source host:port whichever shard sends it, so
/// pinning a viewer's control/STUN responses to its send shard never changes what the viewer sees.
/// </para>
/// <para>
/// <b>Send coordination is per shard.</b> A <see cref="BatchedDatagramSender"/> is not thread-safe (it reuses
/// per-instance native marshalling buffers), so each shard serialises its own egress — the media fan-out
/// flush (<see cref="SendBatch"/>) and that shard's per-viewer control traffic (<see cref="SendToViewer"/>) —
/// through the shard's own send lock. Different shards never contend, so control-plane latency stays low and
/// the media flushes run genuinely in parallel. Each shard's receive loop is lock-free and independent of the
/// send path (concurrent send + receive on one UDP socket is safe).
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
    private readonly Shard[] _shards;
    private readonly AddressFamily _addressFamily;
    private readonly IPEndPoint _advertisedEndPoint;
    private readonly IceExternalSendHandler _send;
    private readonly CancellationTokenSource _cts = new();

    // Test seam: overrides how one staged batch window (offset, length into a shard's staging array) is
    // handed to the socket, so a test can script a short send (backpressure) and assert DroppedDatagrams
    // deterministically without forcing a real ENOBUFS. Null in production — the real batch sender is used.
    // Read under a shard's send lock. Applies per shard; the default single-shard endpoint tests use it.
    internal Func<int, int, int>? _sendWindowOverrideForTest;

    // Read-mostly demux state, GLOBAL across every shard. _byEndPoint routes established 5-tuples (the hot
    // path); _byUfrag is the first-contact index a new viewer's STUN Binding request is matched against.
    private readonly System.Collections.Concurrent.ConcurrentDictionary<IPEndPoint, ViewerSession> _byEndPoint = new();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, ViewerSession> _byUfrag = new(StringComparer.Ordinal);

    private readonly object _lifecycleLock = new();
    private int _viewerCount;
    private bool _disposed;

    /// <summary>Opens the shared socket pool and starts each shard's receive loop.</summary>
    /// <param name="options">Configuration; defaults are used when null.</param>
    public BroadcastEndpoint(BroadcastEndpointOptions? options = null)
    {
        _options = (options ?? new BroadcastEndpointOptions()).Validate();
        _logger = _options.Logger;

        var sockets = BindSocketPool(_options, out var boundPort);
        _addressFamily = sockets[0].AddressFamily;
        LocalEndPoint = new IPEndPoint(((IPEndPoint)sockets[0].LocalEndPoint!).Address, boundPort);
        _advertisedEndPoint = new IPEndPoint(_options.AdvertisedAddress ?? _options.BindEndPoint.Address, boundPort);

        _shards = new Shard[sockets.Count];
        for (var i = 0; i < sockets.Count; i++)
        {
            // Shard 0 is always flushed inline on the calling thread (no worker); shards 1..N-1 each get a
            // dedicated send worker so the fan-out's per-shard flushes run in parallel.
            _shards[i] = new Shard(this, i, sockets[i], hasWorker: i > 0);
        }

        _send = SendToViewer;
        foreach (var shard in _shards)
        {
            shard.StartReceiveLoop(_cts.Token);
        }

        _logger.Log(
            KeryxLogLevel.Info,
            $"Broadcast endpoint listening on {LocalEndPoint} across {_shards.Length} socket(s), advertising "
            + $"{_advertisedEndPoint} (batched send: {(_shards[0].UsesNativeBatchSend ? "native sendmmsg" : "managed fallback")}).");
    }

    /// <summary>The pool's bound transport address (with the OS-assigned port resolved). Every shard socket
    /// shares this port.</summary>
    public IPEndPoint LocalEndPoint { get; }

    /// <summary>The effective number of sockets the fan-out is sharded across. Equals the requested
    /// <see cref="BroadcastEndpointOptions.SocketPoolSize"/> on Linux with <c>SO_REUSEPORT</c> available, or 1
    /// where the endpoint fell back to a single socket.</summary>
    public int SocketPoolSize => _shards.Length;

    /// <summary>The number of viewer sessions currently held.</summary>
    public int ViewerCount => Volatile.Read(ref _viewerCount);

    /// <summary>
    /// The total number of media datagrams <see cref="SendBatch"/> has dropped, across every shard, after a
    /// shard's send buffer stayed full across every retry (the tail-drop that keeps one viewer's transient
    /// <c>ENOBUFS</c> from stalling the whole fan-out — <c>broadcast-scale.md</c> §3.1). A steadily climbing
    /// count is the signal to raise the socket send-buffer size (see
    /// <see cref="BroadcastEndpointOptions.SendBufferSize"/>) or shed load; it is otherwise expected to stay
    /// at or near zero. Monotonic for the endpoint's lifetime.
    /// </summary>
    public long DroppedDatagrams
    {
        get
        {
            long total = 0;
            foreach (var shard in _shards)
            {
                total += shard.Dropped;
            }

            return total;
        }
    }

    /// <summary>True when the pool's batched send path uses the native <c>sendmmsg(2)</c> fast path; false
    /// when the managed one-syscall-per-datagram fallback is in use (non-Linux, or the native symbol was
    /// unavailable).</summary>
    public bool UsesNativeBatchSend => _shards[0].UsesNativeBatchSend;

    /// <summary>
    /// Re-registers a viewer's first-contact demux binding after an ICE restart (RFC 8445 §9,
    /// <c>broadcast-scale.md</c> §2): an endpoint-session-mode restart regenerates the connection's local
    /// ICE ufrag, so the endpoint adopts the new ufrag and moves its <c>ufrag→session</c> map entry. Call
    /// it once the restart offer/answer has regenerated the credentials (e.g. right after
    /// <c>CreateOfferAsync(iceRestart: true)</c> / applying a restart answer) and before the viewer's
    /// fresh checks arrive from a new 5-tuple; an already-established 5-tuple keeps routing throughout.
    /// </summary>
    /// <param name="session">The viewer whose ICE credentials were just restarted.</param>
    /// <returns>True when the ufrag changed and the binding was moved; false when it was unchanged
    /// (nothing to do) or the connection has no ICE ufrag yet.</returns>
    /// <exception cref="InvalidOperationException">The endpoint is disposed, or the session is not held here.</exception>
    public bool RebindViewerIceUfrag(ViewerSession session)
    {
        ArgumentNullException.ThrowIfNull(session);

        var current = session.Connection.LocalIceUfrag;
        if (current is null)
        {
            return false;
        }

        lock (_lifecycleLock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            var previous = session.LocalIceUfrag;
            if (string.Equals(previous, current, StringComparison.Ordinal))
            {
                return false;
            }

            if (!_byUfrag.TryGetValue(previous, out var held) || !ReferenceEquals(held, session))
            {
                throw new InvalidOperationException(
                    $"Session '{session.Id}' is not registered on this endpoint under ufrag '{previous}'.");
            }

            // Register the new ufrag first, then adopt it on the session and drop the old entry, so a
            // first-contact check racing the swap resolves under one ufrag or the other, never neither.
            _byUfrag[current] = session;
            session.SetLocalIceUfrag(current);
            _byUfrag.TryRemove(new KeyValuePair<string, ViewerSession>(previous, session));
        }

        _logger.Log(KeryxLogLevel.Debug, $"Broadcast viewer {session.Id} rebound to restarted ufrag '{current}'.");
        return true;
    }

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

        // Stop each shard: close the socket (unblocks its receive loop), stop and join its send worker,
        // then dispose its batch sender once no flush is mid-send.
        foreach (var shard in _shards)
        {
            shard.BeginShutdown();
        }

        foreach (var shard in _shards)
        {
            await shard.StopAsync().ConfigureAwait(false);
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

        foreach (var shard in _shards)
        {
            shard.Dispose();
        }
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

    // Dispatches one demuxed datagram (from any shard's receive loop) to the owning viewer session. The
    // demux maps are global, so which shard received it is irrelevant to correctness.
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

        // First writer wins if two datagrams from the same new 5-tuple race in on two receive loops; either
        // way the mapping is stable afterwards. GetOrAdd returns the established binding.
        session = _byEndPoint.GetOrAdd(from, candidate);
        session.NoteBoundEndPoint(from);
        _logger.Log(KeryxLogLevel.Debug, $"Broadcast first-contact: {from} bound to {session.Id} via ufrag '{localUfrag}'.");
        return true;
    }

    /// <summary>
    /// Flushes one fan-out batch — the per-viewer datagrams a <c>BroadcastFanout</c> pass produced for
    /// this ingest packet — out of the socket pool in as few syscalls as possible. Each datagram is routed
    /// to its viewer's pinned shard (a stable hash of the destination), and every shard flushes its own
    /// sub-batch in one <c>sendmmsg(2)</c> on Linux (a managed <see cref="Socket.SendTo(System.ReadOnlySpan{byte},SocketFlags,EndPoint)"/>
    /// loop elsewhere) — in parallel across shards. This is the high-volume media egress; it bypasses the
    /// per-datagram control seam (<see cref="SendToViewer"/>) precisely so the fan-out can batch.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Each shard's flush is serialised against that shard's control traffic through the shard's send lock
    /// (see the type remarks); callers may invoke this from any thread, but a single endpoint expects one
    /// fan-out driver. Call it once per ingest packet with that packet's whole fan-out; it never throws for
    /// a per-datagram send error. The call returns only once every shard has finished flushing.
    /// </para>
    /// <para>
    /// Each datagram's <see cref="BroadcastDatagram.Payload"/> is read in place (a window into the owning
    /// subscriber's output buffer) and must stay valid for the duration of the call — do not begin the next
    /// fan-out pass for these subscribers until <see cref="SendBatch"/> returns.
    /// </para>
    /// </remarks>
    /// <param name="datagrams">The fan-out's produced datagrams: per-viewer payload plus destination.</param>
    /// <returns>The total number of datagrams accepted by the kernel across all shards; a short count means a
    /// shard's send buffer filled and its un-sent tail was dropped for this packet.</returns>
    public int SendBatch(IReadOnlyList<BroadcastDatagram> datagrams)
    {
        ArgumentNullException.ThrowIfNull(datagrams);

        var count = datagrams.Count;
        if (count == 0)
        {
            return 0;
        }

        // Fast path: a single shard needs no partitioning or fork-join — stage the whole batch and flush it
        // inline, exactly as the original single-socket endpoint did.
        if (_shards.Length == 1)
        {
            var only = _shards[0];
            only.ResetStaging();
            for (var i = 0; i < count; i++)
            {
                only.Stage(ToDatagram(datagrams[i]));
            }

            return only.Flush();
        }

        // Partition the batch by destination shard, then fork the flushes across the shards' send workers and
        // join. Shard 0 is flushed inline on this thread so it is never idle during the parallel flush.
        foreach (var shard in _shards)
        {
            shard.ResetStaging();
        }

        for (var i = 0; i < count; i++)
        {
            var datagram = ToDatagram(datagrams[i]);
            _shards[ShardFor(datagram.Destination)].Stage(datagram);
        }

        for (var i = 1; i < _shards.Length; i++)
        {
            _shards[i].SignalWorkIfStaged();
        }

        var total = _shards[0].Flush();

        for (var i = 1; i < _shards.Length; i++)
        {
            total += _shards[i].WaitForFlush();
        }

        return total;
    }

    private Datagram ToDatagram(in BroadcastDatagram datagram)
    {
        var destination = datagram.Destination is IPEndPoint ip ? NormalizeOutbound(ip) : datagram.Destination;
        return new Datagram(datagram.Payload, destination);
    }

    private void SendToViewer(ReadOnlySpan<byte> datagram, IPEndPoint destination)
    {
        var to = NormalizeOutbound(destination);
        _shards[ShardFor(to)].SendControl(datagram, to);
    }

    // Pin a destination to a shard by a stable hash of its 5-tuple. IPEndPoint.GetHashCode combines the
    // address and port and is stable within the process, so a given viewer always maps to the same shard —
    // keeping that viewer's outbound (media + control) on one socket and preserving its per-viewer ordering.
    private int ShardFor(EndPoint destination)
    {
        if (_shards.Length == 1)
        {
            return 0;
        }

        var hash = destination is IPEndPoint ip ? ip.GetHashCode() : 0;
        return (int)((uint)hash % (uint)_shards.Length);
    }

    // The mirror of Normalize on the way out: a dual-stack v6 socket cannot send to a native IPv4
    // endpoint, so map an IPv4 destination to its v4-mapped v6 form first.
    private IPEndPoint NormalizeOutbound(IPEndPoint destination)
        => _addressFamily == AddressFamily.InterNetworkV6
            && destination.AddressFamily == AddressFamily.InterNetwork
            ? new IPEndPoint(destination.Address.MapToIPv6(), destination.Port)
            : destination;

    // Test seam: drives the coordinated control-plane send path (the SendToViewer half of a shard's send
    // lock) directly, so a stress test can pound control traffic concurrently with SendBatch media.
    internal void SendControlForTest(byte[] datagram, IPEndPoint destination)
        => SendToViewer(datagram, destination);

    // Bind the requested socket pool. On Linux with SO_REUSEPORT the whole pool binds one port; anywhere the
    // option is unavailable or rejected the endpoint falls back to a single socket (correct everywhere).
    private List<Socket> BindSocketPool(BroadcastEndpointOptions options, out int boundPort)
    {
        var bind = options.BindEndPoint;
        var requested = options.SocketPoolSize;
        var sockets = new List<Socket>(requested);

        // Socket 0 always binds. When a pool is requested and SO_REUSEPORT is available, set it before this
        // first bind too, so the later sockets can share the port.
        var first = CreateSocket(bind, options.SendBufferSize);
        var poolReuse = requested > 1 && ReusePortSocketOption.TrySet(first);
        try
        {
            first.Bind(bind);
        }
        catch
        {
            first.Dispose();
            throw;
        }

        sockets.Add(first);
        boundPort = ((IPEndPoint)first.LocalEndPoint!).Port;

        if (requested > 1 && !poolReuse)
        {
            _logger.Log(
                KeryxLogLevel.Info,
                $"SO_REUSEPORT is unavailable on this platform; the broadcast endpoint falls back to a single "
                + $"socket (requested pool size {requested}). Multi-core fan-out sharding is a Linux feature.");
            return sockets;
        }

        // Bind the rest of the pool to the concrete resolved port with SO_REUSEPORT. If any bind fails, keep
        // what already bound — every socket shares the port, so a partial pool is still correct.
        var concrete = new IPEndPoint(bind.Address, boundPort);
        for (var i = 1; i < requested; i++)
        {
            var socket = CreateSocket(concrete, options.SendBufferSize);
            if (!ReusePortSocketOption.TrySet(socket))
            {
                socket.Dispose();
                break;
            }

            try
            {
                socket.Bind(concrete);
            }
            catch (SocketException ex)
            {
                _logger.Log(KeryxLogLevel.Warning, $"Broadcast socket pool bound {sockets.Count}/{requested} sockets.", ex);
                socket.Dispose();
                break;
            }

            sockets.Add(socket);
        }

        return sockets;
    }

    private static Socket CreateSocket(IPEndPoint bind, int? sendBufferSize)
    {
        var socket = new Socket(bind.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        if (bind.AddressFamily == AddressFamily.InterNetworkV6 && bind.Address.Equals(IPAddress.IPv6Any))
        {
            // One dual-stack v6 socket then carries IPv4 too, as v4-mapped addresses that the receive
            // loop and SendToViewer normalise back to native IPv4.
            socket.DualMode = true;
        }

        if (sendBufferSize is { } bytes)
        {
            // Absorb bigger fan-out bursts before the batch tail-drop (see DroppedDatagrams). The OS may
            // clamp this to its configured maximum; the effective size is observable on SendBufferSize.
            socket.SendBufferSize = bytes;
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

    /// <summary>
    /// One shard of the endpoint: a single UDP socket with its own receive loop, its own
    /// <see cref="BatchedDatagramSender"/>, and (for every shard but shard 0) a dedicated send worker so its
    /// fan-out flush runs in parallel with the other shards'. All of a shard's egress — media flush and
    /// per-viewer control — is serialised through <see cref="_sendLock"/>, since the batch sender reuses
    /// per-instance native buffers.
    /// </summary>
    private sealed class Shard : IDisposable
    {
        private readonly BroadcastEndpoint _owner;
        private readonly Socket _socket;
        private readonly BatchedDatagramSender _sender;
        private readonly object _sendLock = new();

        // Staging for the shard's slice of the current fan-out batch. Written only by the SendBatch thread
        // during staging; read by this shard's flush (which runs strictly after staging completes).
        private Datagram[] _staging = [];
        private int _stagedCount;
        private int _lastSent;
        private long _dropped;

        private Task? _receiveLoop;

        // Send worker (null for shard 0, which is flushed inline by the SendBatch caller). The worker blocks
        // on _workReady until a flush is signalled, flushes, then releases _workDone.
        private readonly Thread? _worker;
        private readonly SemaphoreSlim? _workReady;
        private readonly SemaphoreSlim? _workDone;
        private volatile bool _shutdown;
        private bool _signalled;

        public Shard(BroadcastEndpoint owner, int index, Socket socket, bool hasWorker)
        {
            _owner = owner;
            Index = index;
            _socket = socket;
            _sender = new BatchedDatagramSender(socket);

            if (hasWorker)
            {
                _workReady = new SemaphoreSlim(0, 1);
                _workDone = new SemaphoreSlim(0, 1);
                _worker = new Thread(WorkerLoop)
                {
                    IsBackground = true,
                    Name = $"keryx-broadcast-shard-{index}",
                };
                _worker.Start();
            }
        }

        public int Index { get; }

        public bool UsesNativeBatchSend => _sender.UsesNativeBatchSend;

        public long Dropped => Interlocked.Read(ref _dropped);

        public void StartReceiveLoop(CancellationToken cancellationToken)
            => _receiveLoop = Task.Run(() => ReceiveLoopAsync(cancellationToken), CancellationToken.None);

        public void ResetStaging() => _stagedCount = 0;

        public void Stage(in Datagram datagram)
        {
            if (_stagedCount >= _staging.Length)
            {
                Array.Resize(ref _staging, Math.Max(4, _staging.Length * 2));
            }

            _staging[_stagedCount++] = datagram;
        }

        // Flush this shard's staged sub-batch inline (shard 0, or the single-shard fast path). Returns the
        // datagrams accepted by the kernel.
        public int Flush()
        {
            if (_stagedCount == 0)
            {
                return 0;
            }

            lock (_sendLock)
            {
                return FlushLocked();
            }
        }

        // Wake this shard's worker to flush, but only if it has staged datagrams this pass.
        public void SignalWorkIfStaged()
        {
            if (_stagedCount == 0)
            {
                _signalled = false;
                return;
            }

            _signalled = true;
            _workReady!.Release();
        }

        // Join this shard's worker flush that SignalWorkIfStaged started; returns its accepted count.
        public int WaitForFlush()
        {
            if (!_signalled)
            {
                return 0;
            }

            _workDone!.Wait();
            return _lastSent;
        }

        public void SendControl(ReadOnlySpan<byte> datagram, IPEndPoint destination)
        {
            lock (_sendLock)
            {
                try
                {
                    _socket.SendTo(datagram, SocketFlags.None, destination);
                }
                catch (SocketException ex)
                {
                    _owner._logger.Log(KeryxLogLevel.Warning, $"Failed to send a broadcast datagram to {destination}.", ex);
                }
                catch (ObjectDisposedException)
                {
                    // The endpoint was disposed while a send was in flight.
                }
            }
        }

        public void BeginShutdown()
        {
            _shutdown = true;
            _socket.Close();
            _workReady?.Release();
        }

        public async Task StopAsync()
        {
            _worker?.Join(TimeSpan.FromSeconds(2));

            if (_receiveLoop is not null)
            {
                try
                {
                    await _receiveLoop.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
                }
                catch (Exception)
                {
                    // The loop only ever faults because the socket was closed above.
                }
            }

            // Free the batch sender's native buffers, but only once no flush is mid-send.
            lock (_sendLock)
            {
                _sender.Dispose();
            }
        }

        public void Dispose()
        {
            _workReady?.Dispose();
            _workDone?.Dispose();
            _socket.Dispose();
        }

        private void WorkerLoop()
        {
            while (true)
            {
                _workReady!.Wait();
                if (_shutdown)
                {
                    return;
                }

                lock (_sendLock)
                {
                    _lastSent = FlushLocked();
                }

                _workDone!.Release();
            }
        }

        // Drain the staged sub-batch through the shard's sender. Held under _sendLock. A partial send
        // (backpressure) retries the un-sent tail a bounded number of times, then drops it: a fan-out must
        // never stall on one full socket buffer. Never throws for a send error.
        private int FlushLocked()
        {
            var count = _stagedCount;
            var total = 0;
            var attempts = 0;
            try
            {
                while (total < count)
                {
                    var window = count - total;
                    var sent = _owner._sendWindowOverrideForTest is { } over
                        ? over(total, window)
                        : _sender.Send(_staging.AsSpan(total, window));
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
                _owner._logger.Log(KeryxLogLevel.Warning, "A broadcast fan-out batch was truncated by a send error.", ex);
            }
            catch (ObjectDisposedException)
            {
                // The endpoint was disposed while a flush was in flight.
            }

            if (total < count)
            {
                Interlocked.Add(ref _dropped, count - total);
                _owner._logger.Log(
                    KeryxLogLevel.Trace,
                    $"Broadcast shard {Index} flush sent {total}/{count} datagrams; the tail ({count - total}) was "
                    + "dropped (send buffer full). BroadcastEndpoint.DroppedDatagrams tracks the running total.");
            }

            return total;
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
                    _owner._logger.Log(KeryxLogLevel.Trace, "Broadcast socket receive error; continuing.", ex);
                    continue;
                }

                if (result.ReceivedBytes <= 0 || result.RemoteEndPoint is not IPEndPoint from)
                {
                    continue;
                }

                _owner.Dispatch(buffer.AsSpan(0, result.ReceivedBytes), Normalize(from));
            }
        }
    }
}
