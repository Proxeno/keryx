using System.Buffers;
using System.Net;
using System.Net.Sockets;
using Keryx.Core;
using Keryx.Stun;

namespace Keryx.Turn;

/// <summary>Receives one datagram a TURN server relayed from <paramref name="peer"/>.</summary>
/// <param name="data">The application payload, valid only for the duration of the call.</param>
/// <param name="peer">The peer transport address the server received it from.</param>
public delegate void TurnRelayedDataHandler(ReadOnlySpan<byte> data, IPEndPoint peer);

/// <summary>
/// A TURN client (RFC 8656): it allocates a relayed transport address on a TURN server, keeps the
/// allocation and its permissions alive, and carries datagrams to and from permitted peers.
/// </summary>
/// <remarks>
/// <para>
/// Like <see cref="StunClient"/>, the client does not own a socket. It sends through a
/// <see cref="StunDatagramSender"/> and is fed inbound datagrams through
/// <see cref="TryHandleDatagram"/>, so an ICE agent can run the allocation over the very socket it
/// uses for connectivity checks and media - which is what makes the relayed address a usable ICE
/// candidate whose base is that socket.
/// </para>
/// <para>
/// <b>Data path.</b> Keryx binds a channel to every peer and carries relayed datagrams as
/// ChannelData (RFC 8656 section 12). A Send indication costs 36 bytes of header and a STUN parse
/// per packet; ChannelData costs four bytes and a length check, which at 60 fps video is the
/// difference between roughly 200 kbit/s of pure overhead and 22 kbit/s. Send and Data indications
/// are still implemented and used: they are the bootstrap path before the ChannelBind transaction
/// completes, and a server may legitimately deliver inbound traffic as a Data indication at any
/// time. Set <see cref="TurnClientOptions.UseChannelData"/> to false to stay on indications.
/// </para>
/// <para>
/// <b>Threading.</b> Transactions are serialised so that the long-term-credential nonce is never
/// updated by two challenges at once. <see cref="OnRelayedData"/> is raised on the thread that
/// called <see cref="TryHandleDatagram"/> - the caller's receive loop - and handlers must not
/// block.
/// </para>
/// </remarks>
public sealed class TurnClient : IDisposable
{
    /// <summary>
    /// How many times an authenticated request is re-sent after an authentication challenge: once
    /// for the initial 401 that carries the realm and nonce, and once more for a 438 Stale Nonce
    /// that arrives on the retry (RFC 8489 section 9.2.5).
    /// </summary>
    private const int MaxAuthenticationRetries = 2;

    /// <summary>
    /// The 13-character prefix RFC 8489 section 9.2 puts in front of a nonce to advertise the STUN
    /// Security Features: the literal "obMatJos2" and four base64 characters holding 24 feature bits.
    /// </summary>
    private const string NonceCookie = "obMatJos2";

    private const int SendBufferSize = 2048;

    private readonly IPEndPoint _server;
    private readonly string _username;
    private readonly string _credential;
    private readonly TurnClientOptions _options;
    private readonly IKeryxLogger _logger;
    private readonly StunDatagramSender _sender;
    private readonly StunClient _stun;
    private readonly object _lock = new();
    private readonly SemaphoreSlim _transactionGate = new(1, 1);
    private readonly Dictionary<IPAddress, long> _permissions = [];
    private readonly Dictionary<IPEndPoint, TurnChannel> _channels = [];
    private readonly Dictionary<ushort, IPEndPoint> _channelPeers = [];
    private readonly CancellationTokenSource _cts = new();

    private string? _realm;
    private string? _nonce;
    private byte[]? _key;
    private StunPasswordAlgorithm? _passwordAlgorithm;
    private StunPasswordAlgorithmsAttribute? _pendingPasswordAlgorithmsEcho;
    private IPEndPoint? _relayed;
    private IPEndPoint? _mapped;
    private TimeSpan _grantedLifetime;
    private long _nextRefreshAt;
    private ushort _nextChannelNumber = StunChannelNumberAttribute.MinChannelNumber;
    private Task? _maintenanceLoop;
    private bool _disposed;

    /// <summary>Creates a client for one TURN server over a caller-owned socket.</summary>
    /// <param name="server">The server's resolved transport address.</param>
    /// <param name="username">The long-term credential username.</param>
    /// <param name="credential">The long-term credential password.</param>
    /// <param name="sender">Callback that puts a datagram on the wire.</param>
    /// <param name="options">Lifetime and refresh settings; defaults if null.</param>
    public TurnClient(
        IPEndPoint server,
        string username,
        string credential,
        StunDatagramSender sender,
        TurnClientOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentException.ThrowIfNullOrEmpty(username);
        ArgumentException.ThrowIfNullOrEmpty(credential);
        ArgumentNullException.ThrowIfNull(sender);

        _server = server;
        _username = username;
        _credential = credential;
        _options = (options ?? new TurnClientOptions()).Validate();
        _logger = _options.Logger ?? NullLogger.Instance;
        _sender = sender;
        _stun = new StunClient(sender, _options.StunClientOptions, _logger);
    }

    /// <summary>Raised for every datagram the server relays in, whether as ChannelData or a Data indication.</summary>
    public event TurnRelayedDataHandler? OnRelayedData;

    /// <summary>The TURN server's transport address.</summary>
    public IPEndPoint ServerEndPoint => _server;

    /// <summary>
    /// The relayed transport address from the Allocate response's XOR-RELAYED-ADDRESS, or null
    /// before a successful Allocate (RFC 8656 section 18.5).
    /// </summary>
    public IPEndPoint? RelayedEndPoint
    {
        get
        {
            lock (_lock)
            {
                return _relayed;
            }
        }
    }

    /// <summary>
    /// The server-reflexive transport address from the Allocate response's XOR-MAPPED-ADDRESS.
    /// This is the base of the relayed candidate, and is what RFC 8445 section 5.1.1.2 puts in the
    /// candidate's <c>raddr</c>/<c>rport</c>.
    /// </summary>
    public IPEndPoint? MappedEndPoint
    {
        get
        {
            lock (_lock)
            {
                return _mapped;
            }
        }
    }

    /// <summary>The lifetime the server granted in the last Allocate or Refresh response.</summary>
    public TimeSpan GrantedLifetime
    {
        get
        {
            lock (_lock)
            {
                return _grantedLifetime;
            }
        }
    }

    /// <summary>True once an allocation exists and has not been released.</summary>
    public bool IsAllocated => RelayedEndPoint is not null;

    /// <summary>The peer addresses this client currently holds a permission for (RFC 8656 section 9).</summary>
    public IReadOnlyCollection<IPAddress> Permissions
    {
        get
        {
            lock (_lock)
            {
                return [.. _permissions.Keys];
            }
        }
    }

    /// <summary>The peers a channel has been bound for, with their channel numbers.</summary>
    public IReadOnlyDictionary<IPEndPoint, ushort> BoundChannels
    {
        get
        {
            lock (_lock)
            {
                var map = new Dictionary<IPEndPoint, ushort>(_channels.Count);
                foreach (var (peer, channel) in _channels)
                {
                    if (channel.Bound)
                    {
                        map[peer] = channel.Number;
                    }
                }

                return map;
            }
        }
    }

    /// <summary>
    /// Runs the Allocate transaction, including the RFC 8656 section 9.2 long-term-credential
    /// dance: an unauthenticated Allocate draws a 401 carrying REALM and NONCE, and the request is
    /// re-sent signed with MESSAGE-INTEGRITY over <c>MD5(username:realm:password)</c> - or, when
    /// the server negotiates RFC 8489 password algorithms, MESSAGE-INTEGRITY-SHA256 over an MD5- or
    /// SHA-256-derived key (see <see cref="StunPasswordAlgorithm"/>).
    /// </summary>
    /// <param name="cancellationToken">Cancels the transaction.</param>
    /// <returns>
    /// The relayed transport address the server allocated - IPv4 unless
    /// <see cref="TurnClientOptions.RequestedAddressFamily"/> asks for IPv6.
    /// </returns>
    /// <exception cref="StunErrorResponseException">The server refused the allocation.</exception>
    /// <exception cref="StunTimeoutException">The server did not answer.</exception>
    /// <exception cref="StunFormatException">
    /// The success response was not a usable Allocate response, or allocated a relayed address from
    /// a family other than the one requested.
    /// </exception>
    public async Task<IPEndPoint> AllocateAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        await _transactionGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var response = await AuthenticatedRequestAsync(
                () =>
                {
                    var request = new StunMessage(StunClass.Request, StunMethod.Allocate)
                        .Add(new StunRequestedTransportAttribute(TurnTransportProtocol.Udp))
                        .Add(new StunLifetimeAttribute(_options.RequestedLifetime));

                    if (_options.RequestedAddressFamily is { } family)
                    {
                        // RFC 8656 section 18.6: omitting REQUESTED-ADDRESS-FAMILY asks for the
                        // server's default (an IPv4 relayed address, section 6.1); naming a family
                        // asks for a relayed address from that family specifically.
                        request.Add(new StunRequestedAddressFamilyAttribute(family));
                    }

                    return request;
                },
                cancellationToken).ConfigureAwait(false);

            var relayed = response.RelayedAddress
                          ?? throw new StunFormatException("The Allocate success response carried no XOR-RELAYED-ADDRESS.");
            if (_options.RequestedAddressFamily is { } requestedFamily && relayed.AddressFamily != requestedFamily)
            {
                throw new StunFormatException(
                    $"Requested a {requestedFamily} relayed address but the server allocated {relayed}.");
            }

            var granted = response.GetAttribute<StunLifetimeAttribute>()?.Lifetime
                          ?? TimeSpan.FromSeconds(StunLifetimeAttribute.DefaultAllocationSeconds);

            lock (_lock)
            {
                _relayed = relayed;
                _mapped = response.MappedAddress;
                _grantedLifetime = granted;
                _nextRefreshAt = Environment.TickCount64 + RefreshDelayMilliseconds(granted);
            }

            _logger.Log(
                KeryxLogLevel.Info,
                $"TURN allocation on {_server}: relayed {relayed}, reflexive {response.MappedAddress?.ToString() ?? "unknown"}, lifetime {granted.TotalSeconds:0}s.");

            _maintenanceLoop ??= Task.Run(() => MaintenanceLoopAsync(_cts.Token), CancellationToken.None);
            return relayed;
        }
        finally
        {
            _transactionGate.Release();
        }
    }

    /// <summary>
    /// Runs a Refresh transaction, extending the allocation (RFC 8656 section 7.5).
    /// </summary>
    /// <param name="lifetime">
    /// The lifetime to ask for, or null for <see cref="TurnClientOptions.RequestedLifetime"/>.
    /// <see cref="TimeSpan.Zero"/> releases the allocation.
    /// </param>
    /// <param name="cancellationToken">Cancels the transaction.</param>
    /// <returns>The lifetime the server granted.</returns>
    public async Task<TimeSpan> RefreshAsync(TimeSpan? lifetime = null, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var requested = lifetime ?? _options.RequestedLifetime;
        await _transactionGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            StunMessage? response;
            try
            {
                response = await AuthenticatedRequestAsync(
                    () => new StunMessage(StunClass.Request, StunMethod.Refresh)
                        .Add(new StunLifetimeAttribute(requested)),
                    cancellationToken).ConfigureAwait(false);
            }
            catch (StunErrorResponseException ex)
                when (requested == TimeSpan.Zero && ex.Code == StunErrorCodeAttribute.AllocationMismatch)
            {
                // RFC 8656 section 8.3: a 437 to a delete means the allocation is already gone, and
                // the client "should consider its request as having effectively succeeded".
                response = null;
            }

            var granted = response?.GetAttribute<StunLifetimeAttribute>()?.Lifetime ?? requested;
            lock (_lock)
            {
                if (requested == TimeSpan.Zero)
                {
                    // RFC 8656 section 7.5: a Refresh with LIFETIME 0 deletes the allocation, so
                    // everything hanging off it - permissions, channel bindings - is gone too.
                    _relayed = null;
                    _mapped = null;
                    _grantedLifetime = TimeSpan.Zero;
                    _permissions.Clear();
                    _channels.Clear();
                    _channelPeers.Clear();
                }
                else
                {
                    _grantedLifetime = granted;
                    _nextRefreshAt = Environment.TickCount64 + RefreshDelayMilliseconds(granted);
                }
            }

            _logger.Log(
                KeryxLogLevel.Debug,
                requested == TimeSpan.Zero
                    ? $"TURN allocation on {_server} released."
                    : $"TURN allocation on {_server} refreshed for {granted.TotalSeconds:0}s.");
            return granted;
        }
        finally
        {
            _transactionGate.Release();
        }
    }

    /// <summary>
    /// Releases the allocation with a Refresh carrying LIFETIME 0 and waits for the response
    /// (RFC 8656 section 7.5).
    /// </summary>
    /// <param name="cancellationToken">Cancels the transaction.</param>
    public Task ReleaseAsync(CancellationToken cancellationToken = default)
        => RefreshAsync(TimeSpan.Zero, cancellationToken);

    /// <summary>
    /// Sends a single Refresh with LIFETIME 0 without waiting for the response, for use on a
    /// synchronous close path where blocking is not acceptable. The allocation is dropped locally
    /// straight away; a lost datagram only means the server expires it on its own schedule.
    /// </summary>
    public void SendRelease()
    {
        byte[]? key;
        string? realm;
        string? nonce;
        StunPasswordAlgorithm? algorithm;
        lock (_lock)
        {
            if (_relayed is null)
            {
                return;
            }

            key = _key;
            realm = _realm;
            nonce = _nonce;
            algorithm = _passwordAlgorithm;
            _relayed = null;
            _mapped = null;
            _permissions.Clear();
            _channels.Clear();
            _channelPeers.Clear();
        }

        if (key is null || realm is null || nonce is null)
        {
            return;
        }

        var request = new StunMessage(StunClass.Request, StunMethod.Refresh)
            .Add(new StunLifetimeAttribute(0u))
            .Add(new StunUsernameAttribute(_username))
            .Add(new StunRealmAttribute(realm))
            .Add(new StunNonceAttribute(nonce));

        if (algorithm is { } selected)
        {
            request.Add(new StunPasswordAlgorithmAttribute(selected));
        }

        try
        {
            _sender(request.Encode(key, appendFingerprint: true, useMessageIntegritySha256: algorithm is not null), _server);
            _logger.Log(KeryxLogLevel.Debug, $"TURN allocation on {_server} released (fire and forget).");
        }
        catch (SocketException ex)
        {
            _logger.Log(KeryxLogLevel.Debug, $"Could not send the TURN release to {_server}.", ex);
        }
        catch (ObjectDisposedException)
        {
            // The socket was already closed; the server will expire the allocation.
        }
    }

    /// <summary>
    /// Installs (or refreshes) permission for the server to relay traffic from
    /// <paramref name="peers"/> (RFC 8656 section 9). A permission matches on IP address only -
    /// the port in each entry is ignored by the server - and lives 300 seconds.
    /// </summary>
    /// <param name="peers">The peer transport addresses to permit.</param>
    /// <param name="cancellationToken">Cancels the transaction.</param>
    public async Task CreatePermissionAsync(IEnumerable<IPEndPoint> peers, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(peers);
        ObjectDisposedException.ThrowIf(_disposed, this);

        var wanted = new List<IPEndPoint>();
        var seen = new HashSet<IPAddress>();
        foreach (var peer in peers)
        {
            if (peer.AddressFamily is (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6) && seen.Add(peer.Address))
            {
                wanted.Add(peer);
            }
        }

        if (wanted.Count == 0)
        {
            return;
        }

        await _transactionGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await AuthenticatedRequestAsync(
                () =>
                {
                    var request = new StunMessage(StunClass.Request, StunMethod.CreatePermission);
                    foreach (var peer in wanted)
                    {
                        request.Add(new StunXorPeerAddressAttribute(peer));
                    }

                    return request;
                },
                cancellationToken).ConfigureAwait(false);

            var now = Environment.TickCount64;
            lock (_lock)
            {
                foreach (var peer in wanted)
                {
                    _permissions[peer.Address] = now;
                }
            }

            _logger.Log(
                KeryxLogLevel.Debug,
                $"TURN permission created on {_server} for {string.Join(", ", wanted.Select(static p => p.Address))}.");
        }
        finally
        {
            _transactionGate.Release();
        }
    }

    /// <summary>Installs (or refreshes) permission for a single peer.</summary>
    /// <param name="peer">The peer transport address to permit.</param>
    /// <param name="cancellationToken">Cancels the transaction.</param>
    public Task CreatePermissionAsync(IPEndPoint peer, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(peer);
        return CreatePermissionAsync([peer], cancellationToken);
    }

    /// <summary>
    /// Binds a channel to <paramref name="peer"/> so its traffic can travel as ChannelData
    /// (RFC 8656 section 11). A successful ChannelBind also installs a permission for the peer, so
    /// no separate CreatePermission is needed afterwards.
    /// </summary>
    /// <param name="peer">The peer transport address; the binding is to the exact address and port.</param>
    /// <param name="cancellationToken">Cancels the transaction.</param>
    /// <returns>The channel number bound to the peer.</returns>
    public async Task<ushort> BindChannelAsync(IPEndPoint peer, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(peer);
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (peer.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
        {
            throw new ArgumentException("A TURN channel peer must be an IPv4 or IPv6 transport address.", nameof(peer));
        }

        await _transactionGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ushort number;
            lock (_lock)
            {
                if (_channels.TryGetValue(peer, out var existing))
                {
                    number = existing.Number;
                }
                else
                {
                    number = NextChannelNumberLocked();
                    _channels[peer] = new TurnChannel(number);
                    _channelPeers[number] = peer;
                }
            }

            await AuthenticatedRequestAsync(
                () => new StunMessage(StunClass.Request, StunMethod.ChannelBind)
                    .Add(new StunChannelNumberAttribute(number))
                    .Add(new StunXorPeerAddressAttribute(peer)),
                cancellationToken).ConfigureAwait(false);

            var now = Environment.TickCount64;
            lock (_lock)
            {
                _channels[peer] = new TurnChannel(number) { Bound = true, BoundAt = now };

                // RFC 8656 section 11.2: a ChannelBind also creates or refreshes the permission,
                // so the permission clock restarts here too.
                _permissions[peer.Address] = now;
            }

            _logger.Log(KeryxLogLevel.Debug, $"TURN channel 0x{number:X4} bound to {peer} on {_server}.");
            return number;
        }
        finally
        {
            _transactionGate.Release();
        }
    }

    /// <summary>
    /// Sends one datagram to <paramref name="peer"/> through the allocation: as ChannelData when a
    /// channel is bound, otherwise as a Send indication (RFC 8656 sections 10 and 12).
    /// </summary>
    /// <param name="datagram">The application payload.</param>
    /// <param name="peer">The destination peer; a permission for it must already exist.</param>
    /// <exception cref="InvalidOperationException">No allocation exists.</exception>
    public void SendTo(ReadOnlySpan<byte> datagram, IPEndPoint peer)
    {
        ArgumentNullException.ThrowIfNull(peer);

        ushort? channel = null;
        lock (_lock)
        {
            if (_relayed is null)
            {
                throw new InvalidOperationException("There is no TURN allocation; nothing can be relayed.");
            }

            if (_channels.TryGetValue(peer, out var bound) && bound.Bound)
            {
                channel = bound.Number;
            }
        }

        var buffer = ArrayPool<byte>.Shared.Rent(Math.Max(SendBufferSize, datagram.Length + 64));
        try
        {
            int length;
            if (channel is { } number)
            {
                length = TurnChannelData.Encode(buffer, number, datagram);
            }
            else
            {
                // RFC 8656 section 10.1: a Send indication carries no MESSAGE-INTEGRITY - the
                // long-term credential mechanism authenticates transactions, not indications.
                var indication = new StunMessage(StunClass.Indication, StunMethod.Send)
                    .Add(new StunXorPeerAddressAttribute(peer))
                    .Add(new StunDataAttribute(datagram));
                length = indication.EncodeTo(buffer, integrityKey: null, appendFingerprint: false);
            }

            _sender(buffer.AsSpan(0, length), _server);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Offers an inbound datagram to the client.
    /// </summary>
    /// <param name="datagram">The received bytes.</param>
    /// <param name="from">The address the datagram arrived from.</param>
    /// <returns>
    /// True when the datagram belonged to this allocation and has been consumed - a response to one
    /// of our transactions, a Data indication, or ChannelData, the last two having been surfaced
    /// through <see cref="OnRelayedData"/>. False when the caller should handle it.
    /// </returns>
    public bool TryHandleDatagram(ReadOnlySpan<byte> datagram, IPEndPoint from)
    {
        ArgumentNullException.ThrowIfNull(from);

        if (!from.Equals(_server))
        {
            return false;
        }

        if (TurnChannelData.TryDecode(datagram, out var channelNumber, out var payload))
        {
            IPEndPoint? peer;
            lock (_lock)
            {
                _channelPeers.TryGetValue(channelNumber, out peer);
            }

            if (peer is null)
            {
                _logger.Log(KeryxLogLevel.Warning, $"Dropping ChannelData for unbound channel 0x{channelNumber:X4} from {from}.");
                return true;
            }

            OnRelayedData?.Invoke(payload, peer);
            return true;
        }

        if (!StunMessage.LooksLikeStun(datagram))
        {
            return false;
        }

        if (_stun.TryHandleDatagram(datagram))
        {
            return true;
        }

        if (!StunMessage.TryDecode(datagram, out var message))
        {
            return false;
        }

        if (message.Class != StunClass.Indication || message.Method != StunMethod.Data)
        {
            return false;
        }

        // RFC 8656 section 10.3: a Data indication carries the peer address and the payload. It is
        // how a server delivers traffic before a channel exists, and stays legal afterwards.
        var peerAddress = message.GetAttribute<StunXorPeerAddressAttribute>()?.EndPoint;
        var data = message.GetAttribute<StunDataAttribute>();
        if (peerAddress is null || data is null)
        {
            _logger.Log(KeryxLogLevel.Warning, $"Dropping a TURN Data indication from {from} without XOR-PEER-ADDRESS and DATA.");
            return true;
        }

        // RFC 8656 section 11.4: the client SHOULD discard a Data indication naming an address it
        // holds no permission for - it is the only defence against a server that was tricked into
        // installing permissions the client never asked for.
        bool permitted;
        lock (_lock)
        {
            permitted = _permissions.ContainsKey(peerAddress.Address);
        }

        if (!permitted)
        {
            _logger.Log(KeryxLogLevel.Warning, $"Dropping a TURN Data indication from {from} for unpermitted peer {peerAddress}.");
            return true;
        }

        OnRelayedData?.Invoke(data.Value, peerAddress);
        return true;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        lock (_lock)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
        }

        _cts.Cancel();
        try
        {
            _maintenanceLoop?.Wait(TimeSpan.FromSeconds(2));
        }
        catch (Exception)
        {
            // The maintenance loop only ever faults because the client was disposed.
        }

        _cts.Dispose();
        _transactionGate.Dispose();
    }

    /// <summary>
    /// True when the challenge advertises RFC 8489's password-algorithms Security Feature, which
    /// means the client must negotiate a PASSWORD-ALGORITHM rather than assume the RFC 5389
    /// MD5-and-HMAC-SHA1 defaults.
    /// </summary>
    private static bool RequiresPasswordAlgorithmNegotiation(StunMessage response)
    {
        var nonce = response.Nonce;
        if (nonce is null || nonce.Length < NonceCookie.Length + 4 || !nonce.StartsWith(NonceCookie, StringComparison.Ordinal))
        {
            return false;
        }

        Span<byte> features = stackalloc byte[3];
        if (!Convert.TryFromBase64Chars(nonce.AsSpan(NonceCookie.Length, 4), features, out var written) || written < 1)
        {
            return false;
        }

        // RFC 8489 section 18.1: bit 0 - the most significant bit of the first byte - is
        // "Password algorithms".
        return (features[0] & 0x80) != 0;
    }

    private long RefreshDelayMilliseconds(TimeSpan granted)
        => Math.Max(1, (long)(granted.TotalMilliseconds * _options.RefreshFraction));

    private ushort NextChannelNumberLocked()
    {
        for (var i = 0; i <= StunChannelNumberAttribute.MaxChannelNumber - StunChannelNumberAttribute.MinChannelNumber; i++)
        {
            var candidate = _nextChannelNumber;
            _nextChannelNumber = candidate >= StunChannelNumberAttribute.MaxChannelNumber
                ? StunChannelNumberAttribute.MinChannelNumber
                : (ushort)(candidate + 1);

            if (!_channelPeers.ContainsKey(candidate))
            {
                return candidate;
            }
        }

        throw new InvalidOperationException("Every channel number in the RFC 8656 range 0x4000-0x4FFF is already bound.");
    }

    private async Task<StunMessage> AuthenticatedRequestAsync(Func<StunMessage> factory, CancellationToken cancellationToken)
    {
        for (var attempt = 0; ; attempt++)
        {
            string? realm;
            string? nonce;
            byte[]? key;
            StunPasswordAlgorithm? algorithm;
            StunPasswordAlgorithmsAttribute? algorithmsEcho;
            lock (_lock)
            {
                realm = _realm;
                nonce = _nonce;
                key = _key;
                algorithm = _passwordAlgorithm;
                algorithmsEcho = _pendingPasswordAlgorithmsEcho;

                // The echo is one-shot: RFC 8489 section 9.2.5 only requires it on the retry that
                // immediately answers the challenge which offered it, not on every request after.
                _pendingPasswordAlgorithmsEcho = null;
            }

            var request = factory();
            if (key is not null && realm is not null && nonce is not null)
            {
                // RFC 8656 section 9.2: an authenticated request repeats the USERNAME, REALM and
                // NONCE from the challenge, and message integrity keys on the negotiated password
                // algorithm's key (RFC 5389 MD5 by default, or RFC 8489 PASSWORD-ALGORITHM).
                request.Add(new StunUsernameAttribute(_username))
                    .Add(new StunRealmAttribute(realm))
                    .Add(new StunNonceAttribute(nonce));

                if (algorithm is { } selected)
                {
                    // RFC 8489 section 9.2.3.2: every request after negotiation names the algorithm
                    // the key was derived with.
                    request.Add(new StunPasswordAlgorithmAttribute(selected));
                }

                if (algorithmsEcho is not null)
                {
                    // RFC 8489 section 9.2.5: echo PASSWORD-ALGORITHMS back unmodified so the server
                    // can detect a bid-down attacker having tampered with the list in transit.
                    request.Add(algorithmsEcho);
                }
            }

            // RFC 8489 section 9.2.5: once a response has carried PASSWORD-ALGORITHMS, every request
            // from then on is authenticated with MESSAGE-INTEGRITY-SHA256 instead of MESSAGE-INTEGRITY
            // - independent of which PASSWORD-ALGORITHM ended up selected for the key itself.
            var useSha256Integrity = algorithm is not null;
            var response = await _stun.RequestAsync(request, _server, key, useSha256Integrity, cancellationToken)
                .ConfigureAwait(false);

            if (response.Class == StunClass.SuccessResponse)
            {
                var validated = key is null
                    || (useSha256Integrity ? response.ValidateMessageIntegritySha256(key) : response.ValidateMessageIntegrity(key));
                if (!validated)
                {
                    throw new StunFormatException(
                        $"The {request.Method} success response from {_server} failed MESSAGE-INTEGRITY validation.");
                }

                return response;
            }

            var error = response.GetAttribute<StunErrorCodeAttribute>();
            var code = error?.Code ?? StunErrorCodeAttribute.ServerError;
            var reason = error?.Reason ?? "unknown";

            // RFC 8656 section 9.2: 401 challenges an unauthenticated request and carries the realm
            // and nonce to use; 438 says the nonce we used has aged out and carries a fresh one.
            // Both are answered by adopting what the response carries and re-sending once.
            var isChallenge = code is StunErrorCodeAttribute.Unauthorized or StunErrorCodeAttribute.StaleNonce;

            var negotiatedAlgorithm = algorithm;
            StunPasswordAlgorithmsAttribute? offeredAlgorithms = null;
            if (isChallenge && RequiresPasswordAlgorithmNegotiation(response))
            {
                offeredAlgorithms = response.GetAttribute<StunPasswordAlgorithmsAttribute>();
                if (offeredAlgorithms is null)
                {
                    // RFC 8489 section 9.2.5: the nonce cookie advertises the feature but the
                    // response carries no PASSWORD-ALGORITHMS - the client MUST NOT retry.
                    throw new StunFormatException(
                        $"The {code} response from {_server} advertised RFC 8489 password algorithms in its NONCE but carried no PASSWORD-ALGORITHMS attribute.");
                }

                negotiatedAlgorithm = SelectPasswordAlgorithm(offeredAlgorithms);
                if (negotiatedAlgorithm is null)
                {
                    // RFC 8489 section 9.2.5: none of the offered algorithms are ones the client
                    // supports - the client MUST NOT retry.
                    throw new StunFormatException(
                        $"The TURN server at {_server} only offered RFC 8489 password algorithms Keryx does not implement: "
                        + string.Join(", ", offeredAlgorithms.Algorithms) + ".");
                }
            }

            // RFC 8489 section 9.2.5: a 401 answering a request that was already authenticated means
            // the credentials are wrong, and the client "MUST NOT perform this retry if it is not
            // changing the USERNAME, USERHASH, REALM, or its associated password". Only a fresh
            // realm justifies another attempt; anything else would be an infinite challenge loop.
            var isStaleNonce = code == StunErrorCodeAttribute.StaleNonce;
            var isFirstChallenge = key is null;
            var realmChanged = response.Realm is { } offeredRealm && !string.Equals(offeredRealm, realm, StringComparison.Ordinal);
            if (isChallenge && !(isStaleNonce || isFirstChallenge || realmChanged))
            {
                throw new StunErrorResponseException(code, reason);
            }

            if (isChallenge && attempt < MaxAuthenticationRetries && response.Nonce is { } freshNonce)
            {
                var freshRealm = response.Realm ?? realm;
                if (freshRealm is null)
                {
                    throw new StunFormatException($"The {code} response from {_server} carried a NONCE but no REALM.");
                }

                lock (_lock)
                {
                    _realm = freshRealm;
                    _nonce = freshNonce;
                    _passwordAlgorithm = negotiatedAlgorithm;
                    _key = StunCredentials.LongTermKey(
                        _username, freshRealm, _credential, negotiatedAlgorithm ?? StunPasswordAlgorithm.Md5);
                    _pendingPasswordAlgorithmsEcho = offeredAlgorithms;
                }

                _logger.Log(
                    KeryxLogLevel.Debug,
                    $"TURN {request.Method} to {_server} answered {code}; retrying with realm '{freshRealm}'"
                    + (negotiatedAlgorithm is { } picked ? $" using RFC 8489 password algorithm {picked}." : "."));
                continue;
            }

            throw new StunErrorResponseException(code, reason);
        }
    }

    /// <summary>
    /// Picks the first algorithm in <paramref name="offered"/> that Keryx implements, preserving the
    /// server's preference order (RFC 8489 section 9.2.5: "the first algorithm supported on the
    /// list"). Null when none of the offered algorithms are supported.
    /// </summary>
    private static StunPasswordAlgorithm? SelectPasswordAlgorithm(StunPasswordAlgorithmsAttribute offered)
    {
        foreach (var code in offered.Algorithms)
        {
            if (code is (ushort)StunPasswordAlgorithm.Md5 or (ushort)StunPasswordAlgorithm.Sha256)
            {
                return (StunPasswordAlgorithm)code;
            }
        }

        return null;
    }

    private async Task MaintenanceLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                await Task.Delay(_options.MaintenanceInterval, cancellationToken).ConfigureAwait(false);
                await MaintainOnceAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // The client was disposed.
        }
        catch (Exception ex)
        {
            _logger.Log(KeryxLogLevel.Error, $"The TURN maintenance loop for {_server} stopped unexpectedly.", ex);
        }
    }

    private async Task MaintainOnceAsync(CancellationToken cancellationToken)
    {
        var now = Environment.TickCount64;

        bool refreshDue;
        List<IPEndPoint> permissionsDue = [];
        List<IPEndPoint> channelsDue = [];
        lock (_lock)
        {
            if (_relayed is null)
            {
                return;
            }

            refreshDue = now >= _nextRefreshAt;

            foreach (var (peer, channel) in _channels)
            {
                if (channel.Bound && now - channel.BoundAt >= (long)_options.ChannelRefreshInterval.TotalMilliseconds)
                {
                    channelsDue.Add(peer);
                }
            }

            var permissionInterval = (long)_options.PermissionRefreshInterval.TotalMilliseconds;
            foreach (var (address, createdAt) in _permissions)
            {
                if (now - createdAt >= permissionInterval)
                {
                    permissionsDue.Add(new IPEndPoint(address, 0));
                }
            }
        }

        if (refreshDue)
        {
            await RunMaintenanceStepAsync("Refresh", RefreshAsync(cancellationToken: cancellationToken)).ConfigureAwait(false);
        }

        foreach (var peer in channelsDue)
        {
            await RunMaintenanceStepAsync("ChannelBind", BindChannelAsync(peer, cancellationToken)).ConfigureAwait(false);
        }

        if (permissionsDue.Count > 0)
        {
            await RunMaintenanceStepAsync("CreatePermission", CreatePermissionAsync(permissionsDue, cancellationToken)).ConfigureAwait(false);
        }
    }

    private async Task RunMaintenanceStepAsync(string what, Task step)
    {
        try
        {
            await step.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is StunTimeoutException or StunErrorResponseException or StunFormatException or SocketException or InvalidOperationException or ObjectDisposedException)
        {
            _logger.Log(KeryxLogLevel.Warning, $"TURN {what} against {_server} failed; the allocation may be lost.", ex);
        }
    }

    private sealed class TurnChannel(ushort number)
    {
        public ushort Number { get; } = number;

        public bool Bound { get; init; }

        public long BoundAt { get; init; }
    }
}
