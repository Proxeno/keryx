using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Keryx.Core;
using Keryx.Stun;

namespace Keryx.Ice;

/// <summary>
/// A full ICE agent for a single-BUNDLE, rtcp-muxed WebRTC session: it gathers candidates, runs
/// RFC 8445 connectivity checks over one UDP socket, and exposes the selected pair as an
/// <see cref="IDatagramTransport"/> that DTLS and RTP ride on.
/// </summary>
/// <remarks>
/// <para><b>Threading.</b> One receive-loop task reads the socket and one check-loop task paces
/// connectivity checks; all mutable state is guarded by a single lock. Events
/// (<see cref="OnStateChanged"/>, <see cref="OnLocalCandidate"/>, <see cref="OnRemoteCandidate"/>,
/// <see cref="OnGatheringComplete"/>, <see cref="OnSelectedPairChanged"/>) and
/// <see cref="IDatagramTransport.OnReceived"/> are raised on those loop threads, never under the
/// lock. Handlers must be quick and must not block, or they will stall the socket.</para>
/// <para><b>Demultiplexing.</b> Every inbound datagram that is not STUN (RFC 7983: DTLS records
/// start with 20-63, RTP/RTCP with 128-191) is handed straight to
/// <see cref="IDatagramTransport.OnReceived"/> on <see cref="Transport"/>, from the very first
/// packet - nothing is buffered until a pair is nominated, because DTLS can arrive immediately
/// after the peer's first successful check.</para>
/// <para><b>Simplifications in this version.</b> Aggressive nomination: a controlling agent sets
/// USE-CANDIDATE on every check, so the first pair to succeed is the selected one; this is
/// permitted by RFC 8445 section 8.1.1.2 and keeps setup to a single round trip. Only IPv4 pairs
/// are formed. Because a single bundled socket sends every check, the check list holds one pair
/// per remote candidate, formed against the highest-priority local candidate; pair priorities
/// still follow RFC 8445 section 6.1.2.3. Candidate pairs are never frozen - with one component
/// and one stream every pair starts in <see cref="IceCandidatePairState.Waiting"/>.</para>
/// </remarks>
public sealed class IceAgent : IDisposable
{
    private const int MaxDatagram = 1472;
    private const int ReceiveBufferSize = 2048;

    private readonly object _lock = new();
    private readonly IceAgentOptions _options;
    private readonly IKeryxLogger _logger;
    private readonly IceTransport _transport;
    private readonly ConcurrentQueue<Action> _events = new();
    private readonly List<IceCandidate> _localCandidates = [];
    private readonly List<IceCandidate> _remoteCandidates = [];
    private readonly List<IceCandidatePair> _pairs = [];
    private readonly Dictionary<StunTransactionId, OutstandingCheck> _checks = [];
    private readonly Queue<IceCandidatePair> _triggered = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly byte[] _localKey;

    private Socket? _socket;
    private Task? _receiveLoop;
    private Task? _checkLoop;
    private StunClient? _gatherClient;
    private IceRole _role;
    private ulong _tieBreaker;
    private IceAgentState _state = IceAgentState.New;
    private string? _remoteUfrag;
    private string? _remotePassword;
    private byte[]? _remoteKey;
    private IceCandidatePair? _selected;
    private long _checksStartedAt;
    private long _lastKeepaliveAt;
    private long _lastValidResponseAt;
    private int _prflxCounter;
    private bool _disposed;

    /// <summary>Creates an agent. Nothing is bound until <see cref="StartGatheringAsync"/> is called.</summary>
    /// <param name="options">Configuration; defaults are used when null.</param>
    public IceAgent(IceAgentOptions? options = null)
    {
        _options = (options ?? new IceAgentOptions()).Validate();
        _logger = _options.Logger ?? NullLogger.Instance;
        _role = _options.Role;
        _tieBreaker = _options.TieBreaker ?? BitConverter.ToUInt64(RandomNumberGenerator.GetBytes(8));
        LocalUfrag = _options.LocalUfrag ?? IceCredentials.NewUfrag();
        LocalPassword = _options.LocalPassword ?? IceCredentials.NewPassword();
        _localKey = StunCredentials.ShortTermKey(LocalPassword);
        _transport = new IceTransport(this);
    }

    /// <summary>Raised for each local candidate as it is gathered, so it can be trickled to the peer.</summary>
    public event EventHandler<IceCandidate>? OnLocalCandidate;

    /// <summary>Raised when a peer-reflexive remote candidate is discovered from an inbound check.</summary>
    public event EventHandler<IceCandidate>? OnRemoteCandidate;

    /// <summary>Raised once, after the last local candidate has been reported.</summary>
    public event EventHandler? OnGatheringComplete;

    /// <summary>Raised on every <see cref="State"/> transition.</summary>
    public event EventHandler<IceAgentState>? OnStateChanged;

    /// <summary>Raised when the pair carrying application traffic changes.</summary>
    public event EventHandler<IceCandidatePair>? OnSelectedPairChanged;

    /// <summary>The local username fragment to signal in SDP as <c>a=ice-ufrag</c>.</summary>
    public string LocalUfrag { get; }

    /// <summary>The local password to signal in SDP as <c>a=ice-pwd</c>.</summary>
    public string LocalPassword { get; }

    /// <summary>The agent's current role, which a 487 role conflict may change.</summary>
    public IceRole Role
    {
        get
        {
            lock (_lock)
            {
                return _role;
            }
        }
    }

    /// <summary>The tie-breaker advertised in ICE-CONTROLLING/ICE-CONTROLLED.</summary>
    public ulong TieBreaker
    {
        get
        {
            lock (_lock)
            {
                return _tieBreaker;
            }
        }
    }

    /// <summary>The agent's lifecycle state.</summary>
    public IceAgentState State
    {
        get
        {
            lock (_lock)
            {
                return _state;
            }
        }
    }

    /// <summary>A snapshot of the gathered local candidates.</summary>
    public IReadOnlyList<IceCandidate> LocalCandidates
    {
        get
        {
            lock (_lock)
            {
                return [.. _localCandidates];
            }
        }
    }

    /// <summary>A snapshot of the known remote candidates, including discovered peer-reflexive ones.</summary>
    public IReadOnlyList<IceCandidate> RemoteCandidates
    {
        get
        {
            lock (_lock)
            {
                return [.. _remoteCandidates];
            }
        }
    }

    /// <summary>A snapshot of the check list, highest priority first.</summary>
    public IReadOnlyList<IceCandidatePair> CheckList
    {
        get
        {
            lock (_lock)
            {
                return [.. _pairs];
            }
        }
    }

    /// <summary>The pair currently carrying application traffic, or null before any check succeeds.</summary>
    public IceCandidatePair? SelectedPair
    {
        get
        {
            lock (_lock)
            {
                return _selected;
            }
        }
    }

    /// <summary>The local transport address the socket is bound to, or null before gathering.</summary>
    public IPEndPoint? LocalEndPoint
    {
        get
        {
            lock (_lock)
            {
                return _socket?.LocalEndPoint as IPEndPoint;
            }
        }
    }

    /// <summary>
    /// The datagram seam for the layers above. Subscribe to
    /// <see cref="IDatagramTransport.OnReceived"/> before gathering starts: non-STUN packets are
    /// surfaced from the first one received, whether or not a pair has been nominated yet.
    /// <see cref="IDatagramTransport.Send"/> throws until a pair has succeeded.
    /// </summary>
    public IDatagramTransport Transport => _transport;

    /// <summary>
    /// Binds the socket, gathers host candidates and, when STUN servers are configured, a
    /// server-reflexive candidate, raising <see cref="OnLocalCandidate"/> for each and
    /// <see cref="OnGatheringComplete"/> at the end.
    /// </summary>
    /// <param name="cancellationToken">Cancels the STUN queries; host candidates are already reported.</param>
    public async Task StartGatheringAsync(CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_state != IceAgentState.New)
            {
                throw new InvalidOperationException($"Gathering has already started; the agent is {_state}.");
            }

            SetStateLocked(IceAgentState.Gathering);
        }

        DrainEvents();

        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            Bind(socket);
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        var boundPort = ((IPEndPoint)socket.LocalEndPoint!).Port;
        lock (_lock)
        {
            _socket = socket;
        }

        _receiveLoop = Task.Run(() => ReceiveLoopAsync(socket, _cts.Token), CancellationToken.None);
        _checkLoop = Task.Run(() => CheckLoopAsync(_cts.Token), CancellationToken.None);

        var addresses = LocalAddresses();
        for (var i = 0; i < addresses.Count; i++)
        {
            var localPreference = Math.Max(0, IcePriority.MaxLocalPreference - i);
            var candidate = new IceCandidate(
                Foundation(IceCandidateType.Host, addresses[i], null),
                component: 1,
                IceCandidate.UdpTransport,
                IcePriority.Compute(IceCandidateType.Host, localPreference),
                addresses[i],
                boundPort,
                IceCandidateType.Host)
            {
                LocalPreference = localPreference,
            };

            AddLocalCandidate(candidate);
        }

        await GatherServerReflexiveAsync(boundPort, cancellationToken).ConfigureAwait(false);

        _events.Enqueue(() => OnGatheringComplete?.Invoke(this, EventArgs.Empty));
        DrainEvents();
        _logger.Log(KeryxLogLevel.Info, $"ICE gathering complete on {socket.LocalEndPoint} with {LocalCandidates.Count} candidate(s).");
    }

    /// <summary>Supplies the peer's <c>a=ice-ufrag</c> and <c>a=ice-pwd</c>. Checks cannot start until this is called.</summary>
    /// <param name="ufrag">The remote username fragment.</param>
    /// <param name="password">The remote password.</param>
    public void SetRemoteCredentials(string ufrag, string password)
    {
        ArgumentException.ThrowIfNullOrEmpty(ufrag);
        ArgumentException.ThrowIfNullOrEmpty(password);

        lock (_lock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _remoteUfrag = ufrag;
            _remotePassword = password;
            _remoteKey = StunCredentials.ShortTermKey(password);
        }
    }

    /// <summary>
    /// Adds a candidate signalled by the peer. Safe to call at any time, including before
    /// gathering and after the agent is connected, which is what trickle ICE requires.
    /// </summary>
    /// <param name="candidate">The remote candidate.</param>
    public void AddRemoteCandidate(IceCandidate candidate)
    {
        ArgumentNullException.ThrowIfNull(candidate);

        lock (_lock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_state is IceAgentState.Closed)
            {
                return;
            }

            if (!AddRemoteCandidateLocked(candidate))
            {
                return;
            }
        }

        DrainEvents();
    }

    /// <summary>Parses and adds a candidate in SDP attribute syntax.</summary>
    /// <param name="candidateAttribute">An <c>a=candidate:...</c> line or bare attribute value.</param>
    /// <returns>True when the attribute parsed and the candidate was accepted.</returns>
    public bool AddRemoteCandidate(string candidateAttribute)
    {
        if (!IceCandidate.TryParse(candidateAttribute, out var candidate))
        {
            _logger.Log(KeryxLogLevel.Warning, $"Ignoring unparsable remote candidate '{candidateAttribute}'.");
            return false;
        }

        AddRemoteCandidate(candidate);
        return true;
    }

    /// <summary>
    /// Completes when the agent reaches <see cref="IceAgentState.Connected"/>, or returns false if
    /// it fails, closes, or <paramref name="timeout"/> elapses first.
    /// </summary>
    /// <param name="timeout">How long to wait.</param>
    /// <param name="cancellationToken">Cancels the wait.</param>
    public async Task<bool> WaitForConnectedAsync(TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        void Handler(object? sender, IceAgentState state)
        {
            switch (state)
            {
                case IceAgentState.Connected:
                    completion.TrySetResult(true);
                    break;
                case IceAgentState.Failed:
                case IceAgentState.Closed:
                    completion.TrySetResult(false);
                    break;
                default:
                    break;
            }
        }

        OnStateChanged += Handler;
        try
        {
            switch (State)
            {
                case IceAgentState.Connected:
                    return true;
                case IceAgentState.Failed:
                case IceAgentState.Closed:
                    return false;
                default:
                    break;
            }

            return await completion.Task.WaitAsync(timeout, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            return false;
        }
        finally
        {
            OnStateChanged -= Handler;
        }
    }

    /// <summary>Stops the loops, closes the socket and moves to <see cref="IceAgentState.Closed"/>.</summary>
    public void Close()
    {
        Socket? socket;
        lock (_lock)
        {
            if (_state == IceAgentState.Closed)
            {
                return;
            }

            SetStateLocked(IceAgentState.Closed);
            socket = _socket;
            _socket = null;
        }

        _cts.Cancel();
        socket?.Close();
        DrainEvents();
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

        Close();

        try
        {
            Task.WhenAll(_receiveLoop ?? Task.CompletedTask, _checkLoop ?? Task.CompletedTask)
                .Wait(TimeSpan.FromSeconds(2));
        }
        catch (Exception)
        {
            // The loops only ever fault because the socket was closed above.
        }

        _cts.Dispose();
    }

    internal void SendOnSelectedPair(ReadOnlySpan<byte> datagram)
    {
        if (datagram.Length > MaxDatagram)
        {
            throw new ArgumentException($"An ICE datagram may be at most {MaxDatagram} bytes.", nameof(datagram));
        }

        Socket? socket;
        IPEndPoint? destination;
        lock (_lock)
        {
            socket = _socket;
            destination = (_selected ?? BestUsablePairLocked())?.RemoteEndPoint;
        }

        if (socket is null || destination is null)
        {
            throw new InvalidOperationException("No candidate pair has succeeded yet; the ICE transport is not usable.");
        }

        socket.SendTo(datagram, SocketFlags.None, destination);
    }

    // ---------------------------------------------------------------- gathering

    private void Bind(Socket socket)
    {
        var address = _options.BindAddress ?? IPAddress.Any;
        if (_options.MinPort <= 0)
        {
            socket.Bind(new IPEndPoint(address, 0));
            return;
        }

        var span = _options.MaxPort - _options.MinPort + 1;
        var start = RandomNumberGenerator.GetInt32(span);
        for (var i = 0; i < span; i++)
        {
            var port = _options.MinPort + ((start + i) % span);
            try
            {
                socket.Bind(new IPEndPoint(address, port));
                return;
            }
            catch (SocketException)
            {
                // Port in use; try the next one in the configured range.
            }
        }

        throw new InvalidOperationException(
            $"No free UDP port in the range {_options.MinPort}-{_options.MaxPort} on {address}.");
    }

    private List<IPAddress> LocalAddresses()
    {
        if (_options.BindAddress is { } bindAddress && !bindAddress.Equals(IPAddress.Any))
        {
            return [bindAddress];
        }

        var addresses = new List<IPAddress>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up
                || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
            {
                continue;
            }

            foreach (var unicast in nic.GetIPProperties().UnicastAddresses)
            {
                var address = unicast.Address;
                if (address.AddressFamily == AddressFamily.InterNetwork
                    && !IPAddress.IsLoopback(address)
                    && !addresses.Contains(address))
                {
                    addresses.Add(address);
                }
            }
        }

        return addresses;
    }

    private async Task GatherServerReflexiveAsync(int boundPort, CancellationToken cancellationToken)
    {
        if (_options.StunServers.Count == 0)
        {
            return;
        }

        IceCandidate? baseCandidate;
        lock (_lock)
        {
            baseCandidate = _localCandidates.Count > 0 ? _localCandidates[0] : null;
        }

        if (baseCandidate is null)
        {
            return;
        }

        var client = new StunClient(SendRaw, _options.StunClientOptions, _logger);
        Volatile.Write(ref _gatherClient, client);
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _cts.Token);
            foreach (var server in _options.StunServers)
            {
                try
                {
                    var mapped = await client.BindingRequestAsync(server, linked.Token).ConfigureAwait(false);
                    if (mapped.AddressFamily != AddressFamily.InterNetwork)
                    {
                        continue;
                    }

                    var candidate = new IceCandidate(
                        Foundation(IceCandidateType.ServerReflexive, baseCandidate.Address, server),
                        component: 1,
                        IceCandidate.UdpTransport,
                        IcePriority.Compute(IceCandidateType.ServerReflexive, baseCandidate.LocalPreference),
                        mapped.Address,
                        mapped.Port,
                        IceCandidateType.ServerReflexive,
                        baseCandidate.Address,
                        boundPort)
                    {
                        LocalPreference = baseCandidate.LocalPreference,
                    };

                    AddLocalCandidate(candidate);
                }
                catch (Exception ex) when (ex is StunTimeoutException or StunErrorResponseException or StunFormatException or SocketException or OperationCanceledException)
                {
                    _logger.Log(KeryxLogLevel.Warning, $"STUN server {server} produced no server-reflexive candidate.", ex);
                }
            }
        }
        finally
        {
            Volatile.Write(ref _gatherClient, null);
        }
    }

    private void AddLocalCandidate(IceCandidate candidate)
    {
        lock (_lock)
        {
            if (_localCandidates.Contains(candidate))
            {
                return;
            }

            _localCandidates.Add(candidate);
            _localCandidates.Sort(static (a, b) => b.Priority.CompareTo(a.Priority));
            RebuildPairsLocked();
        }

        _logger.Log(KeryxLogLevel.Debug, $"ICE local candidate {candidate}.");
        _events.Enqueue(() => OnLocalCandidate?.Invoke(this, candidate));
        DrainEvents();
    }

    private static string Foundation(IceCandidateType type, IPAddress baseAddress, IPEndPoint? server)
    {
        // RFC 8445 section 5.1.1.3: candidates sharing type, base, STUN/TURN server and protocol
        // must share a foundation. A stable 32-bit hash of those inputs satisfies that, and looks
        // like the numeric foundations Chrome emits.
        var key = $"{type}|{baseAddress}|{server?.ToString() ?? "-"}|udp";
        var hash = 2166136261u;
        foreach (var b in Encoding.UTF8.GetBytes(key))
        {
            hash = (hash ^ b) * 16777619u;
        }

        return hash.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    // ---------------------------------------------------------------- receive

    private async Task ReceiveLoopAsync(Socket socket, CancellationToken cancellationToken)
    {
        var buffer = new byte[ReceiveBufferSize];
        EndPoint any = new IPEndPoint(IPAddress.Any, 0);

        while (!cancellationToken.IsCancellationRequested)
        {
            SocketReceiveFromResult result;
            try
            {
                result = await socket.ReceiveFromAsync(buffer, SocketFlags.None, any, cancellationToken).ConfigureAwait(false);
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
                _logger.Log(KeryxLogLevel.Trace, "ICE socket receive error; continuing.", ex);
                continue;
            }

            if (result.ReceivedBytes <= 0 || result.RemoteEndPoint is not IPEndPoint from)
            {
                continue;
            }

            var datagram = buffer.AsSpan(0, result.ReceivedBytes);
            if (StunMessage.LooksLikeStun(datagram))
            {
                HandleStun(datagram, from);
            }
            else
            {
                // RFC 7983 demultiplexing: everything that is not STUN belongs to the layer above
                // and must be surfaced immediately, even before nomination completes.
                _transport.Raise(datagram);
            }

            DrainEvents();
        }
    }

    private void HandleStun(ReadOnlySpan<byte> datagram, IPEndPoint from)
    {
        if (!StunMessage.TryDecode(datagram, out var message) || message.Method != StunMethod.Binding)
        {
            _logger.Log(KeryxLogLevel.Warning, $"Dropping malformed STUN datagram from {from}.");
            return;
        }

        switch (message.Class)
        {
            case StunClass.Request:
                HandleBindingRequest(message, from);
                break;
            case StunClass.SuccessResponse:
            case StunClass.ErrorResponse:
                if (Volatile.Read(ref _gatherClient)?.TryHandleDatagram(datagram) == true)
                {
                    return;
                }

                HandleCheckResponse(message, from);
                break;
            case StunClass.Indication:
                lock (_lock)
                {
                    _lastValidResponseAt = Environment.TickCount64;
                }

                break;
            default:
                break;
        }
    }

    private void HandleBindingRequest(StunMessage request, IPEndPoint from)
    {
        if (!request.ValidateFingerprint())
        {
            _logger.Log(KeryxLogLevel.Warning, $"Dropping ICE check from {from} with a missing or bad FINGERPRINT.");
            return;
        }

        var username = request.Username;
        if (username is null || !username.StartsWith(LocalUfrag + ":", StringComparison.Ordinal))
        {
            _logger.Log(KeryxLogLevel.Warning, $"Dropping ICE check from {from} with USERNAME '{username}'.");
            return;
        }

        if (!request.ValidateMessageIntegrity(_localKey))
        {
            _logger.Log(KeryxLogLevel.Warning, $"Dropping ICE check from {from} with a bad MESSAGE-INTEGRITY.");
            SendStun(StunMessage.CreateErrorResponse(request, StunErrorCodeAttribute.Unauthorized, "Unauthorized"), from, key: null);
            return;
        }

        byte[]? responseKey;
        StunMessage? response = null;
        lock (_lock)
        {
            if (_state is IceAgentState.Closed)
            {
                return;
            }

            responseKey = _localKey;

            // RFC 8445 section 7.3.1.1: resolve a role conflict before doing anything else.
            var controlling = request.GetAttribute<StunIceControllingAttribute>();
            var controlled = request.GetAttribute<StunIceControlledAttribute>();
            if (_role == IceRole.Controlling && controlling is not null)
            {
                if (_tieBreaker >= controlling.TieBreaker)
                {
                    response = StunMessage.CreateErrorResponse(request, StunErrorCodeAttribute.RoleConflict, "Role Conflict");
                }
                else
                {
                    SwitchRoleLocked(IceRole.Controlled);
                }
            }
            else if (_role == IceRole.Controlled && controlled is not null)
            {
                if (_tieBreaker >= controlled.TieBreaker)
                {
                    SwitchRoleLocked(IceRole.Controlling);
                }
                else
                {
                    response = StunMessage.CreateErrorResponse(request, StunErrorCodeAttribute.RoleConflict, "Role Conflict");
                }
            }

            if (response is null)
            {
                var remote = FindOrCreatePeerReflexiveLocked(from, request.GetAttribute<StunPriorityAttribute>()?.Priority);
                var pair = remote is null ? null : FindPairLocked(remote);
                if (pair is not null)
                {
                    var useCandidate = request.HasAttribute(StunAttributeType.UseCandidate);
                    if (useCandidate && _role == IceRole.Controlled)
                    {
                        if (pair.State == IceCandidatePairState.Succeeded)
                        {
                            NominateLocked(pair);
                        }
                        else
                        {
                            pair.NominateOnSuccess = true;
                        }
                    }

                    // RFC 8445 section 7.3.1.4: an inbound check schedules a triggered check back.
                    if (pair.State is not (IceCandidatePairState.Succeeded or IceCandidatePairState.InProgress)
                        && !_triggered.Contains(pair))
                    {
                        pair.State = IceCandidatePairState.Waiting;
                        _triggered.Enqueue(pair);
                    }
                }

                response = StunMessage.CreateSuccessResponse(request)
                    .Add(new StunXorMappedAddressAttribute(from));
            }
        }

        SendStun(response, from, responseKey);
        DrainEvents();
    }

    private void HandleCheckResponse(StunMessage response, IPEndPoint from)
    {
        OutstandingCheck? check;
        lock (_lock)
        {
            if (!_checks.Remove(response.TransactionId, out check))
            {
                return;
            }
        }

        if (!from.Equals(check.Pair.RemoteEndPoint))
        {
            // RFC 8445 section 7.2.5.2.1: a response from a different address is a failure.
            _logger.Log(KeryxLogLevel.Warning, $"ICE check response for {check.Pair} arrived from {from}; ignoring.");
            return;
        }

        var remoteKey = Volatile.Read(ref _remoteKey);
        if (remoteKey is null || !response.ValidateFingerprint() || !response.ValidateMessageIntegrity(remoteKey))
        {
            _logger.Log(KeryxLogLevel.Warning, $"Dropping ICE check response from {from} that failed authentication.");
            return;
        }

        lock (_lock)
        {
            if (response.Class == StunClass.ErrorResponse)
            {
                if (response.ErrorCode == StunErrorCodeAttribute.RoleConflict)
                {
                    // RFC 8445 section 7.2.5.1. Only switch when the conflict has not already been
                    // resolved by an inbound request since this check was sent - otherwise two
                    // agents that both started controlling would oscillate forever.
                    if (check.RoleWhenSent == _role)
                    {
                        SwitchRoleLocked(_role == IceRole.Controlling ? IceRole.Controlled : IceRole.Controlling);
                    }

                    check.Pair.State = IceCandidatePairState.Waiting;
                    if (!_triggered.Contains(check.Pair))
                    {
                        _triggered.Enqueue(check.Pair);
                    }
                }
                else
                {
                    check.Pair.State = IceCandidatePairState.Failed;
                }

                return;
            }

            _lastValidResponseAt = Environment.TickCount64;
            check.Pair.State = IceCandidatePairState.Succeeded;

            if (check.UseCandidate || check.Pair.NominateOnSuccess)
            {
                NominateLocked(check.Pair);
            }
            else
            {
                UpdateSelectedLocked();
            }

            if (_state is IceAgentState.Gathering or IceAgentState.Checking or IceAgentState.Disconnected or IceAgentState.New)
            {
                SetStateLocked(IceAgentState.Connected);
            }
        }

        DrainEvents();
    }

    // ---------------------------------------------------------------- checks

    private async Task CheckLoopAsync(CancellationToken cancellationToken)
    {
        var pending = new List<(byte[] Datagram, IPEndPoint Destination)>();
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                await Task.Delay(_options.CheckInterval, cancellationToken).ConfigureAwait(false);

                pending.Clear();
                lock (_lock)
                {
                    TickLocked(pending);
                }

                foreach (var (datagram, destination) in pending)
                {
                    SendRaw(datagram, destination);
                }

                DrainEvents();
            }
        }
        catch (OperationCanceledException)
        {
            // Agent closed.
        }
        catch (Exception ex)
        {
            _logger.Log(KeryxLogLevel.Error, "The ICE check loop stopped unexpectedly.", ex);
        }
    }

    private void TickLocked(List<(byte[] Datagram, IPEndPoint Destination)> pending)
    {
        if (_state is IceAgentState.Closed or IceAgentState.Failed || _socket is null)
        {
            return;
        }

        if (_remoteUfrag is null || _remotePassword is null || _pairs.Count == 0)
        {
            return;
        }

        var now = Environment.TickCount64;
        if (_state is IceAgentState.New or IceAgentState.Gathering)
        {
            _checksStartedAt = now;
            SetStateLocked(IceAgentState.Checking);
        }

        RetransmitLocked(now, pending);

        var next = DequeueTriggeredLocked() ?? NextWaitingLocked();
        if (next is not null)
        {
            pending.Add(BuildCheckLocked(next, now, isKeepalive: false));
        }

        if (_selected is { } selected
            && _state is IceAgentState.Connected or IceAgentState.Disconnected
            && now - _lastKeepaliveAt >= (long)_options.KeepaliveInterval.TotalMilliseconds)
        {
            _lastKeepaliveAt = now;
            pending.Add(BuildCheckLocked(selected, now, isKeepalive: true));
        }

        EvaluateTimeoutsLocked(now);
    }

    private void RetransmitLocked(long now, List<(byte[] Datagram, IPEndPoint Destination)> pending)
    {
        List<OutstandingCheck>? expired = null;
        foreach (var check in _checks.Values)
        {
            if (now < check.NextTransmitAt)
            {
                continue;
            }

            if (check.Transmissions >= _options.MaxCheckTransmissions)
            {
                (expired ??= []).Add(check);
                continue;
            }

            check.Transmissions++;
            check.Rto *= 2;
            check.NextTransmitAt = now + check.Rto;
            pending.Add((check.Datagram, check.Pair.RemoteEndPoint));
        }

        if (expired is null)
        {
            return;
        }

        foreach (var check in expired)
        {
            _checks.Remove(check.TransactionId);
            if (!check.IsKeepalive && check.Pair.State == IceCandidatePairState.InProgress)
            {
                check.Pair.State = IceCandidatePairState.Failed;
                _logger.Log(KeryxLogLevel.Debug, $"ICE pair failed after {check.Transmissions} check(s): {check.Pair}.");
            }
        }
    }

    private IceCandidatePair? DequeueTriggeredLocked()
    {
        while (_triggered.Count > 0)
        {
            var pair = _triggered.Dequeue();
            if (pair.State is not (IceCandidatePairState.InProgress or IceCandidatePairState.Succeeded))
            {
                return pair;
            }
        }

        return null;
    }

    private IceCandidatePair? NextWaitingLocked()
    {
        foreach (var pair in _pairs)
        {
            if (pair.State == IceCandidatePairState.Waiting)
            {
                return pair;
            }
        }

        return null;
    }

    private (byte[] Datagram, IPEndPoint Destination) BuildCheckLocked(IceCandidatePair pair, long now, bool isKeepalive)
    {
        // RFC 8445 section 7.1.1: PRIORITY carries the priority the peer-reflexive candidate the
        // peer may discover from this check would have.
        var prflxPriority = IcePriority.Compute(IceCandidateType.PeerReflexive, pair.Local.LocalPreference, pair.Local.Component);
        var useCandidate = _role == IceRole.Controlling;

        var request = new StunMessage(StunClass.Request, StunMethod.Binding)
            .Add(new StunUsernameAttribute($"{_remoteUfrag}:{LocalUfrag}"))
            .Add(new StunPriorityAttribute(prflxPriority))
            .Add(_role == IceRole.Controlling
                ? new StunIceControllingAttribute(_tieBreaker)
                : new StunIceControlledAttribute(_tieBreaker));

        if (useCandidate)
        {
            // Aggressive nomination (RFC 8445 section 8.1.1.2): every check from the controlling
            // agent carries USE-CANDIDATE, so the first success is also the nomination.
            request.Add(StunUseCandidateAttribute.Instance);
        }

        var datagram = request.Encode(_remoteKey, appendFingerprint: true);
        var rto = (long)_options.CheckRetransmissionTimeout.TotalMilliseconds;
        _checks[request.TransactionId] = new OutstandingCheck(
            request.TransactionId, pair, datagram, useCandidate, isKeepalive, _role)
        {
            Transmissions = 1,
            Rto = rto,
            NextTransmitAt = now + rto,
        };

        if (!isKeepalive)
        {
            pair.State = IceCandidatePairState.InProgress;
        }

        return (datagram, pair.RemoteEndPoint);
    }

    private void EvaluateTimeoutsLocked(long now)
    {
        switch (_state)
        {
            case IceAgentState.Checking when now - _checksStartedAt > (long)_options.ConnectivityTimeout.TotalMilliseconds:
                _logger.Log(KeryxLogLevel.Error, "ICE connectivity checks timed out with no usable pair.");
                SetStateLocked(IceAgentState.Failed);
                break;

            case IceAgentState.Connected when now - _lastValidResponseAt > (long)_options.DisconnectedTimeout.TotalMilliseconds:
                SetStateLocked(IceAgentState.Disconnected);
                break;

            case IceAgentState.Disconnected when now - _lastValidResponseAt > (long)_options.ConsentTimeout.TotalMilliseconds:
                _logger.Log(KeryxLogLevel.Error, "ICE consent expired on the selected pair.");
                SetStateLocked(IceAgentState.Failed);
                break;

            default:
                break;
        }
    }

    // ---------------------------------------------------------------- state helpers

    private bool AddRemoteCandidateLocked(IceCandidate candidate)
    {
        if (_remoteCandidates.Contains(candidate))
        {
            return false;
        }

        _remoteCandidates.Add(candidate);
        RebuildPairsLocked();
        _logger.Log(KeryxLogLevel.Debug, $"ICE remote candidate {candidate}.");
        return true;
    }

    private IceCandidate? FindOrCreatePeerReflexiveLocked(IPEndPoint from, uint? priority)
    {
        foreach (var candidate in _remoteCandidates)
        {
            if (candidate.EndPoint.Equals(from))
            {
                return candidate;
            }
        }

        if (from.AddressFamily != AddressFamily.InterNetwork)
        {
            return null;
        }

        // RFC 8445 section 7.3.1.3: a valid check from an unknown address reveals a peer-reflexive
        // candidate. Its priority comes from the PRIORITY attribute the peer sent.
        var discovered = new IceCandidate(
            $"prflx{++_prflxCounter}",
            component: 1,
            IceCandidate.UdpTransport,
            priority ?? IcePriority.Compute(IceCandidateType.PeerReflexive),
            from.Address,
            from.Port,
            IceCandidateType.PeerReflexive);

        _remoteCandidates.Add(discovered);
        RebuildPairsLocked();
        _logger.Log(KeryxLogLevel.Info, $"ICE discovered peer-reflexive candidate {discovered}.");
        _events.Enqueue(() => OnRemoteCandidate?.Invoke(this, discovered));
        return discovered;
    }

    private void RebuildPairsLocked()
    {
        if (_localCandidates.Count == 0)
        {
            return;
        }

        foreach (var remote in _remoteCandidates)
        {
            if (FindPairLocked(remote) is not null)
            {
                continue;
            }

            IceCandidate? local = null;
            foreach (var candidate in _localCandidates)
            {
                if (candidate.Address.AddressFamily == remote.Address.AddressFamily)
                {
                    local = candidate;
                    break;
                }
            }

            if (local is null)
            {
                continue;
            }

            _pairs.Add(new IceCandidatePair(local, remote, _role));
        }

        _pairs.Sort(static (a, b) => b.Priority.CompareTo(a.Priority));
    }

    private IceCandidatePair? FindPairLocked(IceCandidate remote)
    {
        foreach (var pair in _pairs)
        {
            if (pair.Remote.Equals(remote))
            {
                return pair;
            }
        }

        return null;
    }

    private void SwitchRoleLocked(IceRole role)
    {
        if (_role == role)
        {
            return;
        }

        _role = role;
        _logger.Log(KeryxLogLevel.Info, $"ICE role conflict resolved; this agent is now {role}.");
        foreach (var pair in _pairs)
        {
            pair.RecomputePriority(role);
        }

        _pairs.Sort(static (a, b) => b.Priority.CompareTo(a.Priority));
    }

    private void NominateLocked(IceCandidatePair pair)
    {
        pair.Nominated = true;
        pair.NominateOnSuccess = false;
        UpdateSelectedLocked();
    }

    private void UpdateSelectedLocked()
    {
        var best = BestUsablePairLocked();
        if (best is null || ReferenceEquals(best, _selected))
        {
            return;
        }

        _selected = best;
        _logger.Log(KeryxLogLevel.Info, $"ICE selected pair {best}.");
        _events.Enqueue(() => OnSelectedPairChanged?.Invoke(this, best));
    }

    private IceCandidatePair? BestUsablePairLocked()
    {
        IceCandidatePair? best = null;
        foreach (var pair in _pairs)
        {
            if (pair.State != IceCandidatePairState.Succeeded)
            {
                continue;
            }

            if (best is null
                || (pair.Nominated && !best.Nominated)
                || (pair.Nominated == best.Nominated && pair.Priority > best.Priority))
            {
                best = pair;
            }
        }

        return best;
    }

    private void SetStateLocked(IceAgentState state)
    {
        if (_state == state || _state == IceAgentState.Closed)
        {
            return;
        }

        _state = state;
        _logger.Log(KeryxLogLevel.Info, $"ICE agent state -> {state}.");
        _events.Enqueue(() => OnStateChanged?.Invoke(this, state));
    }

    private void DrainEvents()
    {
        while (_events.TryDequeue(out var action))
        {
            try
            {
                action();
            }
            catch (Exception ex)
            {
                _logger.Log(KeryxLogLevel.Error, "An ICE event handler threw.", ex);
            }
        }
    }

    private void SendStun(StunMessage message, IPEndPoint destination, byte[]? key)
        => SendRaw(message.Encode(key, appendFingerprint: true), destination);

    private void SendRaw(ReadOnlySpan<byte> datagram, IPEndPoint destination)
    {
        Socket? socket;
        lock (_lock)
        {
            socket = _socket;
        }

        if (socket is null)
        {
            return;
        }

        try
        {
            socket.SendTo(datagram, SocketFlags.None, destination);
        }
        catch (SocketException ex)
        {
            _logger.Log(KeryxLogLevel.Warning, $"Failed to send an ICE datagram to {destination}.", ex);
        }
        catch (ObjectDisposedException)
        {
            // The agent was closed while a send was in flight.
        }
    }

    private sealed class OutstandingCheck(
        StunTransactionId transactionId,
        IceCandidatePair pair,
        byte[] datagram,
        bool useCandidate,
        bool isKeepalive,
        IceRole roleWhenSent)
    {
        public StunTransactionId TransactionId { get; } = transactionId;

        public IceCandidatePair Pair { get; } = pair;

        public byte[] Datagram { get; } = datagram;

        public bool UseCandidate { get; } = useCandidate;

        public bool IsKeepalive { get; } = isKeepalive;

        public IceRole RoleWhenSent { get; } = roleWhenSent;

        public int Transmissions { get; set; }

        public long Rto { get; set; }

        public long NextTransmitAt { get; set; }
    }

    private sealed class IceTransport(IceAgent agent) : IDatagramTransport
    {
        public int MaxDatagramSize => MaxDatagram;

        public event DatagramReceivedHandler? OnReceived;

        public void Send(ReadOnlySpan<byte> datagram) => agent.SendOnSelectedPair(datagram);

        internal void Raise(ReadOnlySpan<byte> datagram) => OnReceived?.Invoke(datagram);
    }
}
