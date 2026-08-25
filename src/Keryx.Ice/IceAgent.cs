using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using Keryx.Core;
using Keryx.Stun;
using Keryx.Turn;

namespace Keryx.Ice;

/// <summary>
/// A full ICE agent for a single-BUNDLE, rtcp-muxed WebRTC session: it gathers host,
/// server-reflexive and TURN-relayed candidates, runs RFC 8445 connectivity checks over one UDP
/// socket, and exposes the selected pair as an <see cref="IDatagramTransport"/> that DTLS and RTP
/// ride on.
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
/// after the peer's first successful check. Once a pair has been selected,
/// <see cref="IceAgentOptions.StrictInboundSourceValidation"/> (on by default) additionally requires
/// such a datagram's source to match that pair's remote endpoint before it is surfaced - an
/// off-path attacker who can put UDP on the socket is not on that pair's path and is dropped here,
/// before DTLS or SRTP ever see the datagram. This is defense-in-depth, not authentication: DTLS and
/// SRTP validate their own traffic regardless.</para>
/// <para><b>Relayed candidates.</b> Each configured TURN server gets an allocation made over this
/// same socket, so the relayed candidate's base is the socket and its <c>raddr</c>/<c>rport</c> are
/// the reflexive address the TURN server observed (RFC 8445 section 5.1.1.2). Checks and media on a
/// pair whose local candidate is relayed travel through the allocation as ChannelData, and inbound
/// relayed datagrams are unwrapped and fed back through exactly the same demultiplexing path as
/// direct ones - so a relayed ICE check is handled like any other check, and relayed media reaches
/// <see cref="IDatagramTransport.OnReceived"/> without DTLS or SRTP knowing a relay is involved.</para>
/// <para><b>Nomination.</b> The controlling agent defaults to regular nomination (RFC 8445
/// section 8.1.1.1): it picks the best valid pair, sends USE-CANDIDATE on that one pair, and then
/// freezes the selection, so a later higher-priority success does not silently re-point live media
/// (the flapping that pure aggressive nomination causes). The selection re-opens only if the
/// nominated pair goes dead, when the agent fails over to the next best valid pair and nominates
/// again. Aggressive nomination (USE-CANDIDATE on every check, first success wins, each higher
/// success re-selects; RFC 8445 section 8.1.1.2) stays available via
/// <see cref="IceAgentOptions.NominationMode"/>.</para>
/// <para><b>Simplifications in this version.</b> Host and
/// server-reflexive candidates of both address families are gathered over one dual-stack socket and
/// only ever paired with a remote candidate of the same family. Because a single bundled socket
/// sends every check, the check list holds one pair
/// per remote candidate formed against the highest-priority non-relayed local candidate, plus one
/// per remote candidate for each TURN allocation; pair priorities still follow RFC 8445
/// section 6.1.2.3, so relayed pairs (type preference 0) are only reached when the direct ones
/// fail.</para>
/// <para><b>Freezing.</b> Pairs start <see cref="IceCandidatePairState.Frozen"/> except one
/// representative per foundation, which starts <see cref="IceCandidatePairState.Waiting"/> so
/// checking can begin (RFC 8445 section 6.1.2.6); with every candidate this agent produces on
/// component 1, the spec's "lowest component ID" tie-break never applies, so the representative is
/// simply the highest-priority pair newly sharing a not-yet-seen foundation. A success on any pair
/// unfreezes every other pair - present or later trickled in - that shares its foundation (sections
/// 7.2.5.3.3 and 6.1.4.2). The scheduler still only ever starts a
/// <see cref="IceCandidatePairState.Waiting"/> pair, so freezing changes the order checks run in,
/// never whether a pair eventually gets checked.</para>
/// </remarks>
public sealed class IceAgent : IDisposable
{
    private const int MaxDatagram = 1472;
    private const int ReceiveBufferSize = 2048;

    // The mDNS negative cache is a short-lived flood suppressant, not a store: this ceiling bounds it
    // regardless of the configured TTL, so distinct failing names arriving faster than they expire
    // still cannot grow it without bound.
    private const int MaxMdnsNegativeCacheEntries = 256;

    private readonly object _lock = new();
    private readonly IceAgentOptions _options;
    private readonly IKeryxLogger _logger;
    private readonly IceTransport _transport;

    // Non-null only in endpoint-session mode (broadcast-scale.md §2): the agent owns no socket and
    // instead sends through this seam and receives datagrams the owner pushes in via InjectDatagram.
    private readonly IceExternalTransportOptions? _externalTransport;
    private readonly ConcurrentQueue<Action> _events = new();
    private readonly List<IceCandidate> _localCandidates = [];
    private readonly List<IceCandidate> _remoteCandidates = [];
    private readonly List<IceCandidatePair> _pairs = [];
    private readonly HashSet<string> _foundationsWithRepresentative = [];
    private readonly HashSet<string> _unfrozenFoundations = [];
    private readonly Dictionary<StunTransactionId, OutstandingCheck> _checks = [];
    private readonly Queue<IceCandidatePair> _triggered = new();
    private readonly List<RelayAllocation> _allocations = [];
    private readonly CancellationTokenSource _cts = new();

    // ICE-TCP (RFC 6544), only in play when IceAgentOptions.GatherTcpCandidates is set. Connections
    // are keyed by the peer's transport address - the same key whether this agent accepted the
    // connection on its passive listener or dialed a remote passive candidate - so a check or media
    // for a TCP pair finds the one connection to that peer. _tcpDialsInFlight de-duplicates dials.
    private readonly ConcurrentDictionary<IPEndPoint, IceTcpConnection> _tcpConnections = new();
    private readonly ConcurrentDictionary<IPEndPoint, byte> _tcpDialsInFlight = new();

    // The short-term key derived from LocalPassword. Not readonly: an ICE restart (RFC 8445 section 9)
    // regenerates the local credentials and re-derives this in place.
    private byte[] _localKey;
    private readonly IMdnsResolver? _mdnsResolver;
    private readonly SemaphoreSlim _mdnsResolutionSlots;
    private readonly object _mdnsLock = new();
    private readonly HashSet<string> _mdnsInFlight = [];
    private readonly Dictionary<string, long> _mdnsNegativeCache = [];

    private Socket? _socket;
    private Socket? _tcpListener;
    private int _tcpPort;
    private Task? _receiveLoop;
    private Task? _tcpAcceptLoop;
    private Task? _checkLoop;
    private StunClient? _gatherClient;
    private IceRole _role;
    private ulong _tieBreaker;
    private IceAgentState _state = IceAgentState.New;
    private string? _remoteUfrag;
    private string? _remotePassword;
    private byte[]? _remoteKey;
    private IceCandidatePair? _selected;
    private IceCandidatePair? _nominee;
    private long _checksStartedAt;
    private long _lastKeepaliveAt;
    private long _selectedValidAt;
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
        _mdnsResolver = _options.ResolveMdnsCandidates ? (_options.MdnsResolver ?? MulticastMdnsResolver.Shared) : null;
        _mdnsResolutionSlots = new SemaphoreSlim(_options.MaxConcurrentMdnsResolutions, _options.MaxConcurrentMdnsResolutions);
        _externalTransport = _options.ExternalTransport;
        _transport = new IceTransport(this);
    }

    /// <summary>
    /// True when the agent runs in endpoint-session mode over a caller-provided datagram seam
    /// (<see cref="IceExternalTransportOptions"/>) rather than owning its own bound UDP socket.
    /// </summary>
    public bool IsEndpointSession => _externalTransport is not null;

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

    /// <summary>
    /// The local username fragment to signal in SDP as <c>a=ice-ufrag</c>. Regenerated by
    /// <see cref="Restart"/> for an ICE restart (RFC 8445 section 9).
    /// </summary>
    public string LocalUfrag { get; private set; }

    /// <summary>
    /// The local password to signal in SDP as <c>a=ice-pwd</c>. Regenerated by <see cref="Restart"/>
    /// for an ICE restart (RFC 8445 section 9).
    /// </summary>
    public string LocalPassword { get; private set; }

    /// <summary>
    /// The peer's most recently supplied <c>a=ice-ufrag</c>, or null before
    /// <see cref="SetRemoteCredentials"/> has been called. A restart offer/answer carries a fresh value,
    /// so a caller compares against this to tell an ICE restart from a plain renegotiation.
    /// </summary>
    public string? RemoteUfrag
    {
        get
        {
            lock (_lock)
            {
                return _remoteUfrag;
            }
        }
    }

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

    /// <summary>
    /// A snapshot of the gathered local candidates. When <see cref="IceAgentOptions.RelayOnly"/> is
    /// set, the host and server-reflexive candidates gathered internally as TURN allocation bases are
    /// withheld here - only relayed candidates are exposed, so an SDP built from this list can never
    /// carry a non-relay candidate.
    /// </summary>
    public IReadOnlyList<IceCandidate> LocalCandidates
    {
        get
        {
            lock (_lock)
            {
                return _options.RelayOnly
                    ? [.. _localCandidates.Where(static c => c.Type == IceCandidateType.Relayed)]
                    : [.. _localCandidates];
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
    /// Binds the socket, gathers host candidates, a server-reflexive candidate for each configured
    /// STUN server and a relayed candidate for each configured TURN server, raising
    /// <see cref="OnLocalCandidate"/> for each and <see cref="OnGatheringComplete"/> at the end.
    /// </summary>
    /// <param name="cancellationToken">Cancels the STUN and TURN transactions; host candidates are already reported.</param>
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

        if (_externalTransport is not null)
        {
            StartEndpointSession(_externalTransport);
            return;
        }

        var socket = CreateSocket();
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

        // RFC 6544: a passive TCP listener alongside the UDP socket, when TCP gathering is enabled.
        // It binds the same address family and an ephemeral port, then an accept loop takes inbound
        // connections; each passive TCP host candidate advertises that listening port.
        if (_options.GatherTcpCandidates)
        {
            StartTcpListener();
        }

        var addresses = LocalAddresses(socket);
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

            if (_tcpListener is not null)
            {
                // RFC 6544 section 4.5: a passive TCP host candidate, advertised with
                // "tcptype passive"; its priority uses the TCP host type preference, so it always
                // ranks below the UDP host candidate on the same interface.
                var tcpCandidate = new IceCandidate(
                    Foundation(IceCandidateType.Host, addresses[i], null, IceCandidate.TcpTransport),
                    component: 1,
                    IceCandidate.TcpTransport,
                    IcePriority.Compute(IcePriority.TcpHostTypePreference, localPreference),
                    addresses[i],
                    _tcpPort,
                    IceCandidateType.Host,
                    extensions: [new KeyValuePair<string, string>("tcptype", "passive")])
                {
                    LocalPreference = localPreference,
                };

                AddLocalCandidate(tcpCandidate);
            }
        }

        await GatherServerReflexiveAsync(boundPort, cancellationToken).ConfigureAwait(false);
        await GatherRelayedAsync(boundPort, cancellationToken).ConfigureAwait(false);

        _events.Enqueue(() => OnGatheringComplete?.Invoke(this, EventArgs.Empty));
        DrainEvents();
        _logger.Log(KeryxLogLevel.Info, $"ICE gathering complete on {socket.LocalEndPoint} with {LocalCandidates.Count} candidate(s).");
    }

    /// <summary>
    /// Brings up the agent in endpoint-session mode (<see cref="IceExternalTransportOptions"/>): no
    /// socket is bound and no receive loop runs. Host candidates are advertised for the shared
    /// socket's endpoints, the check loop starts, and inbound datagrams arrive via
    /// <see cref="InjectDatagram"/>. STUN/TURN gathering is skipped — endpoint-session mode is the
    /// ICE-lite server shape, one host candidate at a fixed advertised port.
    /// </summary>
    private void StartEndpointSession(IceExternalTransportOptions external)
    {
        _checkLoop = Task.Run(() => CheckLoopAsync(_cts.Token), CancellationToken.None);

        var endpoints = external.LocalEndPoints;
        for (var i = 0; i < endpoints.Count; i++)
        {
            var endpoint = endpoints[i];

            // The first advertised endpoint gets the highest local preference, mirroring how the
            // self-owned path ranks multiple interface addresses.
            var localPreference = Math.Max(0, IcePriority.MaxLocalPreference - i);
            var candidate = new IceCandidate(
                Foundation(IceCandidateType.Host, endpoint.Address, null),
                component: 1,
                IceCandidate.UdpTransport,
                IcePriority.Compute(IceCandidateType.Host, localPreference),
                endpoint.Address,
                endpoint.Port,
                IceCandidateType.Host)
            {
                LocalPreference = localPreference,
            };

            AddLocalCandidate(candidate);
        }

        _events.Enqueue(() => OnGatheringComplete?.Invoke(this, EventArgs.Empty));
        DrainEvents();
        _logger.Log(
            KeryxLogLevel.Info,
            $"ICE endpoint-session ready over a shared socket with {LocalCandidates.Count} advertised candidate(s).");
    }

    /// <summary>
    /// Pushes one inbound datagram, demultiplexed to this agent by its owner (a broadcast endpoint's
    /// 5-tuple demux), into the agent's processing path — the endpoint-session counterpart of the
    /// self-owned receive loop. STUN is validated and answered here; everything else is surfaced on
    /// <see cref="Transport"/> for DTLS/SRTP. Only valid in endpoint-session mode.
    /// </summary>
    /// <param name="datagram">The received datagram; valid only for the duration of the call.</param>
    /// <param name="from">The remote transport address the datagram arrived from.</param>
    public void InjectDatagram(ReadOnlySpan<byte> datagram, IPEndPoint from)
    {
        if (_externalTransport is null)
        {
            throw new InvalidOperationException("InjectDatagram is only valid for an endpoint-session-mode agent.");
        }

        ArgumentNullException.ThrowIfNull(from);
        if (datagram.Length == 0)
        {
            return;
        }

        ProcessInboundDatagram(datagram, Normalize(from));
        DrainEvents();
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

            // After a restart the check list is armed (Checking) but idle until the peer's fresh
            // credentials arrive, because TickLocked will not send a check without them. Start the
            // connectivity-timeout clock from here, so a slow restart answer does not eat into the
            // ConnectivityTimeout window that only meaningfully begins now.
            if (_state == IceAgentState.Checking && _selected is null)
            {
                _checksStartedAt = Environment.TickCount64;
            }
        }
    }

    /// <summary>
    /// Restarts ICE on this agent (RFC 8445 section 9): generates fresh local credentials, discards the
    /// peer's credentials and the entire check list, and re-arms connectivity checks — while keeping the
    /// bound socket and the gathered local candidates, so the base is reused and the datagram transport
    /// seam (<see cref="Transport"/>) that DTLS/SRTP/SCTP ride is never disturbed.
    /// </summary>
    /// <remarks>
    /// <para>The caller drives the surrounding exchange: after <see cref="Restart"/> it re-emits the local
    /// candidates and the new <see cref="LocalUfrag"/>/<see cref="LocalPassword"/> in a fresh offer or
    /// answer, feeds the peer's restart candidates back through <see cref="AddRemoteCandidate(string)"/>,
    /// and supplies the peer's fresh credentials through <see cref="SetRemoteCredentials"/>. Connectivity
    /// checks then re-run from scratch and nominate a new selected pair.</para>
    /// <para>The previously selected pair is cleared, so <see cref="Transport"/> sends throw for the brief
    /// window until a new pair succeeds; every layer above tolerates that (it is the same gap trickle ICE
    /// already produces before the first pair is nominated). A no-op before gathering has bound a socket.</para>
    /// </remarks>
    public void Restart()
    {
        lock (_lock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_state is IceAgentState.Closed or IceAgentState.Failed || _socket is null)
            {
                // Nothing to restart: either the agent is done, or it never gathered (the first
                // negotiation has not run), in which case the normal gather path applies.
                return;
            }

            // RFC 8445 section 9: an ICE restart MUST use new ufrag/pwd values.
            LocalUfrag = IceCredentials.NewUfrag();
            LocalPassword = IceCredentials.NewPassword();
            _localKey = StunCredentials.ShortTermKey(LocalPassword);

            // The peer's credentials and candidates from the previous session no longer apply; the restart
            // offer/answer re-supplies them. Clearing them stops any in-flight check authenticating.
            _remoteUfrag = null;
            _remotePassword = null;
            _remoteKey = null;
            _remoteCandidates.Clear();

            // Tear the check list down to nothing: pairs, outstanding transactions, the triggered queue,
            // per-foundation freeze bookkeeping, the selected/nominated pair and the peer-reflexive
            // counter all belonged to the previous credentials. RebuildPairsLocked reforms pairs as the
            // peer's restart candidates arrive.
            _pairs.Clear();
            _checks.Clear();
            _triggered.Clear();
            _foundationsWithRepresentative.Clear();
            _unfrozenFoundations.Clear();
            _selected = null;
            _nominee = null;
            _prflxCounter = 0;

            _checksStartedAt = Environment.TickCount64;

            // Move to Checking so the check loop re-runs its full connectivity phase once the fresh remote
            // credentials and candidates are in. A restart from Connected/Disconnected re-opens selection.
            SetStateLocked(IceAgentState.Checking);
        }

        DrainEvents();
        _logger.Log(KeryxLogLevel.Info, "ICE restart: regenerated local credentials and reset the check list.");
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

        // RFC 8656 section 9: the relay drops anything from an address it has no permission for,
        // so every remote candidate must be permitted on every allocation as it arrives.
        PermitRemoteOnAllocations(candidate.EndPoint);
        DrainEvents();
    }

    /// <summary>Parses and adds a candidate in SDP attribute syntax.</summary>
    /// <param name="candidateAttribute">An <c>a=candidate:...</c> line or bare attribute value.</param>
    /// <returns>
    /// True when the attribute was recognised: either it parsed and the candidate was accepted, or
    /// it is an mDNS <c>.local</c> host candidate that was handed off for asynchronous resolution
    /// (which may still end up unresolvable). False only for an attribute that is not valid syntax.
    /// </returns>
    public bool AddRemoteCandidate(string candidateAttribute)
    {
        if (IceCandidate.TryParse(candidateAttribute, out var candidate))
        {
            AddRemoteCandidate(candidate);
            return true;
        }

        // A browser obfuscates its host candidate as <uuid>.local, which TryParse rejects because the
        // connection address is not an IP. Resolve it off this path rather than dropping it, so a
        // same-LAN direct pair can still form (draft mdns-ice-candidates).
        if (_mdnsResolver is not null
            && IceCandidate.TryParseMdnsCandidate(candidateAttribute, out var hostName, out var resolve))
        {
            _logger.Log(KeryxLogLevel.Debug, $"Resolving mDNS remote candidate host '{hostName}'.");
            ResolveMdnsCandidate(hostName, resolve, candidateAttribute);
            return true;
        }

        _logger.Log(KeryxLogLevel.Warning, $"Ignoring unparsable remote candidate '{candidateAttribute}'.");
        return false;
    }

    /// <summary>
    /// Resolves an mDNS host candidate off the intake path and, on success, adds the resolved
    /// candidate. A timeout or failure is logged as an unresolvable mDNS candidate - distinct from
    /// the unparsable-attribute path - and the candidate is skipped without disturbing the agent.
    /// </summary>
    private void ResolveMdnsCandidate(string hostName, Func<IPAddress, IceCandidate> resolve, string candidateAttribute)
    {
        var resolver = _mdnsResolver;
        if (resolver is null)
        {
            return;
        }

        // A single hostile signalling peer can flood distinct <uuid>.local lines; each resolution
        // otherwise spawns a task, one or two UDP sockets and a LAN multicast query. Four bounds keep
        // that in check: a negative cache suppresses a repeat of a name that just failed, an in-flight
        // set collapses duplicate names still resolving, a pending ceiling drops names once too many
        // are already outstanding (so a flood cannot spawn unbounded tasks), and a slot semaphore the
        // admitted tasks queue on caps how many actually open sockets at once. A legitimate burst is
        // admitted in full and simply served a few at a time.
        var key = hostName.ToLowerInvariant();
        lock (_mdnsLock)
        {
            var now = Environment.TickCount64;
            if (_mdnsNegativeCache.TryGetValue(key, out var expiry))
            {
                if (now < expiry)
                {
                    _logger.Log(KeryxLogLevel.Debug, $"Skipping recently-unresolved mDNS remote candidate host '{hostName}'.");
                    return;
                }

                _mdnsNegativeCache.Remove(key);
            }

            if (_mdnsInFlight.Contains(key))
            {
                _logger.Log(KeryxLogLevel.Debug, $"Coalescing duplicate in-flight mDNS remote candidate host '{hostName}'.");
                return;
            }

            if (_mdnsInFlight.Count >= _options.MaxPendingMdnsResolutions)
            {
                _logger.Log(KeryxLogLevel.Warning, $"Dropping mDNS remote candidate '{candidateAttribute}': too many pending resolutions.");
                return;
            }

            _mdnsInFlight.Add(key);
        }

        _ = Task.Run(
            async () =>
            {
                var resolved = false;
                var acquired = false;
                try
                {
                    try
                    {
                        await _mdnsResolutionSlots.WaitAsync(_cts.Token).ConfigureAwait(false);
                        acquired = true;
                    }
                    catch (OperationCanceledException)
                    {
                        return;
                    }

                    IPAddress? address;
                    try
                    {
                        address = await resolver.ResolveAsync(hostName, _cts.Token).ConfigureAwait(false);
                    }
                    catch (Exception ex) when (ex is OperationCanceledException or SocketException)
                    {
                        _logger.Log(KeryxLogLevel.Warning, $"Skipping unresolvable mDNS remote candidate '{candidateAttribute}'.", ex);
                        return;
                    }

                    if (address is null)
                    {
                        _logger.Log(KeryxLogLevel.Warning, $"Skipping unresolvable mDNS remote candidate '{candidateAttribute}'; host '{hostName}' did not answer.");
                        return;
                    }

                    if (_cts.IsCancellationRequested)
                    {
                        return;
                    }

                    resolved = true;
                    _logger.Log(KeryxLogLevel.Debug, $"Resolved mDNS candidate host '{hostName}' to {address}.");
                    AddRemoteCandidate(resolve(address));
                }
                finally
                {
                    if (acquired)
                    {
                        _mdnsResolutionSlots.Release();
                    }

                    lock (_mdnsLock)
                    {
                        _mdnsInFlight.Remove(key);
                        if (!resolved)
                        {
                            NegativeCacheMdnsFailureLocked(key);
                        }
                    }
                }
            },
            CancellationToken.None);
    }

    /// <summary>
    /// Records a failed <c>.local</c> resolution so an immediate re-signal of the same name is
    /// skipped. Expired entries are purged on the way in, and the table is size-capped, so a flood of
    /// distinct failing names cannot grow it without bound.
    /// </summary>
    private void NegativeCacheMdnsFailureLocked(string key)
    {
        var now = Environment.TickCount64;
        if (_mdnsNegativeCache.Count > 0)
        {
            List<string>? expired = null;
            foreach (var entry in _mdnsNegativeCache)
            {
                if (now >= entry.Value)
                {
                    (expired ??= []).Add(entry.Key);
                }
            }

            if (expired is not null)
            {
                foreach (var name in expired)
                {
                    _mdnsNegativeCache.Remove(name);
                }
            }
        }

        // A hard ceiling independent of the TTL: even if failures arrive faster than they expire, the
        // table stays small. Once full, further failures simply are not remembered (they still had to
        // pass the slot cap to get here), which is safe - they just are not suppressed early.
        if (_mdnsNegativeCache.Count >= MaxMdnsNegativeCacheEntries)
        {
            return;
        }

        _mdnsNegativeCache[key] = now + (long)_options.MdnsNegativeCacheDuration.TotalMilliseconds;
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
        List<RelayAllocation> allocations;
        lock (_lock)
        {
            if (_state == IceAgentState.Closed)
            {
                return;
            }

            SetStateLocked(IceAgentState.Closed);
            socket = _socket;
            allocations = [.. _allocations];
            _allocations.Clear();
        }

        // RFC 8656 section 7.5: a Refresh with LIFETIME 0 frees the allocation immediately instead
        // of leaving the server holding a relayed port for up to ten minutes. It goes out before
        // the socket is dropped - the release travels over that socket - and is not waited on, as a
        // lost release only costs the server a timeout.
        foreach (var allocation in allocations)
        {
            allocation.Client.SendRelease();
        }

        lock (_lock)
        {
            _socket = null;
        }

        _cts.Cancel();
        socket?.Close();
        CloseTcp();

        foreach (var allocation in allocations)
        {
            allocation.Client.Dispose();
        }

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
            Task.WhenAll(
                    _receiveLoop ?? Task.CompletedTask,
                    _checkLoop ?? Task.CompletedTask,
                    _tcpAcceptLoop ?? Task.CompletedTask)
                .Wait(TimeSpan.FromSeconds(2));
        }
        catch (Exception)
        {
            // The loops only ever fault because the socket was closed above.
        }

        _cts.Dispose();
        _mdnsResolutionSlots.Dispose();
    }

    internal void SendOnSelectedPair(ReadOnlySpan<byte> datagram)
    {
        if (datagram.Length > MaxDatagram)
        {
            throw new ArgumentException($"An ICE datagram may be at most {MaxDatagram} bytes.", nameof(datagram));
        }

        Socket? socket;
        IceCandidatePair? pair;
        lock (_lock)
        {
            socket = _socket;
            pair = _selected ?? BestUsablePairLocked();
        }

        // In endpoint-session mode there is no _socket; readiness is having a usable pair to send on.
        if ((socket is null && _externalTransport is null) || pair is null)
        {
            throw new InvalidOperationException("No candidate pair has succeeded yet; the ICE transport is not usable.");
        }

        SendForPair(pair, datagram);
    }

    // ---------------------------------------------------------------- gathering

    // The agent keeps its single bundled socket but upgrades it to dual-stack IPv6 when it is
    // gathering on every interface (no explicit BindAddress) and the OS has an IPv6 stack: that one
    // socket then sends and receives both families, so IPv6 host and server-reflexive candidates are
    // gathered and paired without giving up the single-socket design. An explicit BindAddress pins
    // the family to that address, so an IPv4 bind stays on a pure IPv4 socket.
    private Socket CreateSocket()
    {
        var family = _options.BindAddress?.AddressFamily
            ?? (Socket.OSSupportsIPv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork);
        var socket = new Socket(family, SocketType.Dgram, ProtocolType.Udp);
        if (family == AddressFamily.InterNetworkV6 && _options.BindAddress is null)
        {
            // DualMode lets the one v6 socket carry IPv4 too, as v4-mapped addresses that SendRaw and
            // the receive loop normalise back to native IPv4.
            socket.DualMode = true;
        }

        return socket;
    }

    private void Bind(Socket socket)
    {
        var address = _options.BindAddress
            ?? (socket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any);
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

    private List<IPAddress> LocalAddresses(Socket socket)
    {
        if (_options.BindAddress is { } bindAddress
            && !bindAddress.Equals(IPAddress.Any)
            && !bindAddress.Equals(IPAddress.IPv6Any))
        {
            return [bindAddress];
        }

        // A v6 socket is dual-stack here (BindAddress is null), so it gathers both families; a v4
        // socket - the fallback when the OS has no IPv6 - gathers IPv4 only.
        var v6 = socket.AddressFamily == AddressFamily.InterNetworkV6;
        var includeV4 = !v6 || socket.DualMode;
        var includeV6 = v6;

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
                if (IPAddress.IsLoopback(address) || addresses.Contains(address))
                {
                    continue;
                }

                // Link-local IPv6 (fe80::/10) is skipped: it only works with a scope id ICE has no
                // way to carry, and every network that offers IPv6 also offers a routable address.
                switch (address.AddressFamily)
                {
                    case AddressFamily.InterNetwork when includeV4:
                    case AddressFamily.InterNetworkV6 when includeV6 && !address.IsIPv6LinkLocal:
                        addresses.Add(address);
                        break;
                    default:
                        break;
                }
            }
        }

        // IPv4 first so it keeps the higher local preference where both families are present; a
        // dual-stack peer then prefers IPv4 exactly as it does today, while an IPv6-only peer still
        // has usable candidates instead of none.
        addresses.Sort(static (a, b) =>
            (a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1)
                .CompareTo(b.AddressFamily == AddressFamily.InterNetwork ? 0 : 1));
        return addresses;
    }

    /// <summary>The highest-priority host candidate of <paramref name="family"/>, or null when none was gathered.</summary>
    private IceCandidate? HostCandidateForFamily(AddressFamily family)
    {
        lock (_lock)
        {
            foreach (var candidate in _localCandidates)
            {
                if (candidate.Type == IceCandidateType.Host && candidate.Address.AddressFamily == family)
                {
                    return candidate;
                }
            }

            return null;
        }
    }

    private async Task GatherServerReflexiveAsync(int boundPort, CancellationToken cancellationToken)
    {
        if (_options.StunServers.Count == 0 && _options.StunServerHosts.Count == 0)
        {
            return;
        }

        lock (_lock)
        {
            if (_localCandidates.Count == 0)
            {
                return;
            }
        }

        var client = new StunClient(SendRaw, _options.StunClientOptions, _logger);
        Volatile.Write(ref _gatherClient, client);
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _cts.Token);

            // Already-resolved endpoints first (the back-compat form), then the host+port entries,
            // each resolved via DNS the same way TURN servers are. Resolution failures are logged
            // and skipped alongside query failures, so one bad entry never aborts the rest.
            var servers = new List<IPEndPoint>(_options.StunServers);
            foreach (var host in _options.StunServerHosts)
            {
                try
                {
                    servers.Add(await host.ResolveAsync(linked.Token).ConfigureAwait(false));
                }
                catch (Exception ex) when (ex is SocketException or InvalidOperationException or OperationCanceledException)
                {
                    _logger.Log(KeryxLogLevel.Warning, $"STUN server {host} did not resolve to a queryable address.", ex);
                }
            }

            foreach (var server in servers)
            {
                try
                {
                    var mapped = await client.BindingRequestAsync(server, linked.Token).ConfigureAwait(false);

                    // The base is the host candidate of the same family as the mapped address, so an
                    // IPv4 srflx keeps an IPv4 raddr and an IPv6 srflx an IPv6 one (RFC 8445 5.1.1.2).
                    var baseCandidate = HostCandidateForFamily(mapped.AddressFamily);
                    if (baseCandidate is null)
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

    private async Task GatherRelayedAsync(int boundPort, CancellationToken cancellationToken)
    {
        if (_options.TurnServers.Count == 0)
        {
            return;
        }

        lock (_lock)
        {
            if (_localCandidates.Count == 0)
            {
                return;
            }
        }

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _cts.Token);
        foreach (var server in _options.TurnServers)
        {
            RelayAllocation? allocation = null;
            try
            {
                var endPoint = await server.ResolveAsync(linked.Token).ConfigureAwait(false);

                // UDP allocates over the agent's own socket, so the client sends through SendRaw and
                // is fed inbound datagrams by the receive loop (TryHandleTurn). TCP and TLS
                // (RFC 5766 section 2.1) instead own a dedicated connection to the server: ConnectAsync
                // opens it and the client drives its own framing and reassembly, so the relayed data
                // path never touches the UDP socket - only the relayed candidate it produces does.
                var client = server.ClientTransport == TurnClientTransport.Udp
                    ? new TurnClient(endPoint, server.Username, server.Credential, SendRaw, TurnOptions())
                    : await TurnClient.ConnectAsync(
                        endPoint,
                        server.Username,
                        server.Credential,
                        server.ClientTransport,
                        TurnOptions(),
                        server.TlsServerName ?? server.Host,
                        linked.Token).ConfigureAwait(false);

                // Registered before the Allocate goes out, not after: for a UDP allocation the
                // response comes back on the shared socket, and the receive loop can only route it to
                // the right allocation if the allocation is already in the list. (A TCP/TLS client
                // routes its own responses through its connection, but the ordering is kept uniform.)
                // The candidate is filled in once the server has told us what the relayed address is.
                allocation = new RelayAllocation(client, endPoint);
                client.OnRelayedData += allocation.Handle;
                allocation.Received += HandleRelayedDatagram;
                lock (_lock)
                {
                    _allocations.Add(allocation);
                }

                var relayed = await client.AllocateAsync(linked.Token).ConfigureAwait(false);

                // The base is the host candidate of the relayed family (Keryx relays over IPv4), so
                // the relayed candidate's raddr/foundation stay family-consistent.
                var baseCandidate = HostCandidateForFamily(relayed.AddressFamily);
                if (baseCandidate is null)
                {
                    throw new InvalidOperationException(
                        $"No host candidate of the relayed address family {relayed.AddressFamily} to base the relay on.");
                }

                // RFC 8445 section 5.1.1.2: the relayed candidate's base is the relayed address
                // itself, and its raddr/rport are the server-reflexive address the TURN server saw,
                // which the Allocate response hands back as XOR-MAPPED-ADDRESS.
                var reflexive = client.MappedEndPoint;
                var relayCandidate = new IceCandidate(
                    Foundation(IceCandidateType.Relayed, baseCandidate.Address, endPoint),
                    component: 1,
                    IceCandidate.UdpTransport,
                    IcePriority.Compute(IceCandidateType.Relayed, baseCandidate.LocalPreference),
                    relayed.Address,
                    relayed.Port,
                    IceCandidateType.Relayed,
                    reflexive?.Address ?? baseCandidate.Address,
                    reflexive?.Port ?? boundPort)
                {
                    LocalPreference = baseCandidate.LocalPreference,
                };

                lock (_lock)
                {
                    allocation.Candidate = relayCandidate;
                }

                // RFC 8445 section 5.1.1.2 again: an Allocate response also reveals a
                // server-reflexive candidate, for free, on the same socket - but only for a UDP
                // allocation. Over TCP/TLS the XOR-MAPPED-ADDRESS is the reflexive of the TURN
                // control connection, a TCP address on a different port that is no use as a UDP srflx
                // candidate, so it is not harvested.
                if (server.ClientTransport == TurnClientTransport.Udp
                    && reflexive is not null
                    && reflexive.AddressFamily == relayed.AddressFamily)
                {
                    AddLocalCandidate(new IceCandidate(
                        Foundation(IceCandidateType.ServerReflexive, baseCandidate.Address, endPoint),
                        component: 1,
                        IceCandidate.UdpTransport,
                        IcePriority.Compute(IceCandidateType.ServerReflexive, baseCandidate.LocalPreference),
                        reflexive.Address,
                        reflexive.Port,
                        IceCandidateType.ServerReflexive,
                        baseCandidate.Address,
                        boundPort)
                    {
                        LocalPreference = baseCandidate.LocalPreference,
                    });
                }

                AddLocalCandidate(relayCandidate);
                PermitKnownRemotesOn(allocation);
            }
            catch (Exception ex) when (ex is StunTimeoutException or StunErrorResponseException or StunFormatException or SocketException or IOException or AuthenticationException or InvalidOperationException or OperationCanceledException)
            {
                _logger.Log(KeryxLogLevel.Warning, $"TURN server {server} produced no relayed candidate.", ex);
                if (allocation is not null)
                {
                    lock (_lock)
                    {
                        _allocations.Remove(allocation);
                    }

                    allocation.Client.Dispose();
                }
            }
        }
    }

    private TurnClientOptions TurnOptions()
    {
        var options = _options.TurnClientOptions ?? new TurnClientOptions();
        options.Logger ??= _logger;
        return options;
    }

    private RelayAllocation? FindAllocation(IceCandidate local)
    {
        lock (_lock)
        {
            foreach (var allocation in _allocations)
            {
                if (local.Equals(allocation.Candidate))
                {
                    return allocation;
                }
            }

            return null;
        }
    }

    /// <summary>
    /// Opens the allocation to every remote candidate already known. RFC 8656 section 9 makes a
    /// permission a precondition for the relay accepting anything from that address, so this runs
    /// as soon as an allocation exists and again from
    /// <see cref="AddRemoteCandidate(IceCandidate)"/> as candidates trickle in.
    /// </summary>
    private void PermitKnownRemotesOn(RelayAllocation allocation)
    {
        List<IPEndPoint> peers;
        lock (_lock)
        {
            peers = [.. _remoteCandidates.Select(static c => c.EndPoint)];
        }

        foreach (var peer in peers)
        {
            PermitPeer(allocation, peer);
        }
    }

    private void PermitRemoteOnAllocations(IPEndPoint peer)
    {
        List<RelayAllocation> allocations;
        lock (_lock)
        {
            allocations = [.. _allocations];
        }

        foreach (var allocation in allocations)
        {
            PermitPeer(allocation, peer);
        }
    }

    private void PermitPeer(RelayAllocation allocation, IPEndPoint peer)
    {
        // RFC 8656 section 9: a permission's address family must match the relayed family, so a peer
        // is only permitted on an allocation whose relayed candidate shares its family. Keryx relays
        // over IPv4 today, so an IPv6 peer is simply not permitted on a relay yet.
        IceCandidate? relay;
        lock (_lock)
        {
            relay = allocation.Candidate;
        }

        if (relay is null
            || peer.AddressFamily != relay.Address.AddressFamily
            || !allocation.MarkPermissionRequested(peer))
        {
            return;
        }

        _ = Task.Run(
            async () =>
            {
                try
                {
                    // The permission first, because it is what lets the peer's packets in at all;
                    // then the channel, which is only an efficiency win on the way out.
                    await allocation.Client.CreatePermissionAsync(peer, _cts.Token).ConfigureAwait(false);
                    if (TurnOptions().UseChannelData)
                    {
                        await allocation.Client.BindChannelAsync(peer, _cts.Token).ConfigureAwait(false);
                    }
                }
                catch (Exception ex) when (ex is StunTimeoutException or StunErrorResponseException or StunFormatException or SocketException or InvalidOperationException or ObjectDisposedException or OperationCanceledException)
                {
                    allocation.ClearPermissionRequest(peer);
                    _logger.Log(KeryxLogLevel.Warning, $"Could not permit {peer} on the TURN allocation at {allocation.Server}.", ex);
                }
            },
            CancellationToken.None);
    }

    private void HandleRelayedDatagram(RelayAllocation allocation, ReadOnlySpan<byte> datagram, IPEndPoint peer)
    {
        IceCandidate? candidate;
        lock (_lock)
        {
            candidate = allocation.Candidate;
        }

        if (candidate is null)
        {
            return;
        }

        // Unwrapped relayed traffic re-enters the agent exactly where a direct datagram would, so a
        // relayed ICE check is just an ICE check and relayed media is just media (RFC 7983).
        if (StunMessage.LooksLikeStun(datagram))
        {
            HandleStun(datagram, peer, candidate, viaTcp: null);
        }
        else if (IsAcceptableInboundSource(peer))
        {
            _transport.Raise(datagram);
        }
        else
        {
            _logger.Log(KeryxLogLevel.Warning, $"Dropping relayed datagram from {peer}: not the selected pair's remote endpoint.");
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

        // RelayOnly withholds a host/server-reflexive candidate from the outside world entirely: it
        // stays in _localCandidates only as a TURN allocation base (HostCandidateForFamily), it is
        // never surfaced through the event a PeerConnection turns into a trickled SDP candidate. See
        // the matching filter on LocalCandidates for the non-trickle (initial offer/answer) path.
        if (_options.RelayOnly && candidate.Type != IceCandidateType.Relayed)
        {
            return;
        }

        _events.Enqueue(() => OnLocalCandidate?.Invoke(this, candidate));
        DrainEvents();
    }

    private static string Foundation(IceCandidateType type, IPAddress baseAddress, IPEndPoint? server, string transport = IceCandidate.UdpTransport)
    {
        // RFC 8445 section 5.1.1.3: candidates sharing type, base, STUN/TURN server and protocol
        // must share a foundation. A stable 32-bit hash of those inputs satisfies that, and looks
        // like the numeric foundations Chrome emits. The transport is part of the key so a TCP host
        // candidate never shares a foundation - and so never freezes/unfreezes together - with the
        // UDP host candidate on the same base.
        var key = $"{type}|{baseAddress}|{server?.ToString() ?? "-"}|{transport}";
        var hash = 2166136261u;
        foreach (var b in Encoding.UTF8.GetBytes(key))
        {
            hash = (hash ^ b) * 16777619u;
        }

        return hash.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    // ---------------------------------------------------------------- TCP (RFC 6544)

    /// <summary>
    /// Binds the passive TCP listener alongside the UDP socket and starts accepting. The listener
    /// mirrors the UDP socket's family and dual-stack choice, and binds an ephemeral port (or one
    /// from the configured range), so a passive TCP host candidate can advertise where to reach it.
    /// </summary>
    private void StartTcpListener()
    {
        var family = _options.BindAddress?.AddressFamily
            ?? (Socket.OSSupportsIPv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork);
        var listener = new Socket(family, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            if (family == AddressFamily.InterNetworkV6 && _options.BindAddress is null)
            {
                listener.DualMode = true;
            }

            var address = _options.BindAddress
                ?? (family == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any);
            listener.Bind(new IPEndPoint(address, 0));
            listener.Listen(backlog: 16);
        }
        catch
        {
            listener.Dispose();
            throw;
        }

        _tcpPort = ((IPEndPoint)listener.LocalEndPoint!).Port;
        _tcpListener = listener;
        _tcpAcceptLoop = Task.Run(() => AcceptLoopAsync(listener, _cts.Token), CancellationToken.None);
    }

    private async Task AcceptLoopAsync(Socket listener, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            Socket accepted;
            try
            {
                accepted = await listener.AcceptAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException)
            {
                return;
            }
            catch (SocketException ex)
            {
                _logger.Log(KeryxLogLevel.Trace, "ICE-TCP accept error; continuing.", ex);
                continue;
            }

            if (accepted.RemoteEndPoint is not IPEndPoint remote)
            {
                accepted.Dispose();
                continue;
            }

            RegisterTcpConnection(accepted, Normalize(remote), dialed: false);
        }
    }

    /// <summary>
    /// Wraps an accepted or dialed socket in an <see cref="IceTcpConnection"/> keyed by the peer's
    /// address, unless one to that peer already exists (a dial that raced an accept), and starts its
    /// receive loop.
    /// </summary>
    private void RegisterTcpConnection(Socket socket, IPEndPoint remote, bool dialed)
    {
        // The passive listener accepts before any ICE check has validated the peer, and connecting
        // needs no ICE credentials, so cap how many connections may be held at once. Beyond the cap a
        // freshly accepted (or dialed) connection is dropped rather than tracked, bounding the sockets,
        // receive tasks and reassembly buffers an off-path flood can pin. The count check races the
        // TryAdd below under concurrent accepts, but the cap is a coarse ceiling and a small overshoot
        // is harmless.
        if (_tcpConnections.Count >= _options.MaxTcpConnections)
        {
            _logger.Log(KeryxLogLevel.Warning, $"Refusing ICE-TCP connection from {remote}: connection cap ({_options.MaxTcpConnections}) reached.");
            socket.Dispose();
            return;
        }

        var connection = new IceTcpConnection(socket, remote, _logger, _cts.Token);
        if (!_tcpConnections.TryAdd(remote, connection))
        {
            connection.Dispose();
            return;
        }

        connection.StartReceiving(HandleTcpMessage, OnTcpConnectionClosed);
        _logger.Log(KeryxLogLevel.Debug, $"ICE-TCP connection to {remote} {(dialed ? "dialed" : "accepted")}.");
    }

    private void OnTcpConnectionClosed(IceTcpConnection connection)
    {
        if (_tcpConnections.TryRemove(new KeyValuePair<IPEndPoint, IceTcpConnection>(connection.RemoteEndPoint, connection)))
        {
            connection.Dispose();
        }
    }

    /// <summary>
    /// Feeds one whole framed message from a TCP connection back through the same demultiplexing as a
    /// UDP datagram (RFC 7983): STUN is handled as a check, with the connection carried so the reply
    /// goes back over it; everything else is surfaced to the datagram transport.
    /// </summary>
    private void HandleTcpMessage(IceTcpConnection connection, ReadOnlySpan<byte> message)
    {
        if (StunMessage.LooksLikeStun(message))
        {
            HandleStun(message, connection.RemoteEndPoint, viaRelay: null, connection);
        }
        else if (IsAcceptableInboundSource(connection.RemoteEndPoint))
        {
            _transport.Raise(message);
        }
        else
        {
            _logger.Log(KeryxLogLevel.Warning, $"Dropping non-STUN ICE-TCP message from {connection.RemoteEndPoint}: not the selected pair's remote endpoint.");
        }

        DrainEvents();
    }

    /// <summary>
    /// Sends a datagram for a TCP pair. If a connection to the pair's remote address already exists
    /// (accepted or previously dialed) it is used; otherwise, when this agent is controlling, a dial
    /// is kicked off and the datagram is dropped - the connectivity check that triggered it will be
    /// retransmitted once the connection is up. A controlled agent never dials: it waits for the
    /// controlling peer to connect to its passive candidate, which keeps exactly one TCP connection
    /// per pair and so keeps strict inbound-source validation consistent on both ends.
    /// </summary>
    private void SendOverTcp(IceCandidatePair pair, ReadOnlySpan<byte> datagram)
    {
        var remote = pair.RemoteEndPoint;
        if (_tcpConnections.TryGetValue(remote, out var connection))
        {
            connection.Send(datagram);
            return;
        }

        bool controlling;
        lock (_lock)
        {
            controlling = _role == IceRole.Controlling;
        }

        // Only a remote passive candidate is dialable; a peer-reflexive TCP candidate is one this
        // agent only ever learned by accepting a connection, so there is nothing to dial for it.
        if (controlling && pair.Remote.Type == IceCandidateType.Host && pair.Remote.IsTcp)
        {
            DialTcpConnection(remote);
        }
    }

    private void DialTcpConnection(IPEndPoint remote)
    {
        if (_tcpConnections.ContainsKey(remote) || !_tcpDialsInFlight.TryAdd(remote, 0))
        {
            return;
        }

        _ = Task.Run(
            async () =>
            {
                Socket? socket = null;
                try
                {
                    socket = new Socket(remote.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                    await socket.ConnectAsync(remote, _cts.Token).ConfigureAwait(false);
                    RegisterTcpConnection(socket, remote, dialed: true);
                    socket = null;
                }
                catch (Exception ex) when (ex is SocketException or ObjectDisposedException or OperationCanceledException)
                {
                    _logger.Log(KeryxLogLevel.Debug, $"ICE-TCP dial to {remote} failed.", ex);
                    socket?.Dispose();
                }
                finally
                {
                    _tcpDialsInFlight.TryRemove(remote, out _);
                }
            },
            CancellationToken.None);
    }

    private void CloseTcp()
    {
        _tcpListener?.Close();
        foreach (var connection in _tcpConnections.Values)
        {
            connection.Dispose();
        }

        _tcpConnections.Clear();
    }

    // ---------------------------------------------------------------- receive

    private async Task ReceiveLoopAsync(Socket socket, CancellationToken cancellationToken)
    {
        var buffer = new byte[ReceiveBufferSize];
        EndPoint any = new IPEndPoint(
            socket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);

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

            from = Normalize(from);
            var datagram = buffer.AsSpan(0, result.ReceivedBytes);

            // Anything from a TURN server is offered to that allocation first: it may be a response
            // to one of our TURN transactions, or relayed traffic (ChannelData or a Data
            // indication) that must be unwrapped before the RFC 7983 demultiplex below can classify
            // what is inside.
            if (TryHandleTurn(datagram, from))
            {
                DrainEvents();
                continue;
            }

            ProcessInboundDatagram(datagram, from);

            DrainEvents();
        }
    }

    /// <summary>
    /// The RFC 7983 first-byte demultiplex shared by the self-owned receive loop and endpoint-session
    /// <see cref="InjectDatagram"/>: STUN is validated and answered; everything else is surfaced on
    /// <see cref="Transport"/> for DTLS/SRTP. TURN unwrapping happens before this, in the receive loop.
    /// </summary>
    private void ProcessInboundDatagram(ReadOnlySpan<byte> datagram, IPEndPoint from)
    {
        if (StunMessage.LooksLikeStun(datagram))
        {
            HandleStun(datagram, from, viaRelay: null, viaTcp: null);
        }
        else if (IsAcceptableInboundSource(from))
        {
            // RFC 7983 demultiplexing: everything that is not STUN belongs to the layer above
            // and must be surfaced immediately, even before nomination completes.
            _transport.Raise(datagram);
        }
        else
        {
            _logger.Log(KeryxLogLevel.Warning, $"Dropping non-STUN datagram from {from}: not the selected pair's remote endpoint.");
        }
    }

    /// <summary>
    /// Defense-in-depth source check for a datagram already classified as non-STUN (DTLS/RTP/RTCP):
    /// with <see cref="IceAgentOptions.StrictInboundSourceValidation"/> on, once a pair has been
    /// selected the datagram must come from that pair's remote endpoint. DTLS and SRTP authenticate
    /// their own traffic regardless, so this only cheaply rejects UDP an off-path attacker injects at
    /// the socket before it reaches those layers - it is not the security boundary.
    /// </summary>
    private bool IsAcceptableInboundSource(IPEndPoint from)
    {
        if (!_options.StrictInboundSourceValidation)
        {
            return true;
        }

        IceCandidatePair? selected;
        lock (_lock)
        {
            selected = _selected;
        }

        // Before any pair is selected there is no ground truth to check against, and several
        // candidate sources are legitimately in play while checks are still running (RFC 8445
        // section 7.2) - including peer-reflexive discovery. Re-reading _selected fresh on every
        // datagram, rather than caching it, means a later pair change (renomination, TURN failover)
        // takes effect on the very next datagram.
        if (selected is null)
        {
            return true;
        }

        // RemoteEndPoint is the remote candidate's own advertised transport address (RFC 8445
        // section 5.1): for a peer relaying through their own TURN server that is the relay's
        // address, not their host address, so relayed traffic is validated exactly like direct
        // traffic with no relay-specific handling needed here.
        return from.Equals(selected.RemoteEndPoint);
    }

    private bool TryHandleTurn(ReadOnlySpan<byte> datagram, IPEndPoint from)
    {
        List<RelayAllocation> allocations;
        lock (_lock)
        {
            if (_allocations.Count == 0)
            {
                return false;
            }

            allocations = [.. _allocations];
        }

        foreach (var allocation in allocations)
        {
            if (allocation.Client.TryHandleDatagram(datagram, from))
            {
                return true;
            }
        }

        return false;
    }

    private void HandleStun(ReadOnlySpan<byte> datagram, IPEndPoint from, IceCandidate? viaRelay, IceTcpConnection? viaTcp = null)
    {
        if (!StunMessage.TryDecode(datagram, out var message) || message.Method != StunMethod.Binding)
        {
            _logger.Log(KeryxLogLevel.Warning, $"Dropping malformed STUN datagram from {from}.");
            return;
        }

        switch (message.Class)
        {
            case StunClass.Request:
                HandleBindingRequest(message, from, viaRelay, viaTcp);
                break;
            case StunClass.SuccessResponse:
            case StunClass.ErrorResponse:
                if (Volatile.Read(ref _gatherClient)?.TryHandleDatagram(datagram) == true)
                {
                    return;
                }

                HandleCheckResponse(message, from, viaRelay, viaTcp);
                break;
            case StunClass.Indication:
                // RFC 7675 section 5.1: consent to keep sending is refreshed only by a validated
                // STUN Binding *response* to a request this agent sent - never by an inbound STUN
                // Binding indication. A keepalive indication (RFC 8445 section 11) carries no
                // MESSAGE-INTEGRITY and its source is unverified, so treating it as consent let an
                // off-path attacker keep a dead selected pair alive indefinitely, defeating the
                // consent-freshness safeguard that stops the agent flooding an address the real peer
                // has abandoned. It is ignored here; the agent's own keepalive checks (TickLocked)
                // maintain genuine consent by eliciting authenticated responses.
                break;
            default:
                break;
        }
    }

    private void HandleBindingRequest(StunMessage request, IPEndPoint from, IceCandidate? viaRelay, IceTcpConnection? viaTcp)
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
            SendStun(StunMessage.CreateErrorResponse(request, StunErrorCodeAttribute.Unauthorized, "Unauthorized"), from, key: null, viaRelay, viaTcp);
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
                var remote = FindOrCreatePeerReflexiveLocked(from, request.GetAttribute<StunPriorityAttribute>()?.Priority, overTcp: viaTcp is not null);
                var pair = remote is null ? null : FindPairLocked(remote, viaRelay);
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

        SendStun(response, from, responseKey, viaRelay, viaTcp);
        DrainEvents();
    }

    private void HandleCheckResponse(StunMessage response, IPEndPoint from, IceCandidate? viaRelay, IceTcpConnection? viaTcp)
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

        // The same rule applied to the local end: a check sent through the relay must come back
        // through the relay, a check over a TCP connection must come back over TCP, and a direct
        // check must come back directly.
        var expectedRelay = check.Pair.Local.Type == IceCandidateType.Relayed ? check.Pair.Local : null;
        if (!Equals(expectedRelay, viaRelay) || check.Pair.Local.IsTcp != (viaTcp is not null))
        {
            _logger.Log(KeryxLogLevel.Warning, $"ICE check response for {check.Pair} arrived on the wrong local candidate; ignoring.");
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

            check.Pair.State = IceCandidatePairState.Succeeded;
            UnfreezeFoundationLocked(check.Pair.FoundationPair);
            if (ReferenceEquals(check.Pair, _selected))
            {
                // Consent is fresh only for the pair actually carrying media; a success on some
                // other pair must not keep a dead selected pair alive.
                _selectedValidAt = Environment.TickCount64;
            }

            if (check.UseCandidate || check.Pair.NominateOnSuccess)
            {
                NominateLocked(check.Pair);
            }
            else
            {
                UpdateSelectedLocked();
                StartRegularNominationLocked();
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
        var pending = new List<(byte[] Datagram, IceCandidatePair Pair)>();
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

                foreach (var (datagram, pair) in pending)
                {
                    SendForPair(pair, datagram);
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

    private void TickLocked(List<(byte[] Datagram, IceCandidatePair Pair)> pending)
    {
        // In endpoint-session mode there is no _socket; the send seam carries checks instead.
        if (_state is IceAgentState.Closed or IceAgentState.Failed || (_socket is null && _externalTransport is null))
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
            pending.Add(BuildCheckLocked(next, now, isKeepalive: false, useCandidate: IsAggressiveControllingLocked));
        }

        // Regular nomination: keep sending USE-CANDIDATE on the one chosen pair until it is
        // nominated. The pair is already Succeeded, so this rides the keepalive path (no state
        // reset) rather than a triggered check, which skips succeeded pairs.
        if (_nominee is { Nominated: false } nominee
            && _role == IceRole.Controlling
            && _options.NominationMode == IceNominationMode.Regular
            && !HasOutstandingCheckLocked(nominee))
        {
            pending.Add(BuildCheckLocked(nominee, now, isKeepalive: true, useCandidate: true));
        }

        if (_selected is { } selected
            && _state is IceAgentState.Connected or IceAgentState.Disconnected
            && now - _lastKeepaliveAt >= (long)_options.KeepaliveInterval.TotalMilliseconds)
        {
            _lastKeepaliveAt = now;
            pending.Add(BuildCheckLocked(selected, now, isKeepalive: true, useCandidate: false));
        }

        EvaluateTimeoutsLocked(now);
    }

    private void RetransmitLocked(long now, List<(byte[] Datagram, IceCandidatePair Pair)> pending)
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
            pending.Add((check.Datagram, check.Pair));
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

    private (byte[] Datagram, IceCandidatePair Pair) BuildCheckLocked(IceCandidatePair pair, long now, bool isKeepalive, bool useCandidate)
    {
        // RFC 8445 section 7.1.1: PRIORITY carries the priority the peer-reflexive candidate the
        // peer may discover from this check would have.
        var prflxPriority = IcePriority.Compute(IceCandidateType.PeerReflexive, pair.Local.LocalPreference, pair.Local.Component);

        var request = new StunMessage(StunClass.Request, StunMethod.Binding)
            .Add(new StunUsernameAttribute($"{_remoteUfrag}:{LocalUfrag}"))
            .Add(new StunPriorityAttribute(prflxPriority))
            .Add(_role == IceRole.Controlling
                ? new StunIceControllingAttribute(_tieBreaker)
                : new StunIceControlledAttribute(_tieBreaker));

        if (useCandidate)
        {
            // USE-CANDIDATE nominates the pair once the check succeeds. In aggressive mode every
            // check carries it; in regular mode only the check on the chosen nominee does.
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

        return (datagram, pair);
    }

    private void EvaluateTimeoutsLocked(long now)
    {
        switch (_state)
        {
            case IceAgentState.Checking when now - _checksStartedAt > (long)_options.ConnectivityTimeout.TotalMilliseconds:
                _logger.Log(KeryxLogLevel.Error, "ICE connectivity checks timed out with no usable pair.");
                SetStateLocked(IceAgentState.Failed);
                break;

            case IceAgentState.Connected when _selected is not null
                    && now - _selectedValidAt > (long)_options.DisconnectedTimeout.TotalMilliseconds:
                // The nominated pair has gone silent. Regular nomination fails over to the next
                // best valid pair rather than tearing the session down; if none survives, the
                // agent drops to Disconnected and, later, Failed.
                if (!TryFailoverLocked(now))
                {
                    SetStateLocked(IceAgentState.Disconnected);
                }

                break;

            case IceAgentState.Disconnected when now - _selectedValidAt > (long)_options.ConsentTimeout.TotalMilliseconds:
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

        // RFC 8445 permits limiting the candidate set. Beyond the cap a signalled candidate is dropped
        // cleanly - no throw, no pair rebuild, no TURN permission task - so a peer trickling huge
        // counts cannot drive the O(n) rebuild or the per-add permission work without bound. The cap
        // dwarfs any legitimate session, so a real peer's candidates are never lost to it.
        if (_remoteCandidates.Count >= _options.MaxRemoteCandidates)
        {
            _logger.Log(KeryxLogLevel.Warning, $"Dropping remote candidate {candidate}: remote-candidate cap ({_options.MaxRemoteCandidates}) reached.");
            return false;
        }

        _remoteCandidates.Add(candidate);
        RebuildPairsLocked();
        _logger.Log(KeryxLogLevel.Debug, $"ICE remote candidate {candidate}.");
        return true;
    }

    private IceCandidate? FindOrCreatePeerReflexiveLocked(IPEndPoint from, uint? priority, bool overTcp)
    {
        // A TCP check reveals a TCP peer-reflexive candidate and a UDP check a UDP one, so the
        // transport matches and RebuildPairsLocked pairs it against a local candidate of the same
        // transport (a TCP prflx against the passive TCP host, never against the UDP host).
        var transport = overTcp ? IceCandidate.TcpTransport : IceCandidate.UdpTransport;
        foreach (var candidate in _remoteCandidates)
        {
            if (candidate.EndPoint.Equals(from) && candidate.IsTcp == overTcp)
            {
                return candidate;
            }
        }

        // RFC 8445 section 7.3.1.3: a valid check from an unknown address reveals a peer-reflexive
        // candidate. Its priority comes from the PRIORITY attribute the peer sent.
        var discovered = new IceCandidate(
            $"prflx{++_prflxCounter}",
            component: 1,
            transport,
            priority ?? IcePriority.Compute(IceCandidateType.PeerReflexive),
            from.Address,
            from.Port,
            IceCandidateType.PeerReflexive);

        _remoteCandidates.Add(discovered);
        RebuildPairsLocked();
        _logger.Log(KeryxLogLevel.Info, $"ICE discovered peer-reflexive candidate {discovered}.");
        _events.Enqueue(() => OnRemoteCandidate?.Invoke(this, discovered));
        _events.Enqueue(() => PermitRemoteOnAllocations(discovered.EndPoint));
        return discovered;
    }

    private void RebuildPairsLocked()
    {
        if (_localCandidates.Count == 0)
        {
            return;
        }

        HashSet<IceCandidatePair>? newPairs = null;
        foreach (var remote in _remoteCandidates)
        {
            // The direct pair: one per remote candidate, against the highest-priority local
            // candidate that is not relayed. Every non-relayed local candidate shares the one
            // socket, so pairing them all would only produce duplicate checks. RelayOnly skips this
            // path entirely - the host/server-reflexive candidates it is built from are gathered only
            // as TURN allocation bases and must never be checked against, or the agent could connect
            // directly and never touch the relay it is being asked to prove.
            if (!_options.RelayOnly && FindPairLocked(remote, viaRelay: null) is null)
            {
                IceCandidate? local = null;
                foreach (var candidate in _localCandidates)
                {
                    // Same transport as well as same family: a candidate pair must agree on the
                    // transport protocol (RFC 8445 section 6.1.2.2 / RFC 6544), so a remote TCP
                    // candidate pairs with the local passive TCP host, never with the UDP host.
                    if (candidate.Type != IceCandidateType.Relayed
                        && candidate.Address.AddressFamily == remote.Address.AddressFamily
                        && candidate.IsTcp == remote.IsTcp)
                    {
                        local = candidate;
                        break;
                    }
                }

                if (local is not null)
                {
                    var pair = new IceCandidatePair(local, remote, _role);
                    _pairs.Add(pair);
                    (newPairs ??= []).Add(pair);
                }
            }

            // Relayed pairs are genuinely distinct paths - a different local transport address and
            // a different route - so each allocation gets its own pair per remote candidate.
            foreach (var allocation in _allocations)
            {
                // A relayed candidate is always UDP, so it only pairs with a UDP remote candidate.
                if (allocation.Candidate is not { } relay
                    || relay.Address.AddressFamily != remote.Address.AddressFamily
                    || relay.IsTcp != remote.IsTcp
                    || FindPairLocked(remote, relay) is not null)
                {
                    continue;
                }

                var relayedPair = new IceCandidatePair(relay, remote, _role);
                _pairs.Add(relayedPair);
                (newPairs ??= []).Add(relayedPair);
            }
        }

        _pairs.Sort(static (a, b) => b.Priority.CompareTo(a.Priority));

        if (newPairs is null)
        {
            return;
        }

        // RFC 8445 section 6.1.2.6: assign starting states in priority order so that, among several
        // pairs newly sharing a not-yet-seen foundation, the highest-priority one becomes the
        // per-foundation representative that starts Waiting - the spec's "lowest component ID, ties
        // broken by priority" rule collapses to exactly this because every candidate here is
        // component 1. _pairs is already sorted by priority above.
        foreach (var pair in _pairs)
        {
            if (newPairs.Contains(pair))
            {
                SetInitialPairStateLocked(pair);
            }
        }
    }

    /// <summary>
    /// Assigns a newly formed pair's starting state (RFC 8445 section 6.1.2.6): Frozen, unless it is
    /// either the first pair seen for its foundation - which becomes that foundation's Waiting
    /// representative - or its foundation has already succeeded once, in which case there is nothing
    /// to gain by freezing it: section 7.2.5.3.3 would unfreeze it the moment it existed anyway.
    /// </summary>
    private void SetInitialPairStateLocked(IceCandidatePair pair)
    {
        var foundation = pair.FoundationPair;
        pair.State = _unfrozenFoundations.Contains(foundation) || _foundationsWithRepresentative.Add(foundation)
            ? IceCandidatePairState.Waiting
            : IceCandidatePairState.Frozen;
    }

    /// <summary>
    /// RFC 8445 sections 7.2.5.3.3 / 6.1.4.2: once a check on any pair succeeds, every other pair
    /// sharing its foundation - already in the check list or trickled in later - is released from
    /// Frozen to Waiting instead of waiting for its own turn as a fresh representative.
    /// </summary>
    private void UnfreezeFoundationLocked(string foundation)
    {
        if (!_unfrozenFoundations.Add(foundation))
        {
            return;
        }

        foreach (var pair in _pairs)
        {
            if (pair.State == IceCandidatePairState.Frozen && pair.FoundationPair == foundation)
            {
                pair.State = IceCandidatePairState.Waiting;
            }
        }
    }

    /// <summary>
    /// Finds the pair for <paramref name="remote"/> that runs over <paramref name="viaRelay"/>, or
    /// over the direct path when it is null. The local candidate is part of the identity of a pair:
    /// with a TURN allocation in play the same remote candidate appears in several.
    /// </summary>
    private IceCandidatePair? FindPairLocked(IceCandidate remote, IceCandidate? viaRelay)
    {
        foreach (var pair in _pairs)
        {
            if (!pair.Remote.Equals(remote))
            {
                continue;
            }

            var pairRelay = pair.Local.Type == IceCandidateType.Relayed ? pair.Local : null;
            if (Equals(pairRelay, viaRelay))
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

        // A controlling agent stops nominating once its chosen pair is nominated; a controlled
        // agent adopts whatever pair the peer nominated as its frozen selection.
        if (ReferenceEquals(pair, _nominee))
        {
            _nominee = null;
        }

        UpdateSelectedLocked();
    }

    /// <summary>
    /// Regular nomination (RFC 8445 section 8.1.1.1): once a controlling agent has a valid pair it
    /// picks the best one as the single nominee. <see cref="TickLocked"/> then sends USE-CANDIDATE
    /// on that pair until it is nominated, after which the selection is frozen.
    /// </summary>
    private void StartRegularNominationLocked()
    {
        if (!IsRegularControllingLocked || _nominee is not null || _selected is { Nominated: true })
        {
            return;
        }

        _nominee = BestUsablePairLocked();
    }

    private void UpdateSelectedLocked()
    {
        // Freeze: under regular nomination a nominated, still-succeeding pair is never displaced by
        // a later higher-priority success. That is the whole point - it stops live media flapping
        // onto a newly validated pair. Failover (a dead selected pair) clears this before re-selecting.
        if (_options.NominationMode == IceNominationMode.Regular
            && _selected is { Nominated: true, State: IceCandidatePairState.Succeeded })
        {
            return;
        }

        var best = BestUsablePairLocked();
        if (best is null || ReferenceEquals(best, _selected))
        {
            return;
        }

        _selected = best;
        _selectedValidAt = Environment.TickCount64;
        _logger.Log(KeryxLogLevel.Info, $"ICE selected pair {best}.");
        _events.Enqueue(() => OnSelectedPairChanged?.Invoke(this, best));
    }

    /// <summary>
    /// The nominated pair stopped answering. Retire it and, if another valid pair survives, nominate
    /// that one instead of failing the session. Returns false when nothing usable remains.
    /// </summary>
    private bool TryFailoverLocked(long now)
    {
        if (!IsRegularControllingLocked || _selected is null)
        {
            return false;
        }

        var dead = _selected;
        dead.State = IceCandidatePairState.Failed;
        dead.Nominated = false;
        _selected = null;
        _nominee = null;

        var next = BestUsablePairLocked();
        if (next is null)
        {
            return false;
        }

        // Give the replacement a fresh consent window, provisionally select it so media keeps
        // flowing, and let TickLocked drive a fresh USE-CANDIDATE check to nominate it.
        _selectedValidAt = now;
        _nominee = next;
        UpdateSelectedLocked();
        _logger.Log(KeryxLogLevel.Warning, $"ICE failed over to {next} after the nominated pair went dead.");
        return true;
    }

    private bool IsRegularControllingLocked
        => _role == IceRole.Controlling && _options.NominationMode == IceNominationMode.Regular;

    private bool IsAggressiveControllingLocked
        => _role == IceRole.Controlling && _options.NominationMode == IceNominationMode.Aggressive;

    private bool HasOutstandingCheckLocked(IceCandidatePair pair)
    {
        foreach (var check in _checks.Values)
        {
            if (ReferenceEquals(check.Pair, pair) && check.UseCandidate)
            {
                return true;
            }
        }

        return false;
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

    private void SendStun(StunMessage message, IPEndPoint destination, byte[]? key, IceCandidate? viaRelay, IceTcpConnection? viaTcp = null)
    {
        var datagram = message.Encode(key, appendFingerprint: true);
        if (viaTcp is not null)
        {
            viaTcp.Send(datagram);
            return;
        }

        if (viaRelay is null)
        {
            SendRaw(datagram, destination);
            return;
        }

        SendThroughRelay(viaRelay, datagram, destination);
    }

    /// <summary>
    /// Puts a datagram on the wire for <paramref name="pair"/>: straight out of the socket for a
    /// direct pair, or through the TURN allocation when the pair's local candidate is relayed.
    /// </summary>
    private void SendForPair(IceCandidatePair pair, ReadOnlySpan<byte> datagram)
    {
        if (pair.Local.IsTcp)
        {
            SendOverTcp(pair, datagram);
            return;
        }

        if (pair.Local.Type != IceCandidateType.Relayed)
        {
            SendRaw(datagram, pair.RemoteEndPoint);
            return;
        }

        SendThroughRelay(pair.Local, datagram, pair.RemoteEndPoint);
    }

    private void SendThroughRelay(IceCandidate relay, ReadOnlySpan<byte> datagram, IPEndPoint destination)
    {
        var allocation = FindAllocation(relay);
        if (allocation is null)
        {
            _logger.Log(KeryxLogLevel.Warning, $"Dropping a datagram for {destination}: the TURN allocation behind {relay.EndPoint} is gone.");
            return;
        }

        try
        {
            allocation.Client.SendTo(datagram, destination);
        }
        catch (Exception ex) when (ex is InvalidOperationException or SocketException or ObjectDisposedException)
        {
            _logger.Log(KeryxLogLevel.Warning, $"Failed to relay a datagram to {destination} through {allocation.Server}.", ex);
        }
    }

    // A dual-stack socket reports IPv4 senders as v4-mapped IPv6 (::ffff:a.b.c.d); everything above
    // the socket works in native families, so an inbound address is unmapped here at the boundary.
    private static IPEndPoint Normalize(IPEndPoint endPoint)
        => endPoint.Address.IsIPv4MappedToIPv6
            ? new IPEndPoint(endPoint.Address.MapToIPv4(), endPoint.Port)
            : endPoint;

    private void SendRaw(ReadOnlySpan<byte> datagram, IPEndPoint destination)
    {
        // Endpoint-session mode owns no socket: every datagram leaves through the owner's shared
        // socket via the send seam. This is the single choke point for direct (non-relay, non-TCP)
        // sends, so routing it here covers checks, keepalives, and DTLS/SRTP media alike — and is
        // where broadcast-scale.md §3's batched sender will later replace the per-datagram send.
        if (_externalTransport is { } external)
        {
            external.Send(datagram, destination);
            return;
        }

        Socket? socket;
        lock (_lock)
        {
            socket = _socket;
        }

        if (socket is null)
        {
            return;
        }

        // The mirror of Normalize on the way out: a v6 (dual-stack) socket cannot send to a native
        // IPv4 endpoint, so an IPv4 destination is mapped to v4-mapped v6 first.
        if (socket.AddressFamily == AddressFamily.InterNetworkV6
            && destination.AddressFamily == AddressFamily.InterNetwork)
        {
            destination = new IPEndPoint(destination.Address.MapToIPv6(), destination.Port);
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

    /// <summary>Receives one datagram a TURN allocation relayed in, tagged with the allocation it came from.</summary>
    private delegate void RelayedDatagramHandler(RelayAllocation allocation, ReadOnlySpan<byte> datagram, IPEndPoint peer);

    /// <summary>
    /// One live TURN allocation: the client that owns it, the relayed candidate it produced, and
    /// the set of peers a permission has already been asked for.
    /// </summary>
    private sealed class RelayAllocation(TurnClient client, IPEndPoint server)
    {
        private readonly HashSet<IPEndPoint> _permissionRequests = [];

        public TurnClient Client { get; } = client;

        /// <summary>
        /// The relayed candidate the allocation produced, or null between registering the client
        /// for demultiplexing and the Allocate response coming back. Guarded by the agent's lock.
        /// </summary>
        public IceCandidate? Candidate { get; set; }

        public IPEndPoint Server { get; } = server;

        public event RelayedDatagramHandler? Received;

        public void Handle(ReadOnlySpan<byte> datagram, IPEndPoint peer) => Received?.Invoke(this, datagram, peer);

        public bool MarkPermissionRequested(IPEndPoint peer)
        {
            lock (_permissionRequests)
            {
                return _permissionRequests.Add(peer);
            }
        }

        public void ClearPermissionRequest(IPEndPoint peer)
        {
            lock (_permissionRequests)
            {
                _permissionRequests.Remove(peer);
            }
        }
    }

    private sealed class IceTransport(IceAgent agent) : IDatagramTransport
    {
        public int MaxDatagramSize => MaxDatagram;

        public event DatagramReceivedHandler? OnReceived;

        public void Send(ReadOnlySpan<byte> datagram) => agent.SendOnSelectedPair(datagram);

        internal void Raise(ReadOnlySpan<byte> datagram) => OnReceived?.Invoke(datagram);
    }
}
