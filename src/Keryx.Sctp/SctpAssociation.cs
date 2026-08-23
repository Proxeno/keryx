using System.Buffers.Binary;
using System.Security.Cryptography;
using Keryx.Core;

namespace Keryx.Sctp;

/// <summary>
/// One SCTP association carried over an <see cref="IDatagramTransport"/> — in WebRTC, the DTLS
/// application-data stream — providing the data-channel service of RFC 8831 with in-band DCEP
/// negotiation (RFC 8832).
/// </summary>
/// <remarks>
/// <para>
/// <b>Threading.</b> All state is guarded by a single internal lock. Inbound work is driven by
/// <see cref="IDatagramTransport.OnReceived"/> and timer work by a periodic tick, so events
/// (<see cref="OnAssociated"/>, <see cref="OnChannelOpened"/>, <see cref="DataChannel.OnMessage"/>
/// and friends) are raised on those threads, never on the caller's. Events are dispatched after the
/// lock is released and are serialized with one another, so message ordering on a channel is
/// preserved. Handlers may call back into the association.
/// </para>
/// <para>
/// <b>Scope.</b> Single-homed only: no address parameters are sent or honoured, and there is no
/// path management beyond a liveness heartbeat. RFC 6525 stream reset (RE-CONFIG) is supported so a
/// closed data channel frees its stream identifier for reuse. AUTH, ASCONF, I-DATA and ECN are not
/// implemented.
/// </para>
/// </remarks>
public sealed class SctpAssociation : IDisposable
{
    private const int CookieLength = 64;
    private const int CookieMacOffset = 32;

    // Out-of-order DATA that cannot be reassembled yet is held in _received/_fragments.
    // The advertised a_rwnd (see LocalReceiveWindow) only asks a well-behaved peer to
    // stop; a hostile peer can ignore it and flood us with a never-filling gap or an
    // endless run of B-fragments whose E-fragment never arrives. To avoid an OOM we
    // enforce a hard ceiling on that buffering here, independent of the advertised hint.

    // A peer sending many tiny (or empty) DATA chunks costs little payload per chunk but
    // a full map entry in both _received and _fragments; assume at least this many bytes
    // per buffered chunk to derive a companion cap on the entry count, so the byte cap
    // cannot be side-stepped with a flood of near-empty chunks.
    private const int MinChunkBufferCharge = 256;

    private readonly object _lock = new();
    private readonly IDatagramTransport _lower;
    private readonly SctpAssociationConfig _config;
    private readonly IKeryxLogger _log;
    private readonly TimeProvider _time;
    private readonly long _startTimestamp;
    private readonly byte[] _cookieKey = RandomNumberGenerator.GetBytes(32);

    private readonly List<Action> _events = new();
    private readonly List<SctpChunk> _controlQueue = new();
    private readonly List<OutgoingChunk> _out = new();
    private readonly Dictionary<ushort, ushort> _sendSequence = new();
    private readonly Dictionary<ushort, ReceiveStream> _receiveStreams = new();
    private readonly Dictionary<uint, SctpDataChunk> _fragments = new();
    private readonly HashSet<uint> _received = new();
    private readonly List<uint> _duplicateTsns = new();
    private readonly Dictionary<int, DataChannel> _channels = new();
    private readonly Dictionary<ushort, List<ReassembledMessage>> _orphanMessages = new();

    // RFC 8260 user-message interleaving (I-DATA). Send-side MID counters are kept per stream and
    // per ordering namespace; receive-side reassembly keys on (stream, ordered/unordered, MID) and
    // orders fragments by FSN, with a TSN->key index so FORWARD TSN and stream resets can evict the
    // partial fragments they abandon.
    private readonly Dictionary<ushort, uint> _sendOrderedMid = new();
    private readonly Dictionary<ushort, uint> _sendUnorderedMid = new();
    private readonly Dictionary<IDataKey, IDataReassembly> _iDataReassembly = new();
    private readonly Dictionary<uint, (IDataKey Key, uint Fsn)> _iDataTsnIndex = new();
    private readonly Dictionary<ushort, IDataReceiveStream> _iDataReceiveStreams = new();
    private int _iDataBufferedFragments;

    // RFC 6525 stream reconfiguration (RE-CONFIG). Stream ids freed by a completed reset are
    // held here so a later channel reuses them instead of exhausting the id space; the queue
    // holds ids whose channels have closed and are waiting for an outgoing reset to be driven.
    private readonly SortedSet<int> _freedStreamIds = new();
    private readonly List<ushort> _pendingResetStreams = new();
    private readonly List<SctpOutgoingSsnResetRequest> _deferredIncomingResets = new();

    private bool _started;
    private bool _disposed;
    private bool _dispatching;
    private ITimer? _timer;
    private TaskCompletionSource? _connectSource;

    private SctpAssociationState _state = SctpAssociationState.Closed;
    private uint _localTag;
    private uint _peerTag;
    private uint _localInitialTsn;
    private uint _nextTsn;
    private uint _peerCumulativeAck;
    private uint _advancedPeerAckPoint;
    private uint _cumulativeTsnReceived;
    private uint _peerReceiveWindow = 65535;
    private ushort _outboundStreams;
    private ushort _inboundStreams;
    private bool _peerSupportsForwardTsn;
    private bool _peerSupportsReconfig;
    private bool _peerSupportsInterleaving;
    private int _nextMessageId;
    private int _nextStreamId;
    private long _receiveBufferBytes;

    // Outgoing RE-CONFIG in flight, if any, plus its retransmission bookkeeping.
    private uint _reconfigNextSeq;
    private uint _reconfigNextExpectedRemoteSeq;
    private bool _hasRemoteResetSeq;
    private uint _lastRemoteResetSeq;
    private OutstandingReset? _outstandingReset;
    private long _reconfigExpiry;
    private int _reconfigAttempts;

    private long _flightSize;
    private long _congestionWindow;
    private long _slowStartThreshold;
    private long _partialBytesAcked;

    private double _rto;
    private double _smoothedRtt;
    private double _rttVariance;
    private bool _hasRttSample;
    private uint _rttProbeTsn;
    private long _rttProbeSentMs;
    private bool _rttProbeActive;

    private long _t3Expiry;
    private long _initExpiry;
    private int _initAttempts;
    private SctpInitChunk? _pendingInit;
    private SctpCookieEchoChunk? _pendingCookieEcho;
    private long _shutdownExpiry;
    private int _shutdownAttempts;
    private long _nextHeartbeat;
    private byte[]? _heartbeatNonce;
    private long _heartbeatSentMs;
    private bool _sackPending;

    /// <summary>Creates an association over <paramref name="lower"/>.</summary>
    /// <param name="lower">The transport carrying SCTP packets; for WebRTC, DTLS application data.</param>
    /// <param name="config">Association configuration.</param>
    public SctpAssociation(IDatagramTransport lower, SctpAssociationConfig config)
    {
        ArgumentNullException.ThrowIfNull(lower);
        ArgumentNullException.ThrowIfNull(config);
        _lower = lower;
        _config = config;
        _log = config.Logger;
        _time = config.TimeProvider;
        _startTimestamp = _time.GetTimestamp();

        _localTag = RandomTag();
        _localInitialTsn = RandomTag();
        _nextTsn = _localInitialTsn;
        _reconfigNextSeq = _localInitialTsn;
        _peerCumulativeAck = unchecked(_localInitialTsn - 1);
        _advancedPeerAckPoint = _peerCumulativeAck;
        _outboundStreams = config.OutboundStreams;
        _inboundStreams = config.InboundStreams;
        _nextStreamId = config.UsesEvenStreamIds ? 0 : 1;
        _rto = config.InitialRto.TotalMilliseconds;
        _congestionWindow = InitialCongestionWindow;
        _slowStartThreshold = config.ReceiveWindow;
    }

    /// <summary>Raised once the association reaches <see cref="SctpAssociationState.Established"/>.</summary>
    public event Action? OnAssociated;

    /// <summary>Raised once when the association reaches <see cref="SctpAssociationState.Closed"/>.</summary>
    public event Action? OnClosed;

    /// <summary>Raised when the association fails; the argument describes the failure.</summary>
    public event Action<Exception>? OnError;

    /// <summary>Raised after a peer-initiated DATA_CHANNEL_OPEN has been accepted and acknowledged.</summary>
    public event Action<DataChannel>? OnChannelOpened;

    /// <summary>The association's current state.</summary>
    public SctpAssociationState State
    {
        get
        {
            lock (_lock)
            {
                return _state;
            }
        }
    }

    /// <summary>The local verification tag placed in packets the peer sends to this endpoint.</summary>
    public uint LocalVerificationTag
    {
        get
        {
            lock (_lock)
            {
                return _localTag;
            }
        }
    }

    /// <summary>Every channel currently known to the association, remote- and locally-created.</summary>
    public IReadOnlyCollection<DataChannel> Channels
    {
        get
        {
            lock (_lock)
            {
                return _channels.Values.ToArray();
            }
        }
    }

    /// <summary>Takes a snapshot of the association's transmission state for diagnostics.</summary>
    /// <returns>The current statistics.</returns>
    public SctpAssociationStatistics GetStatistics()
    {
        lock (_lock)
        {
            return new SctpAssociationStatistics(
                _state,
                _cumulativeTsnReceived,
                _peerCumulativeAck,
                _advancedPeerAckPoint,
                _out.Count,
                _flightSize,
                _congestionWindow,
                _slowStartThreshold,
                _peerReceiveWindow,
                LocalReceiveWindow(),
                _rto,
                _smoothedRtt);
        }
    }

    /// <summary>Bytes currently pinned in the out-of-order receive buffer. Test observability only.</summary>
    internal long ReceiveBufferBytes
    {
        get
        {
            lock (_lock)
            {
                return _receiveBufferBytes;
            }
        }
    }

    /// <summary>Number of out-of-order DATA chunks currently buffered. Test observability only.</summary>
    internal int BufferedChunkCount
    {
        get
        {
            lock (_lock)
            {
                return Math.Max(_fragments.Count, _received.Count);
            }
        }
    }

    /// <summary>Largest user payload, in bytes, that fits in a single DATA chunk on this transport.</summary>
    /// <remarks>
    /// When RFC 8260 interleaving has been negotiated, data travels in I-DATA chunks whose fixed
    /// header is four bytes larger, so the per-chunk payload budget shrinks accordingly.
    /// </remarks>
    public int MaxPayloadPerChunk =>
        Math.Max(
            4,
            (_lower.MaxDatagramSize
                - SctpPacket.CommonHeaderLength
                - 4
                - (UseInterleaving ? SctpIDataChunk.FixedHeaderLength : SctpDataChunk.FixedHeaderLength)) & ~3);

    /// <summary>
    /// True once both endpoints have advertised RFC 8260 I-DATA: this endpoint must be configured to
    /// enable it and the peer must have advertised it. Until both hold, data travels as classic DATA.
    /// </summary>
    private bool UseInterleaving => _config.EnableInterleaving && _peerSupportsInterleaving;

    private long InitialCongestionWindow
    {
        get
        {
            long mtu = _lower.MaxDatagramSize;
            return Math.Min(4 * mtu, Math.Max(2 * mtu, 4380));
        }
    }

    private long NowMs => (long)_time.GetElapsedTime(_startTimestamp).TotalMilliseconds;

    /// <summary>
    /// Subscribes to the lower transport and starts the internal timer. Idempotent. After this call
    /// the association answers a peer INIT even when it is not the configured initiator.
    /// </summary>
    public void Start()
    {
        lock (_lock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_started)
            {
                return;
            }

            _started = true;
            _lower.OnReceived += HandleDatagram;
            _timer = _time.CreateTimer(_ => Tick(), null, _config.TickInterval, _config.TickInterval);
            _nextHeartbeat = _config.HeartbeatInterval > TimeSpan.Zero
                ? NowMs + (long)_config.HeartbeatInterval.TotalMilliseconds
                : 0;
        }
    }

    /// <summary>
    /// Starts the association and completes once it is established. When
    /// <see cref="SctpAssociationConfig.IsInitiator"/> is set this sends INIT; otherwise it simply
    /// waits for the peer to initiate.
    /// </summary>
    /// <param name="cancellationToken">Abandons the wait; the association itself keeps running.</param>
    /// <returns>A task that completes when the association is established.</returns>
    public Task ConnectAsync(CancellationToken cancellationToken = default)
    {
        Start();
        Task task;
        lock (_lock)
        {
            if (_state == SctpAssociationState.Established)
            {
                return Task.CompletedTask;
            }

            _connectSource ??= new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            task = _connectSource.Task;
            if (_config.IsInitiator && _state == SctpAssociationState.Closed)
            {
                SendInit();
            }
        }

        DispatchEvents();
        return cancellationToken.CanBeCanceled ? task.WaitAsync(cancellationToken) : task;
    }

    /// <summary>
    /// Creates a data channel and queues its DATA_CHANNEL_OPEN. Safe to call before
    /// <see cref="ConnectAsync"/>: the open is held until the association is established and is
    /// then the first DATA chunk sent on that stream.
    /// </summary>
    /// <param name="label">Channel label.</param>
    /// <param name="ordered">Whether messages are delivered in send order.</param>
    /// <param name="maxRetransmits">
    /// Retransmission limit per message, or null for full reliability. Zero means each message is
    /// transmitted once and abandoned if lost.
    /// </param>
    /// <param name="protocol">Optional sub-protocol name.</param>
    /// <returns>The new channel, initially in <see cref="DataChannelState.Connecting"/>.</returns>
    public DataChannel CreateChannel(string label, bool ordered = true, ushort? maxRetransmits = null, string protocol = "")
    {
        ArgumentNullException.ThrowIfNull(label);
        ArgumentNullException.ThrowIfNull(protocol);
        DataChannel channel;
        lock (_lock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var streamId = AllocateStreamId();
            channel = new DataChannel(this, streamId, label, protocol, ordered, maxRetransmits, negotiatedByPeer: false);
            _channels[streamId] = channel;

            // TSNs are assignable before the association exists, so the OPEN can be queued now and
            // will be the first DATA on the wire once the handshake finishes.
            SendDcepOpen(channel);
            Flush();
        }

        DispatchEvents();
        return channel;
    }

    /// <summary>Begins a graceful shutdown (SHUTDOWN / SHUTDOWN ACK / SHUTDOWN COMPLETE).</summary>
    public void Shutdown()
    {
        lock (_lock)
        {
            if (_state != SctpAssociationState.Established)
            {
                return;
            }

            _state = SctpAssociationState.ShutdownSent;
            _shutdownAttempts = 0;
            _shutdownExpiry = NowMs + (long)_rto;
            _controlQueue.Add(new SctpShutdownChunk(_cumulativeTsnReceived));
            Flush();
        }

        DispatchEvents();
    }

    /// <summary>Tears the association down immediately by sending ABORT.</summary>
    /// <param name="reason">Human-readable reason placed in a User-Initiated-Abort cause.</param>
    public void Abort(string reason)
    {
        ArgumentNullException.ThrowIfNull(reason);
        lock (_lock)
        {
            if (_state == SctpAssociationState.Closed)
            {
                return;
            }

            var abort = new SctpAbortChunk();
            abort.Causes.Add(new SctpErrorCause(
                SctpErrorCauseCode.UserInitiatedAbort,
                System.Text.Encoding.UTF8.GetBytes(reason)));
            SendImmediate(_peerTag, abort);
            CloseInternal(new InvalidOperationException($"Association aborted locally: {reason}"));
        }

        DispatchEvents();
    }

    /// <summary>Stops timers, detaches from the transport and closes every channel.</summary>
    public void Dispose()
    {
        ITimer? timer;
        lock (_lock)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            timer = _timer;
            _timer = null;
            if (_started)
            {
                _lower.OnReceived -= HandleDatagram;
            }

            CloseInternal(null);
        }

        timer?.Dispose();
        DispatchEvents();
    }

    internal void SendOnChannel(DataChannel channel, uint payloadProtocolId, ReadOnlySpan<byte> payload)
    {
        if ((uint)payload.Length > _config.MaxMessageSize)
        {
            throw new ArgumentOutOfRangeException(
                nameof(payload),
                payload.Length,
                $"Message exceeds the configured maximum of {_config.MaxMessageSize} bytes.");
        }

        // RFC 8831 §6.6: an empty message is carried as a single padding byte with an "empty" PPID.
        var body = payload.IsEmpty ? new byte[1] : payload.ToArray();
        var userBytes = payload.Length;

        lock (_lock)
        {
            if (_state is SctpAssociationState.Closed && _started is false)
            {
                throw new InvalidOperationException("Association has not been started.");
            }

            EnqueueMessage(
                (ushort)channel.StreamId,
                payloadProtocolId,
                body,
                ordered: channel.Ordered,
                maxRetransmits: channel.MaxRetransmits,
                channel: channel,
                bufferedBytes: userBytes);
            Flush();
        }

        DispatchEvents();
    }

    private int AllocateStreamId()
    {
        // Prefer an identifier freed by a completed RFC 6525 reset so a long-lived peer that opens
        // and closes many channels does not march _nextStreamId to exhaustion.
        while (_freedStreamIds.Count > 0)
        {
            var candidate = _freedStreamIds.Min;
            _freedStreamIds.Remove(candidate);
            if (!_channels.ContainsKey(candidate))
            {
                return candidate;
            }
        }

        while (_channels.ContainsKey(_nextStreamId))
        {
            _nextStreamId += 2;
        }

        var id = _nextStreamId;
        _nextStreamId += 2;
        return id;
    }

    /// <summary>
    /// Releases every trace of a stream identifier once its channel has closed and any RFC 6525
    /// reset has completed, so a later channel can reuse it with fresh sequence-number state.
    /// </summary>
    private void FreeStreamId(ushort streamId)
    {
        _sendSequence.Remove(streamId);
        _sendOrderedMid.Remove(streamId);
        _sendUnorderedMid.Remove(streamId);
        _receiveStreams.Remove(streamId);
        _orphanMessages.Remove(streamId);
        ResetIDataStream(streamId);

        // Only identifiers this endpoint owns (matching its allocation parity) may be handed back
        // to AllocateStreamId; the peer allocates the other parity.
        var ownParity = _config.UsesEvenStreamIds ? 0 : 1;
        if (streamId % 2 == ownParity)
        {
            _freedStreamIds.Add(streamId);
        }
    }

    private static uint RandomTag()
    {
        Span<byte> bytes = stackalloc byte[4];
        uint value;
        do
        {
            RandomNumberGenerator.Fill(bytes);
            value = BinaryPrimitives.ReadUInt32BigEndian(bytes);
        }
        while (value == 0);

        return value;
    }

    // ---------------------------------------------------------------- inbound

    private void HandleDatagram(ReadOnlySpan<byte> datagram)
    {
        SctpPacket packet;
        try
        {
            packet = SctpPacket.Parse(datagram);
        }
        catch (ByteBufferException ex)
        {
            _log.Log(KeryxLogLevel.Warning, "Discarding malformed SCTP packet.", ex);
            return;
        }

        lock (_lock)
        {
            if (_disposed)
            {
                return;
            }

            if (!VerifyTag(packet))
            {
                _log.Log(KeryxLogLevel.Warning, $"Discarding SCTP packet with verification tag 0x{packet.VerificationTag:X8}.");
                return;
            }

            if (_log.IsEnabled(KeryxLogLevel.Trace))
            {
                _log.Log(KeryxLogLevel.Trace, $"SCTP in tag=0x{packet.VerificationTag:X8} [{string.Join(",", packet.Chunks.Select(c => c.Type))}] len={datagram.Length}");
            }

            foreach (var chunk in packet.Chunks)
            {
                ProcessChunk(chunk, packet);
                if (_state == SctpAssociationState.Closed)
                {
                    break;
                }
            }

            if (_sackPending)
            {
                _sackPending = false;
                _controlQueue.Add(BuildSack());
            }

            Flush();
        }

        DispatchEvents();
    }

    private bool VerifyTag(SctpPacket packet)
    {
        if (packet.Chunks.Count == 0)
        {
            return false;
        }

        var first = packet.Chunks[0];
        return first.Type switch
        {
            SctpChunkType.Init => packet.VerificationTag == 0,
            SctpChunkType.Abort => packet.VerificationTag == _localTag || packet.VerificationTag == _peerTag,
            SctpChunkType.ShutdownComplete => packet.VerificationTag == _localTag || packet.VerificationTag == _peerTag,
            _ => packet.VerificationTag == _localTag,
        };
    }

    private void ProcessChunk(SctpChunk chunk, SctpPacket packet)
    {
        switch (chunk)
        {
            case SctpInitChunk init when init.Type == SctpChunkType.Init:
                HandleInit(init);
                break;
            case SctpInitChunk initAck when initAck.Type == SctpChunkType.InitAck:
                HandleInitAck(initAck);
                break;
            case SctpCookieEchoChunk cookieEcho:
                HandleCookieEcho(cookieEcho);
                break;
            case SctpCookieAckChunk:
                HandleCookieAck();
                break;
            case SctpDataChunk data:
                HandleData(data);
                break;
            case SctpIDataChunk idata:
                HandleIData(idata);
                break;
            case SctpSackChunk sack:
                HandleSack(sack);
                break;
            case SctpForwardTsnChunk forward:
                HandleForwardTsn(forward);
                break;
            case SctpReConfigChunk reconfig:
                HandleReConfig(reconfig);
                break;
            case SctpHeartbeatChunk heartbeat when heartbeat.Type == SctpChunkType.Heartbeat:
                _controlQueue.Add(new SctpHeartbeatChunk(SctpChunkType.HeartbeatAck, heartbeat.Info));
                break;
            case SctpHeartbeatChunk heartbeatAck when heartbeatAck.Type == SctpChunkType.HeartbeatAck:
                HandleHeartbeatAck(heartbeatAck);
                break;
            case SctpAbortChunk abort:
                HandleAbort(abort);
                break;
            case SctpShutdownChunk shutdown:
                HandleShutdown(shutdown);
                break;
            case SctpShutdownAckChunk:
                SendImmediate(_peerTag, new SctpShutdownCompleteChunk());
                CloseInternal(null);
                break;
            case SctpShutdownCompleteChunk:
                CloseInternal(null);
                break;
            case SctpErrorChunk error:
                _log.Log(KeryxLogLevel.Warning, $"Peer reported {error.Causes.Count} SCTP error cause(s).");
                break;
            default:
                _log.Log(KeryxLogLevel.Debug, $"Ignoring unhandled chunk type {chunk.Type} from tag 0x{packet.VerificationTag:X8}.");
                break;
        }
    }

    private void HandleInit(SctpInitChunk init)
    {
        if (_state == SctpAssociationState.Established)
        {
            // A full implementation would run the RFC 9260 §5.2 restart/collision procedures.
            _log.Log(KeryxLogLevel.Warning, "Ignoring INIT received while established; association restart is not implemented.");
            return;
        }

        if (init.InitiateTag == 0)
        {
            SendImmediate(0, MakeAbort(SctpErrorCauseCode.InvalidMandatoryParameter, "zero initiate tag"));
            return;
        }

        var outbound = Math.Min(_config.OutboundStreams, init.NumberOfInboundStreams);
        var inbound = Math.Min(_config.InboundStreams, init.NumberOfOutboundStreams);
        var cookie = BuildCookie(init, outbound, inbound);

        var initAck = new SctpInitChunk(SctpChunkType.InitAck)
        {
            InitiateTag = _localTag,
            AdvertisedReceiverWindow = LocalReceiveWindow(),
            NumberOfOutboundStreams = outbound,
            NumberOfInboundStreams = inbound,
            InitialTsn = _localInitialTsn,
        };
        initAck.Parameters.Add(new SctpParameter(SctpParameterType.StateCookie, cookie));
        initAck.Parameters.Add(new SctpParameter(SctpParameterType.ForwardTsnSupported, Array.Empty<byte>()));
        initAck.Parameters.Add(new SctpParameter(SctpParameterType.SupportedExtensions, SupportedExtensions()));

        SendImmediate(init.InitiateTag, initAck);
        _log.Log(KeryxLogLevel.Debug, "Answered INIT with a stateless INIT ACK.");
    }

    private void HandleInitAck(SctpInitChunk initAck)
    {
        if (_state != SctpAssociationState.CookieWait)
        {
            return;
        }

        var cookie = initAck.StateCookie;
        if (cookie is null)
        {
            Fail(new InvalidOperationException("INIT ACK did not carry a state cookie."));
            return;
        }

        AdoptPeerParameters(
            initAck.InitiateTag,
            initAck.InitialTsn,
            initAck.AdvertisedReceiverWindow,
            Math.Min(_config.OutboundStreams, initAck.NumberOfInboundStreams),
            Math.Min(_config.InboundStreams, initAck.NumberOfOutboundStreams),
            initAck.ForwardTsnSupported,
            initAck.ReconfigSupported,
            initAck.InterleavingSupported);

        _pendingInit = null;
        _pendingCookieEcho = new SctpCookieEchoChunk(cookie);
        _state = SctpAssociationState.CookieEchoed;
        _initAttempts = 0;
        _initExpiry = NowMs + (long)_rto;
        _controlQueue.Add(_pendingCookieEcho);
    }

    private void HandleCookieEcho(SctpCookieEchoChunk cookieEcho)
    {
        if (!TryReadCookie(cookieEcho.Cookie, out var peerTag, out var peerInitialTsn, out var peerRwnd, out var outbound, out var inbound, out var forwardTsn, out var reconfig, out var interleaving))
        {
            _log.Log(KeryxLogLevel.Warning, "Rejecting COOKIE ECHO: cookie failed validation.");
            var abort = MakeAbort(SctpErrorCauseCode.StaleCookieError, "invalid or expired state cookie");
            abort.TagReflected = true;
            SendImmediate(_peerTag, abort);
            return;
        }

        if (_state == SctpAssociationState.Established && _peerTag == peerTag)
        {
            _controlQueue.Add(new SctpCookieAckChunk());
            return;
        }

        AdoptPeerParameters(peerTag, peerInitialTsn, peerRwnd, outbound, inbound, forwardTsn, reconfig, interleaving);
        _controlQueue.Add(new SctpCookieAckChunk());
        Establish();
    }

    private void HandleCookieAck()
    {
        if (_state != SctpAssociationState.CookieEchoed)
        {
            return;
        }

        _pendingCookieEcho = null;
        _initExpiry = 0;
        Establish();
    }

    private void AdoptPeerParameters(uint peerTag, uint peerInitialTsn, uint peerRwnd, ushort outbound, ushort inbound, bool forwardTsn, bool reconfig, bool interleaving)
    {
        _peerTag = peerTag;
        _peerReceiveWindow = peerRwnd;
        _outboundStreams = outbound;
        _inboundStreams = inbound;
        _peerSupportsForwardTsn = forwardTsn;
        _peerSupportsReconfig = reconfig;
        _peerSupportsInterleaving = interleaving;
        _cumulativeTsnReceived = unchecked(peerInitialTsn - 1);
        _reconfigNextExpectedRemoteSeq = peerInitialTsn;
    }

    private void Establish()
    {
        _state = SctpAssociationState.Established;
        _congestionWindow = InitialCongestionWindow;
        _slowStartThreshold = Math.Max(_peerReceiveWindow, InitialCongestionWindow);
        _partialBytesAcked = 0;
        RestampQueuedForInterleaving();
        _log.Log(KeryxLogLevel.Info, $"SCTP association established (peer tag 0x{_peerTag:X8}, forward-TSN {_peerSupportsForwardTsn}).");

        var source = _connectSource;
        _events.Add(() =>
        {
            OnAssociated?.Invoke();
            source?.TrySetResult();
        });
    }

    /// <summary>
    /// Converts data queued before the handshake completed to the negotiated transmission mode.
    /// Channels may be created (and their DCEP OPEN queued) before <see cref="ConnectAsync"/>, at
    /// which point interleaving is not yet known; once it is, any not-yet-transmitted chunk is
    /// re-stamped as I-DATA with a freshly allocated MID so the whole association speaks one wire
    /// format rather than mixing classic DATA with I-DATA.
    /// </summary>
    private void RestampQueuedForInterleaving()
    {
        if (!UseInterleaving)
        {
            return;
        }

        var currentMessageId = int.MinValue;
        uint mid = 0;
        uint fsn = 0;
        foreach (var chunk in _out)
        {
            if (chunk.Interleaved || chunk.Transmits > 0 || chunk.Acked || chunk.Abandoned)
            {
                continue;
            }

            // Fragments of a message keep their enqueue order in _out, so a change of message id
            // marks a new message: allocate its MID and restart the fragment sequence number.
            if (chunk.MessageId != currentMessageId)
            {
                currentMessageId = chunk.MessageId;
                var midMap = chunk.Unordered ? _sendUnorderedMid : _sendOrderedMid;
                midMap.TryGetValue(chunk.StreamId, out mid);
                midMap[chunk.StreamId] = unchecked(mid + 1);
                fsn = 0;
            }

            chunk.Interleaved = true;
            chunk.MessageIdentifier = mid;
            chunk.FragmentSequenceNumber = fsn;
            fsn = unchecked(fsn + 1);
        }
    }

    private void HandleAbort(SctpAbortChunk abort)
    {
        var reason = abort.Causes.Count > 0 ? $"cause {abort.Causes[0].Code}" : "no cause given";
        CloseInternal(new InvalidOperationException($"Peer aborted the association ({reason})."));
    }

    private void HandleShutdown(SctpShutdownChunk shutdown)
    {
        AckUpTo(shutdown.CumulativeTsnAck);
        _state = SctpAssociationState.ShutdownAckSent;
        _controlQueue.Add(new SctpShutdownAckChunk());
        _shutdownExpiry = NowMs + (long)_rto;
        _shutdownAttempts = 0;
    }

    // ------------------------------------------------------------ data receive

    private void HandleData(SctpDataChunk data)
    {
        if (_state is SctpAssociationState.Closed or SctpAssociationState.CookieWait)
        {
            return;
        }

        _sackPending = true;

        if (Serial.Lte(data.Tsn, _cumulativeTsnReceived) || _received.Contains(data.Tsn))
        {
            if (_duplicateTsns.Count < 32)
            {
                _duplicateTsns.Add(data.Tsn);
            }

            return;
        }

        if (data.StreamId >= _inboundStreams)
        {
            _log.Log(KeryxLogLevel.Warning, $"Discarding DATA for out-of-range stream {data.StreamId}.");
            return;
        }

        // A chunk that fills the immediate gap (TSN == cumulative + 1) always makes forward
        // progress: it advances the cumulative TSN and lets buffered fragments drain, so it
        // is never subject to the hard cap even when the buffer is momentarily full. Every
        // other out-of-order chunk only extends a gap; if buffering it would breach the hard
        // cap we drop it (do not buffer, do not ack). A compliant peer honours the zero a_rwnd
        // we advertise long before this and will retransmit once the window reopens; a hostile
        // peer flooding a never-filling gap is bounded to the cap instead of exhausting memory.
        var advancesCumulative = data.Tsn == unchecked(_cumulativeTsnReceived + 1);
        if (!advancesCumulative && WouldExceedReceiveBuffer(data.Payload.Length))
        {
            _log.Log(
                KeryxLogLevel.Warning,
                $"Dropping out-of-order DATA (TSN {data.Tsn}): receive buffer at hard cap " +
                $"({_receiveBufferBytes} bytes / {_fragments.Count} chunks, cap {ReceiveBufferHardCap}).");
            return;
        }

        _received.Add(data.Tsn);
        _fragments[data.Tsn] = data;
        _receiveBufferBytes += data.Payload.Length;
        AdvanceCumulativeReceive();
        TryReassemble(data.Tsn);
        ProcessDeferredIncomingResets();

        // Even in-order chunks can pin memory without bound when a message never terminates
        // (a run of B/continuation fragments whose E-fragment never arrives): the cumulative
        // TSN advances but _fragments never drains. If the buffer stays above the hard cap
        // after attempting reassembly there is no legitimate way to recover it, so abort with
        // an Out-of-Resource cause rather than let a hostile peer OOM the host.
        if (_receiveBufferBytes > (long)ReceiveBufferHardCap || _fragments.Count > MaxBufferedChunks)
        {
            _log.Log(
                KeryxLogLevel.Warning,
                $"Aborting association: out-of-order receive buffer exceeded hard cap " +
                $"({_receiveBufferBytes} bytes / {_fragments.Count} chunks, cap {ReceiveBufferHardCap}).");
            AbortInternal(SctpErrorCauseCode.OutOfResource, "receive buffer exhausted");
        }
    }

    /// <summary>
    /// The hard ceiling on out-of-order receive buffering. <see cref="LocalReceiveWindow"/>
    /// advertises a shrinking a_rwnd as a hint, but a hostile peer can ignore it, so this
    /// caps the memory a peer can pin. We take the larger of the configured receive window
    /// and the maximum message size so a single legitimately fragmented message can still be
    /// reassembled even when the window is configured smaller than one message.
    /// </summary>
    internal ulong ReceiveBufferHardCap =>
        Math.Max(_config.ReceiveWindow, _config.MaxMessageSize);

    /// <summary>
    /// Companion cap on the number of buffered out-of-order chunks, derived from the byte cap
    /// assuming a minimum charge per chunk. Bounds _received/_fragments against a flood of
    /// tiny or empty DATA chunks that barely move the byte total but each cost a map entry.
    /// </summary>
    internal int MaxBufferedChunks =>
        (int)Math.Min((ulong)int.MaxValue, ReceiveBufferHardCap / (ulong)MinChunkBufferCharge);

    /// <summary>
    /// Returns <c>true</c> when buffering another out-of-order chunk of
    /// <paramref name="incomingLength"/> bytes would breach the hard cap on either buffered
    /// bytes or buffered chunk count.
    /// </summary>
    private bool WouldExceedReceiveBuffer(int incomingLength) =>
        (ulong)(_receiveBufferBytes + incomingLength) > ReceiveBufferHardCap
        || _received.Count >= MaxBufferedChunks
        || _fragments.Count >= MaxBufferedChunks;

    /// <summary>Sends an ABORT with the given cause and tears the association down locally.</summary>
    private void AbortInternal(SctpErrorCauseCode cause, string detail)
    {
        if (_state == SctpAssociationState.Closed)
        {
            return;
        }

        SendImmediate(_peerTag, MakeAbort(cause, detail));
        CloseInternal(new InvalidOperationException($"Association aborted: {detail}."));
    }

    private void AdvanceCumulativeReceive()
    {
        while (_received.Remove(unchecked(_cumulativeTsnReceived + 1)))
        {
            _cumulativeTsnReceived = unchecked(_cumulativeTsnReceived + 1);
        }
    }

    private void TryReassemble(uint tsn)
    {
        if (!_fragments.TryGetValue(tsn, out var chunk))
        {
            return;
        }

        var start = tsn;
        while (!_fragments[start].Beginning)
        {
            var previous = unchecked(start - 1);
            if (!_fragments.ContainsKey(previous))
            {
                return;
            }

            start = previous;
        }

        var end = tsn;
        while (!_fragments[end].Ending)
        {
            var next = unchecked(end + 1);
            if (!_fragments.ContainsKey(next))
            {
                return;
            }

            end = next;
        }

        var total = 0;
        for (var t = start; ; t = unchecked(t + 1))
        {
            total += _fragments[t].Payload.Length;
            if (t == end)
            {
                break;
            }
        }

        if ((uint)total > _config.MaxMessageSize)
        {
            _log.Log(KeryxLogLevel.Warning, $"Dropping oversized inbound message of {total} bytes on stream {chunk.StreamId}.");
            DropRange(start, end);
            return;
        }

        var payload = new byte[total];
        var offset = 0;
        for (var t = start; ; t = unchecked(t + 1))
        {
            var fragment = _fragments[t];
            fragment.Payload.CopyTo(payload, offset);
            offset += fragment.Payload.Length;
            if (t == end)
            {
                break;
            }
        }

        var head = _fragments[start];
        DropRange(start, end);

        var message = new ReassembledMessage
        {
            StreamId = head.StreamId,
            PayloadProtocolId = head.PayloadProtocolId,
            Payload = payload,
        };

        if (head.Unordered)
        {
            DeliverMessage(message);
            return;
        }

        var stream = GetReceiveStream(head.StreamId);
        if (head.StreamSequence == stream.NextSequence)
        {
            DeliverMessage(message);
            stream.NextSequence = unchecked((ushort)(stream.NextSequence + 1));
            DrainOrdered(stream);
        }
        else if (Serial.Gt16(head.StreamSequence, stream.NextSequence))
        {
            stream.Buffered[head.StreamSequence] = message;
        }
    }

    private void DropRange(uint start, uint end)
    {
        for (var t = start; ; t = unchecked(t + 1))
        {
            if (_fragments.Remove(t, out var removed))
            {
                _receiveBufferBytes -= removed.Payload.Length;
            }

            if (t == end)
            {
                break;
            }
        }
    }

    private void DrainOrdered(ReceiveStream stream)
    {
        while (stream.Buffered.Remove(stream.NextSequence, out var next))
        {
            DeliverMessage(next);
            stream.NextSequence = unchecked((ushort)(stream.NextSequence + 1));
        }
    }

    private ReceiveStream GetReceiveStream(ushort streamId)
    {
        if (!_receiveStreams.TryGetValue(streamId, out var stream))
        {
            stream = new ReceiveStream();
            _receiveStreams[streamId] = stream;
        }

        return stream;
    }

    /// <summary>
    /// Handles an inbound RFC 8260 I-DATA chunk. The out-of-order/duplicate/flow-control bookkeeping
    /// is identical to <see cref="HandleData"/> — the TSN space, the cumulative acknowledgement and
    /// the receive-buffer caps are shared — but fragments are collected by (stream, MID) and ordered
    /// by FSN rather than by a contiguous TSN run, so an interleaved fragment stream reassembles
    /// correctly and a large message never blocks small messages arriving on other streams.
    /// </summary>
    private void HandleIData(SctpIDataChunk data)
    {
        if (_state is SctpAssociationState.Closed or SctpAssociationState.CookieWait)
        {
            return;
        }

        _sackPending = true;

        if (Serial.Lte(data.Tsn, _cumulativeTsnReceived) || _received.Contains(data.Tsn))
        {
            if (_duplicateTsns.Count < 32)
            {
                _duplicateTsns.Add(data.Tsn);
            }

            return;
        }

        if (data.StreamId >= _inboundStreams)
        {
            _log.Log(KeryxLogLevel.Warning, $"Discarding I-DATA for out-of-range stream {data.StreamId}.");
            return;
        }

        var advancesCumulative = data.Tsn == unchecked(_cumulativeTsnReceived + 1);
        if (!advancesCumulative && WouldExceedReceiveBuffer(data.Payload.Length))
        {
            _log.Log(
                KeryxLogLevel.Warning,
                $"Dropping out-of-order I-DATA (TSN {data.Tsn}): receive buffer at hard cap " +
                $"({_receiveBufferBytes} bytes / {_iDataBufferedFragments} fragments, cap {ReceiveBufferHardCap}).");
            return;
        }

        _received.Add(data.Tsn);
        AdvanceCumulativeReceive();
        BufferIData(data);
        ProcessDeferredIncomingResets();

        if (_receiveBufferBytes > (long)ReceiveBufferHardCap || _iDataBufferedFragments > MaxBufferedChunks)
        {
            _log.Log(
                KeryxLogLevel.Warning,
                $"Aborting association: out-of-order I-DATA receive buffer exceeded hard cap " +
                $"({_receiveBufferBytes} bytes / {_iDataBufferedFragments} fragments, cap {ReceiveBufferHardCap}).");
            AbortInternal(SctpErrorCauseCode.OutOfResource, "receive buffer exhausted");
        }
    }

    private void BufferIData(SctpIDataChunk data)
    {
        var key = new IDataKey(data.StreamId, data.Unordered, data.MessageIdentifier);
        if (!_iDataReassembly.TryGetValue(key, out var entry))
        {
            entry = new IDataReassembly();
            _iDataReassembly[key] = entry;
        }

        // The beginning fragment has an implicit FSN of zero and carries the PPID in place of the FSN.
        var fsn = data.Beginning ? 0u : data.FragmentSequenceNumber;
        if (!entry.Fragments.ContainsKey(fsn))
        {
            entry.Fragments[fsn] = (data.Payload, data.Tsn);
            entry.ByteCount += data.Payload.Length;
            _iDataTsnIndex[data.Tsn] = (key, fsn);
            _iDataBufferedFragments++;
            _receiveBufferBytes += data.Payload.Length;
        }

        if (data.Beginning)
        {
            entry.HasBeginning = true;
            entry.PayloadProtocolId = data.PayloadProtocolId;
        }

        if (data.Ending)
        {
            entry.HasEnd = true;
            entry.EndFsn = fsn;
        }

        TryReassembleIData(key, entry);
    }

    private void TryReassembleIData(IDataKey key, IDataReassembly entry)
    {
        if (!entry.IsComplete)
        {
            return;
        }

        var total = entry.ByteCount;
        var ppid = entry.PayloadProtocolId;
        EvictIDataEntry(key, entry);

        if ((uint)total > _config.MaxMessageSize)
        {
            _log.Log(KeryxLogLevel.Warning, $"Dropping oversized inbound message of {total} bytes on stream {key.StreamId}.");
            return;
        }

        var payload = new byte[total];
        var offset = 0;
        foreach (var fragment in entry.Fragments.Values)
        {
            fragment.Payload.CopyTo(payload, offset);
            offset += fragment.Payload.Length;
        }

        var message = new ReassembledMessage
        {
            StreamId = key.StreamId,
            PayloadProtocolId = ppid,
            Payload = payload,
        };

        if (key.Unordered)
        {
            DeliverMessage(message);
            return;
        }

        var stream = GetIDataReceiveStream(key.StreamId);
        if (key.MessageId == stream.NextMessageId)
        {
            DeliverMessage(message);
            stream.NextMessageId = unchecked(stream.NextMessageId + 1);
            DrainIDataOrdered(stream);
        }
        else if (Serial.Gt(key.MessageId, stream.NextMessageId))
        {
            stream.Buffered[key.MessageId] = message;
        }
    }

    private void DrainIDataOrdered(IDataReceiveStream stream)
    {
        while (stream.Buffered.Remove(stream.NextMessageId, out var next))
        {
            DeliverMessage(next);
            stream.NextMessageId = unchecked(stream.NextMessageId + 1);
        }
    }

    /// <summary>Removes an I-DATA reassembly entry and releases the receive-buffer it charged.</summary>
    private void EvictIDataEntry(IDataKey key, IDataReassembly entry)
    {
        foreach (var fragment in entry.Fragments.Values)
        {
            _iDataTsnIndex.Remove(fragment.Tsn);
        }

        _receiveBufferBytes -= entry.ByteCount;
        _iDataBufferedFragments -= entry.Fragments.Count;
        _iDataReassembly.Remove(key);
    }

    private IDataReceiveStream GetIDataReceiveStream(ushort streamId)
    {
        if (!_iDataReceiveStreams.TryGetValue(streamId, out var stream))
        {
            stream = new IDataReceiveStream();
            _iDataReceiveStreams[streamId] = stream;
        }

        return stream;
    }

    /// <summary>
    /// Discards a single buffered I-DATA fragment whose TSN a FORWARD TSN has skipped past, freeing
    /// the receive-buffer it charged. When this empties a partially reassembled message the whole
    /// entry is dropped, since its remaining fragments can never form a complete message.
    /// </summary>
    private void DropIDataFragmentByTsn(uint tsn)
    {
        if (!_iDataTsnIndex.Remove(tsn, out var located))
        {
            return;
        }

        if (!_iDataReassembly.TryGetValue(located.Key, out var entry)
            || !entry.Fragments.Remove(located.Fsn, out var fragment))
        {
            return;
        }

        _receiveBufferBytes -= fragment.Payload.Length;
        _iDataBufferedFragments--;
        entry.ByteCount -= fragment.Payload.Length;

        if (entry.Fragments.Count == 0)
        {
            _iDataReassembly.Remove(located.Key);
        }
    }

    /// <summary>Drops every buffered I-DATA fragment and ordered-delivery state for a stream.</summary>
    private void ResetIDataStream(ushort streamId)
    {
        _iDataReceiveStreams.Remove(streamId);

        var keys = new List<IDataKey>();
        foreach (var key in _iDataReassembly.Keys)
        {
            if (key.StreamId == streamId)
            {
                keys.Add(key);
            }
        }

        foreach (var key in keys)
        {
            EvictIDataEntry(key, _iDataReassembly[key]);
        }
    }

    private void DeliverMessage(ReassembledMessage message)
    {
        if (message.PayloadProtocolId == SctpPpid.Dcep)
        {
            HandleDcep(message);
            return;
        }

        if (!_channels.TryGetValue(message.StreamId, out var channel))
        {
            // An unordered user message can overtake the ordered DCEP OPEN that creates its
            // channel; hold a bounded number of messages until the OPEN lands.
            if (!_orphanMessages.TryGetValue(message.StreamId, out var pending))
            {
                pending = new List<ReassembledMessage>();
                _orphanMessages[message.StreamId] = pending;
            }

            if (pending.Count < 16)
            {
                pending.Add(message);
            }

            return;
        }

        RaiseMessage(channel, message);
    }

    private void RaiseMessage(DataChannel channel, ReassembledMessage message)
    {
        var isBinary = message.PayloadProtocolId is SctpPpid.Binary or SctpPpid.BinaryEmpty or SctpPpid.BinaryPartial;
        var empty = message.PayloadProtocolId is SctpPpid.StringEmpty or SctpPpid.BinaryEmpty;
        var payload = empty ? Array.Empty<byte>() : message.Payload;
        _events.Add(() => channel.RaiseMessage(isBinary, payload));
    }

    private void HandleDcep(ReassembledMessage message)
    {
        if (message.Payload.Length == 0)
        {
            return;
        }

        switch ((DcepMessageType)message.Payload[0])
        {
            case DcepMessageType.DataChannelOpen:
                HandleDcepOpen(message);
                break;
            case DcepMessageType.DataChannelAck:
                if (_channels.TryGetValue(message.StreamId, out var channel) && channel.State == DataChannelState.Connecting)
                {
                    channel.State = DataChannelState.Open;
                    _events.Add(channel.RaiseOpen);
                }

                break;
            default:
                _log.Log(KeryxLogLevel.Warning, $"Unknown DCEP message type 0x{message.Payload[0]:X2} on stream {message.StreamId}.");
                break;
        }
    }

    private void HandleDcepOpen(ReassembledMessage message)
    {
        DcepOpenMessage open;
        try
        {
            open = DcepOpenMessage.Parse(message.Payload);
        }
        catch (ByteBufferException ex)
        {
            _log.Log(KeryxLogLevel.Warning, $"Discarding malformed DCEP OPEN on stream {message.StreamId}.", ex);
            return;
        }

        var channel = new DataChannel(
            this,
            message.StreamId,
            open.Label,
            open.Protocol,
            ordered: !open.Unordered,
            maxRetransmits: open.MaxRetransmits,
            negotiatedByPeer: true);
        _channels[message.StreamId] = channel;

        // The acknowledgement travels ordered on the same stream, ahead of any user data we send.
        EnqueueMessage(
            message.StreamId,
            SctpPpid.Dcep,
            DcepOpenMessage.EncodeAck(),
            ordered: true,
            maxRetransmits: null,
            channel: null,
            bufferedBytes: 0);

        channel.State = DataChannelState.Open;
        _events.Add(() =>
        {
            OnChannelOpened?.Invoke(channel);
            channel.RaiseOpen();
        });

        if (_orphanMessages.Remove(message.StreamId, out var orphans))
        {
            foreach (var orphan in orphans)
            {
                RaiseMessage(channel, orphan);
            }
        }
    }

    private void SendDcepOpen(DataChannel channel)
    {
        var open = new DcepOpenMessage(
            DcepOpenMessage.ChannelTypeFor(channel.Ordered, channel.MaxRetransmits),
            channel.Label,
            channel.Protocol,
            priority: 0,
            reliabilityParameter: channel.MaxRetransmits ?? 0);

        // RFC 8832 §5.1: DATA_CHANNEL_OPEN is always sent with ordered delivery, even for an
        // unordered channel, so it cannot be overtaken by the channel's own traffic.
        EnqueueMessage(
            (ushort)channel.StreamId,
            SctpPpid.Dcep,
            open.Encode(),
            ordered: true,
            maxRetransmits: null,
            channel: null,
            bufferedBytes: 0);
    }

    // -------------------------------------------- stream reconfiguration (RFC 6525)

    /// <summary>
    /// Begins closing a channel. When the peer negotiated RE-CONFIG this drives an outgoing stream
    /// reset (deferred until the channel's data is acknowledged); otherwise the channel closes
    /// immediately. The stream identifier is freed for reuse once the reset completes.
    /// </summary>
    internal void CloseChannel(DataChannel channel)
    {
        lock (_lock)
        {
            if (channel.State is DataChannelState.Closed or DataChannelState.Closing)
            {
                return;
            }

            var streamId = (ushort)channel.StreamId;

            // No association or no negotiated RE-CONFIG means there is no wire reset to drive:
            // close locally and hand the identifier back right away.
            if (_state != SctpAssociationState.Established || !_peerSupportsReconfig)
            {
                _channels.Remove(channel.StreamId);
                channel.State = DataChannelState.Closed;
                FreeStreamId(streamId);
                _events.Add(channel.RaiseClosed);
            }
            else
            {
                channel.State = DataChannelState.Closing;
                if (!_pendingResetStreams.Contains(streamId))
                {
                    _pendingResetStreams.Add(streamId);
                }

                TryStartOutgoingReset();
                Flush();
            }
        }

        DispatchEvents();
    }

    /// <summary>
    /// Starts an outgoing RE-CONFIG for the queued streams whose data has drained, if none is
    /// already in flight. RFC 6525 §5.1 permits only one outstanding request at a time and forbids
    /// resetting a stream that still has unacknowledged data, so undrained streams stay queued.
    /// </summary>
    private void TryStartOutgoingReset()
    {
        if (_outstandingReset is not null || !_peerSupportsReconfig || _pendingResetStreams.Count == 0)
        {
            return;
        }

        var ready = new List<ushort>();
        foreach (var streamId in _pendingResetStreams)
        {
            if (!HasOutstandingDataOnStream(streamId))
            {
                ready.Add(streamId);
            }
        }

        if (ready.Count == 0)
        {
            return;
        }

        foreach (var streamId in ready)
        {
            _pendingResetStreams.Remove(streamId);
        }

        var requestSeq = _reconfigNextSeq;
        _reconfigNextSeq = unchecked(_reconfigNextSeq + 1);

        _outstandingReset = new OutstandingReset
        {
            RequestSequence = requestSeq,
            ResponseSequence = unchecked(_reconfigNextExpectedRemoteSeq - 1),
            SendersLastAssignedTsn = unchecked(_nextTsn - 1),
            Streams = ready,
        };
        _reconfigAttempts = 0;
        _reconfigExpiry = NowMs + (long)_rto;
        _controlQueue.Add(BuildOutgoingResetChunk(_outstandingReset));
        _log.Log(KeryxLogLevel.Debug, $"Sending RE-CONFIG (seq {requestSeq}) resetting stream(s) {string.Join(",", ready)}.");
    }

    private static SctpReConfigChunk BuildOutgoingResetChunk(OutstandingReset reset) =>
        new(new SctpOutgoingSsnResetRequest(
            reset.RequestSequence,
            reset.ResponseSequence,
            reset.SendersLastAssignedTsn,
            reset.Streams));

    private bool HasOutstandingDataOnStream(ushort streamId)
    {
        foreach (var chunk in _out)
        {
            if (chunk.StreamId == streamId && !chunk.Acked && !chunk.Abandoned)
            {
                return true;
            }
        }

        return false;
    }

    private void HandleReConfig(SctpReConfigChunk chunk)
    {
        if (_state is SctpAssociationState.Closed or SctpAssociationState.CookieWait)
        {
            return;
        }

        var responses = new List<SctpReconfigParameter>();
        foreach (var parameter in chunk.Parameters)
        {
            switch (parameter)
            {
                case SctpOutgoingSsnResetRequest request:
                    HandleOutgoingResetRequest(request, responses);
                    break;
                case SctpIncomingSsnResetRequest request:
                    HandleIncomingResetRequest(request, responses);
                    break;
                case SctpReconfigResponse response:
                    HandleReconfigResponse(response);
                    break;
                default:
                    _log.Log(KeryxLogLevel.Debug, $"Ignoring unhandled RE-CONFIG parameter 0x{(ushort)parameter.Type:X4}.");
                    break;
            }
        }

        if (responses.Count > 0)
        {
            _controlQueue.Add(new SctpReConfigChunk(responses.ToArray()));
        }
    }

    /// <summary>Handles the peer resetting its outgoing streams (our incoming streams).</summary>
    private void HandleOutgoingResetRequest(SctpOutgoingSsnResetRequest request, List<SctpReconfigParameter> responses)
    {
        // A retransmission of a request already performed: re-send success without resetting again.
        if (_hasRemoteResetSeq && !Serial.Gt(request.RequestSequence, _lastRemoteResetSeq))
        {
            responses.Add(new SctpReconfigResponse(request.RequestSequence, SctpReconfigResult.SuccessPerformed));
            return;
        }

        // RFC 6525 §5.2.2: defer until every TSN the peer assigned through Sender's Last Assigned
        // TSN has been received, so the reset stays in order with the stream's data.
        if (Serial.Gt(request.SendersLastAssignedTsn, _cumulativeTsnReceived))
        {
            if (!_deferredIncomingResets.Any(r => r.RequestSequence == request.RequestSequence))
            {
                _deferredIncomingResets.Add(request);
            }

            responses.Add(new SctpReconfigResponse(request.RequestSequence, SctpReconfigResult.InProgress));
            return;
        }

        PerformIncomingReset(request);
        responses.Add(new SctpReconfigResponse(request.RequestSequence, SctpReconfigResult.SuccessPerformed));
    }

    /// <summary>
    /// Handles the peer asking this endpoint to reset its outgoing streams by queuing an outgoing
    /// reset for them and acknowledging the request.
    /// </summary>
    private void HandleIncomingResetRequest(SctpIncomingSsnResetRequest request, List<SctpReconfigParameter> responses)
    {
        foreach (var streamId in request.Streams)
        {
            if (!_pendingResetStreams.Contains(streamId))
            {
                _pendingResetStreams.Add(streamId);
            }
        }

        TryStartOutgoingReset();
        responses.Add(new SctpReconfigResponse(request.RequestSequence, SctpReconfigResult.SuccessPerformed));
    }

    private void PerformIncomingReset(SctpOutgoingSsnResetRequest request)
    {
        var streams = request.Streams.Count > 0
            ? (IReadOnlyList<ushort>)request.Streams
            : _receiveStreams.Keys.ToArray();
        foreach (var streamId in streams)
        {
            ResetStream(streamId, peerInitiated: true);
        }

        _hasRemoteResetSeq = true;
        _lastRemoteResetSeq = request.RequestSequence;
        if (Serial.Gte(request.RequestSequence, _reconfigNextExpectedRemoteSeq))
        {
            _reconfigNextExpectedRemoteSeq = unchecked(request.RequestSequence + 1);
        }
    }

    /// <summary>
    /// Resets a stream's sequence-number state. When the reset was peer-initiated and a channel is
    /// still open on the identifier that this endpoint did not itself close, the channel is closed
    /// and the identifier freed for reuse.
    /// </summary>
    private void ResetStream(ushort streamId, bool peerInitiated)
    {
        if (_receiveStreams.TryGetValue(streamId, out var stream))
        {
            stream.NextSequence = 0;
            stream.Buffered.Clear();
        }

        ResetIDataStream(streamId);

        if (!peerInitiated)
        {
            return;
        }

        if (_channels.TryGetValue(streamId, out var channel))
        {
            // A channel we are already resetting (Closing) is finalised by our own response path.
            if (channel.State == DataChannelState.Closing)
            {
                return;
            }

            _channels.Remove(streamId);
            if (channel.State != DataChannelState.Closed)
            {
                channel.State = DataChannelState.Closed;
                _events.Add(channel.RaiseClosed);
            }
        }

        FreeStreamId(streamId);
    }

    private void HandleReconfigResponse(SctpReconfigResponse response)
    {
        if (_outstandingReset is null || response.ResponseSequence != _outstandingReset.RequestSequence)
        {
            return;
        }

        if (response.Result == SctpReconfigResult.InProgress)
        {
            // The peer deferred; keep the request outstanding and let the timer retransmit.
            return;
        }

        if (response.Result is not (SctpReconfigResult.SuccessPerformed or SctpReconfigResult.SuccessNothingToDo))
        {
            _log.Log(KeryxLogLevel.Warning, $"Peer rejected stream reset (result {response.Result}); freeing streams locally.");
        }

        FinalizeOutgoingReset(_outstandingReset);
        _outstandingReset = null;
        _reconfigExpiry = 0;
        _reconfigAttempts = 0;
        TryStartOutgoingReset();
    }

    private void FinalizeOutgoingReset(OutstandingReset reset)
    {
        foreach (var streamId in reset.Streams)
        {
            if (_channels.Remove(streamId, out var channel) && channel.State != DataChannelState.Closed)
            {
                channel.State = DataChannelState.Closed;
                _events.Add(channel.RaiseClosed);
            }

            FreeStreamId(streamId);
        }
    }

    private void ProcessDeferredIncomingResets()
    {
        if (_deferredIncomingResets.Count == 0)
        {
            return;
        }

        var responses = new List<SctpReconfigParameter>();
        for (var i = 0; i < _deferredIncomingResets.Count; i++)
        {
            var request = _deferredIncomingResets[i];
            if (Serial.Gt(request.SendersLastAssignedTsn, _cumulativeTsnReceived))
            {
                continue;
            }

            _deferredIncomingResets.RemoveAt(i--);
            PerformIncomingReset(request);
            responses.Add(new SctpReconfigResponse(request.RequestSequence, SctpReconfigResult.SuccessPerformed));
        }

        if (responses.Count > 0)
        {
            _controlQueue.Add(new SctpReConfigChunk(responses.ToArray()));
        }
    }

    private void HandleForwardTsn(SctpForwardTsnChunk forward)
    {
        _sackPending = true;

        if (Serial.Gt(forward.NewCumulativeTsn, _cumulativeTsnReceived))
        {
            for (var t = unchecked(_cumulativeTsnReceived + 1); Serial.Lte(t, forward.NewCumulativeTsn); t = unchecked(t + 1))
            {
                _received.Remove(t);
                if (_fragments.Remove(t, out var removed))
                {
                    _receiveBufferBytes -= removed.Payload.Length;
                }

                DropIDataFragmentByTsn(t);
            }

            _cumulativeTsnReceived = forward.NewCumulativeTsn;
            AdvanceCumulativeReceive();
        }

        foreach (var entry in forward.Streams)
        {
            var stream = GetReceiveStream(entry.StreamId);
            if (!Serial.Gte16(entry.StreamSequence, stream.NextSequence))
            {
                continue;
            }

            var skipped = new List<ushort>();
            foreach (var buffered in stream.Buffered.Keys)
            {
                if (!Serial.Gt16(buffered, entry.StreamSequence))
                {
                    skipped.Add(buffered);
                }
            }

            foreach (var key in skipped)
            {
                stream.Buffered.Remove(key);
            }

            stream.NextSequence = unchecked((ushort)(entry.StreamSequence + 1));
            DrainOrdered(stream);
        }

        ProcessDeferredIncomingResets();
    }

    private void HandleHeartbeatAck(SctpHeartbeatChunk ack)
    {
        if (_heartbeatNonce is null || !ack.Info.AsSpan().SequenceEqual(_heartbeatNonce))
        {
            return;
        }

        _heartbeatNonce = null;
        UpdateRto(NowMs - _heartbeatSentMs);
    }

    // --------------------------------------------------------------- data send

    private void EnqueueMessage(
        ushort streamId,
        uint payloadProtocolId,
        byte[] body,
        bool ordered,
        ushort? maxRetransmits,
        DataChannel? channel,
        int bufferedBytes)
    {
        var interleaved = UseInterleaving;

        // Classic DATA carries a 16-bit per-fragment stream sequence number for ordered messages;
        // I-DATA replaces it with a 32-bit message identifier drawn from a per-stream, per-ordering
        // namespace that doubles as the ordered-delivery sequence.
        ushort sequence = 0;
        uint messageIdentifier = 0;
        if (interleaved)
        {
            var midMap = ordered ? _sendOrderedMid : _sendUnorderedMid;
            midMap.TryGetValue(streamId, out messageIdentifier);
            midMap[streamId] = unchecked(messageIdentifier + 1);
        }
        else if (ordered)
        {
            _sendSequence.TryGetValue(streamId, out sequence);
            _sendSequence[streamId] = unchecked((ushort)(sequence + 1));
        }

        var messageId = _nextMessageId++;
        var maxPayload = MaxPayloadPerChunk;
        var offset = 0;
        var remainingBuffered = bufferedBytes;
        uint fsn = 0;

        do
        {
            var length = Math.Min(maxPayload, body.Length - offset);
            var slice = new byte[length];
            Array.Copy(body, offset, slice, 0, length);
            var isLast = offset + length >= body.Length;
            var share = isLast ? remainingBuffered : Math.Min(remainingBuffered, length);
            remainingBuffered -= share;

            _out.Add(new OutgoingChunk
            {
                Tsn = _nextTsn,
                StreamId = streamId,
                StreamSequence = sequence,
                PayloadProtocolId = payloadProtocolId,
                Payload = slice,
                Beginning = offset == 0,
                Ending = isLast,
                Unordered = !ordered,
                Interleaved = interleaved,
                MessageIdentifier = messageIdentifier,
                FragmentSequenceNumber = fsn,
                MessageId = messageId,
                MaxRetransmits = maxRetransmits,
                Channel = channel,
                BufferedBytes = share,
            });

            _nextTsn = unchecked(_nextTsn + 1);
            fsn = unchecked(fsn + 1);
            offset += length;
        }
        while (offset < body.Length);

        channel?.AddBuffered(bufferedBytes);
    }

    private void Flush()
    {
        if (_disposed || _state == SctpAssociationState.Closed)
        {
            return;
        }

        var mtu = _lower.MaxDatagramSize;
        var batch = new List<SctpChunk>();
        var size = SctpPacket.CommonHeaderLength;

        void Emit()
        {
            if (batch.Count == 0)
            {
                return;
            }

            SendImmediate(_peerTag, batch.ToArray());
            batch.Clear();
            size = SctpPacket.CommonHeaderLength;
        }

        void Add(SctpChunk chunk)
        {
            if (size + chunk.PaddedLength > mtu)
            {
                Emit();
            }

            batch.Add(chunk);
            size += chunk.PaddedLength;
        }

        foreach (var control in _controlQueue)
        {
            Add(control);
        }

        _controlQueue.Clear();

        if (_state is SctpAssociationState.Established or SctpAssociationState.ShutdownPending
            or SctpAssociationState.ShutdownReceived or SctpAssociationState.ShutdownSent)
        {
            var now = NowMs;

            foreach (var chunk in _out)
            {
                if (!chunk.NeedsRetransmit || chunk.Acked || chunk.Abandoned)
                {
                    continue;
                }

                chunk.NeedsRetransmit = false;
                chunk.MissIndications = 0;
                chunk.Transmits++;
                chunk.LastSentMs = now;
                chunk.InFlight = true;
                _flightSize += chunk.WireSize;
                Add(chunk.ToChunk());
                StartRetransmissionTimer(now);
            }

            var window = Math.Min(_congestionWindow, (long)_peerReceiveWindow);
            foreach (var chunk in NewDataInSendOrder())
            {
                if (chunk.Transmits > 0 || chunk.Acked || chunk.Abandoned)
                {
                    continue;
                }

                if (_flightSize > 0 && _flightSize + chunk.WireSize > window)
                {
                    break;
                }

                chunk.Transmits = 1;
                chunk.LastSentMs = now;
                chunk.InFlight = true;
                _flightSize += chunk.WireSize;
                if (!_rttProbeActive)
                {
                    _rttProbeActive = true;
                    _rttProbeTsn = chunk.Tsn;
                    _rttProbeSentMs = now;
                }

                Add(chunk.ToChunk());
                StartRetransmissionTimer(now);
            }
        }

        Emit();
    }

    private void StartRetransmissionTimer(long now)
    {
        if (_t3Expiry == 0)
        {
            _t3Expiry = now + (long)_rto;
        }
    }

    /// <summary>
    /// The never-transmitted chunks in the order they should be handed to the wire. With classic
    /// DATA this is simply TSN order, so a message's fragments occupy a contiguous TSN run (the
    /// receiver reassembles by walking adjacent TSNs). With RFC 8260 interleaving negotiated the
    /// chunks are dealt out round-robin across streams — one fragment per stream per round — so a
    /// large message on one stream never blocks small messages queued on others; the receiver
    /// reassembles by (stream, MID) using FSN, which tolerates the interleaved TSNs this produces.
    /// </summary>
    private IEnumerable<OutgoingChunk> NewDataInSendOrder()
    {
        if (!UseInterleaving)
        {
            return _out;
        }

        var perStream = new Dictionary<ushort, Queue<OutgoingChunk>>();
        var order = new List<ushort>();
        foreach (var chunk in _out)
        {
            if (chunk.Transmits > 0 || chunk.Acked || chunk.Abandoned)
            {
                continue;
            }

            if (!perStream.TryGetValue(chunk.StreamId, out var queue))
            {
                queue = new Queue<OutgoingChunk>();
                perStream[chunk.StreamId] = queue;
                order.Add(chunk.StreamId);
            }

            queue.Enqueue(chunk);
        }

        if (order.Count <= 1)
        {
            return _out;
        }

        var interleaved = new List<OutgoingChunk>();
        var drained = true;
        while (drained)
        {
            drained = false;
            foreach (var streamId in order)
            {
                if (perStream[streamId].TryDequeue(out var chunk))
                {
                    interleaved.Add(chunk);
                    drained = true;
                }
            }
        }

        return interleaved;
    }

    /// <summary>
    /// The Supported Extensions chunk-type list advertised in INIT and INIT ACK. I-DATA is offered
    /// only when this endpoint is configured to enable interleaving (RFC 8260 §3).
    /// </summary>
    private byte[] SupportedExtensions()
    {
        if (_config.EnableInterleaving)
        {
            return new[] { (byte)SctpChunkType.ForwardTsn, (byte)SctpChunkType.ReConfig, (byte)SctpChunkType.IData };
        }

        return new[] { (byte)SctpChunkType.ForwardTsn, (byte)SctpChunkType.ReConfig };
    }

    private void SendInit()
    {
        var init = new SctpInitChunk(SctpChunkType.Init)
        {
            InitiateTag = _localTag,
            AdvertisedReceiverWindow = LocalReceiveWindow(),
            NumberOfOutboundStreams = _config.OutboundStreams,
            NumberOfInboundStreams = _config.InboundStreams,
            InitialTsn = _localInitialTsn,
        };
        init.Parameters.Add(new SctpParameter(SctpParameterType.ForwardTsnSupported, Array.Empty<byte>()));
        init.Parameters.Add(new SctpParameter(SctpParameterType.SupportedExtensions, SupportedExtensions()));

        _pendingInit = init;
        _state = SctpAssociationState.CookieWait;
        _initAttempts = 0;
        _initExpiry = NowMs + (long)_rto;
        SendImmediate(0, init);
    }

    private void SendImmediate(uint verificationTag, params SctpChunk[] chunks)
    {
        if (chunks.Length == 0)
        {
            return;
        }

        var packet = new SctpPacket((ushort)_config.LocalPort, (ushort)_config.RemotePort, verificationTag);
        packet.Chunks.AddRange(chunks);
        var buffer = new byte[packet.Length];
        var written = packet.WriteTo(buffer);
        if (_log.IsEnabled(KeryxLogLevel.Trace))
        {
            _log.Log(KeryxLogLevel.Trace, $"SCTP out tag=0x{verificationTag:X8} [{string.Join(",", chunks.Select(c => c.Type))}] len={written}");
        }

        try
        {
            _lower.Send(buffer.AsSpan(0, written));
        }
        catch (Exception ex)
        {
            _log.Log(KeryxLogLevel.Error, "Lower transport rejected an SCTP packet.", ex);
        }
    }

    private SctpAbortChunk MakeAbort(SctpErrorCauseCode code, string detail)
    {
        var abort = new SctpAbortChunk();
        abort.Causes.Add(new SctpErrorCause(code, System.Text.Encoding.UTF8.GetBytes(detail)));
        return abort;
    }

    private uint LocalReceiveWindow()
    {
        var used = Math.Max(0, _receiveBufferBytes);
        var available = _config.ReceiveWindow - (ulong)used;
        return available > _config.ReceiveWindow ? 0 : (uint)Math.Max(0, (long)available);
    }

    private SctpSackChunk BuildSack()
    {
        var sack = new SctpSackChunk
        {
            CumulativeTsnAck = _cumulativeTsnReceived,
            AdvertisedReceiverWindow = LocalReceiveWindow(),
        };

        if (_received.Count > 0)
        {
            var distances = new List<uint>(_received.Count);
            foreach (var tsn in _received)
            {
                var distance = unchecked(tsn - _cumulativeTsnReceived);
                if (distance is > 0 and <= ushort.MaxValue)
                {
                    distances.Add(distance);
                }
            }

            distances.Sort();
            var index = 0;
            while (index < distances.Count && sack.GapAckBlocks.Count < 32)
            {
                var start = distances[index];
                var end = start;
                index++;
                while (index < distances.Count && distances[index] == end + 1)
                {
                    end = distances[index];
                    index++;
                }

                sack.GapAckBlocks.Add(new SctpGapAckBlock((ushort)start, (ushort)end));
            }
        }

        sack.DuplicateTsns.AddRange(_duplicateTsns);
        _duplicateTsns.Clear();
        return sack;
    }

    private void HandleSack(SctpSackChunk sack)
    {
        if (_state == SctpAssociationState.Closed)
        {
            return;
        }

        if (Serial.Lt(sack.CumulativeTsnAck, _peerCumulativeAck))
        {
            return;
        }

        var flightBefore = _flightSize;
        var advanced = Serial.Gt(sack.CumulativeTsnAck, _peerCumulativeAck);
        _peerCumulativeAck = sack.CumulativeTsnAck;
        var ackedBytes = AckUpTo(sack.CumulativeTsnAck);

        var highestGapAck = sack.CumulativeTsnAck;
        foreach (var block in sack.GapAckBlocks)
        {
            for (uint offset = block.Start; offset <= block.End; offset++)
            {
                var tsn = unchecked(sack.CumulativeTsnAck + offset);
                ackedBytes += AckChunk(tsn);
                if (Serial.Gt(tsn, highestGapAck))
                {
                    highestGapAck = tsn;
                }
            }
        }

        _peerReceiveWindow = sack.AdvertisedReceiverWindow;

        if (_rttProbeActive && Serial.Lte(_rttProbeTsn, highestGapAck))
        {
            var probe = FindChunk(_rttProbeTsn);
            if (probe is null || probe.Transmits <= 1)
            {
                UpdateRto(NowMs - _rttProbeSentMs);
            }

            _rttProbeActive = false;
        }

        if (sack.GapAckBlocks.Count > 0)
        {
            var fastRetransmit = false;
            foreach (var chunk in _out)
            {
                if (chunk.Acked || chunk.Abandoned || chunk.Transmits == 0 || !Serial.Lt(chunk.Tsn, highestGapAck))
                {
                    continue;
                }

                chunk.MissIndications++;
                if (chunk.MissIndications != 3)
                {
                    continue;
                }

                if (ShouldAbandon(chunk))
                {
                    AbandonMessage(chunk.MessageId);
                    continue;
                }

                chunk.NeedsRetransmit = true;
                if (chunk.InFlight)
                {
                    chunk.InFlight = false;
                    _flightSize -= chunk.WireSize;
                }

                fastRetransmit = true;
            }

            if (fastRetransmit)
            {
                _slowStartThreshold = Math.Max(_congestionWindow / 2, 4L * _lower.MaxDatagramSize);
                _congestionWindow = _slowStartThreshold;
                _partialBytesAcked = 0;
            }
        }

        if (advanced && ackedBytes > 0)
        {
            GrowCongestionWindow(flightBefore, ackedBytes);
        }

        _out.RemoveAll(c => Serial.Lte(c.Tsn, _peerCumulativeAck));
        MaybeSendForwardTsn();

        // A stream reset queued while its data was still in flight can proceed now that a SACK has
        // acknowledged more data.
        TryStartOutgoingReset();

        if (!HasOutstanding())
        {
            _t3Expiry = 0;
        }
        else if (advanced)
        {
            _t3Expiry = NowMs + (long)_rto;
        }
    }

    private void GrowCongestionWindow(long flightBefore, long ackedBytes)
    {
        if (flightBefore < _congestionWindow)
        {
            return;
        }

        long mtu = _lower.MaxDatagramSize;
        if (_congestionWindow <= _slowStartThreshold)
        {
            _congestionWindow += Math.Min(ackedBytes, mtu);
            return;
        }

        _partialBytesAcked += ackedBytes;
        if (_partialBytesAcked >= _congestionWindow)
        {
            _partialBytesAcked -= _congestionWindow;
            _congestionWindow += mtu;
        }
    }

    private long AckUpTo(uint cumulativeTsn)
    {
        long acked = 0;
        foreach (var chunk in _out)
        {
            if (Serial.Gt(chunk.Tsn, cumulativeTsn))
            {
                continue;
            }

            acked += MarkAcked(chunk);
        }

        return acked;
    }

    private long AckChunk(uint tsn)
    {
        var chunk = FindChunk(tsn);
        return chunk is null ? 0 : MarkAcked(chunk);
    }

    private long MarkAcked(OutgoingChunk chunk)
    {
        if (chunk.Acked)
        {
            return 0;
        }

        chunk.Acked = true;
        ReleaseBuffered(chunk);
        if (!chunk.InFlight)
        {
            return chunk.WireSize;
        }

        chunk.InFlight = false;
        _flightSize -= chunk.WireSize;
        return chunk.WireSize;
    }

    private OutgoingChunk? FindChunk(uint tsn)
    {
        foreach (var chunk in _out)
        {
            if (chunk.Tsn == tsn)
            {
                return chunk;
            }
        }

        return null;
    }

    private void ReleaseBuffered(OutgoingChunk chunk)
    {
        if (chunk.BufferReleased)
        {
            return;
        }

        chunk.BufferReleased = true;
        chunk.Channel?.AddBuffered(-chunk.BufferedBytes);
    }

    private bool HasOutstanding()
    {
        foreach (var chunk in _out)
        {
            if (chunk.InFlight || chunk.NeedsRetransmit)
            {
                return true;
            }
        }

        return Serial.Gt(_advancedPeerAckPoint, _peerCumulativeAck);
    }

    private static bool ShouldAbandon(OutgoingChunk chunk) =>
        chunk.MaxRetransmits.HasValue && chunk.Transmits - 1 >= chunk.MaxRetransmits.Value;

    private void AbandonMessage(int messageId)
    {
        foreach (var chunk in _out)
        {
            if (chunk.MessageId != messageId || chunk.Abandoned || chunk.Acked)
            {
                continue;
            }

            chunk.Abandoned = true;
            chunk.NeedsRetransmit = false;
            ReleaseBuffered(chunk);
            if (chunk.InFlight)
            {
                chunk.InFlight = false;
                _flightSize -= chunk.WireSize;
            }
        }
    }

    private void MaybeSendForwardTsn()
    {
        if (!_peerSupportsForwardTsn)
        {
            return;
        }

        var point = _advancedPeerAckPoint;
        if (Serial.Lt(point, _peerCumulativeAck))
        {
            point = _peerCumulativeAck;
        }

        foreach (var chunk in _out)
        {
            if (chunk.Tsn != unchecked(point + 1))
            {
                continue;
            }

            if (!chunk.Acked && !chunk.Abandoned)
            {
                break;
            }

            point = chunk.Tsn;
        }

        _advancedPeerAckPoint = point;
        if (!Serial.Gt(_advancedPeerAckPoint, _peerCumulativeAck))
        {
            return;
        }

        var forward = new SctpForwardTsnChunk { NewCumulativeTsn = _advancedPeerAckPoint };
        var skips = new Dictionary<ushort, ushort>();
        foreach (var chunk in _out)
        {
            // Interleaved (I-DATA) ordered messages are sequenced by 32-bit MID, which a classic
            // FORWARD TSN stream entry (16-bit SSN) cannot represent, so only the cumulative TSN is
            // advanced for them; the SSN skip list applies to classic DATA only.
            if (!chunk.Abandoned || chunk.Unordered || chunk.Interleaved || Serial.Gt(chunk.Tsn, _advancedPeerAckPoint))
            {
                continue;
            }

            if (!skips.TryGetValue(chunk.StreamId, out var existing) || Serial.Gt16(chunk.StreamSequence, existing))
            {
                skips[chunk.StreamId] = chunk.StreamSequence;
            }
        }

        foreach (var pair in skips)
        {
            forward.Streams.Add(new SctpForwardTsnStream(pair.Key, pair.Value));
        }

        _controlQueue.Add(forward);
        _out.RemoveAll(c => Serial.Lte(c.Tsn, _advancedPeerAckPoint));
    }

    // ------------------------------------------------------------------ timers

    private void Tick()
    {
        lock (_lock)
        {
            if (_disposed || _state == SctpAssociationState.Closed)
            {
                return;
            }

            var now = NowMs;

            if (_initExpiry != 0 && now >= _initExpiry)
            {
                if (++_initAttempts > _config.MaxRetransmitAttempts)
                {
                    Fail(new TimeoutException("SCTP handshake timed out."));
                    goto dispatch;
                }

                _rto = Math.Min(_rto * 2, _config.MaxRto.TotalMilliseconds);
                _initExpiry = now + (long)_rto;
                if (_pendingInit is not null)
                {
                    SendImmediate(0, _pendingInit);
                }
                else if (_pendingCookieEcho is not null)
                {
                    _controlQueue.Add(_pendingCookieEcho);
                }
            }

            if (_t3Expiry != 0 && now >= _t3Expiry)
            {
                HandleRetransmissionTimeout(now);
            }

            if (_shutdownExpiry != 0 && now >= _shutdownExpiry)
            {
                if (++_shutdownAttempts > _config.MaxRetransmitAttempts)
                {
                    CloseInternal(new TimeoutException("SCTP shutdown timed out."));
                    goto dispatch;
                }

                _shutdownExpiry = now + (long)_rto;
                if (_state == SctpAssociationState.ShutdownSent)
                {
                    _controlQueue.Add(new SctpShutdownChunk(_cumulativeTsnReceived));
                }
                else if (_state == SctpAssociationState.ShutdownAckSent)
                {
                    _controlQueue.Add(new SctpShutdownAckChunk());
                }
            }

            if (_reconfigExpiry != 0 && now >= _reconfigExpiry && _outstandingReset is not null)
            {
                if (++_reconfigAttempts > _config.MaxRetransmitAttempts)
                {
                    _log.Log(KeryxLogLevel.Warning, "Stream reset timed out; freeing streams locally.");
                    FinalizeOutgoingReset(_outstandingReset);
                    _outstandingReset = null;
                    _reconfigExpiry = 0;
                    _reconfigAttempts = 0;
                    TryStartOutgoingReset();
                }
                else
                {
                    _reconfigExpiry = now + (long)_rto;
                    _controlQueue.Add(BuildOutgoingResetChunk(_outstandingReset));
                }
            }

            if (_nextHeartbeat != 0 && now >= _nextHeartbeat && _state == SctpAssociationState.Established)
            {
                _nextHeartbeat = now + (long)_config.HeartbeatInterval.TotalMilliseconds;
                _heartbeatNonce = RandomNumberGenerator.GetBytes(8);
                _heartbeatSentMs = now;
                _controlQueue.Add(new SctpHeartbeatChunk(SctpChunkType.Heartbeat, _heartbeatNonce));
            }

            if (_sackPending)
            {
                _sackPending = false;
                _controlQueue.Add(BuildSack());
            }

            Flush();
        }

    dispatch:
        DispatchEvents();
    }

    private void HandleRetransmissionTimeout(long now)
    {
        long mtu = _lower.MaxDatagramSize;
        _slowStartThreshold = Math.Max(_congestionWindow / 2, 4 * mtu);
        _congestionWindow = mtu;
        _partialBytesAcked = 0;
        _rto = Math.Min(_rto * 2, _config.MaxRto.TotalMilliseconds);
        _rttProbeActive = false;

        var abandon = new List<int>();
        foreach (var chunk in _out)
        {
            if (chunk.Acked || chunk.Abandoned || chunk.Transmits == 0)
            {
                continue;
            }

            if (chunk.InFlight)
            {
                chunk.InFlight = false;
                _flightSize -= chunk.WireSize;
            }

            if (ShouldAbandon(chunk))
            {
                abandon.Add(chunk.MessageId);
            }
            else
            {
                chunk.NeedsRetransmit = true;
            }
        }

        foreach (var messageId in abandon)
        {
            AbandonMessage(messageId);
        }

        MaybeSendForwardTsn();
        _t3Expiry = HasOutstanding() ? now + (long)_rto : 0;
    }

    private void UpdateRto(long rttMs)
    {
        var sample = Math.Max(1, rttMs);
        if (!_hasRttSample)
        {
            _hasRttSample = true;
            _smoothedRtt = sample;
            _rttVariance = sample / 2.0;
        }
        else
        {
            _rttVariance = ((1 - 0.25) * _rttVariance) + (0.25 * Math.Abs(_smoothedRtt - sample));
            _smoothedRtt = ((1 - 0.125) * _smoothedRtt) + (0.125 * sample);
        }

        _rto = Math.Clamp(
            _smoothedRtt + (4 * _rttVariance),
            _config.MinRto.TotalMilliseconds,
            _config.MaxRto.TotalMilliseconds);
    }

    // ------------------------------------------------------------------ cookie

    private byte[] BuildCookie(SctpInitChunk init, ushort outbound, ushort inbound)
    {
        var cookie = new byte[CookieLength];
        var writer = new ByteWriter(cookie.AsSpan(0, CookieMacOffset));
        writer.WriteU8(1);
        writer.WriteU8(0);
        writer.WriteU16(0);
        writer.WriteU64((ulong)NowMs);
        writer.WriteU32(init.InitiateTag);
        writer.WriteU32(init.InitialTsn);
        writer.WriteU32(init.AdvertisedReceiverWindow);
        writer.WriteU16(outbound);
        writer.WriteU16(inbound);
        writer.WriteU8(init.ForwardTsnSupported ? (byte)1 : (byte)0);
        writer.WriteU8(init.ReconfigSupported ? (byte)1 : (byte)0);
        writer.WriteU8(init.InterleavingSupported ? (byte)1 : (byte)0);
        writer.WriteU8(0);

        var mac = HMACSHA256.HashData(_cookieKey, cookie.AsSpan(0, CookieMacOffset));
        mac.CopyTo(cookie.AsSpan(CookieMacOffset));
        return cookie;
    }

    private bool TryReadCookie(
        byte[] cookie,
        out uint peerTag,
        out uint peerInitialTsn,
        out uint peerRwnd,
        out ushort outbound,
        out ushort inbound,
        out bool forwardTsn,
        out bool reconfig,
        out bool interleaving)
    {
        peerTag = 0;
        peerInitialTsn = 0;
        peerRwnd = 0;
        outbound = 0;
        inbound = 0;
        forwardTsn = false;
        reconfig = false;
        interleaving = false;

        if (cookie.Length != CookieLength)
        {
            return false;
        }

        var expected = HMACSHA256.HashData(_cookieKey, cookie.AsSpan(0, CookieMacOffset));
        if (!CryptographicOperations.FixedTimeEquals(expected, cookie.AsSpan(CookieMacOffset)))
        {
            return false;
        }

        var reader = new ByteReader(cookie.AsSpan(0, CookieMacOffset));
        if (reader.ReadU8() != 1)
        {
            return false;
        }

        reader.Skip(3);
        var issued = (long)reader.ReadU64();
        var age = NowMs - issued;
        if (age < 0 || age > _config.CookieLifetime.TotalMilliseconds)
        {
            return false;
        }

        peerTag = reader.ReadU32();
        peerInitialTsn = reader.ReadU32();
        peerRwnd = reader.ReadU32();
        outbound = reader.ReadU16();
        inbound = reader.ReadU16();
        forwardTsn = reader.ReadU8() != 0;
        reconfig = reader.ReadU8() != 0;
        interleaving = reader.ReadU8() != 0;
        return peerTag != 0;
    }

    // ------------------------------------------------------------- termination

    private void Fail(Exception error)
    {
        _log.Log(KeryxLogLevel.Error, "SCTP association failed.", error);
        CloseInternal(error);
    }

    private void CloseInternal(Exception? error)
    {
        if (_state == SctpAssociationState.Closed && _channels.Count == 0)
        {
            _connectSource?.TrySetException(error ?? new InvalidOperationException("Association closed."));
            return;
        }

        _state = SctpAssociationState.Closed;
        _t3Expiry = 0;
        _initExpiry = 0;
        _shutdownExpiry = 0;
        _nextHeartbeat = 0;
        _reconfigExpiry = 0;
        _reconfigAttempts = 0;
        _outstandingReset = null;
        _pendingResetStreams.Clear();
        _deferredIncomingResets.Clear();
        _freedStreamIds.Clear();
        _pendingInit = null;
        _pendingCookieEcho = null;
        _controlQueue.Clear();
        _out.Clear();

        // Release any out-of-order receive buffering so a teardown (including an abort
        // triggered by that buffer overflowing) does not leave the memory pinned.
        _fragments.Clear();
        _received.Clear();
        _duplicateTsns.Clear();
        _iDataReassembly.Clear();
        _iDataTsnIndex.Clear();
        _iDataReceiveStreams.Clear();
        _iDataBufferedFragments = 0;
        _receiveBufferBytes = 0;

        var channels = _channels.Values.ToArray();
        _channels.Clear();
        var source = _connectSource;

        _events.Add(() =>
        {
            foreach (var channel in channels)
            {
                if (channel.State != DataChannelState.Closed)
                {
                    channel.State = DataChannelState.Closed;
                    channel.RaiseClosed();
                }
            }

            if (error is not null)
            {
                OnError?.Invoke(error);
                source?.TrySetException(error);
            }
            else
            {
                source?.TrySetException(new InvalidOperationException("Association closed before it was established."));
            }

            OnClosed?.Invoke();
        });
    }

    private void DispatchEvents()
    {
        lock (_lock)
        {
            if (_dispatching)
            {
                return;
            }

            _dispatching = true;
        }

        try
        {
            while (true)
            {
                Action action;
                lock (_lock)
                {
                    if (_events.Count == 0)
                    {
                        _dispatching = false;
                        return;
                    }

                    action = _events[0];
                    _events.RemoveAt(0);
                }

                try
                {
                    action();
                }
                catch (Exception ex)
                {
                    _log.Log(KeryxLogLevel.Error, "An SCTP event handler threw.", ex);
                }
            }
        }
        catch
        {
            lock (_lock)
            {
                _dispatching = false;
            }

            throw;
        }
    }
}
