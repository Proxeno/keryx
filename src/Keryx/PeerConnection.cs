using System.Globalization;
using System.Security.Cryptography;
using Keryx.Core;
using Keryx.Dtls;
using Keryx.Ice;
using Keryx.Rtp;
using Keryx.Sctp;
using Keryx.Sdp;
using Keryx.Srtp;
using SrtpProfile = Keryx.Srtp.SrtpProtectionProfile;

namespace Keryx;

/// <summary>
/// A WebRTC peer connection: the composition root that wires Keryx's STUN, ICE, SDP, DTLS, SRTP, RTP
/// and SCTP layers into one <c>RTCPeerConnection</c>-shaped object.
/// </summary>
/// <remarks>
/// <para><b>Shape.</b> The intended deployment is a media server that offers <c>sendonly</c> H.264 and
/// Opus to <c>recvonly</c> browsers, with bidirectional data channels, BUNDLE, rtcp-mux and trickle
/// ICE. It offers <c>a=setup:actpass</c>, so a browser answering <c>a=setup:active</c> makes Keryx the
/// DTLS server. A minimal answerer path exists as well, which is what makes a Keryx-to-Keryx loopback
/// possible; see the remarks on <see cref="CreateAnswerAsync"/> for its limits.</para>
/// <para><b>Sequencing.</b> <see cref="CreateOfferAsync"/> gathers ICE candidates and returns a
/// complete offer. <see cref="SetRemoteDescriptionAsync"/> applies the answer and starts a background
/// driver that runs ICE connectivity, then the DTLS handshake, then derives SRTP contexts from the
/// RFC 5705 exporter, then starts SCTP and the RTCP reporting loop. Await
/// <see cref="WaitForConnectedAsync"/> or watch <see cref="OnConnectionStateChanged"/> to learn when
/// that is done.</para>
/// <para><b>Threading.</b> Every event on this class is raised on an internal thread — the ICE receive
/// loop, the RTCP timer, the SCTP timer, or the connection driver task. Handlers must be quick and
/// must not block, or they will stall the socket. Spans handed to
/// <see cref="OnRtpPacketReceived"/> and to data channel handlers are valid only for the duration of
/// the call. <see cref="SendVideoFrame"/> and <see cref="SendAudioFrame"/> are safe to call from any
/// thread and serialize internally.</para>
/// <para><b>Resilience.</b> Video is offered with bare <c>a=rtcp-fb nack</c> backed by a real
/// RFC 4588 repair stream: an <c>rtx</c> codec, a dedicated SSRC published through
/// <c>a=ssrc-group:FID</c>, and a ring of recently sent packets that inbound NACKs are served from
/// under a resend rate limit and a bandwidth budget. If the answer drops the <c>rtx</c> codec,
/// retransmission is disabled rather than promised and not delivered. Reception report blocks the
/// peer sends are folded into <see cref="GetStats"/> as loss, jitter and round-trip time.</para>
/// <para><b>Not implemented.</b> No ULPFEC or RED, no outbound transport-cc, no bandwidth estimation
/// or pacing, no simulcast, no renegotiation, no ICE restart, no TURN, no IPv6 candidates, no header
/// extensions (so inbound transport-cc feedback is reported but never solicited by Keryx's own
/// sequence numbering).</para>
/// </remarks>
public sealed partial class PeerConnection : IAsyncDisposable
{
    private const string ExporterLabel = "EXTRACTOR-dtls_srtp";

    private readonly PeerConnectionConfig _config;
    private readonly IKeryxLogger _logger;
    private readonly DtlsCertificate _certificate;
    private readonly bool _ownsCertificate;
    private readonly object _lock = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly List<PendingChannel> _pendingChannels = [];
    private readonly List<string> _pendingRemoteCandidates = [];
    private readonly string _cname;
    private readonly string _streamId;
    private readonly string _videoTrackId;
    private readonly string _audioTrackId;
    private readonly uint _videoSsrc;
    private readonly uint _videoRtxSsrc;
    private readonly uint _audioSsrc;
    private readonly uint _rtcpSenderSsrc;

    private IceAgent? _ice;
    private IDatagramTransport? _transport;
    private DtlsLowerTransport? _dtlsLower;
    private DtlsTransport? _dtls;
    private SctpAssociation? _sctp;
    private SrtpContext? _srtp;
    private Task? _driver;
    private SessionDescription? _localDescription;
    private SessionDescription? _remoteDescription;
    private SdpFingerprint? _remoteFingerprint;
    private DtlsRole _dtlsRole = DtlsRole.Server;
    private int? _remoteSctpPort;
    private bool _isOfferer;
    private int _closed;
    private PeerConnectionState _state = PeerConnectionState.New;

    /// <summary>Creates a peer connection.</summary>
    /// <param name="config">Configuration; a default instance is used when null.</param>
    public PeerConnection(PeerConnectionConfig? config = null)
    {
        _config = config ?? new PeerConnectionConfig();
        _logger = _config.Logger;
        _certificate = _config.Certificate ?? DtlsCertificate.GenerateSelfSigned();
        _ownsCertificate = _config.Certificate is null;
        _cname = _config.Cname ?? NewIdentifier("keryx");
        _streamId = _config.StreamId ?? NewIdentifier("stream");
        _videoTrackId = _config.VideoTrackId ?? NewIdentifier("video");
        _audioTrackId = _config.AudioTrackId ?? NewIdentifier("audio");
        _videoSsrc = NewSsrc();
        _videoRtxSsrc = NewSsrc();
        _audioSsrc = NewSsrc();
        _rtcpSenderSsrc = NewSsrc();
    }

    /// <summary>Raised whenever <see cref="State"/> changes. Terminal state is <see cref="PeerConnectionState.Closed"/>.</summary>
    public event EventHandler<PeerConnectionState>? OnConnectionStateChanged;

    /// <summary>Raised for each local ICE candidate as it is gathered, for trickling out to the peer.</summary>
    public event EventHandler<LocalIceCandidateEventArgs>? OnLocalIceCandidate;

    /// <summary>Raised once local ICE gathering has finished; the description also carries <c>a=end-of-candidates</c>.</summary>
    public event EventHandler? OnIceGatheringComplete;

    /// <summary>Raised for every data channel the peer opens with DCEP.</summary>
    public event EventHandler<DataChannel>? OnDataChannel;

    /// <summary>Raised for each inbound RTP packet that decrypted and parsed.</summary>
    public event RtpPacketReceivedHandler? OnRtpPacketReceived;

    /// <summary>Raised for each inbound Picture Loss Indication.</summary>
    public event EventHandler<PliEventArgs>? OnPictureLossIndication;

    /// <summary>Raised for each inbound Full Intra Request.</summary>
    public event EventHandler<FirEventArgs>? OnFullIntraRequest;

    /// <summary>Raised for each inbound Generic NACK, with the bitmask already expanded.</summary>
    public event EventHandler<NackEventArgs>? OnNack;

    /// <summary>Raised for each inbound transport-wide congestion control feedback packet.</summary>
    public event EventHandler<TransportCcEventArgs>? OnTransportCcFeedback;

    /// <summary>Raised for each inbound report carrying reception report blocks (RR, or SR with blocks).</summary>
    public event EventHandler<ReceiverReportEventArgs>? OnReceiverReport;

    /// <summary>The connection's lifecycle state.</summary>
    public PeerConnectionState State
    {
        get
        {
            lock (_lock)
            {
                return _state;
            }
        }
    }

    /// <summary>The ICE agent's state, or <see cref="IceAgentState.New"/> before gathering starts.</summary>
    public IceAgentState IceState => _ice?.State ?? IceAgentState.New;

    /// <summary>The DTLS transport's state, or <see cref="DtlsTransportState.New"/> before the handshake.</summary>
    public DtlsTransportState DtlsState => _dtls?.State ?? DtlsTransportState.New;

    /// <summary>The SCTP association's state, or <see cref="SctpAssociationState.Closed"/> before it exists.</summary>
    public SctpAssociationState SctpState => _sctp?.State ?? SctpAssociationState.Closed;

    /// <summary>The DTLS role resolved from <c>a=setup</c>, meaningful once a remote description is applied.</summary>
    public DtlsRole LocalDtlsRole
    {
        get
        {
            lock (_lock)
            {
                return _dtlsRole;
            }
        }
    }

    /// <summary>The SRTP protection profile the DTLS handshake agreed on, or null before it completes.</summary>
    public SrtpProfile? NegotiatedSrtpProfile => _srtp?.Profile;

    /// <summary>The local DTLS certificate fingerprint published as <c>a=fingerprint:sha-256</c>.</summary>
    public string LocalFingerprint => _certificate.Sha256Fingerprint;

    /// <summary>The peer's DTLS certificate fingerprint as signalled, or null before a remote description.</summary>
    public string? RemoteFingerprint
    {
        get
        {
            lock (_lock)
            {
                return _remoteFingerprint?.Value;
            }
        }
    }

    /// <summary>The RTCP canonical name this endpoint publishes.</summary>
    public string Cname => _cname;

    /// <summary>The synchronisation source of the outbound video stream.</summary>
    public uint VideoSsrc => _videoSsrc;

    /// <summary>
    /// The synchronisation source of the outbound video retransmission stream, published as the second
    /// member of <c>a=ssrc-group:FID</c> when RFC 4588 RTX is offered.
    /// </summary>
    public uint VideoRtxSsrc => _videoRtxSsrc;

    /// <summary>The synchronisation source of the outbound audio stream.</summary>
    public uint AudioSsrc => _audioSsrc;

    /// <summary>The most recent local description, or null before one was created.</summary>
    public string? LocalDescription
    {
        get
        {
            lock (_lock)
            {
                return _localDescription?.ToSdpString();
            }
        }
    }

    /// <summary>The most recent remote description, or null before one was applied.</summary>
    public string? RemoteDescription
    {
        get
        {
            lock (_lock)
            {
                return _remoteDescription?.ToSdpString();
            }
        }
    }

    /// <summary>Every data channel the association currently knows about, local and remote.</summary>
    public IReadOnlyCollection<DataChannel> DataChannels => _sctp?.Channels ?? [];

    /// <summary>
    /// Creates a data channel. Valid before negotiation: the request is queued and turned into a
    /// DCEP <c>DATA_CHANNEL_OPEN</c> as soon as the SCTP association exists.
    /// </summary>
    /// <param name="label">The channel label the peer will see.</param>
    /// <param name="ordered">Whether messages are delivered to the peer in send order.</param>
    /// <param name="maxRetransmits">
    /// Retransmission limit per message, or null for full reliability. Zero gives the
    /// transmit-once-and-forget behaviour a controller channel wants.
    /// </param>
    /// <param name="protocol">Optional sub-protocol name.</param>
    /// <returns>
    /// A task completing with the channel. It completes synchronously once SCTP is up; before that it
    /// completes when the association is created, which is the earliest point at which a stream
    /// identifier can be allocated — RFC 8832 §6 ties stream parity to the DTLS role, and that role is
    /// not known until the remote description arrives.
    /// </returns>
    /// <exception cref="ObjectDisposedException">The connection is closed.</exception>
    public Task<DataChannel> CreateDataChannel(
        string label,
        bool ordered = true,
        ushort? maxRetransmits = null,
        string protocol = "")
    {
        ArgumentNullException.ThrowIfNull(label);
        ArgumentNullException.ThrowIfNull(protocol);

        SctpAssociation? association;
        lock (_lock)
        {
            ObjectDisposedException.ThrowIf(_closed != 0, this);
            association = _sctp;
            if (association is null)
            {
                var pending = new PendingChannel(
                    label,
                    ordered,
                    maxRetransmits,
                    protocol,
                    new TaskCompletionSource<DataChannel>(TaskCreationOptions.RunContinuationsAsynchronously));
                _pendingChannels.Add(pending);
                return pending.Completion.Task;
            }
        }

        return Task.FromResult(association.CreateChannel(label, ordered, maxRetransmits, protocol));
    }

    /// <summary>
    /// Gathers ICE candidates and produces a complete JSEP offer: BUNDLE group, one m-section per
    /// configured media kind plus the SCTP data channel section, <c>a=setup:actpass</c>, rtcp-mux, and
    /// every gathered <c>a=candidate</c> line followed by <c>a=end-of-candidates</c>.
    /// </summary>
    /// <param name="cancellationToken">Cancels gathering.</param>
    /// <returns>The offer, ready to hand to signalling.</returns>
    /// <exception cref="InvalidOperationException">An offer has already been created, or a remote offer is pending.</exception>
    public async Task<string> CreateOfferAsync(CancellationToken cancellationToken = default)
    {
        IceAgent ice;
        lock (_lock)
        {
            ObjectDisposedException.ThrowIf(_closed != 0, this);
            if (_localDescription is not null)
            {
                throw new InvalidOperationException("This connection has already produced a local description.");
            }

            if (_remoteDescription is not null)
            {
                throw new InvalidOperationException(
                    "A remote offer was applied; call CreateAnswerAsync instead of CreateOfferAsync.");
            }

            _isOfferer = true;
            ice = EnsureIceLocked(IceRole.Controlling);
        }

        await ice.StartGatheringAsync(cancellationToken).ConfigureAwait(false);

        var session = BuildOffer(ice);
        AttachLocalCandidates(session, ice);

        lock (_lock)
        {
            _localDescription = session;
        }

        var sdp = session.ToSdpString();
        _logger.Log(KeryxLogLevel.Info, $"Created offer with {session.MediaDescriptions.Count} m-section(s).");
        return sdp;
    }

    /// <summary>
    /// Produces an answer to the offer applied by <see cref="SetRemoteDescriptionAsync"/>, gathering
    /// ICE candidates first, and then starts the connection driver.
    /// </summary>
    /// <param name="cancellationToken">Cancels gathering.</param>
    /// <returns>The answer, ready to hand to signalling.</returns>
    /// <remarks>
    /// The answerer path is deliberately minimal: it mirrors the offer's m-sections, answers
    /// <c>recvonly</c> on every media section (Keryx does not send media as an answerer) and
    /// <c>a=setup:active</c>, so this endpoint becomes the DTLS client and therefore the SCTP
    /// initiator using even stream identifiers. It exists so a Keryx-to-Keryx loopback can prove the
    /// whole stack; the offerer path is the supported production shape.
    /// </remarks>
    /// <exception cref="InvalidOperationException">No remote offer has been applied.</exception>
    public async Task<string> CreateAnswerAsync(CancellationToken cancellationToken = default)
    {
        IceAgent ice;
        SessionDescription offer;
        lock (_lock)
        {
            ObjectDisposedException.ThrowIf(_closed != 0, this);
            offer = _remoteDescription
                    ?? throw new InvalidOperationException("No remote offer has been applied.");
            if (_isOfferer)
            {
                throw new InvalidOperationException("This connection is the offerer.");
            }

            ice = EnsureIceLocked(IceRole.Controlled);
        }

        if (ice.State == IceAgentState.New)
        {
            await ice.StartGatheringAsync(cancellationToken).ConfigureAwait(false);
        }

        var session = BuildAnswer(offer, ice);
        AttachLocalCandidates(session, ice);

        lock (_lock)
        {
            _localDescription = session;
        }

        var sdp = session.ToSdpString();
        _logger.Log(KeryxLogLevel.Info, "Created answer; starting the connection driver.");
        StartDriver();
        return sdp;
    }

    /// <summary>
    /// Applies a remote description. For <see cref="SdpType.Answer"/> the answer is validated against
    /// the local offer, the negotiated codecs, ICE credentials, candidates, DTLS fingerprint and role
    /// are extracted, and the connection driver is started. For <see cref="SdpType.Offer"/> the offer
    /// is recorded so that <see cref="CreateAnswerAsync"/> can answer it.
    /// </summary>
    /// <param name="sdp">The description, exactly as signalling delivered it.</param>
    /// <param name="type">Whether <paramref name="sdp"/> is an offer or an answer.</param>
    /// <param name="cancellationToken">Reserved; applying a description does no I/O.</param>
    /// <returns>A completed task once the description has been applied.</returns>
    /// <exception cref="SdpException">The description could not be parsed, or the answer violates JSEP alignment.</exception>
    public Task SetRemoteDescriptionAsync(string sdp, SdpType type, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(sdp);
        cancellationToken.ThrowIfCancellationRequested();
        ObjectDisposedException.ThrowIf(_closed != 0, this);

        var description = SessionDescription.Parse(sdp, _logger);
        if (type == SdpType.Answer)
        {
            ApplyAnswer(description);
            StartDriver();
        }
        else
        {
            ApplyRemoteOffer(description);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Adds a candidate the peer trickled in. Empty values and <c>end-of-candidates</c> markers are
    /// accepted and ignored, so a signalling layer can forward everything it receives verbatim.
    /// </summary>
    /// <param name="candidateAttribute">An <c>a=candidate:…</c> line or a bare attribute value.</param>
    /// <param name="sdpMid">
    /// The mid the peer scoped the candidate to. Recorded for diagnostics only: this connection is
    /// max-bundle with rtcp-mux, so every candidate applies to the single transport.
    /// </param>
    public void AddIceCandidate(string candidateAttribute, string? sdpMid = null)
    {
        if (string.IsNullOrWhiteSpace(candidateAttribute))
        {
            return;
        }

        var text = candidateAttribute.Trim();
        if (text.StartsWith("a=", StringComparison.Ordinal))
        {
            text = text[2..];
        }

        if (text.Length == 0 || text.StartsWith("end-of-candidates", StringComparison.OrdinalIgnoreCase))
        {
            _logger.Log(KeryxLogLevel.Debug, $"Remote end-of-candidates for mid '{sdpMid ?? "*"}'.");
            return;
        }

        IceAgent? ice;
        lock (_lock)
        {
            if (_closed != 0)
            {
                return;
            }

            ice = _ice;
            if (ice is null)
            {
                _pendingRemoteCandidates.Add(text);
                return;
            }
        }

        ice.AddRemoteCandidate(text);
    }

    /// <summary>
    /// Completes when the connection reaches <see cref="PeerConnectionState.Connected"/>, or returns
    /// false when it fails, closes, or <paramref name="timeout"/> elapses first.
    /// </summary>
    /// <param name="timeout">How long to wait.</param>
    /// <param name="cancellationToken">Cancels the wait; the connection keeps running.</param>
    /// <returns>True when the connection became usable.</returns>
    public async Task<bool> WaitForConnectedAsync(TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        void Handler(object? sender, PeerConnectionState state)
        {
            switch (state)
            {
                case PeerConnectionState.Connected:
                    completion.TrySetResult(true);
                    break;
                case PeerConnectionState.Failed:
                case PeerConnectionState.Closed:
                    completion.TrySetResult(false);
                    break;
                default:
                    break;
            }
        }

        OnConnectionStateChanged += Handler;
        try
        {
            switch (State)
            {
                case PeerConnectionState.Connected:
                    return true;
                case PeerConnectionState.Failed:
                case PeerConnectionState.Closed:
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
            OnConnectionStateChanged -= Handler;
        }
    }

    /// <summary>Takes a small snapshot of the connection's counters and states.</summary>
    /// <returns>The snapshot.</returns>
    public PeerConnectionStats GetStats() => new(
        State,
        IceState,
        DtlsState,
        VideoStats(),
        AudioStats(),
        new FeedbackStats(
            Interlocked.Read(ref _pliCount),
            Interlocked.Read(ref _firCount),
            Interlocked.Read(ref _nackCount),
            Interlocked.Read(ref _twccCount),
            Interlocked.Read(ref _receiverReportCount)),
        Interlocked.Read(ref _rtpReceived),
        Interlocked.Read(ref _rtcpReceived),
        Interlocked.Read(ref _srtpFailures),
        Interlocked.Read(ref _mediaBeforeReady));

    /// <summary>
    /// Closes the connection: RTCP <c>BYE</c> for every active stream, SCTP shutdown, DTLS
    /// <c>close_notify</c>, ICE socket close, then <see cref="PeerConnectionState.Closed"/>.
    /// Idempotent; safe to call concurrently with anything else.
    /// </summary>
    /// <returns>A task completing once every layer has been torn down.</returns>
    public async Task CloseAsync()
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0)
        {
            return;
        }

        _logger.Log(KeryxLogLevel.Info, "Closing the peer connection.");

        Task? driver;
        List<PendingChannel> pending;
        lock (_lock)
        {
            driver = _driver;
            pending = [.. _pendingChannels];
            _pendingChannels.Clear();
        }

        foreach (var channel in pending)
        {
            channel.Completion.TrySetException(
                new ObjectDisposedException(nameof(PeerConnection), "The connection closed before SCTP started."));
        }

        StopRtcpTimer();
        TrySendGoodbye();

        try
        {
            await _cts.CancelAsync().ConfigureAwait(false);
        }
        catch (ObjectDisposedException)
        {
            // Already disposed by a concurrent close.
        }

        if (driver is not null)
        {
            try
            {
                await driver.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is TimeoutException or OperationCanceledException)
            {
                _logger.Log(KeryxLogLevel.Debug, "The connection driver did not stop promptly; continuing to close.");
            }
            catch (Exception ex)
            {
                _logger.Log(KeryxLogLevel.Debug, "The connection driver ended with an error.", ex);
            }
        }

        SctpAssociation? sctp;
        DtlsTransport? dtls;
        IceAgent? ice;
        SrtpContext? srtp;
        lock (_lock)
        {
            sctp = _sctp;
            dtls = _dtls;
            ice = _ice;
            srtp = _srtp;

            // Only the SRTP context is cleared: that stops the demultiplexer from touching keys that
            // are about to be zeroed. The ICE, DTLS and SCTP references are kept so IceState,
            // DtlsState and SctpState keep reporting the truth after the connection is closed.
            _srtp = null;
        }

        Safely(() => sctp?.Shutdown());
        Safely(() => sctp?.Dispose());
        Safely(() => dtls?.Close());
        Safely(() => dtls?.Dispose());
        Safely(() => ice?.Close());
        Safely(() => ice?.Dispose());
        Safely(() => srtp?.Dispose());
        if (_ownsCertificate)
        {
            Safely(_certificate.Dispose);
        }

        SetState(PeerConnectionState.Closed);
        _cts.Dispose();
    }

    /// <summary>Closes the connection. Equivalent to <see cref="CloseAsync"/>.</summary>
    /// <returns>A task completing once every layer has been torn down.</returns>
    public async ValueTask DisposeAsync() => await CloseAsync().ConfigureAwait(false);

    private void Safely(Action action)
    {
        try
        {
            action();
        }
        catch (Exception ex)
        {
            _logger.Log(KeryxLogLevel.Debug, "Ignoring an error while closing.", ex);
        }
    }

    private static string NewIdentifier(string prefix) =>
        prefix + "-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();

    private static uint NewSsrc() => (uint)RandomNumberGenerator.GetInt32(1, int.MaxValue);

    private void SetState(PeerConnectionState state)
    {
        lock (_lock)
        {
            if (_state == state || _state == PeerConnectionState.Closed)
            {
                return;
            }

            _state = state;
        }

        _logger.Log(KeryxLogLevel.Debug, $"Peer connection state: {state}.");
        OnConnectionStateChanged?.Invoke(this, state);
    }

    private IceAgent EnsureIceLocked(IceRole role)
    {
        if (_ice is not null)
        {
            return _ice;
        }

        var options = new IceAgentOptions
        {
            Role = role,
            BindAddress = _config.BindAddress,
            MinPort = _config.MinPort,
            MaxPort = _config.MaxPort,
            Logger = _logger,
        };

        foreach (var server in _config.StunServers)
        {
            options.StunServers.Add(server);
        }

        var ice = new IceAgent(options);
        var mid = _config.VideoCodecs.Count > 0
            ? _config.VideoMid
            : _config.AudioCodecs.Count > 0 ? _config.AudioMid : _config.ApplicationMid;

        ice.OnLocalCandidate += (_, candidate) =>
            OnLocalIceCandidate?.Invoke(this, new LocalIceCandidateEventArgs(candidate.ToAttributeString(), mid));
        ice.OnGatheringComplete += (_, _) => OnIceGatheringComplete?.Invoke(this, EventArgs.Empty);
        ice.OnStateChanged += (_, state) => HandleIceStateChanged(state);
        // PeerConnectionConfig.TransportInterceptor is the fault-injection / diagnostics seam: the
        // connection sends on, and receives from, whatever it returns rather than the ICE transport
        // itself. It sits below DTLS and SRTP, so a wrapper sees only protected datagrams.
        var transport = _config.TransportInterceptor is { } intercept
            ? intercept(ice.Transport) ?? ice.Transport
            : ice.Transport;
        transport.OnReceived += HandleTransportDatagram;

        _transport = transport;
        _ice = ice;
        _dtlsLower = new DtlsLowerTransport(this);

        foreach (var candidate in _pendingRemoteCandidates)
        {
            ice.AddRemoteCandidate(candidate);
        }

        _pendingRemoteCandidates.Clear();
        return ice;
    }

    private void HandleIceStateChanged(IceAgentState state)
    {
        switch (state)
        {
            case IceAgentState.Disconnected when State == PeerConnectionState.Connected:
                SetState(PeerConnectionState.Disconnected);
                break;
            case IceAgentState.Connected when State == PeerConnectionState.Disconnected:
                SetState(PeerConnectionState.Connected);
                break;
            case IceAgentState.Failed when State is PeerConnectionState.Connecting
                or PeerConnectionState.Connected or PeerConnectionState.Disconnected:
                SetState(PeerConnectionState.Failed);
                break;
            default:
                break;
        }
    }

    private void AttachLocalCandidates(SessionDescription session, IceAgent ice)
    {
        var candidates = ice.LocalCandidates;
        foreach (var media in session.MediaDescriptions)
        {
            foreach (var candidate in candidates)
            {
                media.AddCandidate(candidate.ToValueString());
            }

            media.EndOfCandidates = true;
        }
    }

    private SessionDescription BuildOffer(IceAgent ice)
    {
        var builder = new SdpOfferBuilder
        {
            IceCredentials = new SdpIceCredentials(ice.LocalUfrag, ice.LocalPassword),
            Fingerprint = new SdpFingerprint("sha-256", _certificate.Sha256Fingerprint),
            Setup = SdpSetupRole.ActPass,
            BundlePolicy = SdpBundlePolicy.MaxBundle,
            Cname = _cname,
            StreamId = _streamId,
            TrickleIce = true,
        };

        if (_config.VideoCodecs.Count > 0)
        {
            var codecs = BuildOfferedVideoCodecs();
            var video = SdpMediaOffer.Video(_config.VideoMid, [.. codecs]);
            video.TrackId = _videoTrackId;
            video.Ssrcs.Add(_videoSsrc);
            if (codecs.Exists(static c => c.IsRtx))
            {
                // RFC 5576 §4.2: FID associates the media source with the repair source carrying its
                // retransmissions. Both sources publish the same cname, which the builder writes.
                video.SsrcGroups.Add(new SsrcGroup(SsrcGroup.FidSemantics, [_videoSsrc, _videoRtxSsrc]));
                video.Ssrcs.Add(_videoRtxSsrc);
            }

            builder.AddMedia(video);
        }

        if (_config.AudioCodecs.Count > 0)
        {
            var audio = SdpMediaOffer.Audio(_config.AudioMid, [.. _config.AudioCodecs]);
            audio.TrackId = _audioTrackId;
            audio.Ssrcs.Add(_audioSsrc);
            builder.AddMedia(audio);
        }

        builder.AddDataChannel(_config.ApplicationMid, _config.SctpPort, _config.MaxMessageSize);
        return builder.Build();
    }

    /// <summary>
    /// Copies the configured video codecs and, when retransmission is enabled, gives each one bare
    /// <c>nack</c> feedback and a matching RFC 4588 <c>rtx</c> entry on a free dynamic payload type.
    /// The configured codecs themselves are never mutated.
    /// </summary>
    private List<SdpCodec> BuildOfferedVideoCodecs()
    {
        var codecs = new List<SdpCodec>(_config.VideoCodecs.Count * 2);
        foreach (var codec in _config.VideoCodecs)
        {
            codecs.Add(CloneCodec(codec));
        }

        if (!_config.EnableRetransmission || codecs.Count == 0)
        {
            return codecs;
        }

        var used = new HashSet<int>();
        foreach (var codec in _config.VideoCodecs)
        {
            used.Add(codec.PayloadType);
        }

        foreach (var codec in _config.AudioCodecs)
        {
            used.Add(codec.PayloadType);
        }

        var repairs = new List<SdpCodec>(codecs.Count);
        foreach (var codec in codecs)
        {
            if (codec.IsRtx)
            {
                continue;
            }

            var preferred = repairs.Count == 0 ? _config.RtxPayloadType : null;
            if (NextDynamicPayloadType(used, preferred) is not { } rtxPayloadType)
            {
                _logger.Log(
                    KeryxLogLevel.Warning,
                    "No dynamic payload type is free for an rtx codec; retransmission is not offered.");
                return codecs;
            }

            if (!codec.Feedback.Contains(RtcpFeedback.Nack))
            {
                codec.Feedback.Insert(0, RtcpFeedback.Nack);
            }

            repairs.Add(SdpCodec.Rtx(rtxPayloadType, codec.PayloadType, codec.ClockRate));
        }

        codecs.AddRange(repairs);
        return codecs;
    }

    private static int? NextDynamicPayloadType(HashSet<int> used, int? preferred)
    {
        if (preferred is { } candidate && candidate is >= 0 and <= 127 && used.Add(candidate))
        {
            return candidate;
        }

        // RFC 3551 §6 reserves 96-127 for dynamic assignment, which is what browsers use for rtx.
        for (var payloadType = 96; payloadType <= 127; payloadType++)
        {
            if (used.Add(payloadType))
            {
                return payloadType;
            }
        }

        return null;
    }

    private static SdpCodec CloneCodec(SdpCodec codec)
    {
        var copy = new SdpCodec(codec.PayloadType, codec.EncodingName, codec.ClockRate, codec.Channels)
        {
            Fmtp = codec.Fmtp,
        };

        foreach (var feedback in codec.Feedback)
        {
            copy.Feedback.Add(feedback);
        }

        return copy;
    }

    private static int? AssociatedPayloadType(string? fmtp) =>
        int.TryParse(
            FmtpParameters.GetValue(fmtp, SdpCodec.AssociatedPayloadTypeParameter),
            NumberStyles.None,
            CultureInfo.InvariantCulture,
            out var apt)
            ? apt
            : null;

    private SessionDescription BuildAnswer(SessionDescription offer, IceAgent ice)
    {
        var builder = new SdpOfferBuilder
        {
            IceCredentials = new SdpIceCredentials(ice.LocalUfrag, ice.LocalPassword),
            Fingerprint = new SdpFingerprint("sha-256", _certificate.Sha256Fingerprint),
            Setup = SdpSetupRole.Active,
            BundlePolicy = offer.GetBundleGroup().Count > 0 ? SdpBundlePolicy.MaxBundle : SdpBundlePolicy.Disabled,
            Cname = _cname,
            StreamId = _streamId,
            TrickleIce = true,
        };

        for (var i = 0; i < offer.MediaDescriptions.Count; i++)
        {
            var offered = offer.MediaDescriptions[i];
            var mid = offered.Mid ?? i.ToString(CultureInfo.InvariantCulture);

            if (string.Equals(offered.Media, "application", StringComparison.Ordinal))
            {
                var application = SdpMediaOffer.Application(mid, _config.SctpPort, _config.MaxMessageSize);
                application.Protocol = offered.Protocol;
                builder.AddMedia(application);
                continue;
            }

            var section = new SdpMediaOffer(mid, offered.Media, offered.Protocol)
            {
                Direction = MediaDirection.RecvOnly,
                RtcpMux = offered.RtcpMux,
            };

            var acceptable = string.Equals(offered.Media, "video", StringComparison.Ordinal)
                ? _config.VideoCodecs
                : _config.AudioCodecs;

            var accepted = new HashSet<int>();
            foreach (var payloadType in offered.GetPayloadTypes())
            {
                var rtpMap = offered.GetRtpMap(payloadType);
                if (rtpMap is null)
                {
                    continue;
                }

                var fmtp = offered.GetFmtp(payloadType);
                if (string.Equals(rtpMap.EncodingName, SdpCodec.RtxEncodingName, StringComparison.OrdinalIgnoreCase))
                {
                    // RFC 4588 §8.1: a repair codec is only meaningful when its apt names a codec that
                    // survived, so answer rtx if and only if the stream it repairs was kept.
                    if (AssociatedPayloadType(fmtp) is not { } apt || !accepted.Contains(apt))
                    {
                        continue;
                    }
                }
                else if (!acceptable.Any(c => string.Equals(c.EncodingName, rtpMap.EncodingName, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                var codec = new SdpCodec(payloadType, rtpMap.EncodingName, rtpMap.ClockRate, rtpMap.Channels);
                if (fmtp is not null)
                {
                    // Codec parameters the offerer set — Opus useinbandfec and minptime, H.264
                    // packetization-mode and profile-level-id — are echoed unchanged.
                    codec.Fmtp = fmtp;
                }

                foreach (var feedback in offered.GetRtcpFeedback(payloadType))
                {
                    codec.Feedback.Add(feedback);
                }

                section.Codecs.Add(codec);
                accepted.Add(payloadType);
            }

            if (section.Codecs.Count == 0)
            {
                // Nothing in common: reject the section with port 0, but keep the m-line well formed
                // by echoing the first offered format so JSEP alignment still holds.
                section.Port = 0;
                var first = offered.GetPayloadTypes().FirstOrDefault(-1);
                if (first >= 0)
                {
                    var rtpMap = offered.GetRtpMap(first);
                    section.Codecs.Add(rtpMap is null
                        ? new SdpCodec(first, "unknown", 90000)
                        : new SdpCodec(first, rtpMap.EncodingName, rtpMap.ClockRate, rtpMap.Channels));
                }
            }

            builder.AddMedia(section);
        }

        return builder.Build();
    }

    private void ApplyRemoteOffer(SessionDescription offer)
    {
        IceAgent ice;
        lock (_lock)
        {
            _isOfferer = false;
            _remoteDescription = offer;
            ice = EnsureIceLocked(IceRole.Controlled);
        }

        string? ufrag = null;
        string? password = null;
        var routes = new Dictionary<byte, RtpRoute>();

        foreach (var media in offer.MediaDescriptions)
        {
            ufrag ??= media.IceUfrag ?? offer.IceUfrag;
            password ??= media.IcePwd ?? offer.IcePwd;

            lock (_lock)
            {
                _remoteFingerprint ??= media.Fingerprint ?? offer.Fingerprint;
                if (media.SctpPort is { } port)
                {
                    _remoteSctpPort = port;
                }

                if (media.Setup is { } setup)
                {
                    _dtlsRole = ToDtlsRole(setup.Complement());
                }
            }

            var kind = ToMediaKind(media.Media);
            if (kind is MediaKind.Audio or MediaKind.Video)
            {
                var acceptable = kind == MediaKind.Video ? _config.VideoCodecs : _config.AudioCodecs;
                foreach (var payloadType in media.GetPayloadTypes())
                {
                    if (payloadType is < 0 or > 127)
                    {
                        continue;
                    }

                    var rtpMap = media.GetRtpMap(payloadType);
                    if (rtpMap is null)
                    {
                        continue;
                    }

                    if (string.Equals(rtpMap.EncodingName, SdpCodec.RtxEncodingName, StringComparison.OrdinalIgnoreCase))
                    {
                        // Route inbound repair packets alongside the stream they repair.
                        if (AssociatedPayloadType(media.GetFmtp(payloadType)) is { } apt
                            && apt is >= 0 and <= 127
                            && routes.ContainsKey((byte)apt))
                        {
                            routes[(byte)payloadType] = new RtpRoute(media.Mid ?? string.Empty, kind);
                        }

                        continue;
                    }

                    if (!acceptable.Any(c =>
                            string.Equals(c.EncodingName, rtpMap.EncodingName, StringComparison.OrdinalIgnoreCase)))
                    {
                        continue;
                    }

                    routes[(byte)payloadType] = new RtpRoute(media.Mid ?? string.Empty, kind);
                }
            }

            foreach (var candidate in media.GetCandidates())
            {
                ice.AddRemoteCandidate(candidate);
            }
        }

        if (ufrag is not null && password is not null)
        {
            ice.SetRemoteCredentials(ufrag, password);
        }

        Volatile.Write(ref _routes, routes);
        _logger.Log(
            KeryxLogLevel.Info,
            $"Applied remote offer; local DTLS role {LocalDtlsRole}, {routes.Count} inbound payload type(s).");
    }

    private void ApplyAnswer(SessionDescription answer)
    {
        SessionDescription offer;
        IceAgent ice;
        lock (_lock)
        {
            offer = _localDescription
                    ?? throw new InvalidOperationException("No local offer exists to negotiate the answer against.");
            ice = _ice ?? throw new InvalidOperationException("The ICE agent has not been created.");
            _remoteDescription = answer;
        }

        var result = SdpNegotiator.Negotiate(offer, answer);

        string? ufrag = null;
        string? password = null;
        var routes = new Dictionary<byte, RtpRoute>();

        foreach (var media in result.Media)
        {
            ufrag ??= media.IceUfrag;
            password ??= media.IcePwd;

            lock (_lock)
            {
                _remoteFingerprint ??= media.Fingerprint;
                if (media.SctpPort is { } port)
                {
                    _remoteSctpPort = port;
                }

                if (media.LocalSetup is { } local)
                {
                    _dtlsRole = ToDtlsRole(local);
                }
            }

            foreach (var candidate in media.Candidates)
            {
                ice.AddRemoteCandidate(candidate);
            }

            var kind = ToMediaKind(media.MediaType);
            if (kind is not (MediaKind.Audio or MediaKind.Video))
            {
                continue;
            }

            var configured = kind == MediaKind.Video ? _config.VideoCodecs : _config.AudioCodecs;
            foreach (var codec in media.Codecs)
            {
                if (codec.PayloadType is < 0 or > 127)
                {
                    continue;
                }

                if (!configured.Any(c => string.Equals(c.EncodingName, codec.EncodingName, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                routes[(byte)codec.PayloadType] = new RtpRoute(media.Mid ?? string.Empty, kind);
            }

            var chosen = media.Codecs.FirstOrDefault(c =>
                configured.Any(x => string.Equals(x.EncodingName, c.EncodingName, StringComparison.OrdinalIgnoreCase)));
            if (chosen is null)
            {
                _logger.Log(KeryxLogLevel.Warning, $"The answer kept no usable codec for m-section '{media.Mid}'.");
                continue;
            }

            if (kind == MediaKind.Video)
            {
                byte? rtxPayloadType = null;
                if (_config.EnableRetransmission)
                {
                    // RFC 4588 §8.1: retransmission is negotiated only if the answer keeps an rtx
                    // codec whose apt names the media codec we settled on. Bare a=rtcp-fb nack in the
                    // answer is not enough — without a repair stream there is nowhere to send resends,
                    // and resending on the media SSRC would corrupt its sequence numbering.
                    var rtx = media.FindRtxCodec(chosen.PayloadType);
                    if (rtx is not null && rtx.PayloadType is >= 0 and <= 127)
                    {
                        rtxPayloadType = (byte)rtx.PayloadType;
                        routes[(byte)rtx.PayloadType] = new RtpRoute(media.Mid ?? string.Empty, kind);
                    }
                    else
                    {
                        _logger.Log(
                            KeryxLogLevel.Info,
                            $"The answer kept no rtx codec for payload type {chosen.PayloadType}; retransmission is disabled.");
                    }
                }

                _negotiatedVideo = new NegotiatedTrack(
                    media.Mid ?? _config.VideoMid,
                    (byte)chosen.PayloadType,
                    (uint)chosen.ClockRate,
                    rtxPayloadType);
            }
            else
            {
                _negotiatedAudio = new NegotiatedTrack(media.Mid ?? _config.AudioMid, (byte)chosen.PayloadType, (uint)chosen.ClockRate);
            }
        }

        if (ufrag is not null && password is not null)
        {
            ice.SetRemoteCredentials(ufrag, password);
        }

        Volatile.Write(ref _routes, routes);
        _logger.Log(
            KeryxLogLevel.Info,
            $"Applied answer; local DTLS role {LocalDtlsRole}, video pt {_negotiatedVideo?.PayloadType}"
            + $" (rtx pt {_negotiatedVideo?.RtxPayloadType?.ToString(CultureInfo.InvariantCulture) ?? "none"}),"
            + $" audio pt {_negotiatedAudio?.PayloadType}.");
    }

    private static DtlsRole ToDtlsRole(SdpSetupRole role) => role switch
    {
        SdpSetupRole.Active => DtlsRole.Client,
        SdpSetupRole.Passive => DtlsRole.Server,
        _ => DtlsRole.Server,
    };

    private static MediaKind ToMediaKind(string mediaType) => mediaType switch
    {
        "video" => MediaKind.Video,
        "audio" => MediaKind.Audio,
        "application" => MediaKind.Application,
        _ => MediaKind.Unknown,
    };

    private sealed record PendingChannel(
        string Label,
        bool Ordered,
        ushort? MaxRetransmits,
        string Protocol,
        TaskCompletionSource<DataChannel> Completion);

    private readonly record struct RtpRoute(string Mid, MediaKind Kind);

    /// <summary>
    /// What the answer settled on for one media kind. <paramref name="RtxPayloadType"/> is null when
    /// the answerer dropped the RFC 4588 repair codec, which disables retransmission for the track.
    /// </summary>
    private sealed record NegotiatedTrack(
        string Mid,
        byte PayloadType,
        uint ClockRate,
        byte? RtxPayloadType = null);

    private sealed class DtlsLowerTransport(PeerConnection owner) : IDatagramTransport
    {
        public int MaxDatagramSize => owner._transport?.MaxDatagramSize ?? 1200;

        public event DatagramReceivedHandler? OnReceived;

        public void Send(ReadOnlySpan<byte> datagram)
        {
            var transport = owner._transport;
            if (transport is null)
            {
                return;
            }

            try
            {
                transport.Send(datagram);
            }
            catch (InvalidOperationException)
            {
                // No nominated pair yet, or the agent closed underneath us (ObjectDisposedException
                // derives from InvalidOperationException). DTLS retransmits its flight, so dropping
                // is the correct behaviour here.
            }
        }

        internal void Deliver(ReadOnlySpan<byte> datagram) => OnReceived?.Invoke(datagram);
    }
}
