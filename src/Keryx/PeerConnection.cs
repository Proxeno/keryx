using System.Globalization;
using System.Security.Cryptography;
using Keryx.Core;
using Keryx.Dtls;
using Keryx.Ice;
using Keryx.Rtp;
using Keryx.Rtp.CongestionControl;
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
/// <para><b>Congestion control.</b> Opt-in via
/// <see cref="PeerConnectionConfig.EnableCongestionControl"/>: inbound transport-wide-cc feedback,
/// reception-report loss and REMB drive a send-side GCC estimator whose target bitrate paces outbound
/// RTP and is published through <see cref="TargetBitrateChanged"/> for an encoder to consume. Off by
/// default, leaving the immediate, unbuffered send path in place.</para>
/// <para><b>Not implemented.</b> No ULPFEC or RED, no simulcast, no renegotiation, no ICE restart and
/// no IPv6 relay candidates.</para>
/// </remarks>
public sealed partial class PeerConnection : IAsyncDisposable
{
    private const string ExporterLabel = "EXTRACTOR-dtls_srtp";

    /// <summary>The one-byte <c>a=extmap</c> id offered for the RFC 8843 §9.2 MID header extension.</summary>
    private const int MidHeaderExtensionId = 4;

    private readonly PeerConnectionConfig _config;
    private readonly TimeProvider _time;
    private readonly GccCongestionController? _congestionController;
    private readonly IKeryxLogger _logger;
    private readonly DtlsCertificate _certificate;
    private readonly bool _ownsCertificate;
    private readonly object _lock = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly List<PendingChannel> _pendingChannels = [];
    private readonly List<string> _pendingRemoteCandidates = [];
    private readonly string _cname;
    private readonly string _streamId;
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
        _time = _config.TimeProvider;
        _certificate = _config.Certificate ?? DtlsCertificate.GenerateSelfSigned();
        _ownsCertificate = _config.Certificate is null;
        _cname = _config.Cname ?? NewIdentifier("keryx");
        _streamId = _config.StreamId ?? NewIdentifier("stream");
        _rtcpSenderSsrc = NewSsrc();
        _videoForwarder = new RtpForwarderHandle(this, MediaKind.Video);
        _audioForwarder = new RtpForwarderHandle(this, MediaKind.Audio);

        // Build the legacy per-kind transceivers from the config (session-model.md §5.1). Their senders
        // own the pre-allocated SSRCs and track ids, so the per-kind identity accessors resolve to them.
        BuildLegacyTransceivers();

        if (_config.EnableCongestionControl)
        {
            // The controller is transport-independent: it consumes RTCP feedback and publishes a
            // target bitrate. It exists from construction so the feedback dispatch and any subscriber
            // can bind to it before the transport is up. The pacer that consumes its target is built
            // later, once the send path and its MTU are known (see CreateTrackSenders).
            _congestionController = new GccCongestionController(_config.CongestionControl, _time);
            _congestionController.TargetBitrateChanged += OnControllerTargetBitrateChanged;
        }
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

    /// <summary>
    /// Raised when the send-side congestion controller's target bitrate moves. An encoder rate
    /// controller subscribes to this to retune the codec. Never raised unless
    /// <see cref="PeerConnectionConfig.EnableCongestionControl"/> was set.
    /// </summary>
    /// <remarks>Raised on the RTCP receive thread; handlers must be quick and must not block.</remarks>
    public event EventHandler<TargetBitrateChangedEventArgs>? TargetBitrateChanged;

    /// <summary>
    /// Raised for every received RTCP Sender Report, carrying the NTP↔RTP timestamp correspondence for
    /// the sending SSRC. Supplies the wall-clock mapping a simulcast SFU feeds to
    /// <c>RtpForwarder.RecordSenderReport</c> to align timestamps across layer switches.
    /// </summary>
    public event EventHandler<SenderReportEventArgs>? OnSenderReport;

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

    /// <summary>
    /// The send-side congestion controller, or <see langword="null"/> when
    /// <see cref="PeerConnectionConfig.EnableCongestionControl"/> was not set. Read
    /// <see cref="ICongestionController.TargetBitrateBitsPerSecond"/> for the current target, or
    /// subscribe to <see cref="TargetBitrateChanged"/> to be notified as it moves.
    /// </summary>
    public ICongestionController? CongestionController => _congestionController;

    /// <summary>The synchronisation source of the outbound video stream.</summary>
    public uint VideoSsrc => FirstSender(MediaKind.Video)?.Ssrc ?? 0;

    /// <summary>
    /// The synchronisation source of the outbound video retransmission stream, published as the second
    /// member of <c>a=ssrc-group:FID</c> when RFC 4588 RTX is offered.
    /// </summary>
    public uint VideoRtxSsrc => FirstSender(MediaKind.Video)?.RtxSsrc ?? 0;

    /// <summary>The synchronisation source of the outbound audio stream.</summary>
    public uint AudioSsrc => FirstSender(MediaKind.Audio)?.Ssrc ?? 0;

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
    /// <param name="maxPacketLifetime">
    /// Message lifetime in milliseconds, or null for full reliability. A message still
    /// unacknowledged after this many milliseconds is abandoned (RFC 3758 timed PR-SCTP). Mutually
    /// exclusive with <paramref name="maxRetransmits"/>.
    /// </param>
    /// <returns>
    /// A task completing with the channel. It completes synchronously once SCTP is up; before that it
    /// completes when the association is created, which is the earliest point at which a stream
    /// identifier can be allocated — RFC 8832 §6 ties stream parity to the DTLS role, and that role is
    /// not known until the remote description arrives.
    /// </returns>
    /// <exception cref="ObjectDisposedException">The connection is closed.</exception>
    /// <exception cref="ArgumentException">Both <paramref name="maxRetransmits"/> and <paramref name="maxPacketLifetime"/> are set.</exception>
    public Task<DataChannel> CreateDataChannel(
        string label,
        bool ordered = true,
        ushort? maxRetransmits = null,
        string protocol = "",
        ushort? maxPacketLifetime = null)
    {
        ArgumentNullException.ThrowIfNull(label);
        ArgumentNullException.ThrowIfNull(protocol);
        if (maxRetransmits.HasValue && maxPacketLifetime.HasValue)
        {
            throw new ArgumentException(
                "maxRetransmits and maxPacketLifetime are mutually exclusive; RFC 8832 channel types cannot select both.",
                nameof(maxPacketLifetime));
        }

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
                    maxPacketLifetime,
                    new TaskCompletionSource<DataChannel>(TaskCreationOptions.RunContinuationsAsynchronously));
                _pendingChannels.Add(pending);
                return pending.Completion.Task;
            }
        }

        return Task.FromResult(association.CreateChannel(label, ordered, maxRetransmits, protocol, maxPacketLifetime));
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
    /// The answerer mirrors the offer's m-sections and negotiates each answered direction from the
    /// offered one: a <c>sendrecv</c> or <c>sendonly</c> offer answers <c>recvonly</c> and an
    /// <c>inactive</c> offer stays <c>inactive</c>, while a <c>recvonly</c> offer — the SFU subscriber
    /// shape, where a viewer only wants to receive — answers <c>sendonly</c> and wires a real send
    /// track (local SSRC, SRTP-protected sender, pacer and RFC 4588 repair stream), so
    /// <see cref="SendVideoFrame"/>, <see cref="TryForwardRtp"/> and the introspection accessors all
    /// light up on the answerer just as they do on the offerer. It also answers <c>a=setup:active</c>,
    /// so this endpoint becomes the DTLS client and therefore the SCTP initiator using even stream
    /// identifiers.
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
            Interlocked.Read(ref _receiverReportCount),
            Interlocked.Read(ref _receiverNacksSent),
            Interlocked.Read(ref _receiverTransportCcFeedbacksSent)),
        Interlocked.Read(ref _rtpReceived),
        Interlocked.Read(ref _rtcpReceived),
        Interlocked.Read(ref _srtpFailures),
        Interlocked.Read(ref _mediaBeforeReady),
        BuildTransceiverStats());

    /// <summary>
    /// Forwards a congestion-controller target change to the pacer and to public subscribers. Runs on
    /// the RTCP receive thread that drove the feedback.
    /// </summary>
    private void OnControllerTargetBitrateChanged(object? sender, TargetBitrateChangedEventArgs e)
    {
        _pacedSender?.SetTargetBitrate(e.TargetBitrateBitsPerSecond);
        TargetBitrateChanged?.Invoke(this, e);
    }

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
        _pacedSender?.Dispose();
        if (_congestionController is not null)
        {
            _congestionController.TargetBitrateChanged -= OnControllerTargetBitrateChanged;
        }

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

        foreach (var turnServer in _config.TurnServers)
        {
            options.TurnServers.Add(turnServer);
        }

        var ice = new IceAgent(options);
        var (mid, mLineIndex) = SelectCandidateMediaSection();

        ice.OnLocalCandidate += (_, candidate) =>
            OnLocalIceCandidate?.Invoke(
                this,
                new LocalIceCandidateEventArgs(candidate.ToAttributeString(), mid, mLineIndex));
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

    /// <summary>
    /// Picks the mid a gathered local candidate is reported against, and that mid's 0-based m-line
    /// index in the description that will carry it.
    /// </summary>
    /// <remarks>
    /// Candidates are raised while gathering, before <see cref="BuildOffer"/> / <see cref="BuildAnswer"/>
    /// have run, so there is no built <see cref="SessionDescription"/> to look the index up against yet.
    /// Instead this mirrors the section order those builders are about to produce: when answering,
    /// <see cref="BuildAnswer"/> mirrors the applied offer's sections index-for-index, so the offer's
    /// first m-line is the answer's first m-line; when offering, <see cref="BuildOffer"/> emits video
    /// (if configured), then audio (if configured), then the data channel, in that order. Either way the
    /// selected mid is always the section that ends up first — under Keryx's single max-bundle transport
    /// every candidate belongs to the whole bundle, so it is always scoped to m-line 0. The index is
    /// still computed by position rather than assumed, so this keeps working if that ordering — or which
    /// kind leads it — changes later.
    /// </remarks>
    private (string Mid, int MLineIndex) SelectCandidateMediaSection()
    {
        if (_remoteDescription is { MediaDescriptions.Count: > 0 } remote)
        {
            var firstOffered = remote.MediaDescriptions[0].Mid ?? _config.ApplicationMid;
            return (firstOffered, 0);
        }

        var order = new List<string>(3);
        if (_config.VideoCodecs.Count > 0)
        {
            order.Add(_config.VideoMid);
        }

        if (_config.AudioCodecs.Count > 0)
        {
            order.Add(_config.AudioMid);
        }

        order.Add(_config.ApplicationMid);

        var mid = order[0];
        return (mid, order.IndexOf(mid));
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

        // Allocate mids for any application-added transceivers (session-model.md §3.1), then walk the
        // transceiver set in m-line order. For the legacy transceiver set (one sendonly video, one
        // sendonly audio) this emits byte-identical SDP: same mids, order, directions, codecs, SSRCs and
        // — because the MID extmap is offered only once the transceiver API is used — the same extmaps.
        AllocateOfferMids();

        foreach (var transceiver in _transceivers)
        {
            var sender = transceiver.Sender;
            var mid = transceiver.Mid!;
            if (transceiver.Kind == MediaKind.Video)
            {
                IReadOnlyList<SdpCodec> videoSource = transceiver.OfferCodecs.Count > 0
                    ? transceiver.OfferCodecs
                    : [.. _config.VideoCodecs];
                var codecs = BuildOfferedVideoCodecs(videoSource, transceiver.EnableRetransmissionOnOffer);
                var video = SdpMediaOffer.Video(mid, [.. codecs]);
                video.Direction = transceiver.Direction;
                AddMidExtmap(video);
                if (_config.EnableTransportWideCc)
                {
                    video.HeaderExtensions.Add(SdpExtMap.TransportWideCc(TransportCcExtensionId));
                }

                if (transceiver.Direction.Sends())
                {
                    video.TrackId = sender.TrackId;
                    video.Ssrcs.Add(sender.Ssrc);
                    if (codecs.Exists(static c => c.IsRtx))
                    {
                        // RFC 5576 §4.2: FID associates the media source with the repair source carrying
                        // its retransmissions. Both sources publish the same cname, which the builder writes.
                        video.SsrcGroups.Add(new SsrcGroup(SsrcGroup.FidSemantics, [sender.Ssrc, sender.RtxSsrcRaw]));
                        video.Ssrcs.Add(sender.RtxSsrcRaw);
                    }
                }

                builder.AddMedia(video);
            }
            else if (transceiver.Kind == MediaKind.Audio)
            {
                IReadOnlyList<SdpCodec> audioSource = transceiver.OfferCodecs.Count > 0
                    ? transceiver.OfferCodecs
                    : [.. _config.AudioCodecs];
                var audio = SdpMediaOffer.Audio(mid, [.. audioSource]);
                audio.Direction = transceiver.Direction;
                AddMidExtmap(audio);
                if (_config.EnableTransportWideCc)
                {
                    audio.HeaderExtensions.Add(SdpExtMap.TransportWideCc(TransportCcExtensionId));
                }

                if (transceiver.Direction.Sends())
                {
                    audio.TrackId = sender.TrackId;
                    audio.Ssrcs.Add(sender.Ssrc);
                }

                builder.AddMedia(audio);
            }
        }

        builder.AddDataChannel(_config.ApplicationMid, _config.SctpPort, _config.MaxMessageSize);
        return builder.Build();
    }

    /// <summary>
    /// Offers the RFC 8843 §9.2 MID header extension on an RTP m-line, but only once the public
    /// transceiver API is in use (session-model.md §3.5). A pure legacy single-per-kind config never
    /// reaches this, keeping its offer byte-identical; a multi-m-line offer carries the extension so a
    /// real browser can demux the bundle by mid.
    /// </summary>
    private void AddMidExtmap(SdpMediaOffer section)
    {
        if (_transceiverApiUsed)
        {
            section.HeaderExtensions.Add(new SdpExtMap(MidHeaderExtensionId, RtpHeaderExtensionUri.Mid));
        }
    }

    /// <summary>
    /// Copies <paramref name="source"/>'s video codecs and, when <paramref name="enableRtx"/> is set,
    /// gives each one bare <c>nack</c> feedback and a matching RFC 4588 <c>rtx</c> entry on a free
    /// dynamic payload type. The source codecs themselves are never mutated.
    /// </summary>
    private List<SdpCodec> BuildOfferedVideoCodecs(IReadOnlyList<SdpCodec> source, bool enableRtx)
    {
        var codecs = new List<SdpCodec>(source.Count * 2);
        foreach (var codec in source)
        {
            codecs.Add(CloneCodec(codec));
        }

        if (!enableRtx || codecs.Count == 0)
        {
            return codecs;
        }

        var used = new HashSet<int>();
        foreach (var codec in source)
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

        // The transport-wide sequence number the send path stamps is shared across the BUNDLE; the
        // first sending section that echoed the extension fixes its id for the whole connection.
        byte? answerSendTransportCcId = null;

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

            // Resolve the transceiver bound to this m-line when the offer was applied (session-model.md
            // §3.2) and negotiate the answered direction from the transceiver's direction, which the
            // binding defaulted to the complement of the offered one (unless the application set it). This
            // reproduces the historical answerer rule exactly: Keryx answers as a sender when — and only
            // when — the offer is recvonly (the SFU subscriber shape, where a viewer offers recvonly and
            // Keryx answers sendonly on its own SSRC); every other offered direction leaves the transceiver
            // receive-only, so a sendrecv or sendonly offer answers recvonly and an inactive offer stays
            // inactive.
            var offeredDirection = offered.DirectionOrDefault;
            var kind = ToMediaKind(offered.Media);
            var boundTransceiver = kind is MediaKind.Video or MediaKind.Audio ? GetTransceiver(mid) : null;
            MediaDirection negotiatedDirection;
            if (boundTransceiver is not null)
            {
                negotiatedDirection = SdpDirection.Negotiate(boundTransceiver.Direction, offeredDirection);
                boundTransceiver.CurrentDirection = negotiatedDirection;
            }
            else
            {
                var localCapability = offeredDirection == MediaDirection.RecvOnly
                    ? MediaDirection.SendRecv
                    : MediaDirection.RecvOnly;
                negotiatedDirection = SdpDirection.Negotiate(localCapability, offeredDirection);
            }

            var section = new SdpMediaOffer(mid, offered.Media, offered.Protocol)
            {
                Direction = negotiatedDirection,
                RtcpMux = offered.RtcpMux,
            };

            if (_config.EnableTransportWideCc)
            {
                // RFC 8285 §5: echo the offered transport-wide CC mapping, keeping the offerer's id, so
                // the extension is negotiated symmetrically across the BUNDLE.
                foreach (var extMap in offered.GetExtMaps())
                {
                    if (extMap.IsTransportWideCc && extMap.Id is >= 1 and <= 14)
                    {
                        section.HeaderExtensions.Add(SdpExtMap.TransportWideCc(extMap.Id));

                        // Record the negotiated id for the receive path regardless of media direction: a
                        // receive-only answer still parses inbound transport-wide sequence numbers and
                        // returns feedback, even though it never stamps (that is _sendTransportCcExtensionId).
                        _negotiatedTransportCcExtensionId ??= (byte)extMap.Id;
                        break;
                    }
                }
            }

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

            // Publish this m-line's negotiated receive codecs on the bound transceiver's receiver and the
            // primary codec on the transceiver, so the public model reflects what was settled (§2.1).
            if (boundTransceiver is not null && section.Port != 0)
            {
                var receivePayloadTypes = new List<byte>();
                foreach (var codec in section.Codecs)
                {
                    if (!codec.IsRtx && codec.PayloadType is >= 0 and <= 255)
                    {
                        receivePayloadTypes.Add((byte)codec.PayloadType);
                    }
                }

                boundTransceiver.Receiver.PayloadTypes = receivePayloadTypes;
                if (section.Codecs.FirstOrDefault(c => !c.IsRtx) is { } primaryCodec)
                {
                    boundTransceiver.NegotiatedCodec = new NegotiatedCodec(
                        primaryCodec.PayloadType,
                        new RtpMap(primaryCodec.PayloadType, primaryCodec.EncodingName, primaryCodec.ClockRate, primaryCodec.Channels),
                        primaryCodec.Fmtp,
                        [.. primaryCodec.Feedback]);
                }
            }

            if (_config.EnableSimulcast
                && string.Equals(offered.Media, "video", StringComparison.Ordinal)
                && section.Codecs.Count > 0
                && section.Port != 0
                && SdpNegotiator.AnswerSimulcast(offered) is { HasRidExtension: true } simulcast)
            {
                foreach (var extMap in simulcast.HeaderExtensions)
                {
                    section.HeaderExtensions.Add(extMap);
                }

                foreach (var rid in simulcast.Rids)
                {
                    section.Rids.Add(rid);
                }

                section.Simulcast = simulcast.Simulcast;
            }

            // When the negotiated direction has this endpoint sending (a recvonly offer answered
            // sendonly), wire the send track the driver builds in CreateTrackSenders: pick the primary
            // codec — and its RFC 4588 rtx repair codec, if the answer kept one — record it as the
            // negotiated track so the introspection accessors and TryForwardRtp resolve, and publish
            // this connection's send SSRC (plus the FID repair SSRC) so the peer can correlate the
            // stream it is about to receive.
            if (negotiatedDirection.Sends() && section.Port != 0)
            {
                var primary = section.Codecs.FirstOrDefault(c => !c.IsRtx);
                if (boundTransceiver is not null && kind is MediaKind.Video or MediaKind.Audio && primary is not null)
                {
                    var sender = boundTransceiver.Sender;
                    byte? rtxPayloadType = null;
                    if (kind == MediaKind.Video)
                    {
                        var rtx = section.Codecs.FirstOrDefault(c =>
                            c.IsRtx && AssociatedPayloadType(c.Fmtp) == primary.PayloadType);
                        if (rtx is not null && rtx.PayloadType is >= 0 and <= 127)
                        {
                            rtxPayloadType = (byte)rtx.PayloadType;
                        }
                    }

                    var sendSsrc = sender.Ssrc;
                    section.TrackId = sender.TrackId;
                    section.Ssrcs.Add(sendSsrc);
                    if (rtxPayloadType is not null)
                    {
                        // RFC 5576 §4.2: FID binds the media source to the repair source that carries
                        // its retransmissions; both publish the same cname, which the builder writes.
                        section.SsrcGroups.Add(new SsrcGroup(SsrcGroup.FidSemantics, [sendSsrc, sender.RtxSsrcRaw]));
                        section.Ssrcs.Add(sender.RtxSsrcRaw);
                    }

                    sender.Negotiated = new NegotiatedTrack(
                        mid,
                        (byte)primary.PayloadType,
                        (uint)primary.ClockRate,
                        rtxPayloadType);

                    if (_config.EnableTransportWideCc && answerSendTransportCcId is null)
                    {
                        foreach (var extMap in section.HeaderExtensions)
                        {
                            if (extMap.IsTransportWideCc && extMap.Id is >= 1 and <= 14)
                            {
                                answerSendTransportCcId = (byte)extMap.Id;
                                break;
                            }
                        }
                    }
                }
            }

            // Echo the RFC 8843 §9.2 MID header extension when the offer carried it (session-model.md
            // §3.5), keeping the offerer's id, so a peer demuxes our bundle by mid. Skipped when the
            // section already carries a MID extmap (a simulcast section adds its own), and absent for a
            // synthetic offer with no MID extension, so the golden answers are byte-identical.
            var offeredMidId = FindMidExtensionId(offered.GetExtMaps());
            if (offeredMidId != 0
                && !section.HeaderExtensions.Any(e => string.Equals(e.Uri, RtpHeaderExtensionUri.Mid, StringComparison.Ordinal)))
            {
                section.HeaderExtensions.Add(new SdpExtMap(offeredMidId, RtpHeaderExtensionUri.Mid));
            }

            builder.AddMedia(section);
        }

        _sendTransportCcExtensionId = answerSendTransportCcId;
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
        var routesByMid = new Dictionary<string, Dictionary<byte, RtpRoute>>(StringComparer.Ordinal);
        var ssrcToMid = new Dictionary<uint, string>();
        byte midExtensionId = 0;
        var rtxToMedia = new Dictionary<uint, uint>();

        // Bind each offered RTP m-line to a transceiver now (RFC 8829 §5.10, session-model.md §3.2), so
        // OnTransceiver fires for auto-created ones before CreateAnswerAsync runs and a handler can set
        // the direction. The answer builder later reads the bound transceiver by mid.
        var associated = new HashSet<RtpTransceiver>();
        var autoCreated = new List<RtpTransceiver>();
        var mediaIndex = -1;

        foreach (var media in offer.MediaDescriptions)
        {
            mediaIndex++;
            ufrag ??= media.IceUfrag ?? offer.IceUfrag;
            password ??= media.IcePwd ?? offer.IcePwd;
            CollectFidAssociations(media.GetSsrcGroups(), rtxToMedia);

            // The MID extension is transport-wide across the BUNDLE (RFC 8843 §9.2); the first section
            // that carries it fixes the element id the demux reads. Consumed only — Keryx does not offer
            // the extension on its own SDP yet, so this is populated only when the remote offered it.
            if (midExtensionId == 0)
            {
                midExtensionId = FindMidExtensionId(media.GetExtMaps());
            }

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
                var bindMid = media.Mid ?? mediaIndex.ToString(CultureInfo.InvariantCulture);
                var bound = BindOfferedMediaLine(kind, bindMid, media.DirectionOrDefault, associated, out var created);
                if (created)
                {
                    autoCreated.Add(bound);
                }

                var mid = media.Mid ?? string.Empty;
                var perMid = mid.Length != 0 ? GetOrAddMidRoutes(routesByMid, mid) : null;
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
                            var rtxRoute = new RtpRoute(
                                mid,
                                kind,
                                (uint)rtpMap.ClockRate,
                                IsRtx: true,
                                AptPayloadType: (byte)apt);
                            routes[(byte)payloadType] = rtxRoute;
                            perMid?.TryAdd((byte)payloadType, rtxRoute);
                        }

                        continue;
                    }

                    if (!acceptable.Any(c =>
                            string.Equals(c.EncodingName, rtpMap.EncodingName, StringComparison.OrdinalIgnoreCase)))
                    {
                        continue;
                    }

                    var route = new RtpRoute(mid, kind, (uint)rtpMap.ClockRate);
                    routes[(byte)payloadType] = route;
                    perMid?.TryAdd((byte)payloadType, route);
                }

                // Map every SSRC the section declares (media and RTX alike) to its mid, so a packet with
                // no MID extension still demuxes deterministically to this section (RFC 5576).
                if (mid.Length != 0)
                {
                    foreach (var ssrc in media.GetSsrcs())
                    {
                        ssrcToMid[ssrc] = mid;
                    }
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

        Volatile.Write(ref _routeTable, new RouteTable(routes, routesByMid, ssrcToMid, midExtensionId));
        Volatile.Write(ref _rtxSsrcToMediaSsrc, rtxToMedia);
        Volatile.Write(ref _simulcastByMid, BuildSimulcastTrackers(offer));
        _logger.Log(
            KeryxLogLevel.Info,
            $"Applied remote offer; local DTLS role {LocalDtlsRole}, {routes.Count} inbound payload type(s),"
            + $" mid extmap {(midExtensionId == 0 ? "none" : midExtensionId.ToString(CultureInfo.InvariantCulture))}.");

        // Raise OnTransceiver for auto-created transceivers after the route table is published, outside
        // any lock, so a handler can set Direction before CreateAnswerAsync reads it.
        foreach (var transceiver in autoCreated)
        {
            OnTransceiver?.Invoke(this, transceiver);
        }
    }

    private Dictionary<string, SimulcastReceiveTracker> BuildSimulcastTrackers(SessionDescription offer)
    {
        var trackers = new Dictionary<string, SimulcastReceiveTracker>(StringComparer.Ordinal);
        if (!_config.EnableSimulcast)
        {
            return trackers;
        }

        foreach (var media in offer.MediaDescriptions)
        {
            if (media.Mid is not { } mid
                || !string.Equals(media.Media, "video", StringComparison.Ordinal)
                || SdpNegotiator.AnswerSimulcast(media) is not { HasRidExtension: true } simulcast)
            {
                continue;
            }

            var extensions = ToStreamExtensions(simulcast.HeaderExtensions);
            trackers[mid] = new SimulcastReceiveTracker(extensions);
        }

        return trackers;
    }

    private static Keryx.Rtp.Simulcast.RtpStreamIdentifierExtensions ToStreamExtensions(
        IReadOnlyList<SdpExtMap> extMaps)
    {
        byte mid = 0, rid = 0, repairedRid = 0;
        foreach (var extMap in extMaps)
        {
            if (extMap.Id is < 1 or > 14)
            {
                continue;
            }

            if (string.Equals(extMap.Uri, RtpHeaderExtensionUri.Mid, StringComparison.Ordinal))
            {
                mid = (byte)extMap.Id;
            }
            else if (string.Equals(extMap.Uri, RtpHeaderExtensionUri.Rid, StringComparison.Ordinal))
            {
                rid = (byte)extMap.Id;
            }
            else if (string.Equals(extMap.Uri, RtpHeaderExtensionUri.RepairedRid, StringComparison.Ordinal))
            {
                repairedRid = (byte)extMap.Id;
            }
        }

        return new Keryx.Rtp.Simulcast.RtpStreamIdentifierExtensions(mid, rid, repairedRid);
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
        byte? transportCcExtensionId = null;
        byte midExtensionId = 0;
        var routes = new Dictionary<byte, RtpRoute>();
        var routesByMid = new Dictionary<string, Dictionary<byte, RtpRoute>>(StringComparer.Ordinal);
        var ssrcToMid = new Dictionary<uint, string>();
        var rtxToMedia = new Dictionary<uint, uint>();

        foreach (var media in result.Media)
        {
            ufrag ??= media.IceUfrag;
            password ??= media.IcePwd;
            CollectFidAssociations(media.Answered.GetSsrcGroups(), rtxToMedia);

            // The extension is transport-wide across the BUNDLE, so the first section that kept it fixes
            // the id the send path stamps. An id outside the one-byte range disables stamping.
            if (transportCcExtensionId is null)
            {
                foreach (var extMap in media.HeaderExtensions)
                {
                    if (extMap.IsTransportWideCc && extMap.Id is >= 1 and <= 14)
                    {
                        transportCcExtensionId = (byte)extMap.Id;
                        break;
                    }
                }
            }

            // The MID extension is likewise transport-wide; the first section that kept it fixes the
            // demux element id. Populated only when the remote (answerer) kept it — Keryx does not yet
            // offer the extension, so on the offerer path this is typically absent and demux falls to
            // the SSRC map the answer's a=ssrc lines provide.
            if (midExtensionId == 0)
            {
                midExtensionId = FindMidExtensionId(media.HeaderExtensions);
            }

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

            var mid = media.Mid ?? string.Empty;
            var perMid = mid.Length != 0 ? GetOrAddMidRoutes(routesByMid, mid) : null;
            if (mid.Length != 0)
            {
                foreach (var ssrc in media.Ssrcs)
                {
                    ssrcToMid[ssrc] = mid;
                }
            }

            // The transceiver this answered m-line belongs to, resolved by the mid it was offered under.
            // For a single-video/single-audio session this is the first-of-kind transceiver, exactly as
            // before; for multiple same-kind m-lines each answer section updates its own transceiver.
            var transceiver = media.Mid is { } answeredMid ? GetTransceiver(answeredMid) : FirstTransceiver(kind);

            // Match against the transceiver's own offered codecs when it has them (an application-added
            // transceiver), else the per-kind config that drives the legacy transceivers.
            IEnumerable<SdpCodec> configured = transceiver is { OfferCodecs.Count: > 0 }
                ? transceiver.OfferCodecs
                : (kind == MediaKind.Video ? _config.VideoCodecs : _config.AudioCodecs);
            var receivePayloadTypes = new List<byte>();
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

                var route = new RtpRoute(mid, kind, (uint)codec.ClockRate);
                routes[(byte)codec.PayloadType] = route;
                perMid?.TryAdd((byte)codec.PayloadType, route);
                receivePayloadTypes.Add((byte)codec.PayloadType);
            }

            var chosen = media.Codecs.FirstOrDefault(c =>
                configured.Any(x => string.Equals(x.EncodingName, c.EncodingName, StringComparison.OrdinalIgnoreCase)));
            if (chosen is null)
            {
                _logger.Log(KeryxLogLevel.Warning, $"The answer kept no usable codec for m-section '{media.Mid}'.");
                continue;
            }

            // Publish the negotiated direction, primary codec and receive payload types on the transceiver
            // (session-model.md §2.1). media.Direction is the intersection from the offerer's point of view.
            if (transceiver is not null)
            {
                transceiver.CurrentDirection = media.Direction;
                transceiver.NegotiatedCodec = chosen;
                transceiver.Receiver.PayloadTypes = receivePayloadTypes;
            }

            // Resolve the RFC 4588 rtx codec once: its route lets an inbound repair packet demux (when this
            // side receives), and its payload type wires the outbound repair stream (when this side sends).
            byte? rtxPayloadType = null;
            var rtxEnabled = kind == MediaKind.Video
                && (transceiver?.EnableRetransmissionOnOffer ?? _config.EnableRetransmission);
            if (rtxEnabled)
            {
                // RFC 4588 §8.1: retransmission is negotiated only if the answer keeps an rtx codec whose
                // apt names the media codec we settled on. Bare a=rtcp-fb nack is not enough — without a
                // repair stream there is nowhere to send resends, and resending on the media SSRC would
                // corrupt its sequence numbering.
                var rtx = media.FindRtxCodec(chosen.PayloadType);
                if (rtx is not null && rtx.PayloadType is >= 0 and <= 127)
                {
                    rtxPayloadType = (byte)rtx.PayloadType;
                    var rtxRoute = new RtpRoute(
                        mid,
                        kind,
                        (uint)rtx.ClockRate,
                        IsRtx: true,
                        AptPayloadType: (byte)chosen.PayloadType);
                    routes[(byte)rtx.PayloadType] = rtxRoute;
                    perMid?.TryAdd((byte)rtx.PayloadType, rtxRoute);
                }
                else
                {
                    _logger.Log(
                        KeryxLogLevel.Info,
                        $"The answer kept no rtx codec for payload type {chosen.PayloadType}; retransmission is disabled.");
                }
            }

            // Wire the send track only when the offerer's negotiated direction actually sends. A recvonly
            // transceiver (added via AddTransceiver to ingest media as the offerer) never builds a sender,
            // so CreateTrackSenders leaves it receive-only.
            if (transceiver is not null && media.Direction.Sends())
            {
                transceiver.Sender.Negotiated = kind == MediaKind.Video
                    ? new NegotiatedTrack(
                        media.Mid ?? _config.VideoMid,
                        (byte)chosen.PayloadType,
                        (uint)chosen.ClockRate,
                        rtxPayloadType)
                    : new NegotiatedTrack(media.Mid ?? _config.AudioMid, (byte)chosen.PayloadType, (uint)chosen.ClockRate);
            }
        }

        if (ufrag is not null && password is not null)
        {
            ice.SetRemoteCredentials(ufrag, password);
        }

        _sendTransportCcExtensionId = transportCcExtensionId;
        _negotiatedTransportCcExtensionId = transportCcExtensionId;

        Volatile.Write(ref _routeTable, new RouteTable(routes, routesByMid, ssrcToMid, midExtensionId));
        Volatile.Write(ref _rtxSsrcToMediaSsrc, rtxToMedia);
        var negotiatedVideo = FirstSender(MediaKind.Video)?.Negotiated;
        var negotiatedAudio = FirstSender(MediaKind.Audio)?.Negotiated;
        _logger.Log(
            KeryxLogLevel.Info,
            $"Applied answer; local DTLS role {LocalDtlsRole}, video pt {negotiatedVideo?.PayloadType}"
            + $" (rtx pt {negotiatedVideo?.RtxPayloadType?.ToString(CultureInfo.InvariantCulture) ?? "none"}),"
            + $" audio pt {negotiatedAudio?.PayloadType},"
            + $" transport-cc extmap {(transportCcExtensionId?.ToString(CultureInfo.InvariantCulture) ?? "none")}.");
    }

    private static DtlsRole ToDtlsRole(SdpSetupRole role) => role switch
    {
        SdpSetupRole.Active => DtlsRole.Client,
        SdpSetupRole.Passive => DtlsRole.Server,
        _ => DtlsRole.Server,
    };

    /// <summary>
    /// Folds a section's <c>a=ssrc-group:FID</c> lines (RFC 5576 §4.2) into a repair-SSRC → media-SSRC
    /// map, so an inbound RFC 4588 RTX packet can be decapsulated onto the media source it repairs. The
    /// media source is listed first in an FID group and the repair source second.
    /// </summary>
    private static void CollectFidAssociations(IReadOnlyList<SsrcGroup> groups, Dictionary<uint, uint> rtxToMedia)
    {
        foreach (var group in groups)
        {
            if (string.Equals(group.Semantics, SsrcGroup.FidSemantics, StringComparison.Ordinal)
                && group.Ssrcs.Count >= 2)
            {
                rtxToMedia[group.Ssrcs[1]] = group.Ssrcs[0];
            }
        }
    }

    /// <summary>
    /// Returns the negotiated one-byte element id of the RFC 8843 §9.2 MID header extension from a
    /// section's <c>a=extmap</c> lines, or <c>0</c> when the section did not carry it. Only the one-byte
    /// range (1–14) is accepted, matching the range the header parser reads.
    /// </summary>
    private static byte FindMidExtensionId(IReadOnlyList<SdpExtMap> extMaps)
    {
        foreach (var extMap in extMaps)
        {
            if (string.Equals(extMap.Uri, RtpHeaderExtensionUri.Mid, StringComparison.Ordinal)
                && extMap.Id is >= 1 and <= 14)
            {
                return (byte)extMap.Id;
            }
        }

        return 0;
    }

    /// <summary>
    /// Returns the per-mid payload-type route map for <paramref name="mid"/>, creating and registering
    /// it on first use, so the mid-first demux can resolve a payload type within its own m-section.
    /// </summary>
    private static Dictionary<byte, RtpRoute> GetOrAddMidRoutes(
        Dictionary<string, Dictionary<byte, RtpRoute>> byMid,
        string mid)
    {
        if (!byMid.TryGetValue(mid, out var perMid))
        {
            perMid = [];
            byMid[mid] = perMid;
        }

        return perMid;
    }

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
        ushort? MaxPacketLifetime,
        TaskCompletionSource<DataChannel> Completion);

    /// <summary>
    /// The inbound demux entry for one payload type: the m-section it belongs to, its media kind, the
    /// RTP clock rate its timestamps run at (for the RFC 3550 jitter estimate), and whether it is an RFC
    /// 4588 repair stream (which is reported on through the media stream it repairs, not on its own). For
    /// a repair stream, <paramref name="AptPayloadType"/> carries the media payload type its <c>apt</c>
    /// names, so a decapsulated packet can be routed back onto the media stream it reconstructs.
    /// </summary>
    internal readonly record struct RtpRoute(
        string Mid,
        MediaKind Kind,
        uint ClockRate = 0,
        bool IsRtx = false,
        byte AptPayloadType = 0);

    /// <summary>
    /// What the answer settled on for one media kind. <paramref name="RtxPayloadType"/> is null when
    /// the answerer dropped the RFC 4588 repair codec, which disables retransmission for the track.
    /// </summary>
    internal sealed record NegotiatedTrack(
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
