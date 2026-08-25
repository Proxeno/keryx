using System.Buffers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Keryx.Core;

namespace Keryx.Dtls;

/// <summary>
/// A DTLS 1.2 endpoint (RFC 6347) with DTLS-SRTP key export (RFC 5764), implementing both the
/// client and the server role.
/// </summary>
/// <remarks>
/// <para>
/// A <see cref="DtlsTransport"/> runs <em>over</em> an <see cref="IDatagramTransport"/> — in WebRTC,
/// the selected ICE candidate pair — and <em>is itself</em> an <see cref="IDatagramTransport"/>
/// exposing the decrypted application-data stream, which is what carries SCTP for data channels.
/// SRTP keys are not sent as application data; they are exported from the handshake secrets with
/// <see cref="ExportKeyingMaterial(string, int)"/>.
/// </para>
/// <para>
/// Peer authentication follows the WebRTC model rather than a PKI: any self-signed certificate is
/// accepted at the X.509 level, and trust comes entirely from
/// <see cref="DtlsConfig.ExpectedRemoteFingerprintSha256"/>, which is checked during the handshake
/// and aborts it with a <c>bad_certificate</c> alert on mismatch. If you leave that unset you get
/// encryption without authentication.
/// </para>
/// <para><b>Security status — read this.</b> This is a correctness-focused, from-scratch
/// implementation of the DTLS protocol built on BCL cryptographic primitives (<see cref="AesGcm"/>,
/// <see cref="ECDiffieHellman"/>, <see cref="ECDsa"/>, <see cref="HMACSHA256"/>). It has
/// <b>not been independently security reviewed or audited</b>, and it has not been fuzzed. Only
/// operations on secret material use constant-time comparisons
/// (<see cref="CryptographicOperations.FixedTimeEquals(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>);
/// parsing, state-machine dispatch, and error paths are not constant-time and their timing may
/// reveal message structure. Session resumption, renegotiation, HelloVerifyRequest cookie
/// generation as a server, and DTLS 1.0/1.3 are not implemented. Treat it as suitable for WebRTC
/// media/data-channel use where ICE has already validated the peer address, and review it yourself
/// before relying on it in a hostile setting.</para>
/// </remarks>
public sealed class DtlsTransport : IDatagramTransport, IDisposable
{
    private const int RandomLength = 32;

    private readonly IDatagramTransport _lower;
    private readonly DtlsConfig _config;
    private readonly IKeryxLogger _log;
    private readonly DtlsRole _role;
    private readonly int _mtu;

    private readonly Lock _sync = new();
    private readonly Lock _sendGate = new();
    private readonly List<byte[]> _outbound = [];
    private readonly List<(byte[] Buffer, int Length)> _inboundAppData = [];
    private readonly List<DtlsTransportState> _stateNotifications = [];
    private readonly List<BufferedRecord> _earlyRecords = [];
    private readonly TaskCompletionSource _handshakeCompletion =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    private readonly HandshakeReassembler _reassembler = new();
    private readonly MemoryStream _transcript = new();
    private readonly Timer _retransmitTimer;

    private DtlsTransportState _state = DtlsTransportState.New;
    private bool _handshakeStarted;
    private bool _disposed;

    // Handshake negotiation state.
    private byte[] _clientRandom = [];
    private byte[] _serverRandom = [];
    private ushort _cipherSuite;
    private ushort _negotiatedGroup = NamedGroups.Secp256r1;
    private bool _useExtendedMasterSecret;
    private bool _peerOfferedRenegotiationInfo;
    private bool _peerOfferedEcPointFormats;
    private SigHashAlgorithm _localSignatureAlgorithm = SigHashAlgorithm.EcdsaSha256;
    private ECDiffieHellman? _ecdh;
    private byte[]? _masterSecret;
    private byte[]? _peerCertificateDer;
    private X509Certificate2? _peerCertificate;
    private bool _peerCertificateVerified;
    private bool _expectPeerCertificateVerify;
    private bool _certificateRequested;
    private byte[]? _serverKeyExchangePoint;

    // "Have we already handled one of these?" flags. DTLS carries no per-message state machine of
    // its own — message_seq only orders messages, it does not constrain their type — so every
    // handshake message that mutates negotiated state has to police its own arity. Without this a
    // peer (or an injector, for the unencrypted part of the handshake) can re-send a message with a
    // fresh message_seq and rewrite state that has already been agreed. See RFC 6347 §4.2.4.
    private bool _sawClientHello;
    private bool _sawServerHello;
    private bool _sawPeerCertificate;
    private bool _sawServerKeyExchange;
    private bool _sawCertificateRequest;
    private bool _sawServerHelloDone;
    private bool _sawClientKeyExchange;
    private bool _sawCertificateVerify;
    private bool _sawPeerFinished;

    // Record layer state.
    private ushort _writeEpoch;
    private ulong _writeSequenceEpoch0;
    private ulong _writeSequenceEpoch1;
    private IRecordProtection? _writeCipher;
    private IRecordProtection? _pendingWriteCipher;
    private ushort _readEpoch;
    private IRecordProtection? _readCipher;
    private IRecordProtection? _pendingReadCipher;
    private ReplayWindow _replayWindow = new();

    // Flight / retransmission state.
    private List<FlightItem>? _currentFlight;
    private TimeSpan _retransmitTimeout;
    private long _lastFlightSendTicks;
    private ushort _nextSendMessageSeq;
    private byte[] _cookie = [];
    private bool _sawHelloVerifyRequest;

    /// <summary>
    /// Wraps <paramref name="lower"/> in a DTLS session. The transport immediately begins observing
    /// inbound datagrams so that a ClientHello arriving before
    /// <see cref="HandshakeAsync(CancellationToken)"/> is not lost.
    /// </summary>
    /// <param name="lower">The datagram transport to run DTLS over (in WebRTC, the ICE transport).</param>
    /// <param name="config">Role, certificate, SRTP profiles, and the expected peer fingerprint.</param>
    public DtlsTransport(IDatagramTransport lower, DtlsConfig config)
    {
        ArgumentNullException.ThrowIfNull(lower);
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(config.Certificate);

        // A blank expected fingerprint used to be treated as "no pin" by the certificate check while
        // still counting as "pinning requested" everywhere else, so the transport demanded a peer
        // certificate, reported its fingerprint, and completed the handshake without ever comparing
        // anything — every observable signal said authenticated and nothing was. Config binders that
        // materialise an absent key as "" make that a very ordinary mistake, so it is refused here
        // rather than silently honoured. Null still means "no pinning", which is documented.
        if (config.ExpectedRemoteFingerprintSha256 is { } pin && string.IsNullOrWhiteSpace(pin))
        {
            throw new ArgumentException(
                "ExpectedRemoteFingerprintSha256 must be either null (no pinning) or a real digest; a blank string is not a pin.",
                nameof(config));
        }

        _lower = lower;
        _config = config;
        _log = config.Logger;
        _role = config.Role;
        _mtu = Math.Max(
            DtlsLimits.RecordHeaderLength + RecordProtection.MaxOverhead + 64,
            Math.Min(config.MaxDatagramSize, lower.MaxDatagramSize));
        _retransmitTimeout = config.InitialRetransmitTimeout;
        _retransmitTimer = new Timer(OnRetransmitTimer, null, Timeout.Infinite, Timeout.Infinite);
        _lower.OnReceived += OnLowerReceived;
    }

    /// <summary>Raised with decrypted application data — for WebRTC, the SCTP packet stream.</summary>
    public event DatagramReceivedHandler? OnReceived;

    /// <summary>Raised whenever <see cref="State"/> changes. Handlers run outside the internal lock.</summary>
    public event EventHandler<DtlsTransportState>? OnStateChanged;

    /// <summary>Current lifecycle state.</summary>
    public DtlsTransportState State
    {
        get
        {
            lock (_sync)
            {
                return _state;
            }
        }
    }

    /// <summary>
    /// Largest application payload <see cref="Send(ReadOnlySpan{byte})"/> accepts: the negotiated
    /// datagram size less the DTLS record header and AES-GCM overhead.
    /// </summary>
    public int MaxDatagramSize => _mtu - DtlsLimits.RecordHeaderLength - RecordProtection.MaxOverhead;

    /// <summary>The SRTP protection profile agreed via <c>use_srtp</c>, or <see cref="SrtpProtectionProfile.None"/>.</summary>
    public SrtpProtectionProfile NegotiatedSrtpProfile { get; private set; } = SrtpProtectionProfile.None;

    /// <summary>The peer's end-entity certificate, available once it has been received.</summary>
    public X509Certificate2? RemoteCertificate
    {
        get
        {
            lock (_sync)
            {
                return _peerCertificate;
            }
        }
    }

    /// <summary>
    /// SHA-256 fingerprint of <see cref="RemoteCertificate"/> in SDP form (uppercase, colon
    /// separated), or null before the peer's certificate arrives.
    /// </summary>
    public string? RemoteFingerprint { get; private set; }

    /// <summary>The local certificate's SDP fingerprint, for populating <c>a=fingerprint</c>.</summary>
    public string LocalFingerprint => _config.Certificate.Sha256Fingerprint;

    /// <summary>True when RFC 7627 extended master secret was negotiated.</summary>
    public bool UsedExtendedMasterSecret => _useExtendedMasterSecret;

    /// <summary>The negotiated cipher suite's IANA name, or null before ServerHello.</summary>
    public string? NegotiatedCipherSuite => _cipherSuite == 0 ? null : CipherSuites.Name(_cipherSuite);

    /// <summary>Test hook: the negotiated ECDHE named group (a <see cref="NamedGroups"/> code).</summary>
    internal ushort NegotiatedNamedGroup => _negotiatedGroup;

    /// <summary>Test hook: corrupt the verify_data of the next Finished this endpoint sends.</summary>
    internal bool TestCorruptOutgoingFinished { get; set; }

    /// <summary>Test hook: corrupt the signature of the next CertificateVerify this endpoint sends.</summary>
    internal bool TestCorruptOutgoingCertificateVerify { get; set; }

    /// <summary>
    /// Runs (or awaits) the DTLS handshake. Safe to call once; subsequent calls await the same
    /// result. As a server this simply waits for the peer's ClientHello.
    /// </summary>
    /// <param name="cancellationToken">Cancels the wait and fails the connection.</param>
    /// <returns>A task that completes when the handshake finishes.</returns>
    /// <exception cref="DtlsException">The handshake failed, timed out, or the peer sent a fatal alert.</exception>
    public async Task HandshakeAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var start = false;
        lock (_sync)
        {
            if (!_handshakeStarted)
            {
                _handshakeStarted = true;
                start = true;
            }
        }

        if (start)
        {
            lock (_sync)
            {
                try
                {
                    if (_state == DtlsTransportState.New)
                    {
                        SetStateLocked(DtlsTransportState.Connecting);
                    }

                    if (_role == DtlsRole.Client)
                    {
                        SendClientHelloLocked();
                    }
                }
                catch (DtlsException ex)
                {
                    FailLocked(ex, sendAlert: true);
                }
            }

            Pump();
        }

        try
        {
            await _handshakeCompletion.Task.WaitAsync(_config.HandshakeTimeout, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            var timeout = new DtlsException(
                $"The DTLS handshake did not complete within {_config.HandshakeTimeout}.");
            lock (_sync)
            {
                FailLocked(timeout, sendAlert: false);
            }

            Pump();
            throw timeout;
        }
        catch (OperationCanceledException)
        {
            lock (_sync)
            {
                FailLocked(new DtlsException("The DTLS handshake was cancelled."), sendAlert: false);
            }

            Pump();
            throw;
        }
    }

    /// <summary>
    /// Derives keying material from the completed session using the RFC 5705 exporter with no
    /// context value. For DTLS-SRTP pass <c>"EXTRACTOR-dtls_srtp"</c> and the length required by
    /// <see cref="NegotiatedSrtpProfile"/> (see
    /// <see cref="SrtpProtectionProfileExtensions.KeyingMaterialLength(SrtpProtectionProfile)"/>).
    /// </summary>
    /// <param name="label">The exporter label.</param>
    /// <param name="length">Number of bytes to derive.</param>
    /// <returns>The derived keying material; identical on both peers.</returns>
    /// <exception cref="InvalidOperationException">The handshake has not completed.</exception>
    public byte[] ExportKeyingMaterial(string label, int length)
    {
        ArgumentException.ThrowIfNullOrEmpty(label);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);

        lock (_sync)
        {
            if (_masterSecret is null || _state is not (DtlsTransportState.Connected or DtlsTransportState.Closed))
            {
                throw new InvalidOperationException(
                    "Keying material can only be exported after the DTLS handshake has completed.");
            }

            return TlsPrf.ExportKeyingMaterial(
                _masterSecret, label, _clientRandom, _serverRandom, length, NegotiatedPrfHash());
        }
    }

    /// <summary>Encrypts and sends one application datagram (SCTP, in WebRTC).</summary>
    /// <param name="datagram">The plaintext payload; must not exceed <see cref="MaxDatagramSize"/>.</param>
    /// <exception cref="InvalidOperationException">The connection is not established.</exception>
    public void Send(ReadOnlySpan<byte> datagram)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (datagram.Length > MaxDatagramSize)
        {
            throw new ArgumentException(
                $"Application datagram of {datagram.Length} bytes exceeds the {MaxDatagramSize}-byte maximum.",
                nameof(datagram));
        }

        lock (_sync)
        {
            if (_state != DtlsTransportState.Connected)
            {
                throw new InvalidOperationException(
                    $"Cannot send application data while the DTLS transport is {_state}.");
            }

            EnqueueRecordLocked(ContentType.ApplicationData, _writeEpoch, datagram);
        }

        Pump();
    }

    /// <summary>Sends a <c>close_notify</c> alert and moves to <see cref="DtlsTransportState.Closed"/>.</summary>
    public void Close()
    {
        lock (_sync)
        {
            if (_state is DtlsTransportState.Closed or DtlsTransportState.Failed)
            {
                return;
            }

            if (_state == DtlsTransportState.Connected)
            {
                TrySendAlertLocked(DtlsAlertLevel.Warning, DtlsAlertDescription.CloseNotify);
            }

            SetStateLocked(DtlsTransportState.Closed);
            _handshakeCompletion.TrySetException(new DtlsException("The DTLS transport was closed."));
            StopRetransmitLocked();
        }

        Pump();
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _lower.OnReceived -= OnLowerReceived;

        try
        {
            Close();
        }
        catch (ObjectDisposedException)
        {
            // The lower transport may already be gone.
        }

        lock (_sync)
        {
            _retransmitTimer.Dispose();
            _writeCipher?.Dispose();
            _pendingWriteCipher?.Dispose();
            _readCipher?.Dispose();
            _pendingReadCipher?.Dispose();
            _ecdh?.Dispose();
            _peerCertificate?.Dispose();
            _transcript.Dispose();
            if (_masterSecret is not null)
            {
                CryptographicOperations.ZeroMemory(_masterSecret);
            }

            foreach (var (buffer, _) in _inboundAppData)
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }

            _inboundAppData.Clear();
        }
    }

    // ---------------------------------------------------------------- inbound

    private void OnLowerReceived(ReadOnlySpan<byte> datagram)
    {
        if (_disposed)
        {
            return;
        }

        lock (_sync)
        {
            if (_state is DtlsTransportState.Failed)
            {
                return;
            }

            try
            {
                ProcessDatagramLocked(datagram);
            }
            catch (DtlsException ex)
            {
                FailLocked(ex, sendAlert: true);
            }
            catch (ByteBufferException ex)
            {
                FailLocked(
                    new DtlsException("Malformed DTLS message.", DtlsAlertDescription.DecodeError, ex),
                    sendAlert: true);
            }
        }

        Pump();
    }

    private void ProcessDatagramLocked(ReadOnlySpan<byte> datagram)
    {
        var reader = new DtlsRecordReader(datagram);
        while (reader.TryReadNext(out var record))
        {
            ProcessRecordLocked(record);
        }
    }

    private void ProcessRecordLocked(in DtlsRecord record)
    {
        if (record.Version is not (ProtocolVersions.Dtls12 or ProtocolVersions.Dtls10))
        {
            // Unknown record version: discard silently (RFC 6347 4.1.2.7).
            return;
        }

        if (record.Epoch != _readEpoch)
        {
            if (record.Epoch == (ushort)(_readEpoch + 1) && _pendingReadCipher is not null && _earlyRecords.Count < 16)
            {
                // The peer's ChangeCipherSpec has not arrived yet but its next-epoch records have.
                _earlyRecords.Add(new BufferedRecord(record.Type, record.Epoch, record.SequenceNumber, record.Fragment.ToArray()));
            }

            return;
        }

        var cipher = _readEpoch == 0 ? null : _readCipher;
        if (cipher is null)
        {
            // Epoch 0 is unauthenticated, so there is nothing the anti-replay window may legitimately
            // be updated from: RFC 6347 §4.1.2.6 requires the window not to advance until a record is
            // authenticated. Running it here anyway let one forged 13-byte record with sequence
            // number 2^48-1 anchor the window at the top of the space and silently drop every genuine
            // record that followed, wedging the handshake until it timed out. Duplicate suppression at
            // epoch 0 does not need the window: the reassembler already discards fragments for an
            // already-consumed message_seq and merges duplicate fragments idempotently.
            DispatchPlaintextLocked(record.Type, record.Fragment);
            return;
        }

        if (_replayWindow.IsReplay(record.SequenceNumber))
        {
            return;
        }

        var rented = ArrayPool<byte>.Shared.Rent(Math.Max(1, record.Fragment.Length));
        try
        {
            if (!cipher.TryDecrypt(
                    record.Type,
                    record.Version,
                    record.Epoch,
                    record.SequenceNumber,
                    record.Fragment,
                    rented,
                    out var length))
            {
                _log.Log(KeryxLogLevel.Warning, $"Discarding undecryptable DTLS record (epoch {record.Epoch}, seq {record.SequenceNumber}).");
                return;
            }

            _replayWindow.Accept(record.SequenceNumber);
            DispatchPlaintextLocked(record.Type, rented.AsSpan(0, length));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private void DispatchPlaintextLocked(ContentType type, ReadOnlySpan<byte> plaintext)
    {
        switch (type)
        {
            case ContentType.Handshake:
                HandleHandshakeRecordLocked(plaintext);
                break;

            case ContentType.ChangeCipherSpec:
                HandleChangeCipherSpecLocked(plaintext);
                break;

            case ContentType.Alert:
                HandleAlertLocked(plaintext);
                break;

            case ContentType.ApplicationData:
                if (_state != DtlsTransportState.Connected)
                {
                    return;
                }

                var buffer = ArrayPool<byte>.Shared.Rent(Math.Max(1, plaintext.Length));
                plaintext.CopyTo(buffer);
                _inboundAppData.Add((buffer, plaintext.Length));
                break;

            default:
                _log.Log(KeryxLogLevel.Warning, $"Discarding DTLS record with unknown content type {(byte)type}.");
                break;
        }
    }

    private void HandleAlertLocked(ReadOnlySpan<byte> plaintext)
    {
        if (plaintext.Length < 2)
        {
            return;
        }

        var level = (DtlsAlertLevel)plaintext[0];
        var description = (DtlsAlertDescription)plaintext[1];
        _log.Log(KeryxLogLevel.Debug, $"Received DTLS alert {level}/{description}.");

        if (description == DtlsAlertDescription.CloseNotify)
        {
            SetStateLocked(DtlsTransportState.Closed);
            _handshakeCompletion.TrySetException(
                new DtlsException("The peer closed the DTLS connection.", DtlsAlertDescription.CloseNotify, fromPeer: true));
            StopRetransmitLocked();
            return;
        }

        if (level == DtlsAlertLevel.Fatal)
        {
            FailLocked(
                new DtlsException($"The peer sent a fatal DTLS alert: {description}.", description, fromPeer: true),
                sendAlert: false);
        }
    }

    private void HandleChangeCipherSpecLocked(ReadOnlySpan<byte> plaintext)
    {
        if (plaintext.Length != 1 || plaintext[0] != 1)
        {
            throw new DtlsException("Malformed ChangeCipherSpec.", DtlsAlertDescription.DecodeError);
        }

        if (_pendingReadCipher is null)
        {
            // Either the peer retransmitted its flight (RFC 6347 §4.2.4 requires that to be
            // tolerated, and with no anti-replay at epoch 0 the duplicate now reaches us) or this is
            // injected garbage. Both are discards: acting on it would advance the read epoch a second
            // time with no cipher behind it.
            _log.Log(KeryxLogLevel.Debug, "Discarding a ChangeCipherSpec with no pending read cipher.");
            return;
        }

        _readCipher?.Dispose();
        _readCipher = _pendingReadCipher;
        _pendingReadCipher = null;
        _readEpoch++;
        _replayWindow = new ReplayWindow();
        _log.Log(KeryxLogLevel.Debug, $"Read epoch advanced to {_readEpoch}.");

        if (_earlyRecords.Count == 0)
        {
            return;
        }

        var buffered = _earlyRecords.ToArray();
        _earlyRecords.Clear();
        foreach (var early in buffered)
        {
            if (early.Epoch != _readEpoch)
            {
                continue;
            }

            var rented = ArrayPool<byte>.Shared.Rent(Math.Max(1, early.Body.Length));
            try
            {
                if (_readCipher!.TryDecrypt(
                        early.Type,
                        ProtocolVersions.Dtls12,
                        early.Epoch,
                        early.SequenceNumber,
                        early.Body,
                        rented,
                        out var length)
                    && _replayWindow.Accept(early.SequenceNumber))
                {
                    DispatchPlaintextLocked(early.Type, rented.AsSpan(0, length));
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    private void HandleHandshakeRecordLocked(ReadOnlySpan<byte> plaintext)
    {
        bool progressed;
        bool sawRetransmission;
        try
        {
            progressed = _reassembler.AddRecord(plaintext, out sawRetransmission);
        }
        catch (DtlsException) when (_readEpoch == 0)
        {
            // RFC 6347 §4.1.2.7: an invalid record that arrived with no authentication behind it is
            // discarded, not escalated. Anyone able to put a datagram on the wire could otherwise end
            // a handshake in progress with a single malformed fragment header.
            _log.Log(KeryxLogLevel.Warning, "Discarding a malformed unauthenticated DTLS handshake record.");
            return;
        }
        catch (ByteBufferException) when (_readEpoch == 0)
        {
            _log.Log(KeryxLogLevel.Warning, "Discarding a truncated unauthenticated DTLS handshake record.");
            return;
        }

        if (sawRetransmission && !progressed)
        {
            RetransmitFlightIfDueLocked();
        }

        while (_reassembler.TryTakeNext(out var message))
        {
            if (_readEpoch == 0)
            {
                // The record carried no authentication behind it. RFC 6347 §4.1.2.7 requires an
                // invalid one to be discarded, not escalated — and the guard above already does that
                // for a malformed fragment *header*. A fully reassembled message whose *body* fails to
                // decode (e.g. a Certificate whose certificate_list length overruns the record) must be
                // treated the same way: anyone able to put a datagram on the wire could otherwise end a
                // handshake in progress with one crafted body. The discard must NOT consume the
                // message_seq or keep any transcript bytes the dispatch appended for it, so the peer's
                // genuine retransmission of that same message_seq is still accepted and completes.
                //
                // A body that decodes cleanly but breaks the protocol (a DTLS 1.0 ClientHello, an
                // unexpected or duplicate message, a signature that does not verify, ...) is not a
                // decode failure and stays fatal exactly as before — that is the security check the
                // handshake relies on, and it is preserved by only catching decode failures here.
                var transcriptLength = _transcript.Length;
                try
                {
                    HandleHandshakeMessageLocked(message);
                }
                catch (Exception ex) when (IsDiscardableEpochZeroDecodeFailure(ex))
                {
                    _transcript.SetLength(transcriptLength);
                    _reassembler.Discard(message.MessageSeq);
                    _log.Log(
                        KeryxLogLevel.Warning,
                        $"Discarding a malformed unauthenticated epoch-0 {message.Type} body (seq {message.MessageSeq}); awaiting a retransmission.");
                    return;
                }

                _reassembler.Consume(message.MessageSeq);
            }
            else
            {
                _reassembler.Consume(message.MessageSeq);
                HandleHandshakeMessageLocked(message);
            }

            if (_state is DtlsTransportState.Failed or DtlsTransportState.Closed)
            {
                return;
            }
        }
    }

    /// <summary>
    /// Distinguishes a message body that could not be decoded — malformed, unauthenticated garbage to
    /// be discarded at epoch 0 — from a body that decoded but is illegal for the protocol, which stays
    /// fatal. A <see cref="ByteBufferException"/> is a raw buffer over/underrun while parsing; a
    /// <see cref="DtlsException"/> carrying <see cref="DtlsAlertDescription.DecodeError"/> is a
    /// structural malformation the codec rejected. Every other alert (protocol_version,
    /// unexpected_message, illegal_parameter, decrypt_error, ...) describes a well-formed but
    /// protocol-illegal message and must not be swallowed.
    /// </summary>
    private static bool IsDiscardableEpochZeroDecodeFailure(Exception exception) =>
        exception is ByteBufferException
        || exception is DtlsException { Alert: DtlsAlertDescription.DecodeError };

    private void HandleHandshakeMessageLocked(HandshakeMessage message)
    {
        _log.Log(KeryxLogLevel.Debug, $"Handshake message {message.Type} (seq {message.MessageSeq}, {message.Body.Length} bytes).");

        switch (message.Type)
        {
            case HandshakeType.HelloVerifyRequest:
                // Excluded from the transcript entirely (RFC 6347 4.2.1).
                HandleHelloVerifyRequestLocked(message.Body);
                return;

            case HandshakeType.NewSessionTicket:
                // Keryx never offers the session_ticket extension; ignore a stray ticket rather
                // than failing, but do not add it to the transcript.
                return;

            case HandshakeType.CertificateVerify:
            {
                var rawTranscript = TranscriptBytesLocked();
                AppendTranscriptLocked(message.ToTranscriptBytes());
                HandleCertificateVerifyLocked(message.Body, rawTranscript);
                return;
            }

            case HandshakeType.Finished:
            {
                var transcriptHash = TranscriptHashLocked();
                AppendTranscriptLocked(message.ToTranscriptBytes());
                HandleFinishedLocked(message.Body, transcriptHash);
                return;
            }

            default:
                AppendTranscriptLocked(message.ToTranscriptBytes());
                break;
        }

        switch (message.Type)
        {
            case HandshakeType.ClientHello when _role == DtlsRole.Server:
                HandleClientHelloLocked(message.Body);
                break;

            case HandshakeType.ServerHello when _role == DtlsRole.Client:
                HandleServerHelloLocked(message.Body);
                break;

            case HandshakeType.Certificate:
                HandlePeerCertificateLocked(message.Body);
                break;

            case HandshakeType.ServerKeyExchange when _role == DtlsRole.Client:
                HandleServerKeyExchangeLocked(message.Body);
                break;

            case HandshakeType.CertificateRequest when _role == DtlsRole.Client:
                HandleCertificateRequestLocked(message.Body);
                break;

            case HandshakeType.ServerHelloDone when _role == DtlsRole.Client:
                if (_sawServerHelloDone)
                {
                    throw new DtlsException("A second ServerHelloDone arrived.", DtlsAlertDescription.UnexpectedMessage);
                }

                _sawServerHelloDone = true;
                SendClientFlightLocked();
                break;

            case HandshakeType.ClientKeyExchange when _role == DtlsRole.Server:
                HandleClientKeyExchangeLocked(message.Body);
                break;

            default:
                throw new DtlsException(
                    $"Unexpected handshake message {message.Type} in the {_role} role.",
                    DtlsAlertDescription.UnexpectedMessage);
        }
    }

    // ------------------------------------------------------------- client role

    private void SendClientHelloLocked()
    {
        _clientRandom = RandomNumberGenerator.GetBytes(RandomLength);

        // The ECDHE key is created once the server's ServerKeyExchange tells us which curve was
        // negotiated; the client's public point is not sent until ClientKeyExchange.
        _ecdh?.Dispose();
        _ecdh = null;

        var body = HandshakeCodec.BuildClientHello(
            _clientRandom, _cookie, LocalCipherSuites(), LocalNamedGroups(), _config.SrtpProfiles);
        var hello = NewHandshakeMessageLocked(HandshakeType.ClientHello, body);
        SendFlightLocked([new FlightItem(ContentType.Handshake, hello, 0)], expectResponse: true);
    }

    private void HandleHelloVerifyRequestLocked(byte[] body)
    {
        if (_role != DtlsRole.Client)
        {
            throw new DtlsException("A server received a HelloVerifyRequest.", DtlsAlertDescription.UnexpectedMessage);
        }

        if (_sawHelloVerifyRequest)
        {
            throw new DtlsException("The server sent more than one HelloVerifyRequest.", DtlsAlertDescription.UnexpectedMessage);
        }

        _sawHelloVerifyRequest = true;
        _cookie = HandshakeCodec.ParseHelloVerifyRequestCookie(body);
        _log.Log(KeryxLogLevel.Debug, $"HelloVerifyRequest with a {_cookie.Length}-byte cookie; re-sending ClientHello.");

        // The transcript restarts at the second ClientHello (RFC 6347 4.2.1); message_seq keeps
        // counting, so the retransmitted ClientHello is seq 1.
        _transcript.SetLength(0);

        var body2 = HandshakeCodec.BuildClientHello(
            _clientRandom, _cookie, LocalCipherSuites(), LocalNamedGroups(), _config.SrtpProfiles);
        var hello = NewHandshakeMessageLocked(HandshakeType.ClientHello, body2);
        SendFlightLocked([new FlightItem(ContentType.Handshake, hello, 0)], expectResponse: true);
    }

    private void HandleServerHelloLocked(byte[] body)
    {
        if (_sawServerHello)
        {
            throw new DtlsException(
                "A second ServerHello arrived; Keryx does not support renegotiation.",
                DtlsAlertDescription.UnexpectedMessage);
        }

        var hello = HandshakeCodec.ParseServerHello(body);
        _sawServerHello = true;
        if (hello.Version != ProtocolVersions.Dtls12)
        {
            throw new DtlsException(
                $"The server selected an unsupported protocol version 0x{hello.Version:X4}.",
                DtlsAlertDescription.ProtocolVersion);
        }

        if (!CipherSuites.IsSupported(hello.CipherSuite))
        {
            throw new DtlsException(
                $"The server selected an unsupported cipher suite 0x{hello.CipherSuite:X4}.",
                DtlsAlertDescription.HandshakeFailure);
        }

        if (hello.CompressionMethod != 0)
        {
            throw new DtlsException("The server selected a compression method.", DtlsAlertDescription.IllegalParameter);
        }

        _serverRandom = hello.Random;
        _cipherSuite = hello.CipherSuite;
        _useExtendedMasterSecret = hello.ExtendedMasterSecret;

        if (hello.SrtpProfile is { } profile)
        {
            var chosen = (SrtpProtectionProfile)profile;
            if (!_config.SrtpProfiles.Contains(chosen))
            {
                throw new DtlsException(
                    $"The server selected SRTP profile 0x{profile:X4}, which was not offered.",
                    DtlsAlertDescription.IllegalParameter);
            }

            NegotiatedSrtpProfile = chosen;
        }

        _log.Log(
            KeryxLogLevel.Info,
            $"Negotiated {CipherSuites.Name(_cipherSuite)}, EMS={_useExtendedMasterSecret}, SRTP={NegotiatedSrtpProfile}.");
    }

    private void HandleServerKeyExchangeLocked(byte[] body)
    {
        if (_sawServerKeyExchange)
        {
            throw new DtlsException(
                "A second ServerKeyExchange arrived.",
                DtlsAlertDescription.UnexpectedMessage);
        }

        var ske = HandshakeCodec.ParseServerKeyExchange(body);
        _sawServerKeyExchange = true;
        if (!NamedGroups.IsSupported(ske.NamedCurve) || !LocalNamedGroups().Contains(ske.NamedCurve))
        {
            throw new DtlsException(
                $"The server selected curve 0x{ske.NamedCurve:X4}, which Keryx did not offer.",
                DtlsAlertDescription.HandshakeFailure);
        }

        _negotiatedGroup = ske.NamedCurve;
        _ecdh?.Dispose();
        _ecdh = Ecdhe.Create(_negotiatedGroup);

        var certificate = _peerCertificate
                          ?? throw new DtlsException(
                              "ServerKeyExchange arrived before the server certificate.",
                              DtlsAlertDescription.UnexpectedMessage);

        var signed = new byte[_clientRandom.Length + _serverRandom.Length + ske.SignedParams.Length];
        _clientRandom.CopyTo(signed, 0);
        _serverRandom.CopyTo(signed, _clientRandom.Length);
        ske.SignedParams.CopyTo(signed, _clientRandom.Length + _serverRandom.Length);

        if (!Ecdhe.Verify(certificate, ske.Algorithm, signed, ske.Signature))
        {
            throw new DtlsException(
                "The ServerKeyExchange signature did not verify against the server certificate.",
                DtlsAlertDescription.DecryptError);
        }

        _serverKeyExchangePoint = ske.PublicPoint;
    }

    private void HandleCertificateRequestLocked(byte[] body)
    {
        if (_sawCertificateRequest)
        {
            throw new DtlsException(
                "A second CertificateRequest arrived.",
                DtlsAlertDescription.UnexpectedMessage);
        }

        var request = HandshakeCodec.ParseCertificateRequest(body);
        _sawCertificateRequest = true;
        _certificateRequested = true;
        _localSignatureAlgorithm = ChooseLocalSignatureAlgorithm(request.SignatureAlgorithms);
    }

    private void SendClientFlightLocked()
    {
        if (_serverKeyExchangePoint is null || _ecdh is null)
        {
            throw new DtlsException(
                "ServerHelloDone arrived without a usable ServerKeyExchange.",
                DtlsAlertDescription.UnexpectedMessage);
        }

        var flight = new List<FlightItem>();

        // Certificate — always sent when requested; WebRTC peers always request one.
        if (_certificateRequested)
        {
            var certificateBody = HandshakeCodec.BuildCertificate(_config.Certificate.DerEncoded);
            flight.Add(new FlightItem(
                ContentType.Handshake,
                NewHandshakeMessageLocked(HandshakeType.Certificate, certificateBody),
                0));
        }

        // ClientKeyExchange.
        var point = Ecdhe.ExportPoint(_ecdh, _negotiatedGroup);
        var ckeBody = HandshakeCodec.BuildClientKeyExchange(point);
        flight.Add(new FlightItem(
            ContentType.Handshake,
            NewHandshakeMessageLocked(HandshakeType.ClientKeyExchange, ckeBody),
            0));

        var preMasterSecret = Ecdhe.DerivePreMasterSecret(_ecdh, _serverKeyExchangePoint, _negotiatedGroup);
        DeriveKeysLocked(preMasterSecret);

        // CertificateVerify over the transcript through ClientKeyExchange.
        if (_certificateRequested)
        {
            var transcript = TranscriptBytesLocked();
            var signature = Ecdhe.Sign(_config.Certificate, _localSignatureAlgorithm, transcript);
            if (TestCorruptOutgoingCertificateVerify && signature.Length > 0)
            {
                signature[^1] ^= 0xFF;
            }

            var cvBody = HandshakeCodec.BuildCertificateVerify(_localSignatureAlgorithm, signature);
            flight.Add(new FlightItem(
                ContentType.Handshake,
                NewHandshakeMessageLocked(HandshakeType.CertificateVerify, cvBody),
                0));
        }

        AppendChangeCipherSpecAndFinishedLocked(flight, TlsPrf.ClientFinishedLabel);
        SendFlightLocked(flight, expectResponse: true);
    }

    // ------------------------------------------------------------- server role

    private void HandleClientHelloLocked(byte[] body)
    {
        // RFC 6347 §4.2.4: once the server has committed to a handshake by sending its ServerHello,
        // a further ClientHello is a renegotiation attempt, which Keryx does not implement. Honouring
        // it would let anyone who can place a datagram on the ICE-validated path destroy the
        // in-progress session (fresh server_random and a fresh ECDHE key) and would turn one small
        // ClientHello into a full certificate flight — a reflected amplification vector. A genuine
        // retransmission of the client's first flight reuses message_seq 0 and is absorbed by the
        // reassembler before it ever reaches here, so anything arriving at this point is hostile.
        if (_sawClientHello)
        {
            throw new DtlsException(
                "A second ClientHello arrived; Keryx does not support renegotiation.",
                DtlsAlertDescription.UnexpectedMessage);
        }

        if (_state == DtlsTransportState.New)
        {
            SetStateLocked(DtlsTransportState.Connecting);
        }

        var hello = HandshakeCodec.ParseClientHello(body);

        // DTLS versions are ordered by descending numeric value (DTLS 1.0 = 0xFEFF, 1.2 = 0xFEFD,
        // 1.3 = 0xFEFC), so "at least DTLS 1.2" is "numerically <= 0xFEFD". RFC 5246 §7.4.1.2 and
        // RFC 6347 §4.2.1 require a server whose lowest supported version exceeds the offered
        // client_version to abort with protocol_version rather than answer anyway. Keryx implements
        // DTLS 1.2 only, so a 1.0 ClientHello is refused here instead of being silently answered
        // with a 1.2 ServerHello. A client offering a *newer* version negotiates down to 1.2, which
        // is the behaviour the RFC prescribes.
        if (hello.Version > ProtocolVersions.Dtls12)
        {
            throw new DtlsException(
                $"ClientHello offered version 0x{hello.Version:X4}; Keryx requires DTLS 1.2 (0x{ProtocolVersions.Dtls12:X4}) or newer.",
                DtlsAlertDescription.ProtocolVersion);
        }

        _sawClientHello = true;

        if (Array.IndexOf(hello.CompressionMethods, (byte)0) < 0)
        {
            throw new DtlsException("ClientHello does not offer null compression.", DtlsAlertDescription.HandshakeFailure);
        }

        _negotiatedGroup = ChooseNamedGroup(hello.SupportedGroups);
        _cipherSuite = ChooseCipherSuite(hello.CipherSuites);
        _localSignatureAlgorithm = ChooseLocalSignatureAlgorithm(hello.SignatureAlgorithms);
        _clientRandom = hello.Random;
        _serverRandom = RandomNumberGenerator.GetBytes(RandomLength);
        _useExtendedMasterSecret = hello.ExtendedMasterSecret;
        _peerOfferedRenegotiationInfo = hello.RenegotiationInfo;
        _peerOfferedEcPointFormats = hello.EcPointFormats;
        NegotiatedSrtpProfile = ChooseSrtpProfile(hello.SrtpProfiles);

        _ecdh?.Dispose();
        _ecdh = Ecdhe.Create(_negotiatedGroup);

        _log.Log(
            KeryxLogLevel.Info,
            $"Accepted ClientHello: {CipherSuites.Name(_cipherSuite)}, group=0x{_negotiatedGroup:X4}, EMS={_useExtendedMasterSecret}, SRTP={NegotiatedSrtpProfile}, sig={_localSignatureAlgorithm}.");

        var flight = new List<FlightItem>();

        var serverHelloBody = HandshakeCodec.BuildServerHello(
            _serverRandom,
            _cipherSuite,
            _useExtendedMasterSecret,
            _peerOfferedRenegotiationInfo,
            _peerOfferedEcPointFormats,
            NegotiatedSrtpProfile);
        flight.Add(new FlightItem(
            ContentType.Handshake,
            NewHandshakeMessageLocked(HandshakeType.ServerHello, serverHelloBody),
            0));

        var certificateBody = HandshakeCodec.BuildCertificate(_config.Certificate.DerEncoded);
        flight.Add(new FlightItem(
            ContentType.Handshake,
            NewHandshakeMessageLocked(HandshakeType.Certificate, certificateBody),
            0));

        var point = Ecdhe.ExportPoint(_ecdh, _negotiatedGroup);
        var parameters = HandshakeCodec.BuildServerKeyExchangeParams(_negotiatedGroup, point);
        var signed = new byte[_clientRandom.Length + _serverRandom.Length + parameters.Length];
        _clientRandom.CopyTo(signed, 0);
        _serverRandom.CopyTo(signed, _clientRandom.Length);
        parameters.CopyTo(signed, _clientRandom.Length + _serverRandom.Length);
        var signature = Ecdhe.Sign(_config.Certificate, _localSignatureAlgorithm, signed);
        var skeBody = HandshakeCodec.BuildServerKeyExchange(parameters, _localSignatureAlgorithm, signature);
        flight.Add(new FlightItem(
            ContentType.Handshake,
            NewHandshakeMessageLocked(HandshakeType.ServerKeyExchange, skeBody),
            0));

        // WebRTC always uses mutual authentication.
        var crBody = HandshakeCodec.BuildCertificateRequest(
            [SigHashAlgorithm.EcdsaSha256, SigHashAlgorithm.RsaSha256]);
        flight.Add(new FlightItem(
            ContentType.Handshake,
            NewHandshakeMessageLocked(HandshakeType.CertificateRequest, crBody),
            0));

        flight.Add(new FlightItem(
            ContentType.Handshake,
            NewHandshakeMessageLocked(HandshakeType.ServerHelloDone, []),
            0));

        SendFlightLocked(flight, expectResponse: true);
    }

    private void HandleClientKeyExchangeLocked(byte[] body)
    {
        if (_ecdh is null)
        {
            throw new DtlsException("ClientKeyExchange arrived before ServerHello.", DtlsAlertDescription.UnexpectedMessage);
        }

        // A second ClientKeyExchange would re-run the key schedule and swap the pending ciphers out
        // from under an already-agreed session.
        if (_sawClientKeyExchange)
        {
            throw new DtlsException("A second ClientKeyExchange arrived.", DtlsAlertDescription.UnexpectedMessage);
        }

        var point = HandshakeCodec.ParseClientKeyExchange(body);
        _sawClientKeyExchange = true;
        var preMasterSecret = Ecdhe.DerivePreMasterSecret(_ecdh, point, _negotiatedGroup);
        DeriveKeysLocked(preMasterSecret);
    }

    // --------------------------------------------------------- shared handlers

    private void HandlePeerCertificateLocked(byte[] body)
    {
        // A second Certificate message would replace RemoteCertificate/RemoteFingerprint while
        // _peerCertificateVerified still records the *first* certificate's CertificateVerify, so a
        // peer could complete the handshake proving possession of one key and then have Keryx report
        // a different certificate to the application. Fingerprint pinning independently blocks that,
        // but callers that read RemoteFingerprint to make their own trust decision must not be
        // exposed to it either.
        if (_sawPeerCertificate)
        {
            throw new DtlsException(
                "A second Certificate message arrived.",
                DtlsAlertDescription.UnexpectedMessage);
        }

        var chain = HandshakeCodec.ParseCertificate(body);
        _sawPeerCertificate = true;
        if (chain.Count == 0)
        {
            if (_role == DtlsRole.Server && (_config.RequirePeerCertificate || _config.ExpectedRemoteFingerprintSha256 is not null))
            {
                throw new DtlsException(
                    "The peer did not present a certificate.",
                    DtlsAlertDescription.CertificateRequired);
            }

            _log.Log(KeryxLogLevel.Warning, "The peer presented an empty certificate list.");
            return;
        }

        _peerCertificateDer = chain[0];
        try
        {
            _peerCertificate = X509CertificateLoader.LoadCertificate(_peerCertificateDer);
        }
        catch (CryptographicException ex)
        {
            throw new DtlsException("The peer certificate could not be parsed.", DtlsAlertDescription.BadCertificate, ex);
        }

        RemoteFingerprint = DtlsCertificate.ComputeSha256Fingerprint(_peerCertificateDer);
        _log.Log(KeryxLogLevel.Debug, $"Peer certificate fingerprint {RemoteFingerprint}.");

        // The WebRTC trust decision: the certificate itself is untrusted (self-signed by design);
        // what must match is the fingerprint carried in the signalling channel.
        var expected = _config.ExpectedRemoteFingerprintSha256;
        if (expected is not null && !DtlsCertificate.FingerprintsEqual(expected, RemoteFingerprint))
        {
            throw new DtlsException(
                $"The peer certificate fingerprint {RemoteFingerprint} does not match the expected {expected}.",
                DtlsAlertDescription.BadCertificate);
        }

        if (_role == DtlsRole.Server)
        {
            _expectPeerCertificateVerify = true;
        }
    }

    private void HandleCertificateVerifyLocked(byte[] body, byte[] rawTranscript)
    {
        if (_role != DtlsRole.Server)
        {
            throw new DtlsException(
                "A client received a CertificateVerify.",
                DtlsAlertDescription.UnexpectedMessage);
        }

        if (_sawCertificateVerify)
        {
            throw new DtlsException("A second CertificateVerify arrived.", DtlsAlertDescription.UnexpectedMessage);
        }

        var certificate = _peerCertificate
                          ?? throw new DtlsException(
                              "CertificateVerify arrived without a peer certificate.",
                              DtlsAlertDescription.UnexpectedMessage);

        var (algorithm, signature) = HandshakeCodec.ParseCertificateVerify(body);
        _sawCertificateVerify = true;
        if (!Ecdhe.Verify(certificate, algorithm, rawTranscript, signature))
        {
            throw new DtlsException(
                "The peer's CertificateVerify signature did not verify over the handshake transcript.",
                DtlsAlertDescription.DecryptError);
        }

        _peerCertificateVerified = true;
        _log.Log(KeryxLogLevel.Debug, $"CertificateVerify ({algorithm}) verified.");
    }

    private void HandleFinishedLocked(byte[] body, byte[] transcriptHash)
    {
        // A second Finished would drive the server through AppendChangeCipherSpecAndFinishedLocked
        // a second time, advancing the write epoch with no pending cipher behind it and tearing down
        // an established connection.
        if (_sawPeerFinished)
        {
            throw new DtlsException("A second Finished arrived.", DtlsAlertDescription.UnexpectedMessage);
        }

        if (_masterSecret is null)
        {
            throw new DtlsException("Finished arrived before the master secret was established.", DtlsAlertDescription.UnexpectedMessage);
        }

        if (_readEpoch == 0)
        {
            throw new DtlsException("Finished arrived unencrypted.", DtlsAlertDescription.UnexpectedMessage);
        }

        if (_role == DtlsRole.Server
            && (_config.RequirePeerCertificate || _config.ExpectedRemoteFingerprintSha256 is not null)
            && _peerCertificate is null)
        {
            throw new DtlsException(
                "The peer completed the handshake without presenting a certificate.",
                DtlsAlertDescription.CertificateRequired);
        }

        if (_expectPeerCertificateVerify && !_peerCertificateVerified)
        {
            throw new DtlsException(
                "The peer sent Finished without a valid CertificateVerify.",
                DtlsAlertDescription.UnexpectedMessage);
        }

        _sawPeerFinished = true;
        var label = _role == DtlsRole.Server ? TlsPrf.ClientFinishedLabel : TlsPrf.ServerFinishedLabel;
        var expected = TlsPrf.VerifyData(_masterSecret, label, transcriptHash, NegotiatedPrfHash());
        if (body.Length != expected.Length || !CryptographicOperations.FixedTimeEquals(body, expected))
        {
            throw new DtlsException(
                "The peer's Finished verify_data did not match the handshake transcript.",
                DtlsAlertDescription.DecryptError);
        }

        if (_role == DtlsRole.Server)
        {
            var flight = new List<FlightItem>();
            AppendChangeCipherSpecAndFinishedLocked(flight, TlsPrf.ServerFinishedLabel);
            SendFlightLocked(flight, expectResponse: false);
            CompleteHandshakeLocked();
        }
        else
        {
            CompleteHandshakeLocked();
        }
    }

    private void CompleteHandshakeLocked()
    {
        if (_state == DtlsTransportState.Connected)
        {
            return;
        }

        StopRetransmitLocked();
        SetStateLocked(DtlsTransportState.Connected);
        _handshakeCompletion.TrySetResult();
        _log.Log(
            KeryxLogLevel.Info,
            $"DTLS handshake complete ({_role}, {CipherSuites.Name(_cipherSuite)}, SRTP={NegotiatedSrtpProfile}).");
    }

    // ------------------------------------------------------------- key schedule

    private void DeriveKeysLocked(byte[] preMasterSecret)
    {
        var description = CipherSuites.Describe(_cipherSuite)
            ?? throw new DtlsException(
                "Keys were derived before a cipher suite was negotiated.",
                DtlsAlertDescription.InternalError);
        var prfHash = TlsPrf.FromHashAlgorithm(description.PrfHash);

        try
        {
            _masterSecret = _useExtendedMasterSecret
                ? TlsPrf.ExtendedMasterSecret(preMasterSecret, TranscriptHashLocked(), prfHash)
                : TlsPrf.MasterSecret(preMasterSecret, _clientRandom, _serverRandom, prfHash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(preMasterSecret);
        }

        // Key block layout (RFC 5246 §6.3): client_write_key || server_write_key || client_write_IV ||
        // server_write_IV. There are no MAC keys for an AEAD suite. The IV is the GCM salt (4 bytes) or
        // the ChaCha20 write IV (12 bytes), per the suite.
        var keyLength = description.KeyLength;
        var ivLength = description.FixedIvLength;
        var keyBlock = TlsPrf.KeyBlock(
            _masterSecret, _clientRandom, _serverRandom, 2 * (keyLength + ivLength), prfHash);
        try
        {
            var clientKey = keyBlock.AsSpan(0, keyLength);
            var serverKey = keyBlock.AsSpan(keyLength, keyLength);
            var clientIv = keyBlock.AsSpan(2 * keyLength, ivLength);
            var serverIv = keyBlock.AsSpan((2 * keyLength) + ivLength, ivLength);

            _pendingWriteCipher?.Dispose();
            _pendingReadCipher?.Dispose();
            if (_role == DtlsRole.Client)
            {
                _pendingWriteCipher = RecordProtection.Create(description, clientKey, clientIv);
                _pendingReadCipher = RecordProtection.Create(description, serverKey, serverIv);
            }
            else
            {
                _pendingWriteCipher = RecordProtection.Create(description, serverKey, serverIv);
                _pendingReadCipher = RecordProtection.Create(description, clientKey, clientIv);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBlock);
        }
    }

    private void AppendChangeCipherSpecAndFinishedLocked(List<FlightItem> flight, string finishedLabel)
    {
        if (_masterSecret is null || _pendingWriteCipher is null)
        {
            throw new DtlsException("Cannot send Finished before the keys are derived.", DtlsAlertDescription.InternalError);
        }

        // ChangeCipherSpec travels in the current (old) epoch.
        flight.Add(new FlightItem(ContentType.ChangeCipherSpec, [0x01], _writeEpoch));

        _writeCipher?.Dispose();
        _writeCipher = _pendingWriteCipher;
        _pendingWriteCipher = null;
        _writeEpoch++;

        var verifyData = TlsPrf.VerifyData(_masterSecret, finishedLabel, TranscriptHashLocked(), NegotiatedPrfHash());
        if (TestCorruptOutgoingFinished)
        {
            verifyData[0] ^= 0xFF;
        }

        var finished = NewHandshakeMessageLocked(HandshakeType.Finished, verifyData);
        flight.Add(new FlightItem(ContentType.Handshake, finished, _writeEpoch));
    }

    // ------------------------------------------------------------- flight I/O

    private byte[] NewHandshakeMessageLocked(HandshakeType type, ReadOnlySpan<byte> body)
    {
        var message = HandshakeMessage.Serialize(type, _nextSendMessageSeq, body);
        _nextSendMessageSeq = unchecked((ushort)(_nextSendMessageSeq + 1));
        AppendTranscriptLocked(message);
        return message;
    }

    private void AppendTranscriptLocked(ReadOnlySpan<byte> message)
    {
        if (_transcript.Length + message.Length > DtlsLimits.MaxTranscriptLength)
        {
            throw new DtlsException("The DTLS handshake transcript grew beyond the permitted size.", DtlsAlertDescription.InternalError);
        }

        _transcript.Write(message);
    }

    private byte[] TranscriptBytesLocked() => _transcript.ToArray();

    private byte[] TranscriptHashLocked()
    {
        // The Finished verify_data and the RFC 7627 session hash are taken with the negotiated PRF's
        // hash: SHA-384 for the AES-256-GCM suites, SHA-256 otherwise.
        var transcript = _transcript.GetBuffer().AsSpan(0, (int)_transcript.Length);
        return NegotiatedPrfHash() == PrfHash.Sha384
            ? SHA384.HashData(transcript)
            : SHA256.HashData(transcript);
    }

    private void SendFlightLocked(List<FlightItem> flight, bool expectResponse)
    {
        _currentFlight = flight;
        _retransmitTimeout = _config.InitialRetransmitTimeout;
        _lastFlightSendTicks = Environment.TickCount64;
        SerializeFlightLocked(flight);

        if (expectResponse)
        {
            ScheduleRetransmitLocked();
        }
        else
        {
            StopRetransmitLocked();
        }
    }

    private void RetransmitFlightIfDueLocked()
    {
        if (_currentFlight is null || _state is DtlsTransportState.Failed)
        {
            return;
        }

        // Rate-limit responses to duplicate flights so a chatty peer cannot amplify traffic.
        if (Environment.TickCount64 - _lastFlightSendTicks < 100)
        {
            return;
        }

        _lastFlightSendTicks = Environment.TickCount64;
        _log.Log(KeryxLogLevel.Debug, "Retransmitting the current DTLS flight in response to a duplicate.");
        SerializeFlightLocked(_currentFlight);
    }

    private void SerializeFlightLocked(List<FlightItem> flight)
    {
        foreach (var item in flight)
        {
            if (item.Type != ContentType.Handshake)
            {
                EnqueueRecordLocked(item.Type, item.Epoch, item.Payload);
                continue;
            }

            var overhead = item.Epoch == 0 ? 0 : RecordProtection.MaxOverhead;
            var maxPlaintext = _mtu - DtlsLimits.RecordHeaderLength - overhead;
            var maxFragment = maxPlaintext - DtlsLimits.HandshakeHeaderLength;
            if (maxFragment < 1)
            {
                throw new DtlsException("The negotiated MTU is too small to carry a handshake fragment.", DtlsAlertDescription.InternalError);
            }

            var message = item.Payload;
            var bodyLength = message.Length - DtlsLimits.HandshakeHeaderLength;
            if (bodyLength <= maxFragment)
            {
                EnqueueRecordLocked(ContentType.Handshake, item.Epoch, message);
                continue;
            }

            var type = message[0];
            var messageSeq = (ushort)((message[4] << 8) | message[5]);
            var offset = 0;
            var fragment = new byte[DtlsLimits.HandshakeHeaderLength + maxFragment];
            while (offset < bodyLength)
            {
                var count = Math.Min(maxFragment, bodyLength - offset);
                var writer = new ByteWriter(fragment);
                writer.WriteU8(type);
                writer.WriteU24((uint)bodyLength);
                writer.WriteU16(messageSeq);
                writer.WriteU24((uint)offset);
                writer.WriteU24((uint)count);
                writer.WriteBytes(message.AsSpan(DtlsLimits.HandshakeHeaderLength + offset, count));
                EnqueueRecordLocked(ContentType.Handshake, item.Epoch, writer.Written);
                offset += count;
            }
        }
    }

    private void EnqueueRecordLocked(ContentType type, ushort epoch, ReadOnlySpan<byte> plaintext)
    {
        var sequence = NextWriteSequenceLocked(epoch);
        var cipher = epoch == 0 ? null : _writeCipher;

        if (cipher is null)
        {
            var record = new byte[DtlsLimits.RecordHeaderLength + plaintext.Length];
            DtlsRecordWriter.Write(record, type, ProtocolVersions.Dtls12, epoch, sequence, plaintext);
            _outbound.Add(record);
            return;
        }

        var bodyLength = cipher.ProtectedLength(plaintext.Length);
        var protectedRecord = new byte[DtlsLimits.RecordHeaderLength + bodyLength];
        cipher.Encrypt(
            type,
            ProtocolVersions.Dtls12,
            epoch,
            sequence,
            plaintext,
            protectedRecord.AsSpan(DtlsLimits.RecordHeaderLength));
        DtlsRecordWriter.WriteHeader(protectedRecord, type, ProtocolVersions.Dtls12, epoch, sequence, bodyLength);
        _outbound.Add(protectedRecord);
    }

    private ulong NextWriteSequenceLocked(ushort epoch)
    {
        if (epoch == 0)
        {
            return _writeSequenceEpoch0++;
        }

        return _writeSequenceEpoch1++;
    }

    private void TrySendAlertLocked(DtlsAlertLevel level, DtlsAlertDescription description)
    {
        try
        {
            Span<byte> alert = [(byte)level, (byte)description];
            EnqueueRecordLocked(ContentType.Alert, _writeEpoch, alert);
        }
        catch (Exception ex) when (ex is CryptographicException or ByteBufferException or ObjectDisposedException)
        {
            _log.Log(KeryxLogLevel.Debug, "Failed to emit a DTLS alert.", ex);
        }
    }

    private void FailLocked(DtlsException exception, bool sendAlert)
    {
        if (_state == DtlsTransportState.Failed)
        {
            return;
        }

        _log.Log(KeryxLogLevel.Error, $"DTLS failure: {exception.Message}");
        if (sendAlert && !exception.AlertFromPeer)
        {
            TrySendAlertLocked(DtlsAlertLevel.Fatal, exception.Alert ?? DtlsAlertDescription.InternalError);
        }

        StopRetransmitLocked();
        SetStateLocked(DtlsTransportState.Failed);
        _handshakeCompletion.TrySetException(exception);
    }

    private void SetStateLocked(DtlsTransportState state)
    {
        if (_state == state)
        {
            return;
        }

        _state = state;
        _stateNotifications.Add(state);
    }

    // ------------------------------------------------------------ retransmission

    private void ScheduleRetransmitLocked()
    {
        if (_disposed)
        {
            return;
        }

        try
        {
            _retransmitTimer.Change(_retransmitTimeout, Timeout.InfiniteTimeSpan);
        }
        catch (ObjectDisposedException)
        {
            // Racing with Dispose.
        }
    }

    private void StopRetransmitLocked()
    {
        try
        {
            _retransmitTimer.Change(Timeout.Infinite, Timeout.Infinite);
        }
        catch (ObjectDisposedException)
        {
            // Racing with Dispose.
        }
    }

    private void OnRetransmitTimer(object? state)
    {
        if (_disposed)
        {
            return;
        }

        lock (_sync)
        {
            if (_state != DtlsTransportState.Connecting || _currentFlight is null)
            {
                return;
            }

            var doubled = _retransmitTimeout + _retransmitTimeout;
            _retransmitTimeout = doubled > _config.MaxRetransmitTimeout ? _config.MaxRetransmitTimeout : doubled;
            _lastFlightSendTicks = Environment.TickCount64;
            _log.Log(KeryxLogLevel.Debug, $"Retransmitting DTLS flight; next timeout {_retransmitTimeout}.");

            try
            {
                SerializeFlightLocked(_currentFlight);
            }
            catch (DtlsException ex)
            {
                FailLocked(ex, sendAlert: false);
                return;
            }

            ScheduleRetransmitLocked();
        }

        Pump();
    }

    // ------------------------------------------------------------------- pump

    private void Pump()
    {
        byte[][] datagrams;
        (byte[] Buffer, int Length)[] appData;
        DtlsTransportState[] states;

        lock (_sync)
        {
            datagrams = _outbound.Count == 0 ? [] : [.. _outbound];
            _outbound.Clear();
            appData = _inboundAppData.Count == 0 ? [] : [.. _inboundAppData];
            _inboundAppData.Clear();
            states = _stateNotifications.Count == 0 ? [] : [.. _stateNotifications];
            _stateNotifications.Clear();
        }

        if (datagrams.Length > 0)
        {
            lock (_sendGate)
            {
                foreach (var packed in PackDatagrams(datagrams, _mtu))
                {
                    try
                    {
                        _lower.Send(packed);
                    }
                    catch (Exception ex)
                    {
                        // Best-effort datagram delivery: a dead lower transport must not tear down
                        // the state machine mid-lock.
                        _log.Log(KeryxLogLevel.Warning, "Failed to send a DTLS datagram.", ex);
                    }
                }
            }
        }

        foreach (var state in states)
        {
            OnStateChanged?.Invoke(this, state);
        }

        foreach (var (buffer, length) in appData)
        {
            try
            {
                OnReceived?.Invoke(buffer.AsSpan(0, length));
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
    }

    /// <summary>
    /// Packs consecutive records into as few datagrams as the MTU allows (RFC 6347 §4.1.1 permits
    /// multiple records per datagram).
    /// </summary>
    private static List<byte[]> PackDatagrams(byte[][] records, int mtu)
    {
        var result = new List<byte[]>();
        var start = 0;
        while (start < records.Length)
        {
            var length = 0;
            var end = start;
            while (end < records.Length && (length == 0 || length + records[end].Length <= mtu))
            {
                length += records[end].Length;
                end++;
            }

            if (end == start + 1)
            {
                result.Add(records[start]);
            }
            else
            {
                var datagram = new byte[length];
                var offset = 0;
                for (var i = start; i < end; i++)
                {
                    records[i].CopyTo(datagram, offset);
                    offset += records[i].Length;
                }

                result.Add(datagram);
            }

            start = end;
        }

        return result;
    }

    // -------------------------------------------------------------- negotiation

    private IReadOnlyList<ushort> LocalCipherSuites() =>
        _config.OfferedCipherSuites ?? CipherSuites.PreferenceFor(_config.Certificate.IsEcdsa);

    private IReadOnlyList<ushort> LocalNamedGroups() =>
        _config.OfferedNamedGroups ?? NamedGroups.Preference;

    private ushort ChooseCipherSuite(ushort[] offered)
    {
        // Walk our preference (strongest first) and take the first suite the peer offered that we can
        // actually authenticate with the local certificate's key type.
        var ecdsa = _config.Certificate.IsEcdsa;
        foreach (var candidate in LocalCipherSuites())
        {
            if (Array.IndexOf(offered, candidate) < 0)
            {
                continue;
            }

            if (CipherSuites.Describe(candidate) is { } description && description.RequiresEcdsaCertificate == ecdsa)
            {
                return candidate;
            }
        }

        throw new DtlsException(
            "No mutually supported cipher suite for the local certificate's key type.",
            DtlsAlertDescription.HandshakeFailure);
    }

    private ushort ChooseNamedGroup(IReadOnlyList<ushort> clientGroups)
    {
        // RFC 8422 §5.1.1: an absent supported_groups extension means the client accepts the server's
        // choice, so default to secp256r1 in that case.
        if (clientGroups.Count == 0)
        {
            return NamedGroups.Secp256r1;
        }

        foreach (var candidate in LocalNamedGroups())
        {
            if (clientGroups.Contains(candidate) && NamedGroups.IsSupported(candidate))
            {
                return candidate;
            }
        }

        throw new DtlsException(
            "No mutually supported ECDHE named group.",
            DtlsAlertDescription.HandshakeFailure);
    }

    /// <summary>The PRF hash of the negotiated cipher suite, defaulting to SHA-256 before negotiation.</summary>
    private PrfHash NegotiatedPrfHash() =>
        CipherSuites.Describe(_cipherSuite) is { } description
            ? TlsPrf.FromHashAlgorithm(description.PrfHash)
            : PrfHash.Sha256;

    private SigHashAlgorithm ChooseLocalSignatureAlgorithm(List<SigHashAlgorithm> peerAlgorithms)
    {
        var preferred = _config.Certificate.IsEcdsa ? SigHashAlgorithm.EcdsaSha256 : SigHashAlgorithm.RsaSha256;
        if (peerAlgorithms.Count == 0 || peerAlgorithms.Contains(preferred))
        {
            return preferred;
        }

        var signatureKind = preferred.Signature;
        foreach (var algorithm in peerAlgorithms)
        {
            if (algorithm.Signature == signatureKind
                && algorithm.Hash is HashAlgorithms.Sha256 or HashAlgorithms.Sha384 or HashAlgorithms.Sha512)
            {
                return algorithm;
            }
        }

        throw new DtlsException(
            "The peer does not accept any signature algorithm compatible with the local certificate.",
            DtlsAlertDescription.HandshakeFailure);
    }

    private SrtpProtectionProfile ChooseSrtpProfile(List<ushort> offered)
    {
        if (offered.Count == 0 || _config.SrtpProfiles.Count == 0)
        {
            return SrtpProtectionProfile.None;
        }

        foreach (var candidate in _config.SrtpProfiles)
        {
            if (offered.Contains((ushort)candidate))
            {
                return candidate;
            }
        }

        return SrtpProtectionProfile.None;
    }

    private readonly record struct FlightItem(ContentType Type, byte[] Payload, ushort Epoch);

    private readonly record struct BufferedRecord(ContentType Type, ushort Epoch, ulong SequenceNumber, byte[] Body);
}
