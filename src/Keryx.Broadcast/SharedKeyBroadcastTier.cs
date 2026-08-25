using System.Buffers.Binary;
using System.Net;
using Keryx.Core;
using Keryx.Rtp;
using Keryx.Rtp.Simulcast;
using Keryx.Sdp;
using Keryx.Srtp;

namespace Keryx.Broadcast;

/// <summary>
/// The SFU send side of shared-key encrypt-once public broadcast (<c>broadcast-scale.md</c> §5): one
/// simulcast tier of a public broadcast, rewritten onto a single broadcast SSRC and SRTP-encrypted
/// <b>once per ingest packet</b> under a shared <see cref="PublicBroadcastKey"/>, then fanned out as N
/// byte-identical datagrams to the N enrolled viewers. This is the O(N)→O(1) crypto lever: the only
/// remaining per-viewer work is the destination address, not a rewrite or an encrypt.
/// </summary>
/// <remarks>
/// <para>
/// <b>Security boundary — the paragraph the sign-off is for (spec §5.4).</b> Every enrolled viewer holds
/// the key that decrypts <i>and can forge</i> this broadcast, so the mode is for PUBLIC content only.
/// The boundary is enforced structurally, not by documentation:
/// </para>
/// <list type="number">
/// <item>The key is a <see cref="PublicBroadcastKey"/> — mintable only via
/// <c>CreateForPublicContent</c>, never DTLS-derived (invariant 1).</item>
/// <item><see cref="Enroll(ViewerSession)"/> <b>throws</b> for any session with a receiving media m-line
/// (recvonly/sendrecv). Public broadcast is SFU→viewer send-only; a viewer that could <i>send</i> media
/// under the shared key is a cross-viewer forgery vector, so it can never enroll (invariant 2).</item>
/// <item>The mode lives only in this broadcast-fan-out component, behind the public-named key type. There
/// is no per-<c>PeerConnection</c> "use shared key" switch, so a private/1:1/mixed room has no API path
/// to it (invariant 3).</item>
/// <item>A session can be enrolled into exactly one broadcast's shared key; enrolling it into a second
/// throws (no cross-broadcast key mixing).</item>
/// </list>
/// <para>
/// <b>Composition tradeoffs (spec §5.2), handled here.</b> Identical ciphertext means no per-viewer
/// header rewrite, hence no per-viewer TWCC and no per-viewer GCC on shared-key legs: congestion
/// adaptation is <b>tier selection</b> (<see cref="SelectTier"/>), each tier its own
/// <see cref="SharedKeyBroadcastTier"/> with its own SSRC and encrypt-once. RTX becomes <b>verbatim
/// resend</b> of the shared ciphertext from one shared history buffer (<see cref="TryResend"/>),
/// delivered only to the NACKing viewer. RTCP sender reports for the shared stream also encrypt once
/// (<see cref="FanoutSenderReport"/>); viewer→SFU RTCP stays on each viewer's own DTLS-derived keys and
/// is not this type's concern (spec §5.5).
/// </para>
/// <para>
/// One instance drives one tier's stream and is not thread-safe for its send path: call
/// <see cref="Fanout"/> once per ingest packet, in order, from one thread — exactly as
/// <c>BroadcastFanout</c> requires. Enrollment changes are serialised internally.
/// </para>
/// </remarks>
public sealed class SharedKeyBroadcastTier : IDisposable
{
    private readonly object _membershipLock = new();
    private readonly List<ViewerSession> _viewers = [];
    private readonly List<IPEndPoint> _destinationScratch = [];
    private readonly IKeryxLogger _logger;
    private readonly SharedKeyBroadcastTierOptions _options;
    private readonly RtpForwarder _forwarder;
    private readonly byte[] _rewrite;
    private readonly byte[] _cipher;
    private readonly SharedCiphertextHistory? _history;

    // The current shared key and the encrypt-once context derived from it. Rebuilt on RotateEpoch. Guarded
    // by _membershipLock for the rare rotation; the hot Fanout path reads _encrypt without a lock because
    // Fanout is single-threaded per the type contract and rotation is expected between passes, not during.
    private PublicBroadcastKey _key;
    private SrtpEncryptContext _encrypt;

    // Published destination snapshot the hot path reads without allocating. Rebuilt on membership change
    // and on RefreshDestinations (when a viewer's ICE binding settles after enrollment).
    private volatile IPEndPoint[] _destinations = [];
    private volatile bool _disposed;

    /// <summary>Creates a shared-key tier for one broadcast SSRC under a public broadcast key.</summary>
    /// <param name="key">
    /// The shared public-broadcast key. The tier derives its encrypt-once context from it but does not
    /// take ownership: the caller disposes the key (and any rotated epochs) when the broadcast ends.
    /// </param>
    /// <param name="broadcastSsrc">The single SSRC every viewer of this tier receives.</param>
    /// <param name="options">Tuning; defaults are used when null.</param>
    /// <exception cref="ArgumentNullException"><paramref name="key"/> is null.</exception>
    public SharedKeyBroadcastTier(PublicBroadcastKey key, uint broadcastSsrc, SharedKeyBroadcastTierOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        _options = (options ?? new SharedKeyBroadcastTierOptions()).Validate();
        _logger = _options.Logger;
        _key = key;
        BroadcastSsrc = broadcastSsrc;

        _forwarder = new RtpForwarder(broadcastSsrc, _options.OutboundPayloadType, _options.ClockRate);
        var capacity = _options.MaxIngestPacketSize + 128;
        _rewrite = new byte[capacity];
        _cipher = new byte[capacity + key.Profile.RtpOverhead];
        _encrypt = new SrtpEncryptContext(key.Profile, key.ToSessionKeys(), _logger);
        _history = _options.RetransmitHistoryDepth > 0
            ? new SharedCiphertextHistory(_options.RetransmitHistoryDepth, capacity + key.Profile.RtpOverhead)
            : null;
    }

    /// <summary>The single SSRC every viewer of this tier receives.</summary>
    public uint BroadcastSsrc { get; }

    /// <summary>The epoch of the shared key currently in force.</summary>
    public int Epoch => _key.Epoch;

    /// <summary>The number of viewers currently enrolled in this tier.</summary>
    public int ViewerCount
    {
        get
        {
            lock (_membershipLock)
            {
                return _viewers.Count;
            }
        }
    }

    /// <summary>
    /// Selects the simulcast layer this broadcast tier forwards. This is how a shared-key broadcast adapts
    /// to conditions: since there is no per-viewer rewrite there is no per-viewer TWCC, so the SFU picks a
    /// tier for the whole shared stream (spec §5.2). The switch lands on the next keyframe of the selected
    /// layer, exactly like <see cref="RtpForwarder.SelectLayer"/>.
    /// </summary>
    /// <param name="layerId">The simulcast layer to forward.</param>
    public void SelectTier(SimulcastLayerId layerId) => _forwarder.SelectLayer(layerId);

    /// <summary>
    /// Enrolls a viewer into this shared-key tier. <b>Throws</b> unless the session's RTP surface is
    /// exclusively send-only (SFU→viewer) — any receiving m-line makes the viewer a forgery vector under
    /// the shared key and is refused (spec §5.4). A session already enrolled in a different broadcast's
    /// shared key is also refused.
    /// </summary>
    /// <param name="session">The viewer session to enroll.</param>
    /// <exception cref="ArgumentNullException"><paramref name="session"/> is null.</exception>
    /// <exception cref="InvalidOperationException">
    /// The session has a receiving media m-line, or is already enrolled in another shared-key broadcast,
    /// or the tier is disposed.
    /// </exception>
    public void Enroll(ViewerSession session)
    {
        ArgumentNullException.ThrowIfNull(session);
        ObjectDisposedException.ThrowIf(_disposed, this);

        // THE BOUNDARY. A public broadcast is SFU→viewer send-only. A transceiver whose desired OR
        // negotiated direction receives means the SFU would accept media FROM this viewer — media that,
        // under the shared key every other viewer also holds, any viewer could forge. Refuse it. Both the
        // pre-negotiation (Direction) and post-negotiation (CurrentDirection) views are checked so the
        // guard holds whether enrollment happens before or after the offer/answer settles.
        foreach (var transceiver in session.Connection.Transceivers)
        {
            if (transceiver.Stopped)
            {
                continue;
            }

            var desiredReceives = transceiver.Direction.Receives();
            var negotiatedReceives = transceiver.CurrentDirection is { } current && current.Receives();
            if (desiredReceives || negotiatedReceives)
            {
                throw new InvalidOperationException(
                    $"Session '{session.Id}' cannot enroll in a shared-key public broadcast: transceiver "
                    + $"mid='{transceiver.Mid ?? "(unbound)"}' has a receiving direction "
                    + $"(desired={transceiver.Direction}, negotiated={transceiver.CurrentDirection?.ToString() ?? "none"}). "
                    + "Shared-key broadcast is send-only (SFU→viewer); a viewer that could send media under "
                    + "the shared key is a cross-viewer forgery vector (broadcast-scale.md §5.4).");
            }
        }

        // One session, one broadcast key: enrolling into a second broadcast's shared key is refused so a
        // viewer never holds two broadcasts' keys through this path.
        if (!session.TryClaimSharedKeyTier(this))
        {
            throw new InvalidOperationException(
                $"Session '{session.Id}' is already enrolled in a different shared-key broadcast; a session "
                + "cannot hold two broadcasts' shared keys.");
        }

        lock (_membershipLock)
        {
            if (!_viewers.Contains(session))
            {
                _viewers.Add(session);
            }

            RebuildDestinationsLocked();
        }

        _logger.Log(KeryxLogLevel.Debug, $"Session '{session.Id}' enrolled in shared-key broadcast SSRC 0x{BroadcastSsrc:x8}.");
    }

    /// <summary>Removes a viewer from this tier. Its own DTLS keys are untouched; only its shared-key
    /// enrollment and its fan-out destination are dropped.</summary>
    /// <param name="session">The session to remove.</param>
    /// <returns>True when the session was enrolled and is now removed.</returns>
    public bool Remove(ViewerSession session)
    {
        ArgumentNullException.ThrowIfNull(session);
        bool removed;
        lock (_membershipLock)
        {
            removed = _viewers.Remove(session);
            if (removed)
            {
                RebuildDestinationsLocked();
            }
        }

        if (removed)
        {
            session.ReleaseSharedKeyTier(this);
        }

        return removed;
    }

    /// <summary>
    /// Rebuilds the fan-out destination snapshot from the enrolled viewers' currently-bound 5-tuples. Call
    /// after a viewer's ICE binding settles post-enrollment (first-contact demux binds the 5-tuple on the
    /// endpoint's receive loop, not through the tier), so the next <see cref="Fanout"/> reaches it.
    /// </summary>
    public void RefreshDestinations()
    {
        lock (_membershipLock)
        {
            RebuildDestinationsLocked();
        }
    }

    /// <summary>
    /// Encrypt-once fan-out: rewrites the ingest packet onto the broadcast SSRC ONCE, SRTP-encrypts it
    /// ONCE, records it in the shared history for NACK, then appends one datagram per enrolled viewer —
    /// every datagram pointing at the <b>same</b> ciphertext memory (byte-identical, the O(1) crypto).
    /// <paramref name="datagrams"/> is cleared first. The shared payload is valid until the next
    /// <see cref="Fanout"/> overwrites it, so send the batch before the next pass.
    /// </summary>
    /// <param name="classification">The ingest packet's simulcast-layer classification.</param>
    /// <param name="ingestPacket">The complete ingest RTP packet.</param>
    /// <param name="canStartLayer">True when the packet begins an independently decodable unit of its layer.</param>
    /// <param name="datagrams">Receives the produced datagrams; cleared before the pass appends.</param>
    /// <returns>The number of datagrams appended (one per enrolled viewer destination), or 0 when the
    /// packet did not forward (wrong layer, malformed, or no viewers).</returns>
    /// <exception cref="ArgumentNullException"><paramref name="datagrams"/> is null.</exception>
    public int Fanout(
        in RtpLayerClassification classification,
        ReadOnlyMemory<byte> ingestPacket,
        bool canStartLayer,
        List<BroadcastDatagram> datagrams)
    {
        ArgumentNullException.ThrowIfNull(datagrams);
        datagrams.Clear();
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!TryEncryptOnce(in classification, ingestPacket.Span, canStartLayer, out var cipherLength, out var broadcastSeq))
        {
            return 0;
        }

        var destinations = _destinations;
        if (destinations.Length == 0)
        {
            return 0;
        }

        _history?.Record(broadcastSeq, _cipher.AsSpan(0, cipherLength));

        var payload = _cipher.AsMemory(0, cipherLength);
        foreach (var destination in destinations)
        {
            datagrams.Add(new BroadcastDatagram(payload, destination));
        }

        return datagrams.Count;
    }

    /// <summary>
    /// Serves a NACK by verbatim resend (spec §5.2): if the requested broadcast sequence number is still
    /// in the shared history, produces a datagram carrying the <b>identical stored ciphertext</b> to only
    /// the one viewer that asked. Duplicate-safe on the receiver by SRTP replay semantics. Returns false
    /// when the packet has aged out of the history or the history is disabled.
    /// </summary>
    /// <param name="broadcastSequenceNumber">The broadcast-stream sequence number the viewer NACKed.</param>
    /// <param name="destination">The NACKing viewer's transport endpoint.</param>
    /// <param name="datagram">On success, the verbatim-resend datagram.</param>
    /// <returns>True when the ciphertext was found and a resend datagram was produced.</returns>
    public bool TryResend(ushort broadcastSequenceNumber, IPEndPoint destination, out BroadcastDatagram datagram)
    {
        ArgumentNullException.ThrowIfNull(destination);
        datagram = default;
        if (_history is null || !_history.TryGet(broadcastSequenceNumber, out var ciphertext))
        {
            return false;
        }

        datagram = new BroadcastDatagram(ciphertext, destination);
        return true;
    }

    /// <summary>
    /// Encrypt-once fan-out for an RTCP sender report of the shared stream (spec §5.5): protects the SR
    /// compound ONCE under the shared key and appends one datagram per viewer sharing that ciphertext.
    /// Viewer→SFU RTCP is never handled here — it rides each viewer's own DTLS-derived SRTCP keys.
    /// </summary>
    /// <param name="senderReport">A complete (possibly compound) RTCP sender report for the broadcast SSRC.</param>
    /// <param name="datagrams">Receives the produced datagrams; cleared before the pass appends.</param>
    /// <returns>The number of datagrams appended.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="datagrams"/> is null.</exception>
    public int FanoutSenderReport(ReadOnlySpan<byte> senderReport, List<BroadcastDatagram> datagrams)
    {
        ArgumentNullException.ThrowIfNull(datagrams);
        datagrams.Clear();
        ObjectDisposedException.ThrowIf(_disposed, this);

        var destinations = _destinations;
        if (destinations.Length == 0)
        {
            return 0;
        }

        var length = _encrypt.ProtectRtcp(senderReport, _cipher);
        var payload = _cipher.AsMemory(0, length);
        foreach (var destination in destinations)
        {
            datagrams.Add(new BroadcastDatagram(payload, destination));
        }

        return datagrams.Count;
    }

    /// <summary>Exports the current shared key for delivery to a viewer (spec §5.1).</summary>
    /// <returns>The current key export.</returns>
    public PublicBroadcastKeyExport ExportKey() => _key.Export();

    /// <summary>
    /// Encodes the current shared key and this tier's broadcast SSRC as the Keryx-defined control message
    /// the SFU sends over each viewer's already-DTLS-authenticated data channel (spec §5.1).
    /// </summary>
    /// <returns>The encoded key message.</returns>
    public byte[] EncodeKeyMessage() => PublicBroadcastKeyMessage.Encode(_key.Export(), [BroadcastSsrc]);

    /// <summary>
    /// Rotates to a new epoch (spec §5.1): mints a fresh random key, rebuilds the encrypt-once context,
    /// and returns the new export to distribute over the viewers' data channels. Distribute the new key,
    /// then switch: viewers hold both epochs across the switch (they try current then previous). The
    /// previous <see cref="PublicBroadcastKey"/> handed to the constructor is left undisposed for the
    /// caller to retire once no packet under it can still be in flight.
    /// </summary>
    /// <returns>The new epoch's key export.</returns>
    /// <exception cref="ObjectDisposedException">The tier is disposed.</exception>
    public PublicBroadcastKeyExport RotateEpoch()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        lock (_membershipLock)
        {
            var next = _key.RotateEpoch();
            var encrypt = new SrtpEncryptContext(next.Profile, next.ToSessionKeys(), _logger);
            _encrypt.Dispose();
            _encrypt = encrypt;
            _key = next;
            _logger.Log(KeryxLogLevel.Info, $"Shared-key broadcast SSRC 0x{BroadcastSsrc:x8} rotated to epoch {next.Epoch}.");
            return next.Export();
        }
    }

    private bool TryEncryptOnce(
        in RtpLayerClassification classification,
        ReadOnlySpan<byte> ingestPacket,
        bool canStartLayer,
        out int cipherLength,
        out ushort broadcastSequenceNumber)
    {
        cipherLength = 0;
        broadcastSequenceNumber = 0;

        if (!RtpHeader.TryParse(ingestPacket, out var header))
        {
            return false;
        }

        var payload = ingestPacket[header.HeaderLength..];
        var result = _forwarder.TryForward(in classification, in header, payload, canStartLayer, _rewrite, out var rewritten);
        if (result != RtpForwardResult.Forwarded)
        {
            return false;
        }

        // The rewritten packet carries the broadcast SSRC and the tier's contiguous sequence space; its
        // sequence number (bytes 2-3) keys the shared NACK history.
        broadcastSequenceNumber = BinaryPrimitives.ReadUInt16BigEndian(_rewrite.AsSpan(2, 2));
        cipherLength = _encrypt.ProtectRtp(_rewrite.AsSpan(0, rewritten), _cipher);
        return true;
    }

    private void RebuildDestinationsLocked()
    {
        _destinationScratch.Clear();
        foreach (var viewer in _viewers)
        {
            viewer.CopyBoundEndPointsTo(_destinationScratch);
        }

        _destinations = _destinationScratch.Count == 0 ? [] : [.. _destinationScratch];
    }

    /// <summary>Disposes the encrypt-once context and releases every viewer's enrollment claim.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        lock (_membershipLock)
        {
            foreach (var viewer in _viewers)
            {
                viewer.ReleaseSharedKeyTier(this);
            }

            _viewers.Clear();
            _destinations = [];
            _encrypt.Dispose();
        }
    }
}
