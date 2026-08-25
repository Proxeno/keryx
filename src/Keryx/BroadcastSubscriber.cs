using System.Net;
using Keryx.Rtp;
using Keryx.Rtp.Simulcast;
using Keryx.Srtp;

namespace Keryx;

/// <summary>
/// One subscriber's broadcast fan-out state: the <see cref="RtpForwarder"/> that rewrites the ingest
/// stream onto this subscriber's SSRC/sequence space and the <see cref="SrtpEncryptContext"/> that
/// protects the rewritten packet under this subscriber's own keys, plus the destination endpoint and
/// the reusable scratch/output buffers the fan-out writes into.
/// </summary>
/// <remarks>
/// <para>
/// <b>Single-owner by construction.</b> Every piece of mutable state a fan-out pass touches for this
/// subscriber — the forwarder's rewrite bookkeeping, the SRTP context's per-SSRC rollover/replay state,
/// the rewrite scratch buffer, and the output buffer — is owned by this one instance and shared with no
/// other subscriber. That is what makes a parallel fan-out safe: two <see cref="BroadcastSubscriber"/>
/// instances have entirely disjoint state, so <see cref="BroadcastFanout"/> can process them on
/// different worker threads with no lock and no contention (see <see cref="BroadcastFanout"/>).
/// </para>
/// <para>
/// A single instance is <em>not</em> itself thread-safe and must not be shared across concurrent
/// fan-out passes: its forwarder and SRTP context are stateful and the per-subscriber stream ordering
/// (sequence numbers, SRTP rollover) depends on packets being offered one at a time, in order. Drive
/// one instance from one fan-out at a time.
/// </para>
/// <para>
/// The instance takes ownership of the supplied <see cref="SrtpEncryptContext"/> and disposes it on
/// <see cref="Dispose"/>. <see cref="RtpForwarder"/> holds no unmanaged resources and is not disposed.
/// </para>
/// </remarks>
public sealed class BroadcastSubscriber : IDisposable
{
    /// <summary>Default largest ingest RTP packet a subscriber sizes its buffers for (a safe MTU-plus margin).</summary>
    public const int DefaultMaxIngestPacketSize = 1500;

    // Extra room over the ingest packet for the rewritten header. Egress rewriting can add a MID
    // extension block a source packet did not carry; the forwarder refuses (BufferTooSmall) rather than
    // overrun, but this margin keeps the common rewrite well clear of the edge.
    private const int RewriteHeadroom = 128;

    private readonly RtpForwarder _forwarder;
    private readonly SrtpEncryptContext _srtp;
    private readonly EndPoint _destination;
    private readonly byte[] _rewriteScratch;
    private readonly byte[] _output;

    private RtpForwardResult _lastResult;
    private int _lastLength;
    private bool _disposed;

    /// <summary>Creates a fan-out subscriber over a forwarder, its SRTP context, and a destination.</summary>
    /// <param name="forwarder">
    /// The subscriber's rewrite primitive. Its selected layer must already be driven by the application
    /// (via <see cref="RtpForwarder.SelectLayer"/>); the fan-out only offers packets to it.
    /// </param>
    /// <param name="srtp">
    /// The subscriber's outbound SRTP context. Ownership transfers to this instance, which disposes it.
    /// </param>
    /// <param name="destination">The subscriber transport endpoint every produced datagram is sent to.</param>
    /// <param name="maxIngestPacketSize">
    /// The largest ingest RTP packet the subscriber sizes its reusable buffers for; a larger ingest
    /// packet yields <see cref="RtpForwardResult.BufferTooSmall"/> rather than an overrun.
    /// </param>
    public BroadcastSubscriber(
        RtpForwarder forwarder,
        SrtpEncryptContext srtp,
        EndPoint destination,
        int maxIngestPacketSize = DefaultMaxIngestPacketSize)
    {
        ArgumentNullException.ThrowIfNull(forwarder);
        ArgumentNullException.ThrowIfNull(srtp);
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxIngestPacketSize, RtpHeader.FixedLength);

        _forwarder = forwarder;
        _srtp = srtp;
        _destination = destination;

        var rewriteCapacity = maxIngestPacketSize + RewriteHeadroom;
        _rewriteScratch = new byte[rewriteCapacity];
        _output = new byte[rewriteCapacity + srtp.Profile.RtpOverhead];
    }

    /// <summary>The subscriber's rewrite primitive, for driving layer selection and reading its state.</summary>
    public RtpForwarder Forwarder => _forwarder;

    /// <summary>The SSRC every datagram this subscriber produces carries.</summary>
    public uint OutboundSsrc => _forwarder.OutboundSsrc;

    /// <summary>The subscriber transport endpoint produced datagrams are sent to.</summary>
    public EndPoint Destination => _destination;

    /// <summary>The outcome of the most recent fan-out pass for this subscriber.</summary>
    public RtpForwardResult LastResult => _lastResult;

    /// <summary>
    /// The protected datagram produced by the most recent fan-out pass, when that pass forwarded.
    /// The payload is a window into this subscriber's output buffer and is overwritten by the next pass.
    /// </summary>
    /// <param name="datagram">The ready-to-send datagram, valid until the next pass.</param>
    /// <returns>True when the last pass forwarded and a datagram is available; otherwise false.</returns>
    public bool TryGetDatagram(out BroadcastDatagram datagram)
    {
        if (_lastResult == RtpForwardResult.Forwarded)
        {
            datagram = new BroadcastDatagram(_output.AsMemory(0, _lastLength), _destination);
            return true;
        }

        datagram = default;
        return false;
    }

    /// <summary>
    /// Rewrites and SRTP-encrypts one ingest packet for this subscriber, recording the outcome for
    /// <see cref="LastResult"/> and <see cref="TryGetDatagram"/>. Called by <see cref="BroadcastFanout"/>
    /// on the single worker that owns this subscriber for the pass; never call it concurrently for the
    /// same instance. Never throws — a malformed or oversized packet is recorded as a non-forward result.
    /// </summary>
    /// <param name="classification">The ingest packet's layer classification.</param>
    /// <param name="header">The parsed ingest RTP header (read-only; shared read across a worker's range).</param>
    /// <param name="payload">The ingest RTP payload.</param>
    /// <param name="canStartLayer">True when the packet begins an independently decodable unit of its layer.</param>
    internal void Process(
        in RtpLayerClassification classification,
        in RtpHeader header,
        ReadOnlySpan<byte> payload,
        bool canStartLayer)
    {
        var result = _forwarder.TryForward(
            in classification,
            in header,
            payload,
            canStartLayer,
            _rewriteScratch,
            out var rewritten);

        if (result != RtpForwardResult.Forwarded)
        {
            _lastResult = result;
            _lastLength = 0;
            return;
        }

        // Protect the rewritten packet under this subscriber's own keys. ProtectRtp advances this
        // subscriber's SRTP rollover/replay state, which no other subscriber shares — the property the
        // parallel fan-out relies on.
        _lastLength = _srtp.ProtectRtp(_rewriteScratch.AsSpan(0, rewritten), _output);
        _lastResult = RtpForwardResult.Forwarded;
    }

    /// <summary>Disposes the owned SRTP context, releasing its derived session keys.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _srtp.Dispose();
    }
}
