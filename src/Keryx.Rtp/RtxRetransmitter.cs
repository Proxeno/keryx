using Keryx.Core;
using Keryx.Rtp.Rtcp;

namespace Keryx.Rtp;

/// <summary>How one retransmission attempt ended.</summary>
public enum RtxRetransmitResult
{
    /// <summary>An RTX packet was written to the destination and must be sent.</summary>
    Retransmitted,

    /// <summary>The requested sequence number is no longer in the send history.</summary>
    HistoryMiss,

    /// <summary>The packet was retransmitted too recently; the request was dropped.</summary>
    RateLimited,

    /// <summary>The retransmission bandwidth budget is exhausted; the request was dropped.</summary>
    BandwidthLimited,
}

/// <summary>Policy limits applied to NACK-driven retransmission.</summary>
public sealed class RtxRetransmitOptions
{
    /// <summary>
    /// Smallest interval between two retransmissions of the same sequence number. A receiver repeats a
    /// NACK until the packet arrives, so without this a single loss costs one resend per NACK for a
    /// whole round trip. 50 ms is below a typical wide-area round trip and above a local one.
    /// </summary>
    public TimeSpan MinimumResendInterval { get; set; } = TimeSpan.FromMilliseconds(50);

    /// <summary>
    /// Sustained retransmission budget in bytes per second, refilled continuously. Zero or negative
    /// removes the limit. The default of 250 kB/s (2 Mbit/s) lets a burst loss be repaired without
    /// letting a misbehaving or badly congested receiver double the stream's bitrate.
    /// </summary>
    public int MaxBytesPerSecond { get; set; } = 250_000;

    /// <summary>
    /// Largest instantaneous burst the budget may accumulate, in bytes. Defaults to 64 kB, roughly one
    /// key frame's worth of repair.
    /// </summary>
    public int MaxBurstBytes { get; set; } = 64_000;
}

/// <summary>Counters describing one retransmission stream.</summary>
/// <param name="Ssrc">The RTX stream's synchronisation source.</param>
/// <param name="PayloadType">The negotiated <c>rtx</c> payload type.</param>
/// <param name="RequestedPackets">Sequence numbers NACKs asked to be resent, bitmasks expanded.</param>
/// <param name="PacketsRetransmitted">RTX packets actually produced and sent.</param>
/// <param name="BytesRetransmitted">Bytes of RTX packets produced, RTP headers and OSN included.</param>
/// <param name="HistoryMisses">Requests for a sequence number no longer in the send history.</param>
/// <param name="Suppressed">Requests dropped by the resend rate limit or the bandwidth budget.</param>
public readonly record struct RtxStats(
    uint Ssrc,
    byte PayloadType,
    long RequestedPackets,
    long PacketsRetransmitted,
    long BytesRetransmitted,
    long HistoryMisses,
    long Suppressed);

/// <summary>
/// Serves generic NACKs (RFC 4585 §6.2.1) out of an <see cref="RtpSendHistory"/> as RTX packets
/// (RFC 4588 §4), under a rate limit and a bandwidth budget.
/// </summary>
/// <remarks>
/// <para>
/// The retransmission stream is a full RTP stream in its own right: it has its own SSRC — advertised
/// as the second member of <c>a=ssrc-group:FID</c> — its own payload type, and its own sequence
/// number space, which is why an <see cref="RtpStreamSender"/> backs it. Only the RTP timestamp and
/// the marker bit are copied from the original packet.
/// </para>
/// <para>
/// <b>Thread safety.</b> <see cref="TryRetransmit(ushort, Span{byte}, out int)"/> mutates the RTX
/// sequence number and must be
/// serialised with itself and with the SRTP encryption of the packets it produces; a
/// <c>PeerConnection</c> does that under its send lock. <see cref="GetStats"/> and
/// <see cref="History"/> are safe to call from any thread.
/// </para>
/// </remarks>
public sealed class RtxRetransmitter
{
    private readonly RtpStreamSender _stream;
    private readonly RtxRetransmitOptions _options;
    private readonly TimeProvider _time;
    private readonly byte[] _scratch;
    private readonly IKeryxLogger _logger;

    private long _requested;
    private long _retransmitted;
    private long _bytes;
    private long _misses;
    private long _suppressed;

    private double _budget;
    private long _budgetAt;

    /// <summary>Creates a retransmitter.</summary>
    /// <param name="ssrc">The RTX stream's SSRC. Must differ from the repaired stream's SSRC.</param>
    /// <param name="payloadType">The negotiated <c>rtx</c> payload type.</param>
    /// <param name="clockRate">The repaired codec's clock rate; RTX shares it (RFC 4588 §8.1).</param>
    /// <param name="history">The send history the repaired stream fills.</param>
    /// <param name="options">Rate and bandwidth limits; defaults are used when null.</param>
    /// <param name="initialSequenceNumber">Overrides the random initial RTX sequence number; for tests.</param>
    /// <param name="timeProvider">Clock used for rate limiting; <see cref="TimeProvider.System"/> when null.</param>
    /// <param name="logger">Optional logger.</param>
    /// <exception cref="ArgumentNullException"><paramref name="history"/> is <see langword="null"/>.</exception>
    public RtxRetransmitter(
        uint ssrc,
        byte payloadType,
        uint clockRate,
        RtpSendHistory history,
        RtxRetransmitOptions? options = null,
        ushort? initialSequenceNumber = null,
        TimeProvider? timeProvider = null,
        IKeryxLogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(history);
        History = history;
        _options = options ?? new RtxRetransmitOptions();
        _time = timeProvider ?? TimeProvider.System;
        _logger = logger ?? NullLogger.Instance;
        _stream = new RtpStreamSender(ssrc, payloadType, clockRate, initialSequenceNumber, logger: logger);
        _scratch = new byte[history.MaxPacketSize];
        _budget = Math.Max(0, _options.MaxBurstBytes);
        _budgetAt = _time.GetTimestamp();
    }

    /// <summary>The RTX stream's synchronisation source.</summary>
    public uint Ssrc => _stream.Ssrc;

    /// <summary>The <c>rtx</c> payload type stamped on retransmissions.</summary>
    public byte PayloadType => _stream.PayloadType;

    /// <summary>The send history retransmissions are served from.</summary>
    public RtpSendHistory History { get; }

    /// <summary>The sequence number the next RTX packet will carry, in the RTX stream's own space.</summary>
    public ushort NextSequenceNumber => _stream.NextSequenceNumber;

    /// <summary>RTX packets written so far, for the retransmission stream's sender report.</summary>
    public uint PacketCount => _stream.PacketCount;

    /// <summary>
    /// Largest RTX packet this retransmitter can produce: the retained packet plus the two-octet OSN.
    /// </summary>
    public int MaxPacketSize => History.MaxPacketSize + RtxPacket.OriginalSequenceNumberLength;

    /// <summary>Reads the counters. Safe to call from any thread.</summary>
    /// <returns>A consistent-enough snapshot; individual counters are read atomically.</returns>
    public RtxStats GetStats() => new(
        Ssrc,
        PayloadType,
        Interlocked.Read(ref _requested),
        Interlocked.Read(ref _retransmitted),
        Interlocked.Read(ref _bytes),
        Interlocked.Read(ref _misses),
        Interlocked.Read(ref _suppressed));

    /// <summary>
    /// Builds a sender report for the retransmission stream (RFC 3550 §6.4.1). RFC 4588 §4 makes the
    /// RTX stream a separate source, so it reports separately.
    /// </summary>
    /// <param name="wallClock">The wall-clock instant the report describes.</param>
    /// <returns>The sender report.</returns>
    public RtcpSenderReport CreateSenderReport(DateTimeOffset wallClock) => _stream.CreateSenderReport(wallClock);

    /// <summary>
    /// Retransmits one NACKed packet as an RTX packet: the RTX SSRC and payload type, the next
    /// sequence number from the RTX stream's own space, the original packet's timestamp and marker
    /// bit, and a payload of the original sequence number followed by the original payload
    /// (RFC 4588 §4).
    /// </summary>
    /// <param name="originalSequenceNumber">The sequence number the peer reported missing.</param>
    /// <param name="destination">
    /// Buffer receiving the RTX packet. Must hold <see cref="MaxPacketSize"/> bytes plus whatever
    /// headroom SRTP needs for its tag.
    /// </param>
    /// <param name="length">On <see cref="RtxRetransmitResult.Retransmitted"/>, the packet's length.</param>
    /// <returns>Whether a packet was produced, and if not, why.</returns>
    /// <exception cref="ByteBufferException">The destination cannot hold the RTX packet.</exception>
    public RtxRetransmitResult TryRetransmit(ushort originalSequenceNumber, Span<byte> destination, out int length) =>
        TryRetransmit(originalSequenceNumber, 0, 0, destination, out length);

    /// <summary>
    /// Retransmits one NACKed packet as an RTX packet, additionally stamping the transport-wide
    /// congestion-control header extension (<c>draft-holmer-rmcat-transport-wide-cc-extensions-01</c>) so
    /// the repair packet is visible to the remote's feedback like any other outbound packet.
    /// </summary>
    /// <param name="originalSequenceNumber">The sequence number the peer reported missing.</param>
    /// <param name="transportCcExtensionId">
    /// The negotiated <c>a=extmap</c> element identifier (1–14) for the transport-wide sequence number.
    /// </param>
    /// <param name="transportWideSequenceNumber">
    /// The transport-wide sequence number to stamp, drawn from the connection's shared counter.
    /// </param>
    /// <param name="destination">
    /// Buffer receiving the RTX packet. Must hold <see cref="MaxPacketSize"/> bytes plus whatever headroom
    /// SRTP needs for its tag.
    /// </param>
    /// <param name="length">On <see cref="RtxRetransmitResult.Retransmitted"/>, the packet's length.</param>
    /// <returns>Whether a packet was produced, and if not, why.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The extension identifier is outside 1–14.</exception>
    /// <exception cref="ByteBufferException">The destination cannot hold the RTX packet.</exception>
    public RtxRetransmitResult TryRetransmit(
        ushort originalSequenceNumber,
        byte transportCcExtensionId,
        ushort transportWideSequenceNumber,
        Span<byte> destination,
        out int length)
    {
        length = 0;
        Interlocked.Increment(ref _requested);

        var extensionOverhead = transportCcExtensionId == 0 ? 0 : TransportCcExtension.OneByteHeaderOverhead;

        var lookup = History.TryCopy(
            originalSequenceNumber,
            _options.MinimumResendInterval,
            _scratch,
            out var storedLength);

        switch (lookup)
        {
            case RtpSendHistoryResult.Missing:
                Interlocked.Increment(ref _misses);
                return RtxRetransmitResult.HistoryMiss;

            case RtpSendHistoryResult.Suppressed:
                Interlocked.Increment(ref _suppressed);
                return RtxRetransmitResult.RateLimited;

            default:
                break;
        }

        if (!RtpHeader.TryParse(_scratch.AsSpan(0, storedLength), out var header))
        {
            // A retained buffer that no longer parses means the history was corrupted by an unlocked
            // writer; treat it as a miss rather than emitting a malformed packet.
            Interlocked.Increment(ref _misses);
            return RtxRetransmitResult.HistoryMiss;
        }

        var headerLength = header.HeaderLength;
        var payloadLength = storedLength - headerLength;
        var rtxLength = RtpHeader.FixedLength
            + extensionOverhead
            + RtxPacket.OriginalSequenceNumberLength
            + payloadLength;
        if (destination.Length < rtxLength)
        {
            throw new ByteBufferException(
                $"An RTX packet of {rtxLength} byte(s) does not fit a {destination.Length}-byte destination.");
        }

        if (!TryConsumeBudget(rtxLength))
        {
            // The packet stays exactly as eligible as it was: a repair the budget refused was never
            // sent, so it must not start the packet's minimum-resend interval.
            Interlocked.Increment(ref _suppressed);
            return RtxRetransmitResult.BandwidthLimited;
        }

        // From here the repair is certain to be produced, so the rate limit starts now.
        History.MarkRetransmitted(originalSequenceNumber);

        // Build the RTX payload where the RTP header (fixed part plus any stamped extension) will end, so
        // the sender's payload copy becomes a no-op self-copy and the packet is assembled in one buffer.
        var payloadSlot = destination.Slice(
            RtpHeader.FixedLength + extensionOverhead,
            RtxPacket.OriginalSequenceNumberLength + payloadLength);
        RtxPacket.WritePayload(
            header.SequenceNumber,
            _scratch.AsSpan(headerLength, payloadLength),
            payloadSlot);

        if (extensionOverhead == 0)
        {
            length = _stream.WritePacket(payloadSlot, header.Marker, header.Timestamp, destination);
        }
        else
        {
            Span<byte> extensionBody = stackalloc byte[TransportCcExtension.OneByteBodyLength];
            TransportCcExtension.WriteOneByteBody(extensionBody, transportCcExtensionId, transportWideSequenceNumber);
            length = _stream.WritePacket(
                payloadSlot,
                header.Marker,
                header.Timestamp,
                RtpHeaderExtension.OneByteProfile,
                extensionBody,
                destination);
        }

        Interlocked.Increment(ref _retransmitted);
        Interlocked.Add(ref _bytes, length);

        if (_logger.IsEnabled(KeryxLogLevel.Trace))
        {
            _logger.Log(
                KeryxLogLevel.Trace,
                $"RTX ssrc={Ssrc:x8} pt={PayloadType} seq={_stream.LastSequenceNumber} osn={header.SequenceNumber} len={length}");
        }

        return RtxRetransmitResult.Retransmitted;
    }

    private bool TryConsumeBudget(int bytes)
    {
        if (_options.MaxBytesPerSecond <= 0)
        {
            return true;
        }

        var now = _time.GetTimestamp();
        var elapsed = _time.GetElapsedTime(_budgetAt, now).TotalSeconds;
        _budgetAt = now;
        _budget = Math.Min(
            Math.Max(0, _options.MaxBurstBytes),
            _budget + (elapsed * _options.MaxBytesPerSecond));

        if (_budget < bytes)
        {
            return false;
        }

        _budget -= bytes;
        return true;
    }
}
