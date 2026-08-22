using System.Security.Cryptography;
using Keryx.Core;
using Keryx.Rtp.Rtcp;

namespace Keryx.Rtp;

/// <summary>
/// Per-outbound-stream RTP state: SSRC, payload type, sequence numbering, timestamp management and
/// the packet/octet counters a sender report needs (RFC 3550 §6.4.1).
/// </summary>
/// <remarks>
/// <para>
/// The sender serializes packets into caller-supplied buffers and never allocates, so the buffer can
/// be the same one SRTP will encrypt in place.
/// </para>
/// <para>
/// <b>Thread safety: single-writer.</b> One stream is owned by one sending thread or one serialized
/// task chain. The class does no locking; concurrent calls to <see cref="WritePacket(ReadOnlySpan{byte}, bool, Span{byte})"/>
/// will corrupt the sequence number and counters.
/// </para>
/// </remarks>
public sealed class RtpStreamSender
{
    private readonly IKeryxLogger _logger;
    private ushort _sequenceNumber;
    private bool _started;

    /// <summary>
    /// Creates a stream sender. The initial sequence number and timestamp are drawn from a
    /// cryptographic random source, as RFC 3550 §5.1 requires.
    /// </summary>
    /// <param name="ssrc">The stream's synchronization source identifier.</param>
    /// <param name="payloadType">The RTP payload type to stamp on outgoing packets.</param>
    /// <param name="clockRate">The payload format's clock rate in Hz, used by <see cref="AdvanceTimestampByDuration"/>.</param>
    /// <param name="initialSequenceNumber">Overrides the random initial sequence number; for tests and interop fixtures.</param>
    /// <param name="initialTimestamp">Overrides the random initial timestamp; for tests and interop fixtures.</param>
    /// <param name="logger">Optional logger.</param>
    /// <exception cref="ArgumentOutOfRangeException">The payload type does not fit seven bits, or the clock rate is not positive.</exception>
    public RtpStreamSender(
        uint ssrc,
        byte payloadType,
        uint clockRate,
        ushort? initialSequenceNumber = null,
        uint? initialTimestamp = null,
        IKeryxLogger? logger = null)
    {
        ArgumentOutOfRangeException.ThrowIfGreaterThan(payloadType, (byte)127);
        ArgumentOutOfRangeException.ThrowIfZero(clockRate);

        Ssrc = ssrc;
        PayloadType = payloadType;
        ClockRate = clockRate;
        _logger = logger ?? NullLogger.Instance;
        _sequenceNumber = initialSequenceNumber ?? (ushort)RandomNumberGenerator.GetInt32(0, ushort.MaxValue + 1);
        Timestamp = initialTimestamp ?? (uint)RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue);
    }

    /// <summary>The stream's synchronization source identifier.</summary>
    public uint Ssrc { get; }

    /// <summary>The payload type stamped on outgoing packets.</summary>
    public byte PayloadType { get; set; }

    /// <summary>The payload format's clock rate in Hz (90000 for video, 48000 for Opus).</summary>
    public uint ClockRate { get; }

    /// <summary>The sequence number the next packet will carry. Wraps at 65535 (RFC 3550 §5.1).</summary>
    public ushort NextSequenceNumber => _sequenceNumber;

    /// <summary>The sequence number of the most recently written packet.</summary>
    /// <exception cref="InvalidOperationException">No packet has been written yet.</exception>
    public ushort LastSequenceNumber => _started
        ? (ushort)(_sequenceNumber - 1)
        : throw new InvalidOperationException("No packet has been written on this stream yet.");

    /// <summary>The RTP timestamp the next packet will carry unless one is supplied explicitly.</summary>
    public uint Timestamp { get; set; }

    /// <summary>Total RTP data packets written, for the sender report's packet count. Wraps at 2^32.</summary>
    public uint PacketCount { get; private set; }

    /// <summary>Total payload octets written, for the sender report's octet count. Wraps at 2^32.</summary>
    public uint OctetCount { get; private set; }

    /// <summary>Advances <see cref="Timestamp"/> by a number of clock ticks, wrapping at 2^32.</summary>
    /// <param name="ticks">Number of ticks of <see cref="ClockRate"/> to advance.</param>
    public void AdvanceTimestamp(uint ticks) => Timestamp = unchecked(Timestamp + ticks);

    /// <summary>Advances <see cref="Timestamp"/> by a wall-clock duration converted with <see cref="ClockRate"/>.</summary>
    /// <param name="duration">The media duration the previous frame occupied.</param>
    public void AdvanceTimestampByDuration(TimeSpan duration) =>
        AdvanceTimestamp((uint)(duration.TotalSeconds * ClockRate));

    /// <summary>Writes one RTP packet using the sender's current timestamp.</summary>
    /// <param name="payload">The payload to carry.</param>
    /// <param name="marker">The marker bit; set on the last packet of a video frame.</param>
    /// <param name="destination">Buffer that receives the complete packet.</param>
    /// <returns>The total packet length in bytes.</returns>
    /// <exception cref="ByteBufferException">The destination cannot hold header plus payload.</exception>
    public int WritePacket(ReadOnlySpan<byte> payload, bool marker, Span<byte> destination) =>
        WritePacket(payload, marker, Timestamp, destination);

    /// <summary>Writes one RTP packet with an explicit timestamp.</summary>
    /// <param name="payload">The payload to carry.</param>
    /// <param name="marker">The marker bit.</param>
    /// <param name="timestamp">The RTP timestamp to stamp on the packet.</param>
    /// <param name="destination">Buffer that receives the complete packet.</param>
    /// <returns>The total packet length in bytes.</returns>
    /// <exception cref="ByteBufferException">The destination cannot hold header plus payload.</exception>
    public int WritePacket(ReadOnlySpan<byte> payload, bool marker, uint timestamp, Span<byte> destination) =>
        WritePacket(payload, marker, timestamp, 0, default, destination);

    /// <summary>Writes one RTP packet carrying a header extension.</summary>
    /// <param name="payload">The payload to carry.</param>
    /// <param name="marker">The marker bit.</param>
    /// <param name="timestamp">The RTP timestamp to stamp on the packet.</param>
    /// <param name="extensionProfile">
    /// The header-extension profile identifier, for example <see cref="RtpHeaderExtension.OneByteProfile"/>.
    /// Pass zero together with an empty <paramref name="extensionData"/> for no extension.
    /// </param>
    /// <param name="extensionData">The extension body; its length must be a multiple of four.</param>
    /// <param name="destination">Buffer that receives the complete packet.</param>
    /// <returns>The total packet length in bytes.</returns>
    /// <exception cref="ByteBufferException">The destination cannot hold the packet.</exception>
    public int WritePacket(
        ReadOnlySpan<byte> payload,
        bool marker,
        uint timestamp,
        ushort extensionProfile,
        ReadOnlySpan<byte> extensionData,
        Span<byte> destination)
    {
        var header = new RtpHeader
        {
            Version = RtpHeader.SupportedVersion,
            Marker = marker,
            PayloadType = PayloadType,
            SequenceNumber = _sequenceNumber,
            Timestamp = timestamp,
            Ssrc = Ssrc,
            HasExtension = extensionProfile != 0,
            ExtensionProfile = extensionProfile,
            ExtensionData = extensionData,
        };

        var headerLength = header.HeaderLength;
        if (destination.Length < headerLength + payload.Length)
        {
            throw new ByteBufferException(
                $"An RTP packet of {headerLength + payload.Length} byte(s) does not fit a {destination.Length}-byte destination.");
        }

        header.WriteTo(destination);
        payload.CopyTo(destination[headerLength..]);

        _sequenceNumber = unchecked((ushort)(_sequenceNumber + 1));
        _started = true;
        PacketCount = unchecked(PacketCount + 1);
        OctetCount = unchecked(OctetCount + (uint)payload.Length);

        if (_logger.IsEnabled(KeryxLogLevel.Trace))
        {
            _logger.Log(
                KeryxLogLevel.Trace,
                $"RTP ssrc={Ssrc:x8} pt={PayloadType} seq={header.SequenceNumber} ts={timestamp} m={(marker ? 1 : 0)} len={payload.Length}");
        }

        return headerLength + payload.Length;
    }

    /// <summary>
    /// Builds a sender report describing this stream's transmission so far (RFC 3550 §6.4.1). The
    /// caller adds any reception report blocks before serializing it.
    /// </summary>
    /// <param name="wallClock">The wall-clock instant the report describes.</param>
    /// <returns>The sender report.</returns>
    public RtcpSenderReport CreateSenderReport(DateTimeOffset wallClock) => new()
    {
        SenderSsrc = Ssrc,
        NtpTimestamp = NtpTime.FromDateTimeOffset(wallClock),
        RtpTimestamp = Timestamp,
        PacketCount = PacketCount,
        OctetCount = OctetCount,
    };
}
