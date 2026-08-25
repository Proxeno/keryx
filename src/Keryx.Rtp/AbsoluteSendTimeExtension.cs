using Keryx.Core;

namespace Keryx.Rtp;

/// <summary>
/// Wire encoding for the absolute send time header extension
/// (<c>http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time</c>): a 24-bit timestamp in 6.18
/// fixed-point seconds — six integer bits and eighteen fractional bits — carrying the wall-clock instant
/// the sender put the packet on the wire, wrapping every 64 seconds.
/// </summary>
/// <remarks>
/// Stamping this element on every outbound RTP packet is what lets a receiver run the classic
/// receive-side delay-gradient estimator and return <see cref="Rtcp.RtcpReceiverEstimatedMaxBitrate"/>
/// (REMB): the receiver pairs the abs-send-time each packet carries with its own arrival clock to recover
/// one-way delay variation without any send-time history of its own. Unlike the transport-wide-cc
/// sequence number, the value is a real timestamp, so it is meaningful on its own and needs no feedback
/// bookkeeping to interpret.
/// </remarks>
public static class AbsoluteSendTimeExtension
{
    /// <summary>Number of significant bits in the timestamp field (24, three octets).</summary>
    public const int TimestampBits = 24;

    /// <summary>Mask isolating the 24-bit timestamp field.</summary>
    public const uint TimestampMask = (1u << TimestampBits) - 1;

    /// <summary>Length in bytes of the timestamp body an element carries (three octets, 24 bits).</summary>
    public const int TimestampLength = 3;

    /// <summary>
    /// Length in bytes of the one-byte-header element body once padded to the RFC 3550 §5.3.1 four-byte
    /// boundary: the <c>id|len</c> octet plus the three timestamp octets, already a four-byte multiple.
    /// </summary>
    public const int OneByteBodyLength = 4;

    /// <summary>
    /// Total bytes a lone stamped extension adds to an RTP header: the four-byte <c>0xBEDE</c> profile and
    /// word-count prefix plus the padded <see cref="OneByteBodyLength"/> body.
    /// </summary>
    public const int OneByteHeaderOverhead = 4 + OneByteBodyLength;

    /// <summary>Fixed-point ticks per second: <c>2^18</c>, the scale of the 18-bit fractional field.</summary>
    private const long TicksPerSecond = 1 << 18;

    private const long MicrosecondsPerSecond = 1_000_000;

    /// <summary>The wrap period of the 24-bit field, in microseconds: <c>2^24 / 2^18 = 64</c> seconds.</summary>
    public const long WrapPeriodMicroseconds = (1L << TimestampBits) * MicrosecondsPerSecond / TicksPerSecond;

    /// <summary>
    /// Encodes a monotonic send instant, in microseconds, as the 24-bit 6.18 fixed-point value the
    /// extension carries. The instant is reduced modulo the 64-second wrap period first, so an arbitrarily
    /// large clock never overflows the fixed-point multiply.
    /// </summary>
    /// <param name="sendTimeMicroseconds">The send instant on any monotonic microsecond clock.</param>
    /// <returns>The 24-bit timestamp, in the low bits of the result.</returns>
    public static uint FromMicroseconds(long sendTimeMicroseconds)
    {
        // Reduce into [0, WrapPeriod) before scaling so the multiply stays well inside a 64-bit range and
        // a negative input (never expected, but cheap to tolerate) still maps to a valid field value.
        var wrapped = ((sendTimeMicroseconds % WrapPeriodMicroseconds) + WrapPeriodMicroseconds)
            % WrapPeriodMicroseconds;
        return (uint)((wrapped * TicksPerSecond / MicrosecondsPerSecond) & TimestampMask);
    }

    /// <summary>
    /// Converts a 24-bit abs-send-time value to microseconds within a single 64-second wrap window. The
    /// result is monotonic only within a window; span the wrap with <see cref="AbsoluteSendTimeUnwrapper"/>.
    /// </summary>
    /// <param name="timestamp">A 24-bit abs-send-time value; bits above <see cref="TimestampMask"/> are ignored.</param>
    /// <returns>The value in microseconds, in <c>[0, WrapPeriodMicroseconds)</c>.</returns>
    public static long ToMicroseconds(uint timestamp) =>
        (timestamp & TimestampMask) * MicrosecondsPerSecond / TicksPerSecond;

    /// <summary>
    /// Writes the one-byte-header extension body (excluding the profile/word-count prefix) carrying
    /// <paramref name="timestamp"/> under the negotiated element identifier.
    /// </summary>
    /// <param name="destination">Buffer receiving the body; must hold at least <see cref="OneByteBodyLength"/> bytes.</param>
    /// <param name="id">The element identifier (1–14) negotiated via <c>a=extmap</c>.</param>
    /// <param name="timestamp">The 24-bit abs-send-time, written big-endian; upper bits are masked off.</param>
    /// <returns>The body length in bytes, always <see cref="OneByteBodyLength"/>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The identifier is outside 1–14.</exception>
    /// <exception cref="ByteBufferException">The destination cannot hold the body.</exception>
    public static int WriteOneByteBody(Span<byte> destination, byte id, uint timestamp)
    {
        if (id is < 1 or > 14)
        {
            throw new ArgumentOutOfRangeException(nameof(id), id, "One-byte-header element identifiers are 1–14.");
        }

        if (destination.Length < OneByteBodyLength)
        {
            throw new ByteBufferException(
                $"An abs-send-time extension body needs {OneByteBodyLength} byte(s) but the destination holds {destination.Length}.");
        }

        // RFC 8285 §4.2: header octet is ID (4 bits) | len-1 (4 bits); the value is three octets, so len-1
        // is 2. The three used bytes plus that header octet already fill the four-byte boundary RFC 3550
        // §5.3.1 requires, so no trailing pad byte is needed.
        var value = timestamp & TimestampMask;
        destination[0] = (byte)((id << 4) | 0x02);
        destination[1] = (byte)(value >> 16);
        destination[2] = (byte)(value >> 8);
        destination[3] = (byte)value;
        return OneByteBodyLength;
    }

    /// <summary>
    /// Reads the 24-bit abs-send-time from a parsed header, if the negotiated element is present. Handles
    /// both the one-byte (RFC 8285 §4.2) and two-byte (§4.3) header forms, since
    /// <see cref="RtpHeader.TryGetExtension"/> resolves whichever the packet used.
    /// </summary>
    /// <param name="header">A parsed RTP header.</param>
    /// <param name="id">The element identifier negotiated via <c>a=extmap</c>.</param>
    /// <param name="timestamp">On success, the decoded 24-bit timestamp in the low bits.</param>
    /// <returns>
    /// <see langword="true"/> when a three-octet element with that identifier is present; never throws for
    /// a malformed or truncated extension.
    /// </returns>
    public static bool TryRead(in RtpHeader header, byte id, out uint timestamp)
    {
        if (header.TryGetExtension(id, out var data) && data.Length == TimestampLength)
        {
            timestamp = ((uint)data[0] << 16) | ((uint)data[1] << 8) | data[2];
            return true;
        }

        timestamp = 0;
        return false;
    }
}

/// <summary>
/// Unwraps a stream of 24-bit abs-send-time values, which wrap every 64 seconds, onto a monotonic
/// microsecond timeline suitable for delay-gradient analysis. Reordering within half the 64-second space
/// is resolved as a backward step rather than a wrap; a genuine wrap advances the timeline by 64 seconds.
/// </summary>
/// <remarks>Not thread-safe: drive one instance from a single receive loop.</remarks>
public sealed class AbsoluteSendTimeUnwrapper
{
    private const uint HalfSpan = 1u << (AbsoluteSendTimeExtension.TimestampBits - 1);

    private bool _hasPrevious;
    private uint _previous;
    private long _baseMicroseconds;

    /// <summary>
    /// Maps one 24-bit abs-send-time value to a monotonic microsecond instant, spanning wraps across the
    /// 64-second field boundary.
    /// </summary>
    /// <param name="timestamp">A 24-bit abs-send-time value; bits above the field are ignored.</param>
    /// <returns>The unwrapped send instant, in microseconds, on a monotonic timeline anchored at the first value.</returns>
    public long Unwrap(uint timestamp)
    {
        var current = timestamp & AbsoluteSendTimeExtension.TimestampMask;
        if (!_hasPrevious)
        {
            _hasPrevious = true;
            _previous = current;
            _baseMicroseconds = 0;
            return AbsoluteSendTimeExtension.ToMicroseconds(current);
        }

        // A forward field difference greater than half the space is a backward step (reorder); a backward
        // field difference greater than half the space is a forward wrap across the 64-second boundary.
        var forward = (current - _previous) & AbsoluteSendTimeExtension.TimestampMask;
        if (forward < HalfSpan)
        {
            if (current < _previous)
            {
                _baseMicroseconds += AbsoluteSendTimeExtension.WrapPeriodMicroseconds;
            }
        }
        else if (current > _previous)
        {
            _baseMicroseconds -= AbsoluteSendTimeExtension.WrapPeriodMicroseconds;
        }

        _previous = current;
        return _baseMicroseconds + AbsoluteSendTimeExtension.ToMicroseconds(current);
    }
}
