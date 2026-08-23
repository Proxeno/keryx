namespace Keryx.Rtp.Packetization;

/// <summary>
/// Opus payload format (RFC 7587): one Opus packet is carried in exactly one RTP payload, with no
/// aggregation header and no fragmentation.
/// </summary>
/// <remarks>
/// Opus goes through the same <see cref="IRtpPayloadizer"/> seam as video so senders have one code
/// path. RFC 7587 §4.1 fixes the RTP clock rate at 48000 Hz regardless of the sampling rate the
/// encoder actually ran at, and §4.2 sets the marker bit on the first packet of a talkspurt after a
/// silence or DTX gap. The packetizer detects that from the media clock alone: it compares this
/// frame's RTP timestamp against the previous frame's and sets the marker when the gap exceeds one
/// frame's duration. Because the decision rests on RTP timestamps rather than wall-clock arrival
/// times, a GC or scheduling pause between calls cannot be mistaken for silence.
/// </remarks>
public sealed class OpusPacketizer : IRtpPayloadizer
{
    /// <summary>The RTP clock rate Opus always uses (RFC 7587 §4.1).</summary>
    public const uint OpusClockRate = 48_000;

    private static readonly int[] SilkAndHybridFrameDurations = [10_000, 20_000, 40_000, 60_000];
    private static readonly int[] CeltFrameDurations = [2_500, 5_000, 10_000, 20_000];

    private uint _lastTimestamp;
    private bool _started;

    /// <inheritdoc />
    public uint ClockRate => OpusClockRate;

    /// <summary>
    /// Reads the Opus TOC byte (RFC 6716 §3.1) to work out how many 48 kHz samples the packet covers,
    /// which is exactly the RTP timestamp increment the next packet needs.
    /// </summary>
    /// <param name="frame">One Opus packet.</param>
    /// <returns>The timestamp increment in 48 kHz ticks, or zero when the packet is empty or malformed.</returns>
    public uint GetTimestampIncrement(ReadOnlySpan<byte> frame)
    {
        var duration = GetDurationMicroseconds(frame);
        return (uint)(duration * OpusClockRate / 1_000_000);
    }

    /// <summary>
    /// Returns the duration an Opus packet covers, in microseconds, from its TOC byte (RFC 6716 §3.1).
    /// </summary>
    /// <param name="frame">One Opus packet.</param>
    /// <returns>The duration in microseconds, or zero when the packet is empty or malformed.</returns>
    public static long GetDurationMicroseconds(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 1)
        {
            return 0;
        }

        var toc = frame[0];
        var config = toc >> 3;
        var perFrame = config < 12
            ? SilkAndHybridFrameDurations[config % 4]
            : config < 16
                ? SilkAndHybridFrameDurations[config % 2]
                : CeltFrameDurations[config % 4];

        var code = toc & 0x03;
        var frames = code switch
        {
            0 => 1,
            1 or 2 => 2,
            _ => frame.Length < 2 ? 0 : frame[1] & 0x3F,
        };

        return (long)perFrame * frames;
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException"><paramref name="writer"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// The Opus packet is larger than <paramref name="maxPayloadSize"/>. RFC 7587 §4.2 gives no way to
    /// fragment one, so the encoder bitrate or frame duration must be reduced instead.
    /// </exception>
    public int Packetize(ReadOnlySpan<byte> frame, uint rtpTimestamp, int maxPayloadSize, IRtpPayloadWriter writer)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxPayloadSize);

        if (frame.Length == 0)
        {
            return 0;
        }

        if (frame.Length > maxPayloadSize)
        {
            throw new ArgumentException(
                $"An Opus packet of {frame.Length} byte(s) exceeds the {maxPayloadSize}-byte payload limit and cannot be fragmented.",
                nameof(frame));
        }

        // RFC 7587 §4.2: mark the first packet of a talkspurt. The signal is a media-clock gap, read
        // straight from the RTP timestamps: the first frame of the stream always opens a talkspurt, and
        // afterwards a jump of more than one frame's worth of ticks means silence/DTX was skipped. The
        // expected step is this frame's own TOC-derived duration (RFC 6716 §3.1), which equals the RTP
        // increment a contiguous predecessor would have used. Unsigned subtraction yields the correct
        // forward delta across the 32-bit RTP timestamp wrap.
        var marker = !_started || rtpTimestamp - _lastTimestamp > GetTimestampIncrement(frame);
        _lastTimestamp = rtpTimestamp;
        _started = true;

        var buffer = writer.GetPayloadBuffer(frame.Length);
        frame.CopyTo(buffer);
        writer.Commit(frame.Length, marker);
        return 1;
    }
}
