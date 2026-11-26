namespace Keryx.Rtp.Packetization;

/// <summary>
/// Payload format for audio codecs that carry one octet per RTP timestamp tick: G.711 PCMU/PCMA
/// (RFC 3551 §4.5.14) and G.722 (RFC 3551 §4.5.2, 8 kHz RTP clock, two 16 kHz samples per octet).
/// </summary>
/// <remarks>
/// The payload is raw sample data, so unlike Opus there is no TOC byte to read. The marker bit is set
/// on the first packet of the stream and on the first packet after silence (RFC 3551 §4.1), detected
/// from the media clock exactly as <see cref="OpusPacketizer"/> does: a jump of the caller-supplied RTP
/// timestamp of more than one frame's worth of ticks (the frame's own octet count). The first packet
/// after a barge-in cut is marked by the sender, independently of this class.
/// </remarks>
public sealed class OctetAudioPacketizer : IRtpPayloadizer
{
    private uint _lastTimestamp;
    private bool _started;

    /// <summary>Creates a packetizer for an octet-per-tick codec.</summary>
    /// <param name="clockRate">The negotiated RTP clock rate in Hz (8000 for G.711 and G.722).</param>
    public OctetAudioPacketizer(uint clockRate) => ClockRate = clockRate;

    /// <inheritdoc />
    public uint ClockRate { get; }

    /// <inheritdoc />
    public uint GetTimestampIncrement(ReadOnlySpan<byte> frame) => (uint)frame.Length;

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException"><paramref name="writer"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">The frame is larger than <paramref name="maxPayloadSize"/>.</exception>
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
                $"An audio frame of {frame.Length} byte(s) exceeds the {maxPayloadSize}-byte payload limit and cannot be fragmented.",
                nameof(frame));
        }

        // Unsigned subtraction gives the right forward delta across the 32-bit timestamp wrap.
        var marker = !_started || rtpTimestamp - _lastTimestamp > GetTimestampIncrement(frame);
        _lastTimestamp = rtpTimestamp;
        _started = true;

        var buffer = writer.GetPayloadBuffer(frame.Length);
        frame.CopyTo(buffer);
        writer.Commit(frame.Length, marker);
        return 1;
    }
}
