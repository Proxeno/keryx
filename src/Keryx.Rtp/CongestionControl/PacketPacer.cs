namespace Keryx.Rtp.CongestionControl;

/// <summary>
/// A leaky-bucket pacer (draft-ietf-rmcat-gcc-02 §5.6): it smooths outbound packets toward the
/// congestion controller's target so a frame's worth of packets does not burst onto the wire at once.
/// The bucket refills at the target times a pacing factor and is capped so a short idle period cannot
/// bank an unbounded burst.
/// </summary>
/// <remarks>
/// This mirrors the token-bucket budget the RTX retransmitter already uses. It is a rate gate, not a
/// queue: callers ask <see cref="TryConsume"/> before sending and, when refused, reschedule after
/// <see cref="TimeUntilNextSend"/>.
/// </remarks>
public sealed class PacketPacer
{
    private readonly TimeProvider _time;
    private readonly double _pacingFactor;
    private readonly double _burstSeconds;

    private double _budgetBytes;
    private long _lastTimestamp;
    private double _pacingRateBytesPerSecond;

    /// <summary>Creates a pacer.</summary>
    /// <param name="targetBitrateBitsPerSecond">The initial target send bitrate, in bits per second.</param>
    /// <param name="timeProvider">Clock used to accrue budget; <see cref="TimeProvider.System"/> when null.</param>
    /// <param name="pacingFactor">
    /// Multiplier on the target to obtain the drain rate, so the pacer stays ahead of the encoder.
    /// Default 2.5.
    /// </param>
    /// <param name="burstSeconds">
    /// How much drain time the bucket may bank as a burst. Default 0.02 s (20 ms).
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="pacingFactor"/> or <paramref name="burstSeconds"/> is not positive.</exception>
    public PacketPacer(
        long targetBitrateBitsPerSecond,
        TimeProvider? timeProvider = null,
        double pacingFactor = 2.5,
        double burstSeconds = 0.02)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(pacingFactor);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(burstSeconds);
        _time = timeProvider ?? TimeProvider.System;
        _pacingFactor = pacingFactor;
        _burstSeconds = burstSeconds;
        _lastTimestamp = _time.GetTimestamp();
        SetTargetBitrate(targetBitrateBitsPerSecond);
    }

    /// <summary>The current drain rate, in bytes per second (the target times the pacing factor).</summary>
    public double PacingRateBytesPerSecond => _pacingRateBytesPerSecond;

    /// <summary>The largest burst the bucket can hold, in bytes.</summary>
    public double MaxBurstBytes => Math.Max(1200.0, _pacingRateBytesPerSecond * _burstSeconds);

    /// <summary>Retargets the pacer, typically from an <see cref="ICongestionController"/> change event.</summary>
    /// <param name="targetBitrateBitsPerSecond">The new target send bitrate, in bits per second.</param>
    public void SetTargetBitrate(long targetBitrateBitsPerSecond)
    {
        var target = Math.Max(0, targetBitrateBitsPerSecond);
        _pacingRateBytesPerSecond = target / 8.0 * _pacingFactor;
        Refill();
        _budgetBytes = Math.Min(_budgetBytes, MaxBurstBytes);
    }

    /// <summary>
    /// Attempts to send <paramref name="bytes"/> now, consuming that much budget when available.
    /// </summary>
    /// <param name="bytes">The packet size on the wire, in bytes.</param>
    /// <returns><see langword="true"/> when the packet may be sent now; <see langword="false"/> when it must wait.</returns>
    public bool TryConsume(int bytes)
    {
        Refill();
        if (_budgetBytes < bytes)
        {
            return false;
        }

        _budgetBytes -= bytes;
        return true;
    }

    /// <summary>How long the caller should wait before <see cref="TryConsume"/> will admit the packet.</summary>
    /// <param name="bytes">The packet size on the wire, in bytes.</param>
    /// <returns>The delay, or <see cref="TimeSpan.Zero"/> when the packet can be sent now.</returns>
    public TimeSpan TimeUntilNextSend(int bytes)
    {
        Refill();
        if (_budgetBytes >= bytes || _pacingRateBytesPerSecond <= 0)
        {
            return TimeSpan.Zero;
        }

        return TimeSpan.FromSeconds((bytes - _budgetBytes) / _pacingRateBytesPerSecond);
    }

    private void Refill()
    {
        var now = _time.GetTimestamp();
        var elapsed = _time.GetElapsedTime(_lastTimestamp, now).TotalSeconds;
        _lastTimestamp = now;
        if (elapsed <= 0)
        {
            return;
        }

        _budgetBytes = Math.Min(MaxBurstBytes, _budgetBytes + (elapsed * _pacingRateBytesPerSecond));
    }
}
