namespace Keryx.Rtp.CongestionControl;

/// <summary>
/// The additive-increase / multiplicative-decrease rate controller of draft-ietf-rmcat-gcc-02 §5.5.
/// It turns the <see cref="BandwidthUsage"/> verdict into a bitrate: multiplicative back-off on
/// overuse, a time-proportional ramp while normal, and hold immediately after an overuse.
/// </summary>
public sealed class AimdRateController
{
    private readonly CongestionControllerOptions _options;
    private bool _hasThroughput;
    private long _throughputBitsPerSecond;

    /// <summary>Creates the controller at its configured start bitrate.</summary>
    /// <param name="options">Bitrate clamps and increase/decrease factors.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    public AimdRateController(CongestionControllerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
        BitrateBitsPerSecond = Math.Clamp(
            options.StartBitrateBitsPerSecond,
            options.MinBitrateBitsPerSecond,
            options.MaxBitrateBitsPerSecond);
    }

    /// <summary>The current delay-based target bitrate, in bits per second.</summary>
    public long BitrateBitsPerSecond { get; private set; }

    /// <summary>Records the latest acknowledged-throughput estimate the increase/decrease rules use.</summary>
    /// <param name="throughputBitsPerSecond">Measured acknowledged throughput, in bits per second.</param>
    public void SetThroughputEstimate(long throughputBitsPerSecond)
    {
        if (throughputBitsPerSecond <= 0)
        {
            return;
        }

        _hasThroughput = true;
        _throughputBitsPerSecond = throughputBitsPerSecond;
    }

    /// <summary>
    /// Advances the bitrate for one detector verdict.
    /// </summary>
    /// <param name="usage">The overuse detector's verdict.</param>
    /// <param name="elapsed">Time since the previous update, used to scale the ramp.</param>
    /// <returns>The updated bitrate, in bits per second.</returns>
    public long Update(BandwidthUsage usage, TimeSpan elapsed)
    {
        switch (usage)
        {
            case BandwidthUsage.Overusing:
                Decrease();
                break;

            case BandwidthUsage.Normal:
                Increase(elapsed);
                break;

            case BandwidthUsage.Underusing:
            default:
                break;
        }

        BitrateBitsPerSecond = Math.Clamp(
            BitrateBitsPerSecond,
            _options.MinBitrateBitsPerSecond,
            _options.MaxBitrateBitsPerSecond);
        return BitrateBitsPerSecond;
    }

    private void Decrease()
    {
        // Back off relative to the bottleneck: use the measured throughput when it is below the
        // current estimate, otherwise the estimate itself, so a real overuse always ratchets down.
        var reference = _hasThroughput && _throughputBitsPerSecond < BitrateBitsPerSecond
            ? _throughputBitsPerSecond
            : BitrateBitsPerSecond;
        BitrateBitsPerSecond = (long)(_options.DecreaseFactor * reference);
    }

    private void Increase(TimeSpan elapsed)
    {
        var seconds = Math.Max(0.0, elapsed.TotalSeconds);
        var factor = Math.Pow(_options.IncreaseFactorPerSecond, seconds);
        var next = (long)(BitrateBitsPerSecond * factor);
        if (next <= BitrateBitsPerSecond)
        {
            // Guarantee forward progress even for a tiny elapsed slice while the path is healthy.
            next = BitrateBitsPerSecond + 1;
        }

        if (_hasThroughput)
        {
            // Never ramp far past what the receiver is actually acknowledging.
            var ceiling = (long)(1.5 * _throughputBitsPerSecond);
            next = Math.Min(next, Math.Max(ceiling, BitrateBitsPerSecond));
        }

        BitrateBitsPerSecond = next;
    }
}
