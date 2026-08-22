namespace Keryx.Rtp.CongestionControl;

/// <summary>
/// The loss-based controller of draft-ietf-rmcat-gcc-02 §6: a coarse rule that raises the estimate
/// when loss is low, holds it in a middle band, and lowers it in proportion to loss when loss is
/// high. It runs alongside the delay-based estimator; the controller takes the minimum of the two.
/// </summary>
public sealed class LossBasedBandwidthEstimator
{
    private const double LowLossThreshold = 0.02;
    private const double HighLossThreshold = 0.10;
    private const double IncreaseFactor = 1.08;

    private readonly CongestionControllerOptions _options;

    /// <summary>Creates the controller at its configured start bitrate.</summary>
    /// <param name="options">Bitrate clamps and factors.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    public LossBasedBandwidthEstimator(CongestionControllerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
        BitrateBitsPerSecond = Math.Clamp(
            options.StartBitrateBitsPerSecond,
            options.MinBitrateBitsPerSecond,
            options.MaxBitrateBitsPerSecond);
    }

    /// <summary>The current loss-based target bitrate, in bits per second.</summary>
    public long BitrateBitsPerSecond { get; private set; }

    /// <summary>Whether at least one loss report has been observed; until then the estimate is not a real cap.</summary>
    public bool HasSample { get; private set; }

    /// <summary>
    /// Advances the bitrate for one reported loss fraction.
    /// </summary>
    /// <param name="fractionLost">Fraction of packets lost since the previous report, 0 to 1.</param>
    /// <returns>The updated bitrate, in bits per second.</returns>
    public long Update(double fractionLost)
    {
        HasSample = true;
        var loss = Math.Clamp(fractionLost, 0.0, 1.0);
        if (loss < LowLossThreshold)
        {
            BitrateBitsPerSecond = (long)(BitrateBitsPerSecond * IncreaseFactor);
        }
        else if (loss > HighLossThreshold)
        {
            BitrateBitsPerSecond = (long)(BitrateBitsPerSecond * (1.0 - (0.5 * loss)));
        }

        BitrateBitsPerSecond = Math.Clamp(
            BitrateBitsPerSecond,
            _options.MinBitrateBitsPerSecond,
            _options.MaxBitrateBitsPerSecond);
        return BitrateBitsPerSecond;
    }
}
