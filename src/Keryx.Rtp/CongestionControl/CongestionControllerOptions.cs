namespace Keryx.Rtp.CongestionControl;

/// <summary>
/// Tunables for a <see cref="GccCongestionController"/> and the estimators it drives. The defaults
/// track the constants in draft-ietf-rmcat-gcc-02 and the WebRTC implementation.
/// </summary>
public sealed class CongestionControllerOptions
{
    /// <summary>Lower clamp for the target bitrate, in bits per second. Default 30 kbit/s.</summary>
    public long MinBitrateBitsPerSecond { get; init; } = 30_000;

    /// <summary>The bitrate the estimator starts at before any feedback, in bits per second. Default 300 kbit/s.</summary>
    public long StartBitrateBitsPerSecond { get; init; } = 300_000;

    /// <summary>Upper clamp for the target bitrate, in bits per second. Default 2 Mbit/s.</summary>
    public long MaxBitrateBitsPerSecond { get; init; } = 2_000_000;

    /// <summary>Multiplicative back-off applied on overuse: <c>rate *= Beta</c>. Default 0.85.</summary>
    public double DecreaseFactor { get; init; } = 0.85;

    /// <summary>Multiplicative ramp per second while the path is not congested. Default 1.08 (8%/s).</summary>
    public double IncreaseFactorPerSecond { get; init; } = 1.08;

    /// <summary>
    /// How long a REMB estimate is honoured after it arrives. Once transport-cc feedback is seen the
    /// delay-based estimate takes precedence and REMB only ever caps it. Default 2 s.
    /// </summary>
    public TimeSpan RembTimeToLive { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>
    /// Number of trend samples the delay filter fits a line over before it produces a verdict.
    /// Default 20.
    /// </summary>
    public int TrendlineWindowSize { get; init; } = 20;

    /// <summary>Relative change in the target that must be crossed before the change event fires. Default 0.01 (1%).</summary>
    public double ChangeNotificationThreshold { get; init; } = 0.01;
}
