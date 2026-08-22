namespace Keryx.Rtp.CongestionControl;

/// <summary>
/// Raised by an <see cref="ICongestionController"/> when its target send bitrate moves. An encoder
/// rate controller subscribes to this to retune the codec's target bitrate.
/// </summary>
public sealed class TargetBitrateChangedEventArgs : EventArgs
{
    /// <summary>Creates the arguments.</summary>
    /// <param name="targetBitrateBitsPerSecond">The new target send bitrate, in bits per second.</param>
    /// <param name="usage">The delay detector's forward-path verdict at the time of the change.</param>
    /// <param name="throughputEstimateBitsPerSecond">
    /// The most recent acknowledged-throughput estimate, in bits per second, or zero when none has
    /// been measured yet.
    /// </param>
    public TargetBitrateChangedEventArgs(
        long targetBitrateBitsPerSecond,
        BandwidthUsage usage,
        long throughputEstimateBitsPerSecond)
    {
        TargetBitrateBitsPerSecond = targetBitrateBitsPerSecond;
        Usage = usage;
        ThroughputEstimateBitsPerSecond = throughputEstimateBitsPerSecond;
    }

    /// <summary>The new target send bitrate, in bits per second.</summary>
    public long TargetBitrateBitsPerSecond { get; }

    /// <summary>The delay detector's forward-path verdict when the target changed.</summary>
    public BandwidthUsage Usage { get; }

    /// <summary>The most recent acknowledged-throughput estimate, in bits per second.</summary>
    public long ThroughputEstimateBitsPerSecond { get; }
}
