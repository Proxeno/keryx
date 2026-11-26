namespace Keryx;

/// <summary>
/// The details of an FEC protection group size change: the media section it applies to, the new group
/// size, and the repair overhead and smoothed loss that produced it.
/// </summary>
/// <remarks>
/// Raised on the RTCP receive loop by <see cref="PeerConnection.FecProtectionChanged"/>. Handlers run on
/// that loop and must not block: return promptly, and marshal any expensive work elsewhere.
/// </remarks>
public sealed class FecProtectionChangedEventArgs : EventArgs
{
    /// <summary>Creates the arguments.</summary>
    /// <param name="mid">The media section's <c>a=mid</c>, empty when unknown.</param>
    /// <param name="groupSize">The new protection group size.</param>
    /// <param name="overheadFraction">The nominal repair share of sent packets, <c>1 / (groupSize + 1)</c>.</param>
    /// <param name="smoothedLoss">The smoothed loss fraction at the time of the change.</param>
    public FecProtectionChangedEventArgs(string mid, int groupSize, double overheadFraction, double smoothedLoss)
    {
        Mid = mid;
        GroupSize = groupSize;
        OverheadFraction = overheadFraction;
        SmoothedLoss = smoothedLoss;
    }

    /// <summary>The <c>a=mid</c> of the media section whose FEC group size changed.</summary>
    public string Mid { get; }

    /// <summary>The new protection group size: media packets protected by one repair packet.</summary>
    public int GroupSize { get; }

    /// <summary>The nominal share of sent packets that are repair packets, <c>1 / (GroupSize + 1)</c>.</summary>
    public double OverheadFraction { get; }

    /// <summary>The smoothed loss fraction that drove the change.</summary>
    public double SmoothedLoss { get; }
}
