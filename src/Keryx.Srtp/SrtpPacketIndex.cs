namespace Keryx.Srtp;

/// <summary>
/// The implicit 48-bit SRTP packet index <c>i = 2^16 * ROC + SEQ</c> of RFC 3711 Section 3.3.1,
/// and the receiver-side rollover-counter estimation of RFC 3711 Appendix A.
/// </summary>
internal static class SrtpPacketIndex
{
    /// <summary>Number of sequence numbers in one rollover period.</summary>
    public const uint SequenceSpace = 1U << 16;

    private const int SequenceMidpoint = 1 << 15;

    /// <summary>Combines a rollover counter and sequence number into the 48-bit packet index.</summary>
    public static ulong Compose(uint rolloverCounter, ushort sequenceNumber) =>
        ((ulong)rolloverCounter << 16) | sequenceNumber;

    /// <summary>
    /// Chooses <c>v</c> from <c>{ ROC-1, ROC, ROC+1 }</c> so that <c>i = 2^16 * v + SEQ</c> is
    /// closest to <c>2^16 * ROC + s_l</c>, exactly as the pseudocode in RFC 3711 Appendix A.
    /// </summary>
    /// <param name="rolloverCounter">The locally maintained ROC.</param>
    /// <param name="highestSequence">The locally maintained <c>s_l</c>.</param>
    /// <param name="sequenceNumber">The sequence number of the packet being processed.</param>
    /// <returns>The candidate rollover counter <c>v</c>.</returns>
    public static uint EstimateRolloverCounter(uint rolloverCounter, ushort highestSequence, ushort sequenceNumber)
    {
        if (highestSequence < SequenceMidpoint)
        {
            if (sequenceNumber - highestSequence > SequenceMidpoint)
            {
                // The packet belongs to the previous rollover period. Index 0 is the floor: an SRTP
                // stream has no packets before ROC 0, so clamp instead of wrapping to 2^32-1.
                return rolloverCounter == 0 ? 0 : rolloverCounter - 1;
            }

            return rolloverCounter;
        }

        if (highestSequence - SequenceMidpoint > sequenceNumber)
        {
            return unchecked(rolloverCounter + 1);
        }

        return rolloverCounter;
    }
}

/// <summary>
/// Per-SSRC SRTP stream state: the rollover counter, the highest sequence number seen
/// (<c>s_l</c>) and, for receivers, the replay list.
/// </summary>
internal sealed class SrtpStreamState
{
    private bool _started;

    /// <summary>The SSRC this state belongs to.</summary>
    public uint Ssrc { get; }

    /// <summary>The rollover counter (RFC 3711 Section 3.3.1).</summary>
    public uint RolloverCounter { get; private set; }

    /// <summary>The highest sequence number processed so far, <c>s_l</c>.</summary>
    public ushort HighestSequence { get; private set; }

    /// <summary>The SRTP replay list for this stream.</summary>
    public SrtpReplayWindow Replay;

    /// <summary>Creates state for a newly observed SSRC with ROC = 0, as RFC 3711 Section 3.3.1 requires.</summary>
    public SrtpStreamState(uint ssrc) => Ssrc = ssrc;

    /// <summary>
    /// Returns the rollover counter to use for <paramref name="sequenceNumber"/> without mutating
    /// state. On the first packet of a stream <c>s_l</c> is initialised to that packet's sequence
    /// number, so the estimate is simply the current ROC.
    /// </summary>
    public uint EstimateRolloverCounter(ushort sequenceNumber) =>
        _started
            ? SrtpPacketIndex.EstimateRolloverCounter(RolloverCounter, HighestSequence, sequenceNumber)
            : RolloverCounter;

    /// <summary>
    /// Applies the RFC 3711 Section 3.3.1 update rules for <c>s_l</c> and ROC once the packet has
    /// been authenticated.
    /// </summary>
    /// <param name="candidate">The <c>v</c> returned by <see cref="EstimateRolloverCounter"/>.</param>
    /// <param name="sequenceNumber">The packet's sequence number.</param>
    public void Commit(uint candidate, ushort sequenceNumber)
    {
        if (!_started)
        {
            _started = true;
            RolloverCounter = candidate;
            HighestSequence = sequenceNumber;
            return;
        }

        if (candidate == RolloverCounter)
        {
            if (sequenceNumber > HighestSequence)
            {
                HighestSequence = sequenceNumber;
            }

            return;
        }

        if (candidate == unchecked(RolloverCounter + 1))
        {
            RolloverCounter = candidate;
            HighestSequence = sequenceNumber;
        }

        // v == ROC-1: an old packet from the previous rollover period; no update.
    }
}
