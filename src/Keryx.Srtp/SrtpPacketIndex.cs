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

/// <summary>
/// Per-SSRC <em>sender</em> state: the rollover counter maintained by counting wraps, and the
/// highest packet index already emitted.
/// </summary>
/// <remarks>
/// <para>
/// A sender must not use the RFC 3711 Appendix A estimation that <see cref="SrtpStreamState"/>
/// implements. Appendix A is specified for receivers, which have to guess which rollover period an
/// arriving sequence number belongs to; a sender knows, because it chose the sequence number. Using
/// the estimator on the send path is actively dangerous: after a genuine wrap, a forward jump of
/// more than 32768 makes it answer <c>ROC-1</c>, rewinding the 48-bit index by 2^16 back into a
/// range the session has already consumed.
/// </para>
/// <para>
/// Index reuse is catastrophic in both profiles. The index is the only varying input to the AES-CM
/// IV (RFC 3711 Section 4.1.1), so a repeat is a repeated keystream — two ciphertexts XOR to the XOR
/// of their plaintexts. It is likewise the only varying input to the RFC 7714 Section 8.1 GCM nonce,
/// and a repeated GCM nonce leaks the GHASH subkey, which hands the attacker forgery rather than
/// merely confidentiality loss. RFC 3711 Section 9.1 states the requirement directly.
/// </para>
/// </remarks>
internal sealed class SrtpSendStreamState
{
    private bool _started;
    private ushort _lastSequence;

    /// <summary>The rollover counter, incremented whenever the sequence number wraps.</summary>
    public uint RolloverCounter { get; private set; }

    /// <summary>The highest 48-bit packet index emitted so far.</summary>
    public ulong HighestIndex { get; private set; }

    /// <summary>
    /// Returns the rollover counter for <paramref name="sequenceNumber"/> and records it as used.
    /// </summary>
    /// <param name="sequenceNumber">The sequence number of the packet about to be protected.</param>
    /// <param name="ssrc">The stream's SSRC, for the diagnostic message.</param>
    /// <returns>The rollover counter to compose the packet index with.</returns>
    /// <exception cref="InvalidOperationException">
    /// The resulting index has already been used for this master key.
    /// </exception>
    public uint NextRolloverCounter(ushort sequenceNumber, uint ssrc)
    {
        if (!_started)
        {
            _started = true;
            _lastSequence = sequenceNumber;
            HighestIndex = SrtpPacketIndex.Compose(RolloverCounter, sequenceNumber);
            return RolloverCounter;
        }

        // Only a backwards step large enough to be a wrap advances the ROC. A small backwards step is
        // an out-of-order or duplicate send, which stays in the current rollover period and is caught
        // by the index check below.
        if (sequenceNumber < _lastSequence && _lastSequence - sequenceNumber > (1 << 15))
        {
            RolloverCounter = unchecked(RolloverCounter + 1);
        }

        var index = SrtpPacketIndex.Compose(RolloverCounter, sequenceNumber);
        if (index <= HighestIndex)
        {
            throw new InvalidOperationException(
                $"SRTP packet index {index} for SSRC 0x{ssrc:x8} sequence number {sequenceNumber} has already been "
                + "used with this master key. Reusing an index repeats the AES-CM keystream and the AES-GCM nonce "
                + "(RFC 3711 Section 9.1), so the packet is refused rather than protected.");
        }

        _lastSequence = sequenceNumber;
        HighestIndex = index;
        return RolloverCounter;
    }
}

