using Keryx.Core;

namespace Keryx.Broadcast;

/// <summary>
/// Tuning for a <see cref="SharedKeyBroadcastTier"/>: the outbound RTP identity of the shared broadcast
/// stream and the depth of the shared retransmission history.
/// </summary>
public sealed class SharedKeyBroadcastTierOptions
{
    /// <summary>The largest ingest RTP packet the tier sizes its rewrite/encrypt buffers for.</summary>
    public int MaxIngestPacketSize { get; set; } = 1500;

    /// <summary>The outbound payload type stamped on the shared stream, or null to keep the ingest one.</summary>
    public byte? OutboundPayloadType { get; set; }

    /// <summary>The RTP clock rate of the media, for the forwarder's timestamp rebasing across tier switches.</summary>
    public uint ClockRate { get; set; } = 90000;

    /// <summary>
    /// How many recent shared ciphertexts to retain for NACK verbatim resend (spec §5.2). One shared
    /// history serves every viewer: a NACK is answered by resending the identical stored ciphertext to
    /// only the viewer that asked. Zero disables the history.
    /// </summary>
    public int RetransmitHistoryDepth { get; set; } = 512;

    /// <summary>Optional logger; defaults to <see cref="NullLogger"/>.</summary>
    public IKeryxLogger Logger { get; set; } = NullLogger.Instance;

    internal SharedKeyBroadcastTierOptions Validate()
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxIngestPacketSize, 64);
        ArgumentOutOfRangeException.ThrowIfNegative(RetransmitHistoryDepth);
        if (ClockRate == 0)
        {
            ClockRate = 90000;
        }

        return this;
    }
}
