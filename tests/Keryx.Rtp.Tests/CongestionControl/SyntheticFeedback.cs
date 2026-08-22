using Keryx.Rtp.CongestionControl;
using Keryx.Rtp.Rtcp;

namespace Keryx.Rtp.Tests.CongestionControl;

/// <summary>
/// Builds transport-cc feedback packets from a scripted list of send/arrival times and records the
/// matching sends, so the delay-based estimator and the controller can be driven with no network.
/// </summary>
internal static class SyntheticFeedback
{
    /// <summary>
    /// Simulates a burst of <paramref name="count"/> packets sent one <paramref name="sendSpacingMs"/>
    /// apart and arriving one <paramref name="arrivalSpacingMs"/> apart, records each send through
    /// <paramref name="onSent"/>, and returns the parsed feedback the receiver would send back.
    /// </summary>
    /// <param name="startSequenceNumber">First transport-wide sequence number in the burst.</param>
    /// <param name="count">Number of packets.</param>
    /// <param name="firstSendMicroseconds">Send time of the first packet, microseconds.</param>
    /// <param name="firstArrivalMicroseconds">Arrival time of the first packet, microseconds.</param>
    /// <param name="sendSpacingMs">Inter-packet send spacing, milliseconds.</param>
    /// <param name="arrivalSpacingMs">Inter-packet arrival spacing, milliseconds (exceeds send spacing to grow delay).</param>
    /// <param name="packetSizeBytes">On-wire size recorded for each packet.</param>
    /// <param name="onSent">Called once per packet with its sequence number, send time and size.</param>
    /// <param name="nextSendMicroseconds">On return, the send time one spacing past the last packet.</param>
    /// <param name="nextArrivalMicroseconds">On return, the arrival time one spacing past the last packet.</param>
    /// <returns>The parsed feedback packet for this burst.</returns>
    public static RtcpTransportCcFeedback Burst(
        ushort startSequenceNumber,
        int count,
        long firstSendMicroseconds,
        long firstArrivalMicroseconds,
        double sendSpacingMs,
        double arrivalSpacingMs,
        int packetSizeBytes,
        Action<ushort, long, int> onSent,
        out long nextSendMicroseconds,
        out long nextArrivalMicroseconds)
    {
        var feedback = new RtcpTransportCcFeedback();
        for (var i = 0; i < count; i++)
        {
            var sequenceNumber = (ushort)(startSequenceNumber + i);
            var sendMicroseconds = firstSendMicroseconds + (long)Math.Round(i * sendSpacingMs * 1000);
            var arrivalMicroseconds = firstArrivalMicroseconds + (long)Math.Round(i * arrivalSpacingMs * 1000);
            onSent(sequenceNumber, sendMicroseconds, packetSizeBytes);
            feedback.AddPacket(sequenceNumber, arrivalMicroseconds);
        }

        nextSendMicroseconds = firstSendMicroseconds + (long)Math.Round(count * sendSpacingMs * 1000);
        nextArrivalMicroseconds = firstArrivalMicroseconds + (long)Math.Round(count * arrivalSpacingMs * 1000);
        return feedback;
    }
}
