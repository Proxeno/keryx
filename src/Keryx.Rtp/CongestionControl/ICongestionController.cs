using Keryx.Rtp.Rtcp;

namespace Keryx.Rtp.CongestionControl;

/// <summary>
/// A send-side bandwidth estimator: it consumes transport feedback and reception reports about the
/// packets this endpoint sent and produces a <see cref="TargetBitrateBitsPerSecond"/> the media
/// pipeline should aim for.
/// </summary>
/// <remarks>
/// The controller is fed from the RTCP receive path — one instance per sending transport (in an SFU,
/// one per downstream subscriber). It never blocks the send path; it only publishes a target that a
/// pacer and an encoder rate controller read. Implementations are not required to be thread-safe;
/// drive one from a single receive loop.
/// </remarks>
public interface ICongestionController
{
    /// <summary>The current target send bitrate, in bits per second.</summary>
    long TargetBitrateBitsPerSecond { get; }

    /// <summary>Raised when <see cref="TargetBitrateBitsPerSecond"/> moves past the notification threshold.</summary>
    event EventHandler<TargetBitrateChangedEventArgs>? TargetBitrateChanged;

    /// <summary>
    /// Records that a packet stamped with a transport-wide sequence number left the wire, so later
    /// feedback naming that sequence number can be paired with its send time.
    /// </summary>
    /// <param name="transportSequenceNumber">The transport-wide sequence number carried by the packet.</param>
    /// <param name="sendTimeMicroseconds">The local send time, in microseconds.</param>
    /// <param name="payloadSizeBytes">The size of the packet on the wire, in bytes.</param>
    void OnPacketSent(ushort transportSequenceNumber, long sendTimeMicroseconds, int payloadSizeBytes);

    /// <summary>Feeds one transport-wide congestion control feedback packet to the delay-based estimator.</summary>
    /// <param name="feedback">The parsed feedback, arrival times reconstructed.</param>
    void OnTransportFeedback(RtcpTransportCcFeedback feedback);

    /// <summary>Feeds the loss fraction from a reception report to the loss-based estimator.</summary>
    /// <param name="fractionLost">Fraction of packets the peer reports lost since the last report, 0 to 1.</param>
    void OnReportedLoss(double fractionLost);

    /// <summary>Feeds a Receiver Estimated Maximum Bitrate message, used as a cap and as a fallback.</summary>
    /// <param name="remb">The parsed REMB message.</param>
    void OnReceiverEstimatedMaxBitrate(RtcpReceiverEstimatedMaxBitrate remb);
}
