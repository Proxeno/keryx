namespace Keryx.Sctp;

/// <summary>
/// A point-in-time snapshot of an association's transmission state, for diagnostics and tests.
/// </summary>
/// <param name="State">The association state at the time of the snapshot.</param>
/// <param name="CumulativeTsnReceived">Highest TSN below which everything has been received.</param>
/// <param name="PeerCumulativeTsnAck">Highest TSN the peer has cumulatively acknowledged.</param>
/// <param name="AdvancedPeerAckPoint">
/// The cumulative TSN the sender has told the peer to move to via FORWARD TSN. While this is ahead
/// of <paramref name="PeerCumulativeTsnAck"/>, an abandoned message is still being skipped.
/// </param>
/// <param name="QueuedChunks">DATA chunks queued, in flight or awaiting acknowledgement.</param>
/// <param name="BytesInFlight">Bytes of DATA transmitted but not yet acknowledged.</param>
/// <param name="CongestionWindow">Current congestion window, in bytes.</param>
/// <param name="SlowStartThreshold">Current slow-start threshold, in bytes.</param>
/// <param name="PeerReceiveWindow">The peer's last advertised receive window, in bytes.</param>
/// <param name="LocalReceiveWindow">The receive window this endpoint advertises, in bytes.</param>
/// <param name="RetransmissionTimeoutMs">Current T3-rtx retransmission timeout, in milliseconds.</param>
/// <param name="SmoothedRoundTripTimeMs">Current smoothed round-trip estimate, in milliseconds.</param>
public readonly record struct SctpAssociationStatistics(
    SctpAssociationState State,
    uint CumulativeTsnReceived,
    uint PeerCumulativeTsnAck,
    uint AdvancedPeerAckPoint,
    int QueuedChunks,
    long BytesInFlight,
    long CongestionWindow,
    long SlowStartThreshold,
    uint PeerReceiveWindow,
    uint LocalReceiveWindow,
    double RetransmissionTimeoutMs,
    double SmoothedRoundTripTimeMs);
