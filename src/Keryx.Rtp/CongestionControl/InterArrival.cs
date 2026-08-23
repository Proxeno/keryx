namespace Keryx.Rtp.CongestionControl;

/// <summary>
/// The InterArrival stage of Google Congestion Control (libwebrtc's <c>InterArrival</c>): it groups
/// packets that were sent close together — within a ~5 ms burst window — and, each time a group
/// completes, emits the send-time, arrival-time and size deltas <em>between consecutive completed
/// groups</em> for the delay filter to consume.
/// </summary>
/// <remarks>
/// <para>
/// Real GCC never feeds the <see cref="TrendlineEstimator"/> one sample per received packet. It first
/// coalesces packets into inter-arrival groups (draft-ietf-rmcat-gcc-02 §5.1) so that the inter-group
/// delay variation it measures reflects queuing at the bottleneck rather than the fine-grained pacing
/// jitter of a high packet-rate stream. Feeding per packet makes the trend noisier and biases the
/// <see cref="OveruseDetector"/> toward false overuse when many packets are in flight; grouping fixes
/// that while preserving the delay-gradient slope the detector is tuned for.
/// </para>
/// <para>
/// Packets must be supplied in non-decreasing send-time order (transport-cc feedback is walked in
/// ascending sequence-number order, which is exactly that). The type keeps only the current and the
/// previous group, so it allocates nothing steady-state and is not thread-safe.
/// </para>
/// </remarks>
internal sealed class InterArrival
{
    /// <summary>
    /// Maximum send-time span of a single packet group. A packet whose send time is more than this past
    /// the group's first send time starts a new group (libwebrtc <c>kTimestampGroupLengthTicks</c>,
    /// which is 5 ms at the 90 kHz media clock).
    /// </summary>
    private const long GroupLengthMicroseconds = 5_000;

    /// <summary>
    /// A reordered arrival within this window of the group's running arrival is still folded into the
    /// current group as part of the same burst when it adds no forward send-time separation (libwebrtc
    /// <c>kBurstDeltaThresholdMs</c>).
    /// </summary>
    private const long BurstDeltaThresholdMicroseconds = 5_000;

    /// <summary>
    /// A burst may not span more than this from the group's first arrival before a new group is forced,
    /// so a long stall cannot glue unrelated packets together (libwebrtc <c>kMaxBurstDurationMs</c>).
    /// </summary>
    private const long MaxBurstDurationMicroseconds = 100_000;

    private Group _current;
    private Group _previous;

    /// <summary>
    /// Adds one received packet to the grouping stage and, when it completes the current group, reports
    /// the deltas between the two most recently completed groups.
    /// </summary>
    /// <param name="sendMicroseconds">The packet's local send time, in microseconds.</param>
    /// <param name="arrivalMicroseconds">The packet's reported arrival time, in microseconds.</param>
    /// <param name="sizeBytes">The packet's on-wire size, in bytes.</param>
    /// <param name="sendDeltaMicroseconds">On a completed group, the send-time delta between groups.</param>
    /// <param name="arrivalDeltaMicroseconds">On a completed group, the arrival-time delta between groups.</param>
    /// <param name="sizeDeltaBytes">On a completed group, the size delta between groups.</param>
    /// <returns><see langword="true"/> when this packet closed a group and deltas were produced.</returns>
    public bool ComputeDeltas(
        long sendMicroseconds,
        long arrivalMicroseconds,
        int sizeBytes,
        out long sendDeltaMicroseconds,
        out long arrivalDeltaMicroseconds,
        out long sizeDeltaBytes)
    {
        sendDeltaMicroseconds = 0;
        arrivalDeltaMicroseconds = 0;
        sizeDeltaBytes = 0;
        var calculatedDeltas = false;

        if (!_current.HasData)
        {
            // First packet ever: seed the current group.
            _current.HasData = true;
            _current.FirstSendMicroseconds = sendMicroseconds;
            _current.SendMicroseconds = sendMicroseconds;
            _current.FirstArrivalMicroseconds = arrivalMicroseconds;
        }
        else if (IsNewGroup(sendMicroseconds, arrivalMicroseconds))
        {
            // The current group is complete. Emit the inter-group deltas once a previous group exists,
            // then rotate the current group into previous and start a fresh group at this packet.
            if (_previous.HasData)
            {
                sendDeltaMicroseconds = _current.SendMicroseconds - _previous.SendMicroseconds;
                arrivalDeltaMicroseconds = _current.CompleteArrivalMicroseconds - _previous.CompleteArrivalMicroseconds;
                sizeDeltaBytes = _current.SizeBytes - _previous.SizeBytes;
                calculatedDeltas = true;
            }

            _previous = _current;
            _current = new Group
            {
                HasData = true,
                FirstSendMicroseconds = sendMicroseconds,
                SendMicroseconds = sendMicroseconds,
                FirstArrivalMicroseconds = arrivalMicroseconds,
            };
        }
        else
        {
            // Same group: track the latest send time so the group's send stamp is its maximum.
            _current.SendMicroseconds = Math.Max(_current.SendMicroseconds, sendMicroseconds);
        }

        _current.SizeBytes += sizeBytes;
        _current.CompleteArrivalMicroseconds = arrivalMicroseconds;
        return calculatedDeltas;
    }

    private bool IsNewGroup(long sendMicroseconds, long arrivalMicroseconds)
    {
        if (BelongsToBurst(sendMicroseconds, arrivalMicroseconds))
        {
            return false;
        }

        return sendMicroseconds - _current.FirstSendMicroseconds > GroupLengthMicroseconds;
    }

    private bool BelongsToBurst(long sendMicroseconds, long arrivalMicroseconds)
    {
        var sendDelta = sendMicroseconds - _current.SendMicroseconds;
        if (sendDelta == 0)
        {
            return true;
        }

        var arrivalDelta = arrivalMicroseconds - _current.CompleteArrivalMicroseconds;
        var propagationDelta = arrivalDelta - sendDelta;
        return propagationDelta < 0
            && arrivalDelta <= BurstDeltaThresholdMicroseconds
            && arrivalMicroseconds - _current.FirstArrivalMicroseconds < MaxBurstDurationMicroseconds;
    }

    private struct Group
    {
        public bool HasData;
        public long FirstSendMicroseconds;
        public long SendMicroseconds;
        public long FirstArrivalMicroseconds;
        public long CompleteArrivalMicroseconds;
        public long SizeBytes;
    }
}
