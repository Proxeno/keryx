using Keryx.Rtp;

namespace Keryx.Rtp.CongestionControl;

/// <summary>
/// The classic receive-side bandwidth estimator (libwebrtc's <c>RemoteBitrateEstimatorAbsSendTime</c>):
/// it recovers one-way delay variation directly from the absolute send time each packet carries paired
/// with the packet's local arrival time, runs that gradient through the same
/// <see cref="TrendlineEstimator"/> and <see cref="OveruseDetector"/> the send-side estimator uses, and
/// drives an <see cref="AimdRateController"/> to an estimated maximum bitrate. That estimate is what a
/// receiver reports back to the sender as REMB (<see cref="Rtcp.RtcpReceiverEstimatedMaxBitrate"/>).
/// </summary>
/// <remarks>
/// <para>
/// Unlike the send-side <see cref="DelayBasedBandwidthEstimator"/>, this estimator needs no send-time
/// history: the abs-send-time extension is the sender's own transmit timestamp, so the receiver has both
/// halves of the delay gradient from the packet alone. Send times are unwrapped across the 64-second
/// abs-send-time field, grouped into ~5 ms inter-arrival bursts, and only completed groups feed the
/// filter — exactly as the send-side path groups transport-cc arrivals.
/// </para>
/// <para>
/// Drive one instance from a single receive loop; it holds no synchronisation and derives all of its
/// timing from the arrival times supplied to <see cref="OnPacketReceived"/>, so it needs no clock of its
/// own and is fully deterministic under test.
/// </para>
/// </remarks>
public sealed class ReceiveSideBandwidthEstimator
{
    private readonly InterArrival _interArrival = new();
    private readonly TrendlineEstimator _trendline;
    private readonly OveruseDetector _detector = new();
    private readonly AimdRateController _rateController;
    private readonly AbsoluteSendTimeUnwrapper _unwrapper = new();

    private bool _hasLastUpdate;
    private long _lastUpdateArrivalMicroseconds;
    private long _windowBytes;
    private bool _hasWindowStart;
    private long _windowStartArrivalMicroseconds;

    /// <summary>Creates a receive-side estimator at its configured start bitrate.</summary>
    /// <param name="options">Bitrate clamps and filter tunables; defaults when null.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null when supplied non-null elsewhere.</exception>
    public ReceiveSideBandwidthEstimator(CongestionControllerOptions? options = null)
    {
        var effective = options ?? new CongestionControllerOptions();
        _trendline = new TrendlineEstimator(effective.TrendlineWindowSize);
        _rateController = new AimdRateController(effective);
    }

    /// <summary>The current estimated maximum receive bitrate, in bits per second.</summary>
    public long BitrateBitsPerSecond => _rateController.BitrateBitsPerSecond;

    /// <summary>The overuse detector's most recent verdict.</summary>
    public BandwidthUsage Usage => _detector.State;

    /// <summary>Whether at least one packet has been observed, so the estimate reflects real arrivals.</summary>
    public bool HasObservedTraffic { get; private set; }

    /// <summary>
    /// Records one inbound packet: unwraps its abs-send-time, groups it with recent arrivals, and — each
    /// time a group completes — feeds the delay gradient to the filter and advances the rate controller
    /// once against the elapsed arrival time.
    /// </summary>
    /// <param name="absoluteSendTime">The 24-bit abs-send-time the packet carried (low bits significant).</param>
    /// <param name="arrivalTimeMicroseconds">The packet's arrival time on the receiver's monotonic clock, in microseconds.</param>
    /// <param name="payloadSizeBytes">The packet's on-wire size, in bytes, feeding the throughput estimate.</param>
    public void OnPacketReceived(uint absoluteSendTime, long arrivalTimeMicroseconds, int payloadSizeBytes)
    {
        HasObservedTraffic = true;
        var sendMicroseconds = _unwrapper.Unwrap(absoluteSendTime);

        if (!_hasWindowStart)
        {
            _hasWindowStart = true;
            _windowStartArrivalMicroseconds = arrivalTimeMicroseconds;
        }

        _windowBytes += payloadSizeBytes;

        if (!_interArrival.ComputeDeltas(
                sendMicroseconds, arrivalTimeMicroseconds, payloadSizeBytes,
                out var sendDeltaMicroseconds, out var arrivalDeltaMicroseconds, out _))
        {
            return;
        }

        // A group completed. Its delay variation is the arrival-gap minus the send-gap; a positive value
        // means the path queue is growing. Feed the filter, then let the detector judge the smoothed trend.
        var delayVariationMs = (arrivalDeltaMicroseconds - sendDeltaMicroseconds) / 1000.0;
        var arrivalMilliseconds = arrivalTimeMicroseconds / 1000.0;
        _trendline.Add(delayVariationMs, arrivalMilliseconds);
        if (_trendline.HasEstimate)
        {
            _detector.Detect(_trendline.ModifiedTrend, arrivalMilliseconds);
        }

        // Acknowledged throughput over the arrival window bounds the AIMD ramp and floors its back-off.
        if (arrivalTimeMicroseconds > _windowStartArrivalMicroseconds)
        {
            var seconds = (arrivalTimeMicroseconds - _windowStartArrivalMicroseconds) / 1_000_000.0;
            _rateController.SetThroughputEstimate((long)(_windowBytes * 8 / seconds));
        }

        _windowBytes = 0;
        _windowStartArrivalMicroseconds = arrivalTimeMicroseconds;

        var elapsed = _hasLastUpdate
            ? TimeSpan.FromMicroseconds(Math.Max(0, arrivalTimeMicroseconds - _lastUpdateArrivalMicroseconds))
            : TimeSpan.Zero;
        _hasLastUpdate = true;
        _lastUpdateArrivalMicroseconds = arrivalTimeMicroseconds;
        _rateController.Update(_detector.State, elapsed);
    }
}
