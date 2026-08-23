using Keryx.Rtp.Rtcp;

namespace Keryx.Rtp.CongestionControl;

/// <summary>
/// The delay-based half of the send-side estimator (draft-ietf-rmcat-gcc-02 §5). It pairs the arrival
/// times reported by transport-cc feedback with the local send times of the same packets to recover
/// one-way delay variation, runs that through a <see cref="TrendlineEstimator"/> and an
/// <see cref="OveruseDetector"/>, and drives an <see cref="AimdRateController"/> to a target bitrate.
/// </summary>
public sealed class DelayBasedBandwidthEstimator
{
    private readonly TimeProvider _time;
    private readonly InterArrival _interArrival = new();
    private readonly TrendlineEstimator _trendline;
    private readonly OveruseDetector _detector = new();
    private readonly AimdRateController _rateController;

    private bool _hasLastUpdate;
    private long _lastUpdateTimestamp;

    /// <summary>Creates a delay-based estimator.</summary>
    /// <param name="options">Bitrate clamps and filter tunables.</param>
    /// <param name="timeProvider">Clock used to scale the ramp; <see cref="TimeProvider.System"/> when null.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    public DelayBasedBandwidthEstimator(CongestionControllerOptions options, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        _time = timeProvider ?? TimeProvider.System;
        _trendline = new TrendlineEstimator(options.TrendlineWindowSize);
        _rateController = new AimdRateController(options);
    }

    /// <summary>The current delay-based target bitrate, in bits per second.</summary>
    public long BitrateBitsPerSecond => _rateController.BitrateBitsPerSecond;

    /// <summary>The overuse detector's most recent verdict.</summary>
    public BandwidthUsage Usage => _detector.State;

    /// <summary>The most recent acknowledged-throughput estimate, in bits per second; zero until measured.</summary>
    public long ThroughputBitsPerSecond { get; private set; }

    /// <summary>
    /// Processes one transport-cc feedback packet: groups the received packets into ~5 ms inter-arrival
    /// bursts, feeds each completed group's delay variation to the filter, updates the throughput
    /// estimate, and advances the rate controller once.
    /// </summary>
    /// <param name="feedback">The parsed feedback packet, arrival times reconstructed.</param>
    /// <param name="sendHistory">The send-time table populated by the send path.</param>
    /// <exception cref="ArgumentNullException"><paramref name="feedback"/> or <paramref name="sendHistory"/> is null.</exception>
    public void ProcessFeedback(RtcpTransportCcFeedback feedback, SendTimeHistory sendHistory)
    {
        ArgumentNullException.ThrowIfNull(feedback);
        ArgumentNullException.ThrowIfNull(sendHistory);

        long receivedBytes = 0;
        var hasSpan = false;
        long firstArrival = 0;
        long lastArrival = 0;

        foreach (var status in feedback.PacketStatuses)
        {
            if (!status.Received
                || !sendHistory.TryGet(status.SequenceNumber, out var sendMicroseconds, out var sizeBytes))
            {
                continue;
            }

            var arrivalMicroseconds = status.ArrivalTimeMicroseconds;
            receivedBytes += sizeBytes;
            if (!hasSpan)
            {
                hasSpan = true;
                firstArrival = arrivalMicroseconds;
            }

            lastArrival = arrivalMicroseconds;

            // Group packets into ~5 ms bursts; only feed the filter when a group completes, using the
            // delay variation measured between consecutive completed groups.
            if (_interArrival.ComputeDeltas(
                    sendMicroseconds, arrivalMicroseconds, sizeBytes,
                    out var sendDeltaMicroseconds, out var arrivalDeltaMicroseconds, out _))
            {
                var delayVariationMs = (arrivalDeltaMicroseconds - sendDeltaMicroseconds) / 1000.0;
                var arrivalMilliseconds = arrivalMicroseconds / 1000.0;
                _trendline.Add(delayVariationMs, arrivalMilliseconds);
                if (_trendline.HasEstimate)
                {
                    _detector.Detect(_trendline.ModifiedTrend, arrivalMilliseconds);
                }
            }
        }

        if (hasSpan && lastArrival > firstArrival)
        {
            var seconds = (lastArrival - firstArrival) / 1_000_000.0;
            ThroughputBitsPerSecond = (long)(receivedBytes * 8 / seconds);
            _rateController.SetThroughputEstimate(ThroughputBitsPerSecond);
        }

        var now = _time.GetTimestamp();
        var elapsed = _hasLastUpdate ? _time.GetElapsedTime(_lastUpdateTimestamp, now) : TimeSpan.Zero;
        _hasLastUpdate = true;
        _lastUpdateTimestamp = now;

        _rateController.Update(_detector.State, elapsed);
    }
}
