using Keryx.Rtp.CongestionControl;

namespace Keryx.Rtp.Rtcp;

/// <summary>
/// The receive-side driver behind <see cref="RtcpReceiverEstimatedMaxBitrate"/> (REMB): it feeds every
/// inbound packet's absolute send time and arrival time into a <see cref="ReceiveSideBandwidthEstimator"/>
/// and, on a feedback cadence, builds the REMB packet that reports the estimate — and the SSRCs it covers
/// — back to the sender's congestion controller.
/// </summary>
/// <remarks>
/// <para>
/// This is the abs-send-time counterpart to <see cref="TransportCcFeedbackGenerator"/>. Where transport-cc
/// feedback ships raw per-packet arrival deltas for a send-side estimator to interpret, REMB ships the
/// receiver's already-computed bitrate estimate, so the estimator lives here rather than at the sender.
/// </para>
/// <para>
/// It owns no clock and no synchronisation: drive it from a single receive loop, passing arrival times on
/// the same monotonic microsecond clock throughout. A feedback packet is due once the interval has elapsed
/// since the last one <em>and</em> an early significant drop in the estimate has not already forced one,
/// mirroring how libwebrtc emits REMB roughly once per second but immediately on a downward correction.
/// </para>
/// </remarks>
public sealed class RembFeedbackGenerator
{
    /// <summary>Default feedback cadence: report the estimate at most this long apart while traffic flows.</summary>
    public static readonly TimeSpan DefaultFeedbackInterval = TimeSpan.FromMilliseconds(1000);

    /// <summary>
    /// A drop of at least this fraction below the last reported estimate forces an immediate REMB rather
    /// than waiting out the interval, so the sender learns of congestion promptly (libwebrtc's 3% trigger).
    /// </summary>
    private const double SignificantDropFraction = 0.03;

    private readonly ReceiveSideBandwidthEstimator _estimator;
    private readonly long _feedbackIntervalMicroseconds;
    private readonly List<uint> _ssrcs = [];
    private readonly HashSet<uint> _ssrcSet = [];

    private bool _hasArrival;
    private long _lastArrivalMicroseconds;
    private bool _hasReported;
    private long _lastFeedbackMicroseconds;
    private long _lastReportedBitrate;

    /// <summary>Creates a generator with the default cadence and estimator options.</summary>
    public RembFeedbackGenerator()
        : this(DefaultFeedbackInterval, null)
    {
    }

    /// <summary>Creates a generator.</summary>
    /// <param name="feedbackInterval">How long apart REMB packets are emitted while traffic flows; must be positive.</param>
    /// <param name="options">Bitrate clamps and filter tunables for the receive-side estimator; defaults when null.</param>
    /// <exception cref="ArgumentOutOfRangeException">The interval is not positive.</exception>
    public RembFeedbackGenerator(TimeSpan feedbackInterval, CongestionControllerOptions? options)
    {
        if (feedbackInterval <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(feedbackInterval), feedbackInterval, "The feedback interval must be positive.");
        }

        _feedbackIntervalMicroseconds = (long)(feedbackInterval.TotalMilliseconds * 1000.0);
        _estimator = new ReceiveSideBandwidthEstimator(options);
    }

    /// <summary>The current estimated maximum receive bitrate, in bits per second.</summary>
    public long EstimatedBitrateBitsPerSecond => _estimator.BitrateBitsPerSecond;

    /// <summary>Whether any inbound packet carrying abs-send-time has been recorded.</summary>
    public bool HasObservedTraffic => _estimator.HasObservedTraffic;

    /// <summary>
    /// Records one inbound packet's abs-send-time, arrival time and size against the estimator, and notes
    /// its SSRC so the emitted REMB names the streams it covers.
    /// </summary>
    /// <param name="absoluteSendTime">The 24-bit abs-send-time the packet carried.</param>
    /// <param name="arrivalTimeMicroseconds">Its arrival time on the receiver's monotonic clock, in microseconds.</param>
    /// <param name="payloadSizeBytes">The packet's on-wire size, in bytes.</param>
    /// <param name="ssrc">The media source SSRC the packet was sent on.</param>
    public void OnPacketReceived(uint absoluteSendTime, long arrivalTimeMicroseconds, int payloadSizeBytes, uint ssrc)
    {
        var firstArrival = !_hasArrival;
        _estimator.OnPacketReceived(absoluteSendTime, arrivalTimeMicroseconds, payloadSizeBytes);
        _hasArrival = true;
        _lastArrivalMicroseconds = arrivalTimeMicroseconds;
        if (_ssrcSet.Add(ssrc))
        {
            _ssrcs.Add(ssrc);
        }

        // Anchor the first feedback deadline to the very first arrival, so the initial REMB fires one
        // interval in rather than immediately on the first packet.
        if (firstArrival)
        {
            _lastFeedbackMicroseconds = arrivalTimeMicroseconds;
        }
    }

    /// <summary>
    /// Whether a REMB packet is due: traffic has been observed and either the feedback interval has elapsed
    /// since the last report or the estimate has dropped significantly since it.
    /// </summary>
    /// <param name="nowMicroseconds">The current time on the same monotonic clock arrivals are stamped with.</param>
    public bool ShouldBuildFeedback(long nowMicroseconds)
    {
        if (_ssrcs.Count == 0 || !_estimator.HasObservedTraffic)
        {
            return false;
        }

        var estimate = _estimator.BitrateBitsPerSecond;
        if (_hasReported
            && _lastReportedBitrate > 0
            && estimate < _lastReportedBitrate * (1.0 - SignificantDropFraction))
        {
            return true;
        }

        // _lastFeedbackMicroseconds is anchored to the first arrival and advanced on each build, so it is
        // always the instant the current interval is measured from.
        return nowMicroseconds - _lastFeedbackMicroseconds >= _feedbackIntervalMicroseconds;
    }

    /// <summary>
    /// Builds the REMB packet reporting the current estimate over every observed SSRC, and rolls the
    /// feedback deadline forward. The estimate is always a valid, clamped bitrate, so the packet is
    /// well-formed from the first report.
    /// </summary>
    /// <param name="senderSsrc">The SSRC to stamp as the feedback sender (the receiver's own).</param>
    /// <param name="remb">On success, the built REMB packet; otherwise null.</param>
    /// <returns><see langword="false"/> when no SSRC has been observed yet.</returns>
    public bool TryBuildFeedback(uint senderSsrc, out RtcpReceiverEstimatedMaxBitrate? remb)
    {
        if (_ssrcs.Count == 0)
        {
            remb = null;
            return false;
        }

        var estimate = _estimator.BitrateBitsPerSecond;
        remb = new RtcpReceiverEstimatedMaxBitrate(senderSsrc, (ulong)Math.Max(0, estimate), [.. _ssrcs]);

        _hasReported = true;
        _lastReportedBitrate = estimate;
        _lastFeedbackMicroseconds = _hasArrival ? _lastArrivalMicroseconds : _lastFeedbackMicroseconds;
        return true;
    }
}
