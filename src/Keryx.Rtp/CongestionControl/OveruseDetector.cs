namespace Keryx.Rtp.CongestionControl;

/// <summary>
/// The overuse detector of draft-ietf-rmcat-gcc-02 §5.4: it compares the trendline estimate against a
/// threshold that adapts to the observed noise, and reports whether the forward path is
/// <see cref="BandwidthUsage.Overusing"/>, <see cref="BandwidthUsage.Underusing"/>, or
/// <see cref="BandwidthUsage.Normal"/>. Overuse is only declared once the trend has stayed over the
/// threshold for a minimum time, so a single spike does not trip it.
/// </summary>
public sealed class OveruseDetector
{
    private const double OverusingTimeThresholdMilliseconds = 10.0;
    private const double MinThreshold = 6.0;
    private const double MaxThreshold = 600.0;
    private const double KUp = 0.0087;
    private const double KDown = 0.039;
    private const double MaxAdaptTimeMilliseconds = 100.0;

    private double _threshold = 12.5;
    private double _timeOverUsing = -1.0;
    private int _overuseCounter;
    private bool _hasLastUpdate;
    private double _lastUpdateMilliseconds;

    /// <summary>The detector's most recent verdict.</summary>
    public BandwidthUsage State { get; private set; } = BandwidthUsage.Normal;

    /// <summary>The current adaptive threshold the trend is compared against.</summary>
    public double Threshold => _threshold;

    /// <summary>
    /// Feeds one scaled trend value and returns the updated state.
    /// </summary>
    /// <param name="modifiedTrend">The <see cref="TrendlineEstimator.ModifiedTrend"/>.</param>
    /// <param name="nowMilliseconds">The current time on the receiver clock, in milliseconds.</param>
    /// <returns>The verdict after this sample.</returns>
    public BandwidthUsage Detect(double modifiedTrend, double nowMilliseconds)
    {
        if (modifiedTrend > _threshold)
        {
            if (_timeOverUsing < 0)
            {
                _timeOverUsing = 0;
            }
            else if (_hasLastUpdate)
            {
                _timeOverUsing += nowMilliseconds - _lastUpdateMilliseconds;
            }

            _overuseCounter++;
            if (_timeOverUsing > OverusingTimeThresholdMilliseconds && _overuseCounter > 1)
            {
                _timeOverUsing = 0;
                _overuseCounter = 0;
                State = BandwidthUsage.Overusing;
            }
        }
        else if (modifiedTrend < -_threshold)
        {
            _timeOverUsing = -1;
            _overuseCounter = 0;
            State = BandwidthUsage.Underusing;
        }
        else
        {
            _timeOverUsing = -1;
            _overuseCounter = 0;
            State = BandwidthUsage.Normal;
        }

        UpdateThreshold(modifiedTrend, nowMilliseconds);
        return State;
    }

    private void UpdateThreshold(double modifiedTrend, double nowMilliseconds)
    {
        var magnitude = Math.Abs(modifiedTrend);
        if (magnitude > _threshold + 15.0)
        {
            _hasLastUpdate = true;
            _lastUpdateMilliseconds = nowMilliseconds;
            return;
        }

        var elapsed = _hasLastUpdate ? nowMilliseconds - _lastUpdateMilliseconds : 0.0;
        elapsed = Math.Min(elapsed, MaxAdaptTimeMilliseconds);
        var k = magnitude < _threshold ? KDown : KUp;
        _threshold += k * (magnitude - _threshold) * elapsed;
        _threshold = Math.Clamp(_threshold, MinThreshold, MaxThreshold);
        _hasLastUpdate = true;
        _lastUpdateMilliseconds = nowMilliseconds;
    }
}
