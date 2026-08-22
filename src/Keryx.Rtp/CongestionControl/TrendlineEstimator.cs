namespace Keryx.Rtp.CongestionControl;

/// <summary>
/// The delay-gradient filter of draft-ietf-rmcat-gcc-02 §5.3 (WebRTC's trendline estimator): it
/// accumulates the one-way delay variation of successive packet groups and fits a line to the
/// smoothed accumulated delay over a sliding window. The slope of that line, scaled, is the trend the
/// <see cref="OveruseDetector"/> compares against its threshold.
/// </summary>
public sealed class TrendlineEstimator
{
    private const double SmoothingCoefficient = 0.9;
    private const double ThresholdGain = 4.0;
    private const int MaxScaledSamples = 60;

    private readonly int _windowSize;
    private readonly Queue<(double Time, double SmoothedDelay)> _window = new();

    private double _accumulatedDelay;
    private double _smoothedDelay;
    private bool _hasFirstArrival;
    private double _firstArrivalMilliseconds;

    /// <summary>Creates a trendline estimator.</summary>
    /// <param name="windowSize">Number of samples fitted per line; must be at least two.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="windowSize"/> is less than two.</exception>
    public TrendlineEstimator(int windowSize)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(windowSize, 2);
        _windowSize = windowSize;
    }

    /// <summary>
    /// The most recent scaled trend: the fitted slope multiplied by the sample count (capped) and the
    /// threshold gain. Positive means growing delay. Zero until the window has filled.
    /// </summary>
    public double ModifiedTrend { get; private set; }

    /// <summary>Whether the window has filled and <see cref="ModifiedTrend"/> is meaningful.</summary>
    public bool HasEstimate { get; private set; }

    /// <summary>
    /// Feeds one packet group's delay variation into the filter.
    /// </summary>
    /// <param name="delayVariationMilliseconds">
    /// The change in one-way delay for this group versus the previous one, in milliseconds:
    /// <c>(arrival_i - arrival_{i-1}) - (send_i - send_{i-1})</c>.
    /// </param>
    /// <param name="arrivalTimeMilliseconds">The group's arrival time on the receiver clock, in milliseconds.</param>
    public void Add(double delayVariationMilliseconds, double arrivalTimeMilliseconds)
    {
        if (!_hasFirstArrival)
        {
            _hasFirstArrival = true;
            _firstArrivalMilliseconds = arrivalTimeMilliseconds;
        }

        _accumulatedDelay += delayVariationMilliseconds;
        _smoothedDelay = (SmoothingCoefficient * _smoothedDelay)
            + ((1.0 - SmoothingCoefficient) * _accumulatedDelay);

        _window.Enqueue((arrivalTimeMilliseconds - _firstArrivalMilliseconds, _smoothedDelay));
        while (_window.Count > _windowSize)
        {
            _window.Dequeue();
        }

        if (_window.Count < _windowSize)
        {
            return;
        }

        var slope = LinearFitSlope();
        HasEstimate = true;
        ModifiedTrend = Math.Min(_window.Count, MaxScaledSamples) * slope * ThresholdGain;
    }

    private double LinearFitSlope()
    {
        double sumTime = 0;
        double sumDelay = 0;
        foreach (var (time, delay) in _window)
        {
            sumTime += time;
            sumDelay += delay;
        }

        var averageTime = sumTime / _window.Count;
        var averageDelay = sumDelay / _window.Count;

        double numerator = 0;
        double denominator = 0;
        foreach (var (time, delay) in _window)
        {
            var dt = time - averageTime;
            numerator += dt * (delay - averageDelay);
            denominator += dt * dt;
        }

        return denominator == 0 ? 0 : numerator / denominator;
    }
}
