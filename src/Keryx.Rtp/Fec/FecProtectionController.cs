namespace Keryx.Rtp.Fec;

/// <summary>
/// Chooses the FEC protection group size from the loss the peer reports, with an immediate tightening
/// and a slow, count-based relaxation.
/// </summary>
/// <remarks>
/// <para>
/// A single XOR repair packet rebuilds one loss per group, so the group is the trade-off knob between
/// repair overhead and recoverable loss: a group of <c>N</c> spends one repair packet per <c>N</c> media
/// packets, and a smaller group can repair a higher loss rate. As reported loss rises the group
/// therefore shrinks. Tightening is immediate — unprotected loss is already visible on the wire and
/// every report that confirms it should buy protection at once. Relaxing is slow and stepwise: the loss
/// has to sit a fifth below a threshold before that threshold is crossed downward (hysteresis), and a
/// run of <see cref="FecProtectionOptions.RelaxAfterReports"/> calm reports buys exactly one step. That
/// stops a path hovering on a threshold from flapping and keeps the overhead fraction an encoder reads
/// stable.
/// </para>
/// <para>
/// The controller counts reports, not time, so it is deterministic under any clock. It is
/// <b>not thread-safe</b>: drive one instance from a single caller, the RTCP receive loop. The send path
/// reads the group size the owner publishes through a volatile write, never this object directly.
/// </para>
/// </remarks>
public sealed class FecProtectionController
{
    private readonly bool _adaptive;
    private readonly int _minGroupSize;
    private readonly int _maxGroupSize;
    private readonly int _relaxAfterReports;

    // The tier ladder with the configured bounds applied: distinct, ascending candidate group sizes
    // the calm path may step through. A relaxation moves to the next entry above the current size.
    private readonly int[] _ladder;

    private int _groupSize;
    private double _smoothedLoss;
    private int _calmReports;
    private bool _hasSample;

    /// <summary>Creates a controller from <paramref name="options"/>, or the defaults when null.</summary>
    /// <param name="options">The group-size bounds and adaptation settings; copied, not retained.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// The bounds are not ordered <c>1 &lt;= MinGroupSize &lt;= InitialGroupSize &lt;= MaxGroupSize &lt;=
    /// <see cref="FecProtectionOptions.MaxSupportedGroupSize"/></c>, or
    /// <see cref="FecProtectionOptions.RelaxAfterReports"/> is less than one.
    /// </exception>
    public FecProtectionController(FecProtectionOptions? options = null)
    {
        options ??= new FecProtectionOptions();

        if (options.MinGroupSize < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options), options.MinGroupSize, "MinGroupSize must be at least one.");
        }

        if (options.MinGroupSize > options.InitialGroupSize)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options), options.MinGroupSize, "MinGroupSize must not exceed InitialGroupSize.");
        }

        if (options.InitialGroupSize > options.MaxGroupSize)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options), options.InitialGroupSize, "InitialGroupSize must not exceed MaxGroupSize.");
        }

        if (options.MaxGroupSize > FecProtectionOptions.MaxSupportedGroupSize)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options),
                options.MaxGroupSize,
                $"MaxGroupSize must not exceed {FecProtectionOptions.MaxSupportedGroupSize}.");
        }

        if (options.RelaxAfterReports < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options), options.RelaxAfterReports, "RelaxAfterReports must be at least one.");
        }

        // Copy the values: later mutation of the caller's options object must not affect behaviour.
        _adaptive = options.AdaptiveGroupSize;
        _minGroupSize = options.MinGroupSize;
        _maxGroupSize = options.MaxGroupSize;
        _relaxAfterReports = options.RelaxAfterReports;
        _groupSize = options.InitialGroupSize;
        _ladder = BuildLadder(_minGroupSize, _maxGroupSize);
    }

    /// <summary>The current protection group size: media packets per repair packet.</summary>
    public int GroupSize => _groupSize;

    /// <summary>The smoothed loss fraction, 0 until the first report arrives.</summary>
    public double SmoothedLoss => _smoothedLoss;

    /// <summary>
    /// The nominal share of all sent packets that are repair packets at the current group size,
    /// <c>1 / (GroupSize + 1)</c>.
    /// </summary>
    public double OverheadFraction => 1.0 / (_groupSize + 1);

    /// <summary>
    /// Folds one reception report's loss fraction into the smoothed estimate and moves the group size
    /// if the loss regime warrants it.
    /// </summary>
    /// <param name="fractionLost">
    /// The report's lost-packet fraction, nominally 0 to 1. NaN is ignored; other values are clamped to
    /// [0, 1].
    /// </param>
    /// <returns><see langword="true"/> when this report changed <see cref="GroupSize"/>.</returns>
    public bool OnReportedLoss(double fractionLost)
    {
        if (double.IsNaN(fractionLost))
        {
            return false;
        }

        var sample = Math.Clamp(fractionLost, 0.0, 1.0);

        // Exponential smoothing with a fast attack and a slow decay: a sudden loss burst is reflected
        // at once, while a path that clears is not declared calm after one lucky report.
        if (!_hasSample)
        {
            _hasSample = true;
            _smoothedLoss = sample;
        }
        else
        {
            var alpha = sample > _smoothedLoss ? 0.5 : 0.125;
            _smoothedLoss += alpha * (sample - _smoothedLoss);
        }

        if (!_adaptive)
        {
            return false;
        }

        var target = Tier(_smoothedLoss);
        if (target < _groupSize)
        {
            // More protection is needed and the loss is already measured: tighten immediately.
            _groupSize = target;
            _calmReports = 0;
            return true;
        }

        // Relaxing requires the loss to sit comfortably below the current tier's threshold: multiplying
        // by 1.25 moves the sample toward the next-higher threshold, so the result only exceeds the
        // current size when there is a real margin. That margin is the hysteresis band.
        var relaxTarget = Tier(_smoothedLoss * 1.25);
        if (relaxTarget <= _groupSize)
        {
            _calmReports = 0;
            return false;
        }

        _calmReports++;
        if (_calmReports < _relaxAfterReports)
        {
            return false;
        }

        _calmReports = 0;
        var next = NextLargerStep(_groupSize);
        if (next == _groupSize)
        {
            return false;
        }

        _groupSize = next;
        return true;
    }

    /// <summary>Maps a loss fraction onto a candidate group size, clamped to the configured bounds.</summary>
    private int Tier(double loss)
    {
        var target = loss < 0.01
            ? _maxGroupSize
            : loss < 0.03
                ? 10
                : loss < 0.06
                    ? 6
                    : loss < 0.10
                        ? 4
                        : 3;

        return Math.Clamp(target, _minGroupSize, _maxGroupSize);
    }

    /// <summary>The smallest ladder step strictly larger than <paramref name="current"/>, or the same value.</summary>
    private int NextLargerStep(int current)
    {
        foreach (var step in _ladder)
        {
            if (step > current)
            {
                return step;
            }
        }

        return current;
    }

    /// <summary>
    /// Builds the ascending, de-duplicated tier ladder <c>{3, 4, 6, 10, MaxGroupSize}</c> after
    /// clamping each step to the configured bounds, so a stepwise relaxation never leaves the range.
    /// </summary>
    private static int[] BuildLadder(int minGroupSize, int maxGroupSize)
    {
        Span<int> raw = [3, 4, 6, 10, maxGroupSize];
        var clamped = new List<int>(raw.Length);
        foreach (var value in raw)
        {
            var step = Math.Clamp(value, minGroupSize, maxGroupSize);
            if (!clamped.Contains(step))
            {
                clamped.Add(step);
            }
        }

        clamped.Sort();
        return [.. clamped];
    }
}
