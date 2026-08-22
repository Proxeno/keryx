using Keryx.Rtp.Rtcp;

namespace Keryx.Rtp.CongestionControl;

/// <summary>
/// The send-side Google Congestion Control estimator: it arbitrates a delay-based estimate (from
/// transport-cc feedback) against a loss-based estimate (from reception reports) and a REMB cap, and
/// publishes the minimum as the target send bitrate.
/// </summary>
/// <remarks>
/// <para>
/// Feed it from the RTCP receive path and record sends through <see cref="OnPacketSent"/>. It is not
/// thread-safe; drive one instance from a single receive loop, one per sending transport.
/// </para>
/// <para>
/// Arbitration follows draft-ietf-rmcat-gcc-02: loss and REMB may only lower the delay-based estimate,
/// never raise it. When no transport-cc feedback has arrived within
/// <see cref="CongestionControllerOptions.RembTimeToLive"/>, the controller falls back to the
/// loss-based estimate and any live REMB value.
/// </para>
/// </remarks>
public sealed class GccCongestionController : ICongestionController
{
    private readonly CongestionControllerOptions _options;
    private readonly TimeProvider _time;
    private readonly SendTimeHistory _sendHistory;
    private readonly DelayBasedBandwidthEstimator _delayBased;
    private readonly LossBasedBandwidthEstimator _lossBased;

    private bool _hasTransportFeedback;
    private long _lastTransportTimestamp;
    private bool _hasRemb;
    private long _rembTimestamp;
    private long _rembBitrateBitsPerSecond;

    /// <summary>Creates a controller at its configured start bitrate.</summary>
    /// <param name="options">Bitrate clamps and tunables; defaults when null.</param>
    /// <param name="timeProvider">Clock for ramp scaling and TTLs; <see cref="TimeProvider.System"/> when null.</param>
    public GccCongestionController(CongestionControllerOptions? options = null, TimeProvider? timeProvider = null)
    {
        _options = options ?? new CongestionControllerOptions();
        _time = timeProvider ?? TimeProvider.System;
        _sendHistory = new SendTimeHistory();
        _delayBased = new DelayBasedBandwidthEstimator(_options, _time);
        _lossBased = new LossBasedBandwidthEstimator(_options);
        TargetBitrateBitsPerSecond = Math.Clamp(
            _options.StartBitrateBitsPerSecond,
            _options.MinBitrateBitsPerSecond,
            _options.MaxBitrateBitsPerSecond);
    }

    /// <inheritdoc />
    public event EventHandler<TargetBitrateChangedEventArgs>? TargetBitrateChanged;

    /// <inheritdoc />
    public long TargetBitrateBitsPerSecond { get; private set; }

    /// <inheritdoc />
    public void OnPacketSent(ushort transportSequenceNumber, long sendTimeMicroseconds, int payloadSizeBytes) =>
        _sendHistory.Add(transportSequenceNumber, sendTimeMicroseconds, payloadSizeBytes);

    /// <inheritdoc />
    public void OnTransportFeedback(RtcpTransportCcFeedback feedback)
    {
        ArgumentNullException.ThrowIfNull(feedback);
        _hasTransportFeedback = true;
        _lastTransportTimestamp = _time.GetTimestamp();
        _delayBased.ProcessFeedback(feedback, _sendHistory);
        Recompute();
    }

    /// <inheritdoc />
    public void OnReportedLoss(double fractionLost)
    {
        _lossBased.Update(fractionLost);
        Recompute();
    }

    /// <inheritdoc />
    public void OnReceiverEstimatedMaxBitrate(RtcpReceiverEstimatedMaxBitrate remb)
    {
        ArgumentNullException.ThrowIfNull(remb);
        _hasRemb = true;
        _rembTimestamp = _time.GetTimestamp();
        _rembBitrateBitsPerSecond = (long)Math.Min(remb.BitrateBitsPerSecond, long.MaxValue);
        Recompute();
    }

    private void Recompute()
    {
        var now = _time.GetTimestamp();
        var transportFresh = _hasTransportFeedback
            && _time.GetElapsedTime(_lastTransportTimestamp, now) <= _options.RembTimeToLive;
        var rembFresh = _hasRemb
            && _time.GetElapsedTime(_rembTimestamp, now) <= _options.RembTimeToLive;

        // Loss and REMB only ever lower the delay-based estimate, and only once they carry real data.
        var lossCap = _lossBased.HasSample ? _lossBased.BitrateBitsPerSecond : long.MaxValue;

        long target;
        if (transportFresh)
        {
            target = Math.Min(_delayBased.BitrateBitsPerSecond, lossCap);
            if (rembFresh)
            {
                target = Math.Min(target, _rembBitrateBitsPerSecond);
            }
        }
        else if (rembFresh)
        {
            // Fallback: no live transport-cc, so drive from REMB, still capped by observed loss.
            target = Math.Min(_rembBitrateBitsPerSecond, lossCap);
        }
        else if (_lossBased.HasSample)
        {
            target = _lossBased.BitrateBitsPerSecond;
        }
        else
        {
            target = _delayBased.BitrateBitsPerSecond;
        }

        target = Math.Clamp(target, _options.MinBitrateBitsPerSecond, _options.MaxBitrateBitsPerSecond);
        Publish(target);
    }

    private void Publish(long target)
    {
        var previous = TargetBitrateBitsPerSecond;
        var delta = Math.Abs(target - previous);
        if (previous > 0 && delta < previous * _options.ChangeNotificationThreshold)
        {
            return;
        }

        if (target == previous)
        {
            return;
        }

        TargetBitrateBitsPerSecond = target;
        TargetBitrateChanged?.Invoke(
            this,
            new TargetBitrateChangedEventArgs(target, _delayBased.Usage, _delayBased.ThroughputBitsPerSecond));
    }
}
