namespace Keryx.IntegrationTests;

/// <summary>
/// A <see cref="TimeProvider"/> with a manually advanced clock and hand-fired timers, so a drain can
/// be driven synchronously and deterministically rather than waiting on the thread pool. Shared by
/// <see cref="PacedRtpSenderDrainTests"/> and <see cref="OutboundAudioCutTests"/>.
/// </summary>
internal sealed class FakeTimerTimeProvider : TimeProvider
{
    private readonly List<FakeTimer> _timers = [];
    private long _timestamp;

    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    public override long GetTimestamp() => Interlocked.Read(ref _timestamp);

    public override DateTimeOffset GetUtcNow() => DateTimeOffset.UnixEpoch.AddTicks(Interlocked.Read(ref _timestamp));

    /// <summary>Advances the clock by <paramref name="delta"/>; timers are not fired until <see cref="FireDueTimers"/>.</summary>
    public void Advance(TimeSpan delta) => Interlocked.Add(ref _timestamp, delta.Ticks);

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = new FakeTimer(callback, state);
        lock (_timers)
        {
            _timers.Add(timer);
        }

        timer.Change(dueTime, period);
        return timer;
    }

    /// <summary>Runs the callback of every timer that has been scheduled to fire.</summary>
    public void FireDueTimers()
    {
        FakeTimer[] snapshot;
        lock (_timers)
        {
            snapshot = [.. _timers];
        }

        foreach (var timer in snapshot)
        {
            timer.FireIfDue();
        }
    }

    private sealed class FakeTimer(TimerCallback callback, object? state) : ITimer
    {
        private bool _due;
        private bool _disposed;

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            if (_disposed)
            {
                return false;
            }

            _due = dueTime != Timeout.InfiniteTimeSpan;
            return true;
        }

        public void FireIfDue()
        {
            if (_disposed || !_due)
            {
                return;
            }

            _due = false;
            callback(state);
        }

        public void Dispose()
        {
            _disposed = true;
            _due = false;
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
