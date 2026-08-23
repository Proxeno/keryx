using System.Collections.Concurrent;
using FluentAssertions;
using Keryx.Core;
using Keryx.Rtp.CongestionControl;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// Regression coverage for <see cref="PeerConnection.PacedRtpSender"/>'s drain loop (EWI-1346): a send
/// that throws — most sharply the SRTP index guard refusing a reused index — must not escape the timer
/// callback and crash the host. The drain must drop the offending packet, keep draining the rest, and
/// remain usable for later packets.
/// </summary>
public class PacedRtpSenderDrainTests
{
    [Fact]
    public void AThrowingSendDoesNotCrashTheDrainAndItKeepsDrainingTheRest()
    {
        var time = new FakeTimerTimeProvider();
        // A generous budget so every enqueued packet is admitted in a single drain pass.
        var pacer = new PacketPacer(100_000_000, time);
        var logger = new RecordingLogger();

        var sent = new ConcurrentQueue<int>();
        var calls = 0;
        void Send(byte[] buffer, int length)
        {
            // The first send throws, exactly as SrtpSendStreamState.NextRolloverCounter does on a
            // reused index; the rest must still go out.
            if (Interlocked.Increment(ref calls) == 1)
            {
                throw new InvalidOperationException("SRTP packet index reused (simulated).");
            }

            sent.Enqueue(length);
        }

        using var sender = new PeerConnection.PacedRtpSender(pacer, time, srtpOverhead: 0, Send, logger);

        // Fill the leaky bucket, then enqueue two packets so both land in one drain batch: the first
        // send throws and the second must still be delivered.
        time.Advance(TimeSpan.FromSeconds(1));
        sender.Enqueue(new byte[100]);
        sender.Enqueue(new byte[120]);

        // Firing the (deterministic) timer runs the drain synchronously. If the throw escaped the
        // callback this call itself would surface it — the process-crash the fix prevents.
        var act = time.FireDueTimers;
        act.Should().NotThrow("no exception may escape the paced drain's timer callback");

        sent.Should().ContainSingle().Which.Should().Be(120, "the packet after the throwing one is still drained");
        logger.Warnings.Should().ContainSingle().Which.Should().Contain("Dropping a paced RTP packet");

        // The sender must still work after absorbing the failure.
        time.Advance(TimeSpan.FromSeconds(1));
        sender.Enqueue(new byte[140]);
        time.FireDueTimers();

        sent.Should().BeEquivalentTo([120, 140], options => options.WithStrictOrdering());
    }

    /// <summary>A recording <see cref="IKeryxLogger"/> that captures warning-level messages.</summary>
    private sealed class RecordingLogger : IKeryxLogger
    {
        public ConcurrentQueue<string> Warnings { get; } = new();

        public bool IsEnabled(KeryxLogLevel level) => true;

        public void Log(KeryxLogLevel level, string message, Exception? exception = null)
        {
            if (level == KeryxLogLevel.Warning)
            {
                Warnings.Enqueue(message);
            }
        }
    }

    /// <summary>
    /// A <see cref="TimeProvider"/> with a manually advanced clock and hand-fired timers, so the drain
    /// can be driven synchronously and deterministically rather than waiting on the thread pool.
    /// </summary>
    private sealed class FakeTimerTimeProvider : TimeProvider
    {
        private readonly List<FakeTimer> _timers = [];
        private long _timestamp;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public override long GetTimestamp() => Interlocked.Read(ref _timestamp);

        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UnixEpoch.AddTicks(Interlocked.Read(ref _timestamp));

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
}
