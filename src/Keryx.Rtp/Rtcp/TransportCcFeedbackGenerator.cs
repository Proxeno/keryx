namespace Keryx.Rtp.Rtcp;

/// <summary>
/// The receive-side counterpart to <see cref="RtcpTransportCcFeedback"/>: it records the arrival of
/// every transport-wide sequence number the peer stamped (<c>draft-holmer-rmcat-transport-wide-cc-extensions-01</c>
/// §2) and, on a feedback cadence, drives the builder to emit the transport-cc feedback the peer's
/// send-side bandwidth estimator runs on.
/// </summary>
/// <remarks>
/// <para>
/// Arrivals are held in an ascending, wrap-aware window keyed by the 16-bit transport-wide sequence
/// number unwrapped onto a monotonic 64-bit counter, so a reordered packet is filed at its true
/// position and a duplicate is ignored. A gap in that window becomes a
/// <see cref="TransportCcStatusSymbol.NotReceived"/> status, filled by
/// <see cref="RtcpTransportCcFeedback.AddPacket"/> when the window is flushed.
/// </para>
/// <para>
/// This type owns no synchronisation: it is meant to be driven from a single receive loop, exactly as
/// the RFC 3550 reception statistics and inbound loss detector are. Each flush rolls the window forward
/// — consumed arrivals are dropped and any sequence number at or below the last flushed one is refused
/// as a late reorder — and bumps the feedback packet count the draft uses to detect feedback loss.
/// </para>
/// </remarks>
public sealed class TransportCcFeedbackGenerator
{
    /// <summary>Default feedback cadence: build a feedback packet at most this long after the oldest pending arrival.</summary>
    public static readonly TimeSpan DefaultFeedbackInterval = TimeSpan.FromMilliseconds(100);

    /// <summary>Default cap on the number of received packets a single feedback packet reports on.</summary>
    public const int DefaultMaxReportedPacketsPerFeedback = 200;

    private readonly SortedDictionary<long, long> _arrivals = [];
    private readonly long _feedbackIntervalMicroseconds;
    private readonly int _maxReportedPacketsPerFeedback;

    private long? _highestUnwrapped;
    private long _lastFlushedUnwrapped = long.MinValue;
    private long _oldestPendingArrivalMicroseconds;
    private byte _feedbackPacketCount;

    /// <summary>Creates a generator with the default cadence and per-packet cap.</summary>
    public TransportCcFeedbackGenerator()
        : this(DefaultFeedbackInterval, DefaultMaxReportedPacketsPerFeedback)
    {
    }

    /// <summary>Creates a generator.</summary>
    /// <param name="feedbackInterval">
    /// How long after the oldest pending arrival a feedback packet becomes due. The draft's cadence is a
    /// few tens of milliseconds; a receiver typically flushes every 50–100 ms.
    /// </param>
    /// <param name="maxReportedPacketsPerFeedback">
    /// The most received packets one feedback packet reports on before the window is split across flushes,
    /// bounding the packet size and the receive-delta run.
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException">The interval is not positive, or the cap is below one.</exception>
    public TransportCcFeedbackGenerator(TimeSpan feedbackInterval, int maxReportedPacketsPerFeedback)
    {
        if (feedbackInterval <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(feedbackInterval), feedbackInterval, "The feedback interval must be positive.");
        }

        if (maxReportedPacketsPerFeedback < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maxReportedPacketsPerFeedback), maxReportedPacketsPerFeedback, "At least one packet must be reportable.");
        }

        _feedbackIntervalMicroseconds = (long)(feedbackInterval.TotalMilliseconds * 1000.0);
        _maxReportedPacketsPerFeedback = maxReportedPacketsPerFeedback;
    }

    /// <summary>The number of feedback packets built so far — the value stamped in the next one's count field.</summary>
    public byte FeedbackPacketCount => _feedbackPacketCount;

    /// <summary>Whether any recorded arrival is waiting to be reported.</summary>
    public bool HasPendingArrivals => _arrivals.Count > 0;

    /// <summary>
    /// Records the arrival of one transport-wide sequence number. Wrap and reordering are resolved
    /// against the window; a duplicate of a sequence number already pending, and any sequence number at
    /// or below the last flushed one, are ignored.
    /// </summary>
    /// <param name="transportSequenceNumber">The transport-wide sequence number the packet carried.</param>
    /// <param name="arrivalTimeMicroseconds">Its arrival time on the receiver's monotonic clock, in microseconds.</param>
    public void OnPacketReceived(ushort transportSequenceNumber, long arrivalTimeMicroseconds)
    {
        var unwrapped = Unwrap(transportSequenceNumber);
        if (unwrapped <= _lastFlushedUnwrapped)
        {
            // The window has already advanced past this sequence number; a feedback packet reporting it
            // was already sent, so a late reorder or duplicate of it is dropped rather than reopening a
            // closed window.
            return;
        }

        if (_arrivals.Count == 0)
        {
            _oldestPendingArrivalMicroseconds = arrivalTimeMicroseconds;
        }

        // First arrival wins for a given sequence number: a duplicate reports the same fate, and the
        // earliest arrival is the one the sender's estimator wants.
        _arrivals.TryAdd(unwrapped, arrivalTimeMicroseconds);
    }

    /// <summary>
    /// Whether a feedback packet is due: there is at least one pending arrival and either the per-packet
    /// cap has been reached or the feedback interval has elapsed since the oldest pending arrival.
    /// </summary>
    /// <param name="nowMicroseconds">The current time on the same monotonic clock arrivals are stamped with.</param>
    public bool ShouldBuildFeedback(long nowMicroseconds)
    {
        if (_arrivals.Count == 0)
        {
            return false;
        }

        return _arrivals.Count >= _maxReportedPacketsPerFeedback
            || nowMicroseconds - _oldestPendingArrivalMicroseconds >= _feedbackIntervalMicroseconds;
    }

    /// <summary>
    /// Builds the next feedback packet from the pending arrivals, rolling the window forward past every
    /// sequence number it reports on. The packet carries the base sequence number, reference time,
    /// per-packet statuses and receive deltas the builder derives from the recorded arrivals, plus the
    /// auto-incrementing feedback packet count.
    /// </summary>
    /// <param name="senderSsrc">The SSRC to stamp as the feedback sender.</param>
    /// <param name="mediaSsrc">The media source SSRC the feedback names.</param>
    /// <param name="feedback">On success, the built feedback packet; otherwise null.</param>
    /// <returns><see langword="false"/> when no arrival is pending.</returns>
    public bool TryBuildFeedback(uint senderSsrc, uint mediaSsrc, out RtcpTransportCcFeedback? feedback)
    {
        if (_arrivals.Count == 0)
        {
            feedback = null;
            return false;
        }

        var built = new RtcpTransportCcFeedback
        {
            SenderSsrc = senderSsrc,
            MediaSsrc = mediaSsrc,
            FeedbackPacketCount = _feedbackPacketCount,
        };

        var reported = 0;
        long lastConsumedUnwrapped = _lastFlushedUnwrapped;
        foreach (var (unwrapped, arrival) in _arrivals)
        {
            try
            {
                built.AddPacket((ushort)unwrapped, arrival);
            }
            catch (InvalidOperationException)
            {
                // The arrival delta overflowed the receive-delta field; end this feedback packet here and
                // leave the rest of the window to open a fresh one on the next flush.
                break;
            }

            lastConsumedUnwrapped = unwrapped;
            if (++reported >= _maxReportedPacketsPerFeedback)
            {
                break;
            }
        }

        // Nothing could be added (the very first arrival overflowed, which cannot happen since the first
        // AddPacket only fixes the reference time). Guarded so a pathological window never spins.
        if (reported == 0)
        {
            _arrivals.Remove(_arrivals.Keys.First());
            feedback = null;
            return false;
        }

        DropConsumed(lastConsumedUnwrapped);
        _lastFlushedUnwrapped = lastConsumedUnwrapped;
        _feedbackPacketCount = unchecked((byte)(_feedbackPacketCount + 1));

        if (_arrivals.Count > 0)
        {
            _oldestPendingArrivalMicroseconds = _arrivals.First().Value;
        }

        feedback = built;
        return true;
    }

    private void DropConsumed(long throughUnwrapped)
    {
        // Remove every reported sequence number. Keys are ascending, so collect the consumed prefix and
        // drop it; the remainder stays as the next window.
        var consumed = new List<long>();
        foreach (var key in _arrivals.Keys)
        {
            if (key > throughUnwrapped)
            {
                break;
            }

            consumed.Add(key);
        }

        foreach (var key in consumed)
        {
            _arrivals.Remove(key);
        }
    }

    private long Unwrap(ushort sequenceNumber)
    {
        if (_highestUnwrapped is not { } highest)
        {
            _highestUnwrapped = sequenceNumber;
            return sequenceNumber;
        }

        // A signed 16-bit difference against the low word of the highest sequence number seen resolves
        // both wrap (…FFFE, FFFF, 0000, 0001…) and reordering within half the sequence space.
        var delta = (short)(sequenceNumber - (ushort)highest);
        var unwrapped = highest + delta;
        if (unwrapped > highest)
        {
            _highestUnwrapped = unwrapped;
        }

        return unwrapped;
    }
}
