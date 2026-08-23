namespace Keryx.Rtp.Rtcp;

/// <summary>Policy limits applied to receiver-driven NACK generation.</summary>
/// <remarks>
/// These bound how hard the receiver asks for a lost packet back, so a burst of loss cannot turn into a
/// burst of NACKs and a packet that has already fallen out of the sender's retransmission window is not
/// asked for at all.
/// </remarks>
public sealed class ReceiverNackOptions
{
    /// <summary>
    /// Smallest interval between two NACKs for the same missing sequence number. A receiver keeps asking
    /// until the packet arrives (RFC 4585 §3.1), so without this a single loss would be re-NACKed on
    /// every subsequent arrival for a whole round trip. 20 ms is below a wide-area round trip and above a
    /// local one, so a lost packet is asked for again roughly once per round trip rather than continuously.
    /// </summary>
    public TimeSpan RetryInterval { get; set; } = TimeSpan.FromMilliseconds(20);

    /// <summary>
    /// Largest number of NACKs sent for one missing sequence number before it is abandoned. Bounds the
    /// cost of a permanently lost packet — one the sender can no longer repair — to a fixed, small number
    /// of feedback packets rather than a NACK on every arrival forever.
    /// </summary>
    public int MaxRetries { get; set; } = 8;

    /// <summary>
    /// A missing sequence number more than this far behind the highest received is abandoned: it has
    /// fallen out of the sender's retransmission window and can no longer be repaired, so continuing to
    /// NACK it only wastes uplink. Also caps how large a forward jump is treated as recoverable loss
    /// rather than a source discontinuity. Defaults to 512, mirroring the default send-history capacity.
    /// </summary>
    public int MaxNackDistance { get; set; } = 512;
}

/// <summary>
/// A per-source inbound loss detector that turns gaps in an arriving RTP sequence stream into the set of
/// sequence numbers a receiver should NACK, rate-limited and bounded to a recovery window so that a
/// remote sender's RFC 4588 retransmission can repair the loss.
/// </summary>
/// <remarks>
/// One instance tracks one media SSRC. It is not thread-safe: <see cref="OnPacket"/>,
/// <see cref="OnRecovered"/> and any reads must be serialised by the caller, exactly like
/// <see cref="ReceptionStatistics"/>, with which it shares the receive path's lock. It holds no timer and
/// sends nothing itself: it is driven off arriving packets and hands the caller the sequence numbers that
/// are due, which the caller emits through its own NACK path.
/// </remarks>
public sealed class ReceiverNackTracker
{
    private readonly ReceiverNackOptions _options;
    private readonly long _retryIntervalMilliseconds;
    private readonly Dictionary<ushort, MissingPacket> _missing = [];
    private readonly List<ushort> _scan = [];
    private bool _initialized;
    private ushort _highest;

    /// <summary>Creates a tracker.</summary>
    /// <param name="options">The rate and window limits to apply.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is <see langword="null"/>.</exception>
    public ReceiverNackTracker(ReceiverNackOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
        _retryIntervalMilliseconds = (long)Math.Max(0, options.RetryInterval.TotalMilliseconds);
    }

    /// <summary>The number of sequence numbers currently believed missing and still inside the window.</summary>
    public int OutstandingCount => _missing.Count;

    /// <summary>
    /// Folds one arriving media sequence number into the detector and appends every sequence number that
    /// is due for a NACK now — the freshly detected gaps and any earlier miss whose retry interval has
    /// elapsed — to <paramref name="due"/>.
    /// </summary>
    /// <param name="sequenceNumber">The arriving packet's RTP sequence number.</param>
    /// <param name="nowMilliseconds">A monotonic clock reading in milliseconds, for the retry interval.</param>
    /// <param name="due">The list the due sequence numbers are appended to; never cleared by this method.</param>
    /// <exception cref="ArgumentNullException"><paramref name="due"/> is <see langword="null"/>.</exception>
    public void OnPacket(ushort sequenceNumber, long nowMilliseconds, List<ushort> due)
    {
        ArgumentNullException.ThrowIfNull(due);

        if (!_initialized)
        {
            _initialized = true;
            _highest = sequenceNumber;
            return;
        }

        var delta = (short)(sequenceNumber - _highest);
        if (delta > 0)
        {
            if (delta - 1 <= _options.MaxNackDistance)
            {
                // Every sequence number strictly between the old highest and this one is newly missing.
                for (var s = (ushort)(_highest + 1); s != sequenceNumber; s = (ushort)(s + 1))
                {
                    _missing[s] = default;
                }
            }
            else
            {
                // A forward jump larger than the recovery window is a source restart or a long outage,
                // not repairable loss: abandon the outstanding misses rather than enumerating a gap of
                // tens of thousands of unrecoverable sequence numbers.
                _missing.Clear();
            }

            _highest = sequenceNumber;
        }
        else if (delta < 0)
        {
            // A late, reordered or retransmitted packet filled a gap: it is recovered, so never NACK it.
            // A duplicate of an already-received packet is simply absent from the set — nothing to do.
            _missing.Remove(sequenceNumber);
        }

        // delta == 0 is a duplicate of the highest; it changes nothing.
        if (_missing.Count != 0)
        {
            ScheduleDue(nowMilliseconds, due);
        }
    }

    /// <summary>
    /// Marks a sequence number recovered — for a repair that arrives on a different stream than the media
    /// SSRC, such as an RFC 4588 RTX packet whose original sequence number this reconstructs — so it is
    /// removed from the missing set and not NACKed again.
    /// </summary>
    /// <param name="sequenceNumber">The original media sequence number that has now been recovered.</param>
    public void OnRecovered(ushort sequenceNumber) => _missing.Remove(sequenceNumber);

    private void ScheduleDue(long nowMilliseconds, List<ushort> due)
    {
        // Snapshot the keys so entries can be removed while scanning. The set is empty on the common
        // no-loss path, so this only allocates and runs while loss is actually outstanding.
        _scan.Clear();
        _scan.AddRange(_missing.Keys);

        foreach (var sequenceNumber in _scan)
        {
            var distance = (ushort)(_highest - sequenceNumber);
            if (distance > _options.MaxNackDistance)
            {
                // Fell out of the recovery window while waiting; the sender can no longer repair it.
                _missing.Remove(sequenceNumber);
                continue;
            }

            var entry = _missing[sequenceNumber];
            if (entry.Retries >= _options.MaxRetries)
            {
                // Asked the agreed number of times without recovery; give up rather than NACK forever.
                _missing.Remove(sequenceNumber);
                continue;
            }

            if (entry.Retries == 0 || nowMilliseconds - entry.LastNackMilliseconds >= _retryIntervalMilliseconds)
            {
                due.Add(sequenceNumber);
                _missing[sequenceNumber] = new MissingPacket(entry.Retries + 1, nowMilliseconds);
            }
        }
    }

    private readonly record struct MissingPacket(int Retries, long LastNackMilliseconds);
}
