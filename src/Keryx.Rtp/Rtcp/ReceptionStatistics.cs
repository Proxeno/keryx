namespace Keryx.Rtp.Rtcp;

/// <summary>
/// Per-source reception statistics for one inbound synchronisation source, maintained exactly as the
/// reference algorithms of RFC 3550 (sequence validation A.1, loss A.3, interarrival jitter A.8)
/// prescribe, so it can produce the reception report block that source is owed (§6.4.1).
/// </summary>
/// <remarks>
/// One instance tracks one SSRC. It is not thread-safe: the receive path
/// (<see cref="OnRtpPacket"/>, <see cref="OnSenderReport"/>) and the report builder
/// (<see cref="BuildReportBlock"/>) must be serialised by the caller. <see cref="BuildReportBlock"/>
/// advances the "since the previous report" interval counters, so it is called once per emitted report.
/// </remarks>
public sealed class ReceptionStatistics
{
    /// <summary>One full turn of the 16-bit RTP sequence-number space (RFC 3550 A.1).</summary>
    private const uint SequenceModulus = 1u << 16;

    /// <summary>Largest forward jump treated as in-order rather than a source restart (RFC 3550 A.1).</summary>
    private const ushort MaxDropout = 3000;

    /// <summary>Largest backward jump treated as reordering rather than a source restart (RFC 3550 A.1).</summary>
    private const ushort MaxMisorder = 100;

    private bool _initialized;
    private ushort _maxSequenceNumber;
    private uint _cycles;
    private uint _baseSequenceNumber;
    private uint _badSequenceNumber;
    private uint _received;
    private uint _expectedPrior;
    private uint _receivedPrior;
    private int _transit;
    private uint _jitterQ4;

    private uint _lastSenderReportCompact;
    private DateTimeOffset? _lastSenderReportArrival;

    /// <summary>Total number of packets received from this source so far.</summary>
    public uint PacketsReceived => _received;

    /// <summary>
    /// Extended highest sequence number received: the accumulated cycle count in the high 16 bits and
    /// the highest sequence number seen in the current cycle in the low 16 bits (RFC 3550 §6.4.1).
    /// </summary>
    public uint ExtendedHighestSequenceNumber => _cycles + _maxSequenceNumber;

    /// <summary>
    /// Cumulative number of packets lost, clamped to the signed 24-bit range the report block carries.
    /// Duplicates and reordering can drive it negative (RFC 3550 §6.4.1).
    /// </summary>
    public int CumulativePacketsLost => Clamp24(CumulativeLostRaw);

    /// <summary>Current interarrival jitter estimate in timestamp units (RFC 3550 §6.4.1).</summary>
    public uint Jitter => _jitterQ4 >> 4;

    private long CumulativeLostRaw
    {
        get
        {
            var expected = ExtendedHighestSequenceNumber - _baseSequenceNumber + 1;
            return (long)expected - _received;
        }
    }

    /// <summary>
    /// Folds one received RTP packet into the statistics: validates its sequence number, counts it, and
    /// updates the interarrival jitter estimate.
    /// </summary>
    /// <param name="sequenceNumber">The packet's RTP sequence number.</param>
    /// <param name="rtpTimestamp">The packet's RTP timestamp.</param>
    /// <param name="arrivalTimestamp">
    /// The arrival instant expressed in the same units and clock as <paramref name="rtpTimestamp"/>
    /// (RFC 3550 A.8): wall-clock arrival scaled by the payload's clock rate. Only differences matter,
    /// so wrap-around is harmless.
    /// </param>
    public void OnRtpPacket(ushort sequenceNumber, uint rtpTimestamp, uint arrivalTimestamp)
    {
        if (!_initialized)
        {
            InitializeSequence(sequenceNumber);
            _initialized = true;
        }

        UpdateSequence(sequenceNumber);

        // RFC 3550 A.8: D(i-1,i) = (arrival_i - arrival_{i-1}) - (ts_i - ts_{i-1}) = transit_i - transit_{i-1}.
        var transit = unchecked((int)(arrivalTimestamp - rtpTimestamp));
        if (_received > 1)
        {
            var d = transit - _transit;
            if (d < 0)
            {
                d = -d;
            }

            // J += |D| - J/16, kept scaled by 16 to preserve precision (RFC 3550 A.8).
            _jitterQ4 += (uint)d - ((_jitterQ4 + 8) >> 4);
        }

        _transit = transit;
    }

    /// <summary>
    /// Records the most recent sender report from this source, for the LSR and DLSR fields of the next
    /// report block (RFC 3550 §6.4.1).
    /// </summary>
    /// <param name="senderReportCompact">The middle 32 bits of the sender report's NTP timestamp.</param>
    /// <param name="arrival">When the sender report arrived.</param>
    public void OnSenderReport(uint senderReportCompact, DateTimeOffset arrival)
    {
        _lastSenderReportCompact = senderReportCompact;
        _lastSenderReportArrival = arrival;
    }

    /// <summary>
    /// Builds the reception report block owed to this source, computing the fraction lost since the
    /// previous report (RFC 3550 A.3) and the delay since the last sender report. Advances the interval
    /// counters, so it must be called once per emitted report.
    /// </summary>
    /// <param name="sourceSsrc">The SSRC this block reports on.</param>
    /// <param name="now">The instant the enclosing report is being sent, for the DLSR field.</param>
    /// <returns>The report block.</returns>
    public RtcpReportBlock BuildReportBlock(uint sourceSsrc, DateTimeOffset now)
    {
        var extendedMax = ExtendedHighestSequenceNumber;
        var expected = extendedMax - _baseSequenceNumber + 1;

        // Fraction lost over the interval since the previous report (RFC 3550 A.3).
        var expectedInterval = expected - _expectedPrior;
        _expectedPrior = expected;
        var receivedInterval = _received - _receivedPrior;
        _receivedPrior = _received;
        var lostInterval = (long)expectedInterval - receivedInterval;

        byte fractionLost;
        if (expectedInterval == 0 || lostInterval <= 0)
        {
            fractionLost = 0;
        }
        else
        {
            fractionLost = (byte)((lostInterval << 8) / expectedInterval);
        }

        var (lastSenderReport, delaySinceLastSenderReport) = SenderReportEcho(now);

        return new RtcpReportBlock(
            sourceSsrc,
            fractionLost,
            Clamp24(CumulativeLostRaw),
            extendedMax,
            Jitter,
            lastSenderReport,
            delaySinceLastSenderReport);
    }

    private (uint LastSenderReport, uint DelaySinceLastSenderReport) SenderReportEcho(DateTimeOffset now)
    {
        if (_lastSenderReportArrival is not { } arrival)
        {
            // RFC 3550 §6.4.1: both fields are zero until a sender report has been received.
            return (0, 0);
        }

        return (_lastSenderReportCompact, NtpTime.ToFixed16(now - arrival));
    }

    private void InitializeSequence(ushort sequenceNumber)
    {
        _baseSequenceNumber = sequenceNumber;
        _maxSequenceNumber = sequenceNumber;

        // RFC 3550 A.1: a value that cannot equal any real (seq + 1) & 0xFFFF, so the first large jump
        // is always treated as tentative rather than a confirmed restart.
        _badSequenceNumber = SequenceModulus + 1;
        _cycles = 0;
        _received = 0;
        _expectedPrior = 0;
        _receivedPrior = 0;
    }

    private void UpdateSequence(ushort sequenceNumber)
    {
        var delta = (ushort)(sequenceNumber - _maxSequenceNumber);

        if (delta < MaxDropout)
        {
            // In order, allowing for the usual small forward gaps of loss.
            if (sequenceNumber < _maxSequenceNumber)
            {
                _cycles += SequenceModulus;
            }

            _maxSequenceNumber = sequenceNumber;
        }
        else if (delta <= SequenceModulus - MaxMisorder)
        {
            // A very large jump: a genuine restart only once a second packet confirms the new sequence.
            if (sequenceNumber == _badSequenceNumber)
            {
                InitializeSequence(sequenceNumber);
                _maxSequenceNumber = sequenceNumber;
            }
            else
            {
                _badSequenceNumber = (uint)((sequenceNumber + 1) & (SequenceModulus - 1));
                return;
            }
        }

        // else: a duplicate or reordered packet within the recent window; it still counts as received.
        _received++;
    }

    private static int Clamp24(long value)
    {
        const int max = 0x7FFFFF;
        const int min = -0x800000;
        if (value > max)
        {
            return max;
        }

        return value < min ? min : (int)value;
    }
}
