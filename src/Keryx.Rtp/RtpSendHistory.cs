using Keryx.Core;

namespace Keryx.Rtp;

/// <summary>How a lookup in an <see cref="RtpSendHistory"/> ended.</summary>
public enum RtpSendHistoryResult
{
    /// <summary>The packet was found and copied out.</summary>
    Found,

    /// <summary>The packet was never stored, was evicted, or has aged past the retention window.</summary>
    Missing,

    /// <summary>
    /// The packet is retained but was retransmitted too recently, so the caller must not resend it yet.
    /// </summary>
    Suppressed,
}

/// <summary>Retention limits for an <see cref="RtpSendHistory"/>.</summary>
/// <remarks>
/// All three limits apply at once; whichever binds first evicts. <see cref="Capacity"/> also fixes
/// the memory the history reserves up front, so it is the limit worth sizing to the stream's packet
/// rate: at roughly 1000 packets per second a capacity of 512 retains half a second of video.
/// </remarks>
public sealed class RtpSendHistoryOptions
{
    /// <summary>
    /// Number of packet slots. Rounded up to a power of two so sequence numbers index the ring with a
    /// mask. Defaults to 512.
    /// </summary>
    public int Capacity { get; set; } = 512;

    /// <summary>
    /// How long a packet stays eligible for retransmission. Defaults to one second, comfortably more
    /// than the round trip on which a NACK could still arrive usefully.
    /// </summary>
    public TimeSpan Retention { get; set; } = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Total retained payload budget in bytes. Defaults to 1 MB, which bounds the history on a
    /// high-bitrate stream long before <see cref="Retention"/> would.
    /// </summary>
    public int MaxBytes { get; set; } = 1_000_000;
}

/// <summary>
/// A ring of recently transmitted RTP packets, keyed by sequence number, from which a NACK
/// (RFC 4585 §6.2.1) can be served by retransmission.
/// </summary>
/// <remarks>
/// <para>
/// <b>Layout.</b> One contiguous arena of <c>capacity × maxPacketSize</c> bytes is allocated at
/// construction and never grown; slot <c>i</c> owns the slab at <c>i × maxPacketSize</c> and a packet
/// with sequence number <c>s</c> lives in slot <c>s &amp; (capacity - 1)</c>. Because a sender's
/// sequence numbers advance by one per packet, that mapping is a ring: storing a packet naturally
/// overwrites the one sent <c>capacity</c> packets earlier. Steady-state operation allocates nothing.
/// </para>
/// <para>
/// <b>Thread safety.</b> Every operation takes a private lock. This is deliberate: packets are stored
/// from the application's send thread while lookups run on the RTCP receive loop, and the two must
/// not tear a slab. The critical sections are a bounds check and one <c>memcpy</c>, so contention
/// between one producer and one occasional consumer is negligible; a lock-free design would need
/// per-slot sequence stamping for no measurable gain at these rates.
/// </para>
/// <para>
/// <b>Eviction.</b> Entries leave the ring when they are overwritten by a wrap, when they age past
/// <see cref="RtpSendHistoryOptions.Retention"/>, or when the retained byte total exceeds
/// <see cref="RtpSendHistoryOptions.MaxBytes"/>. The most recently stored packet is never evicted.
/// </para>
/// </remarks>
public sealed class RtpSendHistory
{
    private readonly object _gate = new();
    private readonly byte[] _arena;
    private readonly Slot[] _slots;
    private readonly int _mask;
    private readonly int _slotSize;
    private readonly long _retentionTicks;
    private readonly long _maxBytes;
    private readonly TimeProvider _time;

    private long _bytes;
    private int _count;
    private ushort _oldest;
    private ushort _newest;

    /// <summary>Creates a history ring.</summary>
    /// <param name="maxPacketSize">
    /// Largest RTP packet the ring must be able to hold, header included. Packets larger than this are
    /// refused by <see cref="Store"/> rather than truncated.
    /// </param>
    /// <param name="options">Retention limits; defaults are used when null.</param>
    /// <param name="timeProvider">Clock used for ageing; <see cref="TimeProvider.System"/> when null.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// The packet size is not positive, or <see cref="RtpSendHistoryOptions.Capacity"/> is outside 1..32768.
    /// </exception>
    public RtpSendHistory(int maxPacketSize, RtpSendHistoryOptions? options = null, TimeProvider? timeProvider = null)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxPacketSize);
        options ??= new RtpSendHistoryOptions();
        ArgumentOutOfRangeException.ThrowIfLessThan(options.Capacity, 1);

        // 32768 slots is half the sequence-number space; beyond that a wrapped sequence number could
        // alias a live entry and the ring would stop being unambiguous.
        ArgumentOutOfRangeException.ThrowIfGreaterThan(options.Capacity, 32768);

        var capacity = (int)System.Numerics.BitOperations.RoundUpToPowerOf2((uint)options.Capacity);
        var arenaSize = (long)capacity * maxPacketSize;
        if (arenaSize > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options),
                $"A capacity of {capacity} slots of {maxPacketSize} byte(s) would need a {arenaSize}-byte arena.");
        }

        _time = timeProvider ?? TimeProvider.System;
        _slotSize = maxPacketSize;
        _mask = capacity - 1;
        _slots = new Slot[capacity];
        _arena = new byte[(int)arenaSize];
        _retentionTicks = options.Retention <= TimeSpan.Zero
            ? 0
            : (long)(options.Retention.TotalSeconds * _time.TimestampFrequency);
        _maxBytes = options.MaxBytes <= 0 ? long.MaxValue : options.MaxBytes;
        Capacity = capacity;
        MaxPacketSize = maxPacketSize;
        Retention = options.Retention;
        MaxBytes = _maxBytes;
    }

    /// <summary>Number of packet slots, rounded up to a power of two.</summary>
    public int Capacity { get; }

    /// <summary>Largest packet the ring accepts, header included.</summary>
    public int MaxPacketSize { get; }

    /// <summary>How long a stored packet stays eligible for retransmission.</summary>
    public TimeSpan Retention { get; }

    /// <summary>Retained byte budget; <see cref="long.MaxValue"/> when unbounded.</summary>
    public long MaxBytes { get; }

    /// <summary>Packets currently retained.</summary>
    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _count;
            }
        }
    }

    /// <summary>Bytes currently retained, RTP headers included.</summary>
    public long ByteCount
    {
        get
        {
            lock (_gate)
            {
                return _bytes;
            }
        }
    }

    /// <summary>Stores a packet that has just been transmitted.</summary>
    /// <param name="sequenceNumber">The packet's RTP sequence number.</param>
    /// <param name="packet">
    /// The complete RTP packet as it went on the wire <em>before</em> SRTP protection: SRTP encrypts in
    /// place, so the plaintext must be captured first.
    /// </param>
    /// <returns>
    /// <see langword="true"/> when the packet was retained, <see langword="false"/> when it is empty or
    /// larger than <see cref="MaxPacketSize"/>.
    /// </returns>
    public bool Store(ushort sequenceNumber, ReadOnlySpan<byte> packet)
    {
        if (packet.IsEmpty || packet.Length > _slotSize)
        {
            return false;
        }

        lock (_gate)
        {
            var now = _time.GetTimestamp();
            var index = sequenceNumber & _mask;
            ref var slot = ref _slots[index];
            if (slot.Occupied)
            {
                _bytes -= slot.Length;
                _count--;
            }

            packet.CopyTo(_arena.AsSpan(index * _slotSize, _slotSize));
            slot.SequenceNumber = sequenceNumber;
            slot.Length = packet.Length;
            slot.StoredAt = now;
            slot.LastResendAt = 0;
            slot.Resends = 0;
            slot.Occupied = true;

            _bytes += packet.Length;
            if (_count == 0)
            {
                _oldest = sequenceNumber;
            }

            _count++;
            _newest = sequenceNumber;
            Trim(now);
            return true;
        }
    }

    /// <summary>
    /// Copies a retained packet out for retransmission, applying the per-packet resend rate limit.
    /// </summary>
    /// <param name="sequenceNumber">The sequence number a NACK reported missing.</param>
    /// <param name="minimumResendInterval">
    /// Smallest interval between two retransmissions of the same sequence number. A packet that has
    /// never been retransmitted is always eligible, so the first NACK is served without delay however
    /// short the round trip is. Pass <see cref="TimeSpan.Zero"/> to disable the limit.
    /// </param>
    /// <param name="destination">Buffer receiving the stored packet.</param>
    /// <param name="length">On <see cref="RtpSendHistoryResult.Found"/>, the packet's length.</param>
    /// <returns>Whether the packet was copied, is unavailable, or is rate limited.</returns>
    /// <remarks>
    /// Copying does not itself start the packet's rate-limit interval: the caller must call
    /// <see cref="MarkRetransmitted"/> once the repair has actually been produced. A caller that
    /// gives up after copying — because a bandwidth budget refused the packet, say — would otherwise
    /// spend a resend that never happened, and the next NACK for a packet the peer has still never
    /// seen would be suppressed.
    /// </remarks>
    /// <exception cref="ByteBufferException">The destination is smaller than the stored packet.</exception>
    public RtpSendHistoryResult TryCopy(
        ushort sequenceNumber,
        TimeSpan minimumResendInterval,
        Span<byte> destination,
        out int length)
    {
        length = 0;
        lock (_gate)
        {
            var index = sequenceNumber & _mask;
            ref var slot = ref _slots[index];
            if (!slot.Occupied || slot.SequenceNumber != sequenceNumber)
            {
                return RtpSendHistoryResult.Missing;
            }

            var now = _time.GetTimestamp();
            if (_retentionTicks > 0 && now - slot.StoredAt > _retentionTicks)
            {
                return RtpSendHistoryResult.Missing;
            }

            if (slot.Resends > 0
                && minimumResendInterval > TimeSpan.Zero
                && _time.GetElapsedTime(slot.LastResendAt, now) < minimumResendInterval)
            {
                return RtpSendHistoryResult.Suppressed;
            }

            if (destination.Length < slot.Length)
            {
                throw new ByteBufferException(
                    $"A retained {slot.Length}-byte packet does not fit a {destination.Length}-byte destination.");
            }

            _arena.AsSpan(index * _slotSize, slot.Length).CopyTo(destination);
            length = slot.Length;
            return RtpSendHistoryResult.Found;
        }
    }

    /// <summary>
    /// Records that a packet copied by <see cref="TryCopy"/> was in fact retransmitted, which starts
    /// its rate-limit interval.
    /// </summary>
    /// <param name="sequenceNumber">The sequence number that was retransmitted.</param>
    /// <returns>
    /// <see langword="true"/> when the packet was still retained; <see langword="false"/> when it had
    /// already been evicted, in which case there is nothing left to rate limit.
    /// </returns>
    public bool MarkRetransmitted(ushort sequenceNumber)
    {
        lock (_gate)
        {
            ref var slot = ref _slots[sequenceNumber & _mask];
            if (!slot.Occupied || slot.SequenceNumber != sequenceNumber)
            {
                return false;
            }

            slot.LastResendAt = _time.GetTimestamp();
            slot.Resends++;
            return true;
        }
    }

    /// <summary>Drops every retained packet.</summary>
    public void Clear()
    {
        lock (_gate)
        {
            Array.Clear(_slots);
            _bytes = 0;
            _count = 0;
            _oldest = 0;
            _newest = 0;
        }
    }

    private void Trim(long now)
    {
        // A sequence-number jump larger than the ring leaves stale slots that can never be reached by
        // walking forward; snap the window to the reachable range first.
        if ((ushort)(_newest - _oldest) >= Capacity)
        {
            _oldest = (ushort)(_newest - Capacity + 1);
        }

        while (_count > 1 && _oldest != _newest)
        {
            ref var slot = ref _slots[_oldest & _mask];
            if (!slot.Occupied || slot.SequenceNumber != _oldest)
            {
                // A gap in the sequence space, or a slot already reused by a newer packet.
                _oldest = (ushort)(_oldest + 1);
                continue;
            }

            var expired = _retentionTicks > 0 && now - slot.StoredAt > _retentionTicks;
            if (!expired && _bytes <= _maxBytes)
            {
                return;
            }

            _bytes -= slot.Length;
            _count--;
            slot.Occupied = false;
            _oldest = (ushort)(_oldest + 1);
        }
    }

    private struct Slot
    {
        public ushort SequenceNumber;
        public int Length;
        public long StoredAt;
        public long LastResendAt;
        public int Resends;
        public bool Occupied;
    }
}
