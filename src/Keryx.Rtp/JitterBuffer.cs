namespace Keryx.Rtp;

/// <summary>Bounds for a <see cref="JitterBuffer"/>: how deep it may grow and how long it may wait.</summary>
/// <remarks>
/// The two limits work together. <see cref="Capacity"/> caps the packets held behind a gap, so a
/// stream that never fills the gap can never grow the buffer without bound; <see cref="MaxWait"/>
/// caps the time the head of the stream is held for a missing packet, so a lost packet is declared
/// lost and the packets behind it are released rather than stalling playout forever.
/// </remarks>
public sealed class JitterBufferOptions
{
    /// <summary>
    /// Largest number of packets the buffer may hold awaiting playout. Rounded up to a power of two so
    /// sequence numbers index the ring with a mask. Defaults to 128, roughly a tenth of a second of
    /// 1000 packet-per-second video. When the buffer is full and its head is still missing, the head is
    /// declared lost and playout advances rather than dropping a newly arrived packet.
    /// </summary>
    public int Capacity { get; set; } = 128;

    /// <summary>
    /// Longest a contiguous run is held for a missing packet before that packet is declared lost and
    /// the run released. Defaults to 120 ms. <see cref="TimeSpan.Zero"/> disables reordering recovery
    /// entirely: any gap is treated as immediate loss, so packets are released strictly in arrival's
    /// sequence order with no wait.
    /// </summary>
    public TimeSpan MaxWait { get; set; } = TimeSpan.FromMilliseconds(120);
}

/// <summary>How an <see cref="JitterBuffer.Insert"/> was resolved.</summary>
public enum JitterBufferInsertResult
{
    /// <summary>The packet was accepted and is awaiting playout.</summary>
    Buffered,

    /// <summary>The sequence number was already buffered; the packet was dropped as a duplicate.</summary>
    Duplicate,

    /// <summary>
    /// The packet arrived after its playout point had already passed — its sequence number is behind
    /// the buffer's release cursor — so it was dropped as too late to be useful.
    /// </summary>
    Late,
}

/// <summary>
/// One packet released from a <see cref="JitterBuffer"/> in playout order.
/// </summary>
/// <remarks>
/// <see cref="Payload"/> aliases storage inside the buffer and is valid only until the next
/// <see cref="JitterBuffer.Insert"/> or <see cref="JitterBuffer.TryGetNext"/> on the same buffer;
/// copy it, or consume it, before calling either again.
/// </remarks>
public readonly ref struct JitterBufferPacket
{
    internal JitterBufferPacket(
        ushort sequenceNumber,
        uint timestamp,
        bool marker,
        byte payloadType,
        ReadOnlySpan<byte> payload)
    {
        SequenceNumber = sequenceNumber;
        Timestamp = timestamp;
        Marker = marker;
        PayloadType = payloadType;
        Payload = payload;
    }

    /// <summary>The RTP sequence number.</summary>
    public ushort SequenceNumber { get; }

    /// <summary>The RTP timestamp, in the codec's clock rate.</summary>
    public uint Timestamp { get; }

    /// <summary>The marker bit; for video it terminates an access unit.</summary>
    public bool Marker { get; }

    /// <summary>The RTP payload type.</summary>
    public byte PayloadType { get; }

    /// <summary>The RTP payload, RFC 3550 §5.1 padding already stripped by the caller that inserted it.</summary>
    public ReadOnlySpan<byte> Payload { get; }
}

/// <summary>
/// A sequence-ordered receive buffer for one RTP synchronisation source: it reorders packets a lossy
/// link delivered out of order, drops duplicates, and releases a contiguous run to playout the moment
/// it is whole — or, when a packet is missing, once <see cref="MaxWait"/> elapses or the buffer fills,
/// declaring that packet lost. Depacketizers assume ordered, loss-free input (RFC 6184 reassembly in
/// particular corrupts an access unit under reorder), so one of these belongs in front of each.
/// </summary>
/// <remarks>
/// <para>
/// <b>Model.</b> A ring of <see cref="Capacity"/> slots holds packets keyed by sequence number: a
/// packet with sequence number <c>s</c> lives in slot <c>s &amp; (Capacity - 1)</c>, exactly as
/// <see cref="RtpSendHistory"/> keys its ring, so steady in-order operation reuses slots without
/// allocating. A release cursor names the next sequence number owed to playout.
/// <see cref="Insert"/> places a packet; <see cref="TryGetNext"/> pops the cursor's packet when it is
/// present, and the caller loops it after every insert (and may poll it on a timer) to drain every
/// packet that has become ready.
/// </para>
/// <para>
/// <b>Playout.</b> When the cursor's packet is present it is released with zero added latency, so a
/// clean in-order stream passes straight through. When it is missing but later packets are buffered,
/// the run is held until either <see cref="MaxWait"/> has elapsed since the wait began or the ring is
/// full; then the missing sequence number (and any consecutive ones) is declared lost, the cursor
/// steps over it, and the buffered run is released.
/// </para>
/// <para>
/// <b>Wraparound.</b> Sequence numbers are compared modulo 2^16 (RFC 3550 §A.1): a packet is a future
/// packet when it is within the forward half of the sequence space from the cursor, and behind it —
/// hence too late — otherwise. <see cref="Capacity"/> is capped at 32768, half the space, so a
/// wrapped sequence number can never alias a live slot.
/// </para>
/// <para><b>Thread safety: single-writer</b>, like the depacketizers it feeds and the rest of this
/// layer's per-stream state. One buffer is driven by one receive loop; it does no locking.</para>
/// </remarks>
public sealed class JitterBuffer
{
    private readonly TimeProvider _time;
    private readonly Slot[] _slots;
    private readonly int _mask;
    private readonly long _maxWaitTicks;

    private ushort _cursor;
    private bool _started;
    private int _count;
    private bool _waiting;
    private long _waitStart;

    private long _packetsBuffered;
    private long _duplicatesDropped;
    private long _latePacketsDropped;
    private long _packetsLost;

    /// <summary>Creates a jitter buffer.</summary>
    /// <param name="options">Depth and wait bounds; defaults are used when null.</param>
    /// <param name="timeProvider">Clock used for the playout wait; <see cref="TimeProvider.System"/> when null.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <see cref="JitterBufferOptions.Capacity"/> is outside 1..32768.
    /// </exception>
    public JitterBuffer(JitterBufferOptions? options = null, TimeProvider? timeProvider = null)
    {
        options ??= new JitterBufferOptions();
        ArgumentOutOfRangeException.ThrowIfLessThan(options.Capacity, 1);

        // 32768 slots is half the sequence-number space; beyond that a wrapped sequence number could
        // alias a live entry and the ring would stop being unambiguous.
        ArgumentOutOfRangeException.ThrowIfGreaterThan(options.Capacity, 32768);

        _time = timeProvider ?? TimeProvider.System;
        var capacity = (int)System.Numerics.BitOperations.RoundUpToPowerOf2((uint)options.Capacity);
        _slots = new Slot[capacity];
        _mask = capacity - 1;
        _maxWaitTicks = options.MaxWait <= TimeSpan.Zero
            ? 0
            : (long)(options.MaxWait.TotalSeconds * _time.TimestampFrequency);
        Capacity = capacity;
        MaxWait = options.MaxWait;
    }

    /// <summary>Number of packet slots, rounded up to a power of two.</summary>
    public int Capacity { get; }

    /// <summary>Longest a run is held for a missing packet before it is declared lost.</summary>
    public TimeSpan MaxWait { get; }

    /// <summary>Packets currently held awaiting playout.</summary>
    public int Count => _count;

    /// <summary>Total packets ever accepted into the buffer.</summary>
    public long PacketsBuffered => _packetsBuffered;

    /// <summary>Packets dropped because their sequence number was already buffered.</summary>
    public long DuplicatesDropped => _duplicatesDropped;

    /// <summary>Packets dropped because they arrived after their playout point had passed.</summary>
    public long LatePacketsDropped => _latePacketsDropped;

    /// <summary>Sequence numbers the buffer skipped over at playout, having declared them lost.</summary>
    public long PacketsLost => _packetsLost;

    /// <summary>
    /// Inserts one received packet.
    /// </summary>
    /// <param name="sequenceNumber">The packet's RTP sequence number.</param>
    /// <param name="timestamp">The packet's RTP timestamp.</param>
    /// <param name="marker">The packet's marker bit.</param>
    /// <param name="payloadType">The packet's RTP payload type.</param>
    /// <param name="payload">The RTP payload; it is copied into the buffer, so the caller may reuse it.</param>
    /// <returns>Whether the packet was buffered, was a duplicate, or arrived too late.</returns>
    public JitterBufferInsertResult Insert(
        ushort sequenceNumber,
        uint timestamp,
        bool marker,
        byte payloadType,
        ReadOnlySpan<byte> payload)
    {
        if (!_started)
        {
            _started = true;
            _cursor = sequenceNumber;
            Store(sequenceNumber, timestamp, marker, payloadType, payload);
            _count++;
            _packetsBuffered++;
            return JitterBufferInsertResult.Buffered;
        }

        var diff = (ushort)(sequenceNumber - _cursor);
        if (diff >= 0x8000)
        {
            // Behind the release cursor: already released, or already declared lost and stepped over.
            _latePacketsDropped++;
            return JitterBufferInsertResult.Late;
        }

        if (diff >= Capacity)
        {
            // Too far ahead to index without aliasing a live slot. Fast-forward the cursor to bring the
            // packet inside the window, declaring the skipped span (and anything buffered in it) lost.
            ForceAdvanceTo((ushort)(sequenceNumber - Capacity + 1));
        }

        ref var slot = ref _slots[sequenceNumber & _mask];
        if (slot.Occupied)
        {
            if (slot.SequenceNumber == sequenceNumber)
            {
                _duplicatesDropped++;
                return JitterBufferInsertResult.Duplicate;
            }

            // A stale occupant the window no longer covers; overwrite it in place.
            _count--;
        }

        Store(sequenceNumber, timestamp, marker, payloadType, payload);
        _count++;
        _packetsBuffered++;

        // Start the playout wait the moment a packet lands behind a gap, not when the caller next polls,
        // so the wait measures how long the run has actually been held rather than time since the poll.
        ArmWaitIfBlocked(_time.GetTimestamp());
        return JitterBufferInsertResult.Buffered;
    }

    /// <summary>
    /// Releases the next packet in playout order, if one is ready.
    /// </summary>
    /// <param name="packet">
    /// On success, the released packet. Its <see cref="JitterBufferPacket.Payload"/> aliases buffer
    /// storage and is valid only until the next <see cref="Insert"/> or <see cref="TryGetNext"/>.
    /// </param>
    /// <returns>
    /// <see langword="true"/> when a packet was released; <see langword="false"/> when the buffer is
    /// empty, or is still holding a run for a missing packet whose wait has not yet elapsed.
    /// </returns>
    public bool TryGetNext(out JitterBufferPacket packet)
    {
        packet = default;
        if (!_started)
        {
            return false;
        }

        var now = _time.GetTimestamp();
        while (true)
        {
            ref var slot = ref _slots[_cursor & _mask];
            if (slot.Occupied && slot.SequenceNumber == _cursor)
            {
                packet = new JitterBufferPacket(
                    slot.SequenceNumber,
                    slot.Timestamp,
                    slot.Marker,
                    slot.PayloadType,
                    slot.Buffer.AsSpan(0, slot.Length));
                slot.Occupied = false;
                _count--;
                _cursor++;
                _waiting = false;
                return true;
            }

            // The cursor's packet is missing. With nothing buffered behind it, simply wait for it.
            if (_count == 0)
            {
                _waiting = false;
                return false;
            }

            // A gap that formed since the last release (rather than at an insert) arms its wait here.
            ArmWaitIfBlocked(now);

            var expired = _maxWaitTicks == 0 || now - _waitStart >= _maxWaitTicks;
            if (!expired && _count < Capacity)
            {
                // Hold the run a little longer for the missing packet to arrive.
                return false;
            }

            // The wait elapsed, or the ring is full and must make room: declare this sequence number
            // lost and step over it. The loop then releases the packet behind it, or repeats for the
            // next missing one — all consecutive holes collapse in this same call.
            _cursor++;
            _packetsLost++;
        }
    }

    /// <summary>Discards every buffered packet and forgets the release cursor.</summary>
    public void Reset()
    {
        Array.Clear(_slots);
        _started = false;
        _count = 0;
        _waiting = false;
        _cursor = 0;
        _waitStart = 0;
    }

    private void ArmWaitIfBlocked(long now)
    {
        if (_waiting || _count == 0)
        {
            return;
        }

        ref var slot = ref _slots[_cursor & _mask];
        if (!(slot.Occupied && slot.SequenceNumber == _cursor))
        {
            _waiting = true;
            _waitStart = now;
        }
    }

    private void ForceAdvanceTo(ushort target)
    {
        while (_cursor != target)
        {
            ref var slot = ref _slots[_cursor & _mask];
            if (slot.Occupied && slot.SequenceNumber == _cursor)
            {
                slot.Occupied = false;
                _count--;
            }

            _packetsLost++;
            _cursor++;
        }

        _waiting = false;
    }

    private void Store(ushort sequenceNumber, uint timestamp, bool marker, byte payloadType, ReadOnlySpan<byte> payload)
    {
        ref var slot = ref _slots[sequenceNumber & _mask];
        if (slot.Buffer is null || slot.Buffer.Length < payload.Length)
        {
            slot.Buffer = new byte[Math.Max(payload.Length, 256)];
        }

        payload.CopyTo(slot.Buffer);
        slot.Length = payload.Length;
        slot.SequenceNumber = sequenceNumber;
        slot.Timestamp = timestamp;
        slot.Marker = marker;
        slot.PayloadType = payloadType;
        slot.Occupied = true;
    }

    private struct Slot
    {
        public byte[]? Buffer;
        public int Length;
        public ushort SequenceNumber;
        public uint Timestamp;
        public byte PayloadType;
        public bool Marker;
        public bool Occupied;
    }
}
