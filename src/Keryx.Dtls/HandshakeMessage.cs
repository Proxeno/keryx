using Keryx.Core;

namespace Keryx.Dtls;

/// <summary>A fully reassembled DTLS handshake message.</summary>
internal sealed class HandshakeMessage
{
    public HandshakeMessage(HandshakeType type, ushort messageSeq, byte[] body)
    {
        Type = type;
        MessageSeq = messageSeq;
        Body = body;
    }

    public HandshakeType Type { get; }

    public ushort MessageSeq { get; }

    public byte[] Body { get; }

    /// <summary>
    /// The message as it must appear in the handshake transcript: the 12-byte DTLS handshake header
    /// with <c>fragment_offset = 0</c> and <c>fragment_length = length</c>, followed by the body.
    /// RFC 6347 §4.2.6 requires the transcript to be computed as if nothing had been fragmented.
    /// </summary>
    public byte[] ToTranscriptBytes() => Serialize(Type, MessageSeq, Body);

    /// <summary>Serializes a complete, unfragmented handshake message.</summary>
    public static byte[] Serialize(HandshakeType type, ushort messageSeq, ReadOnlySpan<byte> body)
    {
        var buffer = new byte[DtlsLimits.HandshakeHeaderLength + body.Length];
        var writer = new ByteWriter(buffer);
        writer.WriteU8((byte)type);
        writer.WriteU24((uint)body.Length);
        writer.WriteU16(messageSeq);
        writer.WriteU24(0);
        writer.WriteU24((uint)body.Length);
        writer.WriteBytes(body);
        return buffer;
    }
}

/// <summary>The header of one handshake fragment as it appears inside a record.</summary>
internal readonly record struct HandshakeFragmentHeader(
    HandshakeType Type,
    int Length,
    ushort MessageSeq,
    int FragmentOffset,
    int FragmentLength);

/// <summary>
/// Reassembles fragmented handshake messages (RFC 6347 §4.2.3) and buffers messages that arrive
/// out of order, keyed by <c>message_seq</c>.
/// </summary>
internal sealed class HandshakeReassembler
{
    private readonly Dictionary<ushort, Partial> _pending = [];
    private readonly int _maxBufferedMessages;

    public HandshakeReassembler(int maxBufferedMessages = 24)
    {
        _maxBufferedMessages = maxBufferedMessages;
    }

    /// <summary>The <c>message_seq</c> the state machine will process next.</summary>
    public ushort NextReceiveSeq { get; private set; }

    /// <summary>Resets the reassembler and the expected sequence, used after a HelloVerifyRequest.</summary>
    public void Reset(ushort nextReceiveSeq)
    {
        _pending.Clear();
        NextReceiveSeq = nextReceiveSeq;
    }

    /// <summary>Advances past a message the state machine has consumed.</summary>
    public void Consume(ushort messageSeq)
    {
        _pending.Remove(messageSeq);
        if (messageSeq == NextReceiveSeq)
        {
            NextReceiveSeq = unchecked((ushort)(NextReceiveSeq + 1));
        }
    }

    /// <summary>
    /// Drops a fully reassembled message <b>without</b> advancing <see cref="NextReceiveSeq"/>. Used
    /// when an unauthenticated epoch-0 message body failed to decode: it must be discarded rather than
    /// escalated (RFC 6347 §4.1.2.7), but its <c>message_seq</c> has to stay the expected one so the
    /// peer's genuine retransmission of the correct message is still accepted rather than being taken
    /// for a stale duplicate. Removing the buffered partial also lets the retransmission rebuild the
    /// message from scratch, even if its length differs from the malformed one.
    /// </summary>
    public void Discard(ushort messageSeq) => _pending.Remove(messageSeq);

    /// <summary>
    /// Parses every handshake fragment inside one record body and files them for reassembly.
    /// Returns true when at least one fragment carried data for a message at or after
    /// <see cref="NextReceiveSeq"/>; false means the record was entirely a retransmission of
    /// already-consumed messages, which the caller should answer by retransmitting its own flight.
    /// </summary>
    public bool AddRecord(ReadOnlySpan<byte> recordBody, out bool sawRetransmission)
    {
        sawRetransmission = false;
        var progressed = false;
        var reader = new ByteReader(recordBody);

        while (reader.Remaining > 0)
        {
            if (reader.Remaining < DtlsLimits.HandshakeHeaderLength)
            {
                throw new DtlsException("Truncated DTLS handshake fragment header.", DtlsAlertDescription.DecodeError);
            }

            var type = (HandshakeType)reader.ReadU8();
            var length = (int)reader.ReadU24();
            var messageSeq = reader.ReadU16();
            var fragmentOffset = (int)reader.ReadU24();
            var fragmentLength = (int)reader.ReadU24();

            if (reader.Remaining < fragmentLength)
            {
                throw new DtlsException("Truncated DTLS handshake fragment body.", DtlsAlertDescription.DecodeError);
            }

            var data = reader.ReadBytes(fragmentLength);

            if (length > DtlsLimits.MaxHandshakeMessageLength)
            {
                throw new DtlsException(
                    $"Handshake message of {length} bytes exceeds the {DtlsLimits.MaxHandshakeMessageLength}-byte limit.",
                    DtlsAlertDescription.DecodeError);
            }

            if (fragmentOffset < 0 || fragmentLength < 0 || (long)fragmentOffset + fragmentLength > length)
            {
                throw new DtlsException("Handshake fragment lies outside its message.", DtlsAlertDescription.DecodeError);
            }

            if (IsBefore(messageSeq, NextReceiveSeq))
            {
                sawRetransmission = true;
                continue;
            }

            if (!_pending.TryGetValue(messageSeq, out var partial))
            {
                // Never abort on a local buffering limit: it is reachable from wholly unauthenticated
                // input, so one datagram of empty fragments carrying distinct far-future message_seq
                // values could otherwise make the next genuine message fatal (RFC 6347 §4.1.2.7 asks
                // for a discard). Evicting the partial furthest ahead of NextReceiveSeq — rather than
                // dropping the arrival — is what keeps that flood from starving the in-order message
                // the handshake is actually waiting on. Anything evicted is recovered by flight
                // retransmission.
                if (_pending.Count >= _maxBufferedMessages && !TryEvictFurthestAhead(messageSeq))
                {
                    continue;
                }

                partial = new Partial(type, length);
                _pending[messageSeq] = partial;
            }
            else if (partial.Type != type || partial.Length != length)
            {
                throw new DtlsException(
                    "Handshake fragments disagree about their message type or length.",
                    DtlsAlertDescription.IllegalParameter);
            }

            if (!partial.Add(fragmentOffset, data))
            {
                // Pathologically fragmented: stop tracking new holes for this message. Contiguous
                // fragments still merge into the intervals already held, so a legitimate
                // retransmission continues to fill the gaps and complete the message.
                continue;
            }

            progressed = true;
        }

        return progressed;
    }

    /// <summary>Returns the next in-order message once every one of its fragments has arrived.</summary>
    public bool TryTakeNext(out HandshakeMessage message)
    {
        message = null!;
        if (!_pending.TryGetValue(NextReceiveSeq, out var partial) || !partial.IsComplete)
        {
            return false;
        }

        message = new HandshakeMessage(partial.Type, NextReceiveSeq, partial.Buffer);
        return true;
    }

    /// <summary>True when a fragment for <paramref name="messageSeq"/> has been seen.</summary>
    public bool HasPending(ushort messageSeq) => _pending.ContainsKey(messageSeq);

    /// <summary>
    /// Frees a slot for <paramref name="arriving"/> by discarding the buffered message furthest ahead
    /// of <see cref="NextReceiveSeq"/>. Returns false when <paramref name="arriving"/> is itself the
    /// furthest ahead, in which case it is the one that should be dropped.
    /// </summary>
    private bool TryEvictFurthestAhead(ushort arriving)
    {
        var furthestSeq = arriving;
        var furthestDistance = Distance(arriving);
        var found = false;

        foreach (var seq in _pending.Keys)
        {
            var distance = Distance(seq);
            if (distance > furthestDistance)
            {
                furthestDistance = distance;
                furthestSeq = seq;
                found = true;
            }
        }

        if (!found)
        {
            return false;
        }

        _pending.Remove(furthestSeq);
        return true;
    }

    /// <summary>How far ahead of <see cref="NextReceiveSeq"/> a message_seq sits, wrapping at 2^16.</summary>
    private ushort Distance(ushort messageSeq) => unchecked((ushort)(messageSeq - NextReceiveSeq));

    private static bool IsBefore(ushort candidate, ushort reference)
    {
        // message_seq wraps at 2^16; treat the nearer half of the space as "in the past".
        return unchecked((ushort)(reference - candidate)) is > 0 and < 0x8000;
    }

    private sealed class Partial
    {
        private readonly List<(int Start, int End)> _ranges = [];

        /// <summary>
        /// Largest number of disjoint received-byte intervals tracked for one message before it is
        /// abandoned. Legitimate fragmenters produce one or two.
        /// </summary>
        private const int MaxRanges = 64;

        public Partial(HandshakeType type, int length)
        {
            Type = type;
            Length = length;
            Buffer = new byte[length];
        }

        public HandshakeType Type { get; }

        public int Length { get; }

        public byte[] Buffer { get; }

        public bool IsComplete => _ranges.Count == 1 && _ranges[0].Start == 0 && _ranges[0].End == Length;

        /// <summary>
        /// Adds a fragment. Returns false when the fragment would open yet another hole in a message
        /// already fragmented past anything legitimate, in which case it is ignored.
        /// </summary>
        public bool Add(int offset, ReadOnlySpan<byte> data)
        {
            if (Length == 0)
            {
                // Zero-length messages (ServerHelloDone) are complete on arrival.
                if (_ranges.Count == 0)
                {
                    _ranges.Add((0, 0));
                }

                return true;
            }

            if (data.Length == 0)
            {
                return true;
            }

            // Merge is linear in the number of disjoint intervals and List.Insert memmoves the tail,
            // so tracking is quadratic overall. A real fragmenter emits contiguous fragments and
            // never exceeds one or two intervals; an attacker sending one-byte fragments at every
            // other offset drives the count to Length/2 and burns that quadratic cost inside the
            // transport lock, which blocks every other datagram and the retransmit timer with it.
            // Measured at roughly a second of CPU per 832 KiB of such input. Sixty-four intervals is
            // far beyond anything legitimate, so past that only fragments that touch an interval
            // already held are accepted — which is every fragment a real peer sends, since real
            // fragmenters emit contiguous pieces.
            if (_ranges.Count >= MaxRanges && !TouchesExistingRange(offset, offset + data.Length))
            {
                return false;
            }

            data.CopyTo(Buffer.AsSpan(offset));
            Merge(offset, offset + data.Length);
            return true;
        }

        private bool TouchesExistingRange(int start, int end)
        {
            foreach (var (rangeStart, rangeEnd) in _ranges)
            {
                if (rangeStart <= end && start <= rangeEnd)
                {
                    return true;
                }
            }

            return false;
        }

        private void Merge(int start, int end)
        {
            var index = 0;
            while (index < _ranges.Count && _ranges[index].End < start)
            {
                index++;
            }

            while (index < _ranges.Count && _ranges[index].Start <= end)
            {
                start = Math.Min(start, _ranges[index].Start);
                end = Math.Max(end, _ranges[index].End);
                _ranges.RemoveAt(index);
            }

            _ranges.Insert(index, (start, end));
        }
    }
}
