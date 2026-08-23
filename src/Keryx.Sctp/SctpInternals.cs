namespace Keryx.Sctp;

/// <summary>Serial-number arithmetic (RFC 1982) for TSNs and stream sequence numbers.</summary>
internal static class Serial
{
    internal static bool Gt(uint a, uint b) => a != b && unchecked(a - b) < 0x80000000u;

    internal static bool Gte(uint a, uint b) => a == b || Gt(a, b);

    internal static bool Lt(uint a, uint b) => Gt(b, a);

    internal static bool Lte(uint a, uint b) => Gte(b, a);

    internal static bool Gt16(ushort a, ushort b) => a != b && unchecked((ushort)(a - b)) < 0x8000;

    internal static bool Gte16(ushort a, ushort b) => a == b || Gt16(a, b);
}

/// <summary>A DATA chunk queued for transmission, together with its reliability bookkeeping.</summary>
internal sealed class OutgoingChunk
{
    internal required uint Tsn { get; init; }

    internal required ushort StreamId { get; init; }

    internal required ushort StreamSequence { get; init; }

    internal required uint PayloadProtocolId { get; init; }

    internal required byte[] Payload { get; init; }

    internal required bool Beginning { get; init; }

    internal required bool Ending { get; init; }

    internal required bool Unordered { get; init; }

    /// <summary>
    /// When true this chunk is transmitted as an RFC 8260 I-DATA chunk carrying
    /// <see cref="MessageIdentifier"/>/<see cref="FragmentSequenceNumber"/>; when false it is a
    /// classic DATA chunk carrying <see cref="StreamSequence"/> and a per-fragment PPID.
    /// </summary>
    internal bool Interleaved { get; set; }

    /// <summary>RFC 8260 message identifier (MID); used only when <see cref="Interleaved"/> is true.</summary>
    internal uint MessageIdentifier { get; set; }

    /// <summary>RFC 8260 fragment sequence number (FSN); used only on continuation I-DATA fragments.</summary>
    internal uint FragmentSequenceNumber { get; set; }

    internal required int MessageId { get; init; }

    internal required ushort? MaxRetransmits { get; init; }

    /// <summary>
    /// RFC 3758 timed partial reliability deadline, in the association's monotonic millisecond
    /// clock (same domain as <see cref="LastSentMs"/>), or null when the message is not
    /// lifetime-limited. Stamped once, when the message is queued, so the timer runs from when it
    /// was presented to SCTP rather than from its (possibly retried) first transmission.
    /// </summary>
    internal long? ExpiresAtMs { get; init; }

    internal DataChannel? Channel { get; init; }

    /// <summary>Bytes of user payload this chunk contributes to the channel's buffered amount.</summary>
    internal int BufferedBytes { get; init; }

    internal int Transmits { get; set; }

    internal long LastSentMs { get; set; }

    internal bool Acked { get; set; }

    internal bool Abandoned { get; set; }

    internal bool InFlight { get; set; }

    internal bool NeedsRetransmit { get; set; }

    internal int MissIndications { get; set; }

    internal bool BufferReleased { get; set; }

    /// <summary>Wire size of the encoded chunk, used for flight-size and congestion accounting.</summary>
    internal int WireSize =>
        4 + (Interleaved ? SctpIDataChunk.FixedHeaderLength : SctpDataChunk.FixedHeaderLength) + Payload.Length;

    internal SctpChunk ToChunk() =>
        Interleaved
            ? new SctpIDataChunk(
                Tsn, StreamId, MessageIdentifier, PayloadProtocolId, FragmentSequenceNumber, Payload, Beginning, Ending, Unordered)
            : new SctpDataChunk(Tsn, StreamId, StreamSequence, PayloadProtocolId, Payload, Beginning, Ending, Unordered);
}

/// <summary>An outgoing RFC 6525 RE-CONFIG request awaiting a Re-configuration Response.</summary>
internal sealed class OutstandingReset
{
    internal required uint RequestSequence { get; init; }

    /// <summary>The outgoing stream identifiers this request resets.</summary>
    internal required List<ushort> Streams { get; init; }

    /// <summary>The last TSN assigned when the request was built, echoed to the peer.</summary>
    internal required uint SendersLastAssignedTsn { get; init; }

    /// <summary>The response sequence number carried by the request.</summary>
    internal required uint ResponseSequence { get; init; }
}

/// <summary>Per-stream ordered-delivery state on the receive side.</summary>
internal sealed class ReceiveStream
{
    internal ushort NextSequence { get; set; }

    internal Dictionary<ushort, ReassembledMessage> Buffered { get; } = new();
}

/// <summary>A fully reassembled user message awaiting ordered delivery.</summary>
internal sealed class ReassembledMessage
{
    internal required ushort StreamId { get; init; }

    internal required uint PayloadProtocolId { get; init; }

    internal required byte[] Payload { get; init; }
}

/// <summary>
/// Identifies an RFC 8260 message under reassembly. Ordered and unordered messages occupy separate
/// MID namespaces on a stream, so the ordering flag is part of the key.
/// </summary>
internal readonly record struct IDataKey(ushort StreamId, bool Unordered, uint MessageId);

/// <summary>
/// Reassembly state for one in-progress I-DATA message, collecting fragments by fragment sequence
/// number until the beginning fragment, the ending fragment and every FSN in between have arrived.
/// </summary>
internal sealed class IDataReassembly
{
    internal bool HasBeginning { get; set; }

    internal bool HasEnd { get; set; }

    internal uint EndFsn { get; set; }

    internal uint PayloadProtocolId { get; set; }

    internal int ByteCount { get; set; }

    /// <summary>Fragment payloads and their transmission sequence numbers, keyed by FSN.</summary>
    internal SortedDictionary<uint, (byte[] Payload, uint Tsn)> Fragments { get; } = new();

    /// <summary>True once the beginning, the end and every intervening fragment are present.</summary>
    internal bool IsComplete =>
        HasBeginning && HasEnd && Fragments.Count == unchecked((int)(EndFsn + 1));
}

/// <summary>Per-stream ordered-delivery state for RFC 8260 I-DATA, sequenced by 32-bit MID.</summary>
internal sealed class IDataReceiveStream
{
    internal uint NextMessageId { get; set; }

    internal Dictionary<uint, ReassembledMessage> Buffered { get; } = new();
}
