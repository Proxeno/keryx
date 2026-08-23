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

    internal required int MessageId { get; init; }

    internal required ushort? MaxRetransmits { get; init; }

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
    internal int WireSize => 4 + SctpDataChunk.FixedHeaderLength + Payload.Length;

    internal SctpDataChunk ToChunk() =>
        new(Tsn, StreamId, StreamSequence, PayloadProtocolId, Payload, Beginning, Ending, Unordered);
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
