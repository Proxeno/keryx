using Keryx.Core;

namespace Keryx.Sctp;

/// <summary>
/// An I-DATA chunk (RFC 8260 §2.1): the user-message-interleaving replacement for
/// <see cref="SctpDataChunk"/>. It carries the same TSN, stream identifier and B/E/U/I flags, but
/// replaces the per-fragment stream sequence number with a 32-bit <see cref="MessageIdentifier"/>
/// (MID) and reuses the fourth 32-bit field for two purposes: on the first fragment (B set) it
/// carries the <see cref="PayloadProtocolId"/>, and on every continuation fragment it carries the
/// <see cref="FragmentSequenceNumber"/> (FSN). Reassembly therefore keys on (stream, MID) and orders
/// fragments by FSN rather than by a contiguous run of TSNs, which is what lets fragments of one
/// message be interleaved on the wire with fragments and whole messages of other streams.
/// </summary>
public sealed class SctpIDataChunk : SctpChunk
{
    /// <summary>Bytes of chunk header an I-DATA chunk adds on top of the four-byte chunk header.</summary>
    public const int FixedHeaderLength = 16;

    /// <summary>Creates an I-DATA chunk.</summary>
    /// <param name="tsn">Transmission sequence number.</param>
    /// <param name="streamId">Stream identifier.</param>
    /// <param name="messageIdentifier">Message identifier (MID); scoped per stream and per ordered/unordered.</param>
    /// <param name="payloadProtocolId">Payload protocol identifier; meaningful only on the first fragment.</param>
    /// <param name="fragmentSequenceNumber">Fragment sequence number; meaningful only on continuation fragments.</param>
    /// <param name="payload">User payload fragment; stored by reference, not copied.</param>
    /// <param name="beginning">Whether this is the first fragment of the message (B).</param>
    /// <param name="ending">Whether this is the last fragment of the message (E).</param>
    /// <param name="unordered">Whether the message bypasses per-stream ordering (U).</param>
    public SctpIDataChunk(
        uint tsn,
        ushort streamId,
        uint messageIdentifier,
        uint payloadProtocolId,
        uint fragmentSequenceNumber,
        byte[] payload,
        bool beginning = true,
        bool ending = true,
        bool unordered = false)
    {
        ArgumentNullException.ThrowIfNull(payload);
        Tsn = tsn;
        StreamId = streamId;
        MessageIdentifier = messageIdentifier;
        PayloadProtocolId = payloadProtocolId;
        FragmentSequenceNumber = fragmentSequenceNumber;
        Payload = payload;
        Beginning = beginning;
        Ending = ending;
        Unordered = unordered;
    }

    /// <inheritdoc />
    public override SctpChunkType Type => SctpChunkType.IData;

    /// <summary>Transmission sequence number.</summary>
    public uint Tsn { get; set; }

    /// <summary>Stream identifier.</summary>
    public ushort StreamId { get; set; }

    /// <summary>Message identifier (MID). Identifies the message a fragment belongs to within a stream.</summary>
    public uint MessageIdentifier { get; set; }

    /// <summary>Payload protocol identifier; carried on the wire only on the first fragment (B set).</summary>
    public uint PayloadProtocolId { get; set; }

    /// <summary>
    /// Fragment sequence number; carried on the wire only on continuation fragments. The first
    /// fragment has an implicit FSN of zero (its slot on the wire holds the PPID instead).
    /// </summary>
    public uint FragmentSequenceNumber { get; set; }

    /// <summary>The user payload fragment.</summary>
    public byte[] Payload { get; }

    /// <summary>Whether this chunk carries the first fragment of a user message (B flag).</summary>
    public bool Beginning
    {
        get => (Flags & SctpDataChunk.BeginningFlag) != 0;
        set => Flags = value ? (byte)(Flags | SctpDataChunk.BeginningFlag) : (byte)(Flags & ~SctpDataChunk.BeginningFlag);
    }

    /// <summary>Whether this chunk carries the last fragment of a user message (E flag).</summary>
    public bool Ending
    {
        get => (Flags & SctpDataChunk.EndingFlag) != 0;
        set => Flags = value ? (byte)(Flags | SctpDataChunk.EndingFlag) : (byte)(Flags & ~SctpDataChunk.EndingFlag);
    }

    /// <summary>Whether the message bypasses per-stream ordering (U flag).</summary>
    public bool Unordered
    {
        get => (Flags & SctpDataChunk.UnorderedFlag) != 0;
        set => Flags = value ? (byte)(Flags | SctpDataChunk.UnorderedFlag) : (byte)(Flags & ~SctpDataChunk.UnorderedFlag);
    }

    /// <summary>Whether the sender asked the receiver not to delay its SACK (I flag).</summary>
    public bool Immediate
    {
        get => (Flags & SctpDataChunk.ImmediateFlag) != 0;
        set => Flags = value ? (byte)(Flags | SctpDataChunk.ImmediateFlag) : (byte)(Flags & ~SctpDataChunk.ImmediateFlag);
    }

    /// <inheritdoc />
    public override int BodyLength => FixedHeaderLength + Payload.Length;

    /// <inheritdoc />
    public override void WriteBody(ref ByteWriter writer)
    {
        writer.WriteU32(Tsn);
        writer.WriteU16(StreamId);
        writer.WriteU16(0);
        writer.WriteU32(MessageIdentifier);
        writer.WriteU32(Beginning ? PayloadProtocolId : FragmentSequenceNumber);
        writer.WriteBytes(Payload);
    }

    internal static SctpIDataChunk ParseBody(byte flags, ReadOnlySpan<byte> body)
    {
        var reader = new ByteReader(body);
        var tsn = reader.ReadU32();
        var streamId = reader.ReadU16();
        reader.Skip(2);
        var mid = reader.ReadU32();
        var ppidOrFsn = reader.ReadU32();
        var payload = reader.Peek().ToArray();
        var beginning = (flags & SctpDataChunk.BeginningFlag) != 0;
        var chunk = new SctpIDataChunk(
            tsn,
            streamId,
            mid,
            beginning ? ppidOrFsn : 0,
            beginning ? 0 : ppidOrFsn,
            payload)
        {
            Flags = flags,
        };
        return chunk;
    }
}
