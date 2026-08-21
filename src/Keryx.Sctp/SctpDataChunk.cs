using Keryx.Core;

namespace Keryx.Sctp;

/// <summary>
/// A DATA chunk (RFC 9260 §3.3.1): one fragment of a user message, carrying a TSN, the stream
/// identifier and sequence number, the payload protocol identifier and the payload itself.
/// </summary>
public sealed class SctpDataChunk : SctpChunk
{
    /// <summary>Flag bit marking the last fragment of a user message (E).</summary>
    public const byte EndingFlag = 0x01;

    /// <summary>Flag bit marking the first fragment of a user message (B).</summary>
    public const byte BeginningFlag = 0x02;

    /// <summary>Flag bit marking the message as unordered (U).</summary>
    public const byte UnorderedFlag = 0x04;

    /// <summary>Flag bit requesting that the receiver not delay its SACK (I).</summary>
    public const byte ImmediateFlag = 0x08;

    /// <summary>Bytes of chunk header a DATA chunk adds on top of the four-byte chunk header.</summary>
    public const int FixedHeaderLength = 12;

    /// <summary>Creates a DATA chunk.</summary>
    /// <param name="tsn">Transmission sequence number.</param>
    /// <param name="streamId">Stream identifier.</param>
    /// <param name="streamSequence">Stream sequence number; ignored when <paramref name="unordered"/> is true.</param>
    /// <param name="payloadProtocolId">Payload protocol identifier (see <see cref="SctpPpid"/>).</param>
    /// <param name="payload">User payload; stored by reference, not copied.</param>
    /// <param name="beginning">Whether this is the first fragment of the message.</param>
    /// <param name="ending">Whether this is the last fragment of the message.</param>
    /// <param name="unordered">Whether the message bypasses per-stream ordering.</param>
    public SctpDataChunk(
        uint tsn,
        ushort streamId,
        ushort streamSequence,
        uint payloadProtocolId,
        byte[] payload,
        bool beginning = true,
        bool ending = true,
        bool unordered = false)
    {
        ArgumentNullException.ThrowIfNull(payload);
        Tsn = tsn;
        StreamId = streamId;
        StreamSequence = streamSequence;
        PayloadProtocolId = payloadProtocolId;
        Payload = payload;
        Beginning = beginning;
        Ending = ending;
        Unordered = unordered;
    }

    /// <inheritdoc />
    public override SctpChunkType Type => SctpChunkType.Data;

    /// <summary>Transmission sequence number.</summary>
    public uint Tsn { get; set; }

    /// <summary>Stream identifier.</summary>
    public ushort StreamId { get; set; }

    /// <summary>Per-stream sequence number, meaningful only for ordered messages.</summary>
    public ushort StreamSequence { get; set; }

    /// <summary>Payload protocol identifier.</summary>
    public uint PayloadProtocolId { get; set; }

    /// <summary>The user payload fragment.</summary>
    public byte[] Payload { get; }

    /// <summary>Whether this chunk carries the first fragment of a user message (B flag).</summary>
    public bool Beginning
    {
        get => (Flags & BeginningFlag) != 0;
        set => Flags = value ? (byte)(Flags | BeginningFlag) : (byte)(Flags & ~BeginningFlag);
    }

    /// <summary>Whether this chunk carries the last fragment of a user message (E flag).</summary>
    public bool Ending
    {
        get => (Flags & EndingFlag) != 0;
        set => Flags = value ? (byte)(Flags | EndingFlag) : (byte)(Flags & ~EndingFlag);
    }

    /// <summary>Whether the message bypasses per-stream ordering (U flag).</summary>
    public bool Unordered
    {
        get => (Flags & UnorderedFlag) != 0;
        set => Flags = value ? (byte)(Flags | UnorderedFlag) : (byte)(Flags & ~UnorderedFlag);
    }

    /// <summary>Whether the sender asked the receiver not to delay its SACK (I flag).</summary>
    public bool Immediate
    {
        get => (Flags & ImmediateFlag) != 0;
        set => Flags = value ? (byte)(Flags | ImmediateFlag) : (byte)(Flags & ~ImmediateFlag);
    }

    /// <inheritdoc />
    public override int BodyLength => FixedHeaderLength + Payload.Length;

    /// <inheritdoc />
    public override void WriteBody(ref ByteWriter writer)
    {
        writer.WriteU32(Tsn);
        writer.WriteU16(StreamId);
        writer.WriteU16(StreamSequence);
        writer.WriteU32(PayloadProtocolId);
        writer.WriteBytes(Payload);
    }

    internal static SctpDataChunk ParseBody(byte flags, ReadOnlySpan<byte> body)
    {
        var reader = new ByteReader(body);
        var tsn = reader.ReadU32();
        var streamId = reader.ReadU16();
        var streamSequence = reader.ReadU16();
        var ppid = reader.ReadU32();
        var payload = reader.Peek().ToArray();
        var chunk = new SctpDataChunk(tsn, streamId, streamSequence, ppid, payload)
        {
            Flags = flags,
        };
        return chunk;
    }
}
