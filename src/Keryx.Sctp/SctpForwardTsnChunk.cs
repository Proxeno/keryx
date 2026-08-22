using Keryx.Core;

namespace Keryx.Sctp;

/// <summary>
/// One stream entry of a FORWARD TSN chunk: the largest stream sequence number the sender
/// abandoned on that stream (RFC 3758 §3.2).
/// </summary>
/// <param name="StreamId">Stream identifier.</param>
/// <param name="StreamSequence">Largest abandoned stream sequence number on that stream.</param>
public readonly record struct SctpForwardTsnStream(ushort StreamId, ushort StreamSequence);

/// <summary>
/// A FORWARD TSN chunk (RFC 3758 §3.2). Tells the peer to move its cumulative TSN ack past
/// messages the sender has abandoned — the mechanism that makes <c>maxRetransmits</c> work.
/// </summary>
public sealed class SctpForwardTsnChunk : SctpChunk
{
    /// <inheritdoc />
    public override SctpChunkType Type => SctpChunkType.ForwardTsn;

    /// <summary>The TSN the receiver should treat as cumulatively acknowledged.</summary>
    public uint NewCumulativeTsn { get; set; }

    /// <summary>Per-stream skip entries so the receiver can advance its ordered-delivery state.</summary>
    public List<SctpForwardTsnStream> Streams { get; } = new();

    /// <inheritdoc />
    public override int BodyLength => 4 + (Streams.Count * 4);

    /// <inheritdoc />
    public override void WriteBody(ref ByteWriter writer)
    {
        writer.WriteU32(NewCumulativeTsn);
        foreach (var stream in Streams)
        {
            writer.WriteU16(stream.StreamId);
            writer.WriteU16(stream.StreamSequence);
        }
    }

    internal static SctpForwardTsnChunk ParseBody(ReadOnlySpan<byte> body)
    {
        var reader = new ByteReader(body);
        var chunk = new SctpForwardTsnChunk { NewCumulativeTsn = reader.ReadU32() };
        while (reader.Remaining >= 4)
        {
            chunk.Streams.Add(new SctpForwardTsnStream(reader.ReadU16(), reader.ReadU16()));
        }

        return chunk;
    }
}
