using Keryx.Core;

namespace Keryx.Sctp;

/// <summary>
/// One gap ack block of a SACK: a run of received TSNs expressed as offsets from the cumulative
/// TSN ack (RFC 9260 §3.3.4). Both bounds are inclusive.
/// </summary>
/// <param name="Start">Offset of the first TSN in the run, relative to the cumulative TSN ack.</param>
/// <param name="End">Offset of the last TSN in the run, relative to the cumulative TSN ack.</param>
public readonly record struct SctpGapAckBlock(ushort Start, ushort End);

/// <summary>A SACK chunk (RFC 9260 §3.3.4).</summary>
public sealed class SctpSackChunk : SctpChunk
{
    /// <inheritdoc />
    public override SctpChunkType Type => SctpChunkType.Sack;

    /// <summary>The highest TSN below which every TSN has been received.</summary>
    public uint CumulativeTsnAck { get; set; }

    /// <summary>The sender's remaining receive window, in bytes.</summary>
    public uint AdvertisedReceiverWindow { get; set; }

    /// <summary>Runs of TSNs received above the cumulative ack, in ascending order.</summary>
    public List<SctpGapAckBlock> GapAckBlocks { get; } = new();

    /// <summary>TSNs the sender received more than once since its previous SACK.</summary>
    public List<uint> DuplicateTsns { get; } = new();

    /// <inheritdoc />
    public override int BodyLength => 12 + (GapAckBlocks.Count * 4) + (DuplicateTsns.Count * 4);

    /// <inheritdoc />
    public override void WriteBody(ref ByteWriter writer)
    {
        writer.WriteU32(CumulativeTsnAck);
        writer.WriteU32(AdvertisedReceiverWindow);
        writer.WriteU16((ushort)GapAckBlocks.Count);
        writer.WriteU16((ushort)DuplicateTsns.Count);
        foreach (var block in GapAckBlocks)
        {
            writer.WriteU16(block.Start);
            writer.WriteU16(block.End);
        }

        foreach (var tsn in DuplicateTsns)
        {
            writer.WriteU32(tsn);
        }
    }

    internal static SctpSackChunk ParseBody(ReadOnlySpan<byte> body)
    {
        var reader = new ByteReader(body);
        var chunk = new SctpSackChunk
        {
            CumulativeTsnAck = reader.ReadU32(),
            AdvertisedReceiverWindow = reader.ReadU32(),
        };
        var gapCount = reader.ReadU16();
        var dupCount = reader.ReadU16();
        for (var i = 0; i < gapCount; i++)
        {
            chunk.GapAckBlocks.Add(new SctpGapAckBlock(reader.ReadU16(), reader.ReadU16()));
        }

        for (var i = 0; i < dupCount; i++)
        {
            chunk.DuplicateTsns.Add(reader.ReadU32());
        }

        return chunk;
    }
}
