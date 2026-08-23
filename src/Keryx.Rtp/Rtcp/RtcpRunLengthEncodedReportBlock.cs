using Keryx.Core;

namespace Keryx.Rtp.Rtcp;

/// <summary>
/// Shared model for the two run-length-encoded report blocks — Loss RLE (RFC 3611 §4.1) and
/// Duplicate RLE (RFC 3611 §4.2) — which are byte-for-byte identical apart from their block type.
/// Each reports on the packets of one source over the sequence-number range
/// <see cref="BeginSequence"/> (inclusive) to <see cref="EndSequence"/> (exclusive) as a list of
/// 16-bit run-length chunks.
/// </summary>
public abstract class RtcpRunLengthEncodedReportBlock : RtcpExtendedReportBlock
{
    private readonly List<ushort> _chunks = [];

    /// <summary>SSRC of the source these statistics describe.</summary>
    public uint SourceSsrc { get; set; }

    /// <summary>
    /// Thinning value (the low four bits of the type-specific field): only sequence numbers that are
    /// zero modulo 2^T are reported.
    /// </summary>
    public byte Thinning { get; set; }

    /// <summary>First sequence number this block reports on (inclusive).</summary>
    public ushort BeginSequence { get; set; }

    /// <summary>Sequence number one past the last this block reports on (exclusive).</summary>
    public ushort EndSequence { get; set; }

    /// <summary>
    /// The run-length chunks (RFC 3611 §4.1.1): run-length or bit-vector chunks, or a terminating
    /// null chunk. Stored verbatim; a trailing null chunk added purely for word alignment is
    /// preserved on parse and re-emitted on write.
    /// </summary>
    public IList<ushort> Chunks => _chunks;

    /// <inheritdoc />
    public override int Length => HeaderLength + 8 + (PaddedChunkCount * 2);

    private int PaddedChunkCount => _chunks.Count + (_chunks.Count & 1);

    /// <inheritdoc />
    public override int WriteTo(Span<byte> destination)
    {
        var offset = WriteBlockHeader(destination, (byte)(Thinning & 0x0F));
        var writer = new ByteWriter(destination[offset..]);
        writer.WriteU32(SourceSsrc);
        writer.WriteU16(BeginSequence);
        writer.WriteU16(EndSequence);
        foreach (var chunk in _chunks)
        {
            writer.WriteU16(chunk);
        }

        if ((_chunks.Count & 1) != 0)
        {
            writer.WriteU16(0); // terminating null chunk pads the block to a 32-bit word boundary
        }

        return offset + writer.Position;
    }

    /// <summary>Populates this block from <paramref name="block"/> after the concrete type has been chosen.</summary>
    /// <param name="block">The complete block, header included.</param>
    /// <param name="expectedType">The block type the concrete subclass expects.</param>
    /// <returns><see langword="false"/> when the header is malformed or the body is truncated.</returns>
    protected bool TryLoad(ReadOnlySpan<byte> block, RtcpExtendedReportBlockType expectedType)
    {
        if (!TryReadHeader(block, out var blockType, out var typeSpecific, out var body)
            || blockType != (byte)expectedType)
        {
            return false;
        }

        try
        {
            var reader = new ByteReader(body);
            SourceSsrc = reader.ReadU32();
            BeginSequence = reader.ReadU16();
            EndSequence = reader.ReadU16();
            Thinning = (byte)(typeSpecific & 0x0F);
            while (reader.Remaining >= 2)
            {
                _chunks.Add(reader.ReadU16());
            }

            return true;
        }
        catch (ByteBufferException)
        {
            return false;
        }
    }
}
