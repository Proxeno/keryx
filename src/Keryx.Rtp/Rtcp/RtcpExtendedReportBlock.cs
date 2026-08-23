using Keryx.Core;

namespace Keryx.Rtp.Rtcp;

/// <summary>
/// Base class for the report blocks carried by an <see cref="RtcpExtendedReport"/> (RFC 3611 §3).
/// Every block starts with the same four-byte header — an eight-bit block type, an eight-bit
/// type-specific field, and a 16-bit length in 32-bit words minus one, including the header — and
/// then a type-specific, word-aligned body.
/// </summary>
public abstract class RtcpExtendedReportBlock
{
    /// <summary>Length of the block header (BT, type-specific, length) in bytes.</summary>
    public const int HeaderLength = 4;

    /// <summary>The block type written into the BT field.</summary>
    public abstract byte BlockType { get; }

    /// <summary>Total serialized length in bytes, including the four-byte block header; always a multiple of four.</summary>
    public abstract int Length { get; }

    /// <summary>Serializes the block, header included.</summary>
    /// <param name="destination">Buffer of at least <see cref="Length"/> bytes.</param>
    /// <returns>The number of bytes written, equal to <see cref="Length"/>.</returns>
    public abstract int WriteTo(Span<byte> destination);

    /// <summary>
    /// Parses one report block from the front of <paramref name="block"/>, dispatching on the block
    /// type. Types Keryx does not model are returned as <see cref="RtcpUnknownExtendedReportBlock"/>
    /// so an extended report stays parseable and re-serializable without loss.
    /// </summary>
    /// <param name="block">Buffer positioned at a report block; may contain trailing blocks.</param>
    /// <param name="parsed">On success, the parsed block.</param>
    /// <returns><see langword="false"/> when the block header is malformed or the body is inconsistent.</returns>
    public static bool TryParse(ReadOnlySpan<byte> block, out RtcpExtendedReportBlock? parsed)
    {
        parsed = null;
        if (!TryReadHeader(block, out var blockType, out var typeSpecific, out var body))
        {
            return false;
        }

        switch ((RtcpExtendedReportBlockType)blockType)
        {
            case RtcpExtendedReportBlockType.LossRle:
                return Wrap(RtcpLossRleReportBlock.TryParse(block, out var loss), loss, out parsed);
            case RtcpExtendedReportBlockType.DuplicateRle:
                return Wrap(RtcpDuplicateRleReportBlock.TryParse(block, out var dup), dup, out parsed);
            case RtcpExtendedReportBlockType.PacketReceiptTimes:
                return Wrap(RtcpPacketReceiptTimesReportBlock.TryParse(block, out var prt), prt, out parsed);
            case RtcpExtendedReportBlockType.ReceiverReferenceTime:
                return Wrap(RtcpReceiverReferenceTimeReportBlock.TryParse(block, out var rrt), rrt, out parsed);
            case RtcpExtendedReportBlockType.DelaySinceLastReceiverReport:
                return Wrap(RtcpDelaySinceLastReceiverReportBlock.TryParse(block, out var dlrr), dlrr, out parsed);
            case RtcpExtendedReportBlockType.StatisticsSummary:
                return Wrap(RtcpStatisticsSummaryReportBlock.TryParse(block, out var stats), stats, out parsed);
            default:
                parsed = new RtcpUnknownExtendedReportBlock(blockType, typeSpecific, body);
                return true;
        }
    }

    /// <summary>Writes the four-byte block header, deriving the length field from <see cref="Length"/>.</summary>
    /// <param name="destination">Destination buffer.</param>
    /// <param name="typeSpecific">The eight-bit type-specific field.</param>
    /// <returns>The number of bytes written, always <see cref="HeaderLength"/>.</returns>
    protected int WriteBlockHeader(Span<byte> destination, byte typeSpecific)
    {
        var writer = new ByteWriter(destination);
        writer.WriteU8(BlockType);
        writer.WriteU8(typeSpecific);
        writer.WriteU16((ushort)((Length / 4) - 1));
        return writer.Position;
    }

    /// <summary>
    /// Reads the four-byte block header and returns the body of exactly the length the header declares.
    /// </summary>
    /// <param name="block">Buffer positioned at a report block.</param>
    /// <param name="blockType">On success, the BT field.</param>
    /// <param name="typeSpecific">On success, the type-specific field.</param>
    /// <param name="body">On success, the block body, excluding the four-byte header.</param>
    /// <returns><see langword="false"/> when the header is truncated or declares a length past the buffer.</returns>
    protected static bool TryReadHeader(
        ReadOnlySpan<byte> block, out byte blockType, out byte typeSpecific, out ReadOnlySpan<byte> body)
    {
        blockType = 0;
        typeSpecific = 0;
        body = default;
        if (block.Length < HeaderLength)
        {
            return false;
        }

        blockType = block[0];
        typeSpecific = block[1];
        var total = ((((block[2] << 8) | block[3]) + 1) * 4);
        if (total > block.Length)
        {
            return false;
        }

        body = block[HeaderLength..total];
        return true;
    }

    private static bool Wrap<T>(bool success, T? parsed, out RtcpExtendedReportBlock? block)
        where T : RtcpExtendedReportBlock
    {
        block = success ? parsed : null;
        return success && parsed is not null;
    }
}

/// <summary>
/// An extended report block whose type Keryx does not model. It preserves the type-specific field and
/// body verbatim so an extended report can be traversed and re-serialized without loss (RFC 3611 §3
/// requires unrecognized block types to be skipped, not treated as fatal).
/// </summary>
public sealed class RtcpUnknownExtendedReportBlock : RtcpExtendedReportBlock
{
    /// <summary>Creates an unknown block from its header fields and body.</summary>
    /// <param name="blockType">The BT field.</param>
    /// <param name="typeSpecific">The type-specific field.</param>
    /// <param name="body">The block body, excluding the four-byte header.</param>
    public RtcpUnknownExtendedReportBlock(byte blockType, byte typeSpecific, ReadOnlySpan<byte> body)
    {
        BlockType = blockType;
        TypeSpecific = typeSpecific;
        Body = body.ToArray();
    }

    /// <inheritdoc />
    public override byte BlockType { get; }

    /// <summary>The eight-bit type-specific field as received.</summary>
    public byte TypeSpecific { get; }

    /// <summary>The block body, excluding the four-byte header.</summary>
    public byte[] Body { get; }

    /// <inheritdoc />
    public override int Length => HeaderLength + Body.Length;

    /// <inheritdoc />
    public override int WriteTo(Span<byte> destination)
    {
        var offset = WriteBlockHeader(destination, TypeSpecific);
        Body.CopyTo(destination[offset..]);
        return offset + Body.Length;
    }
}
