using Keryx.Core;

namespace Keryx.Rtp.Fec;

/// <summary>
/// The redundant audio/video data payload format of RFC 2198 ("RED"), used here to carry a primary
/// media block alongside RFC 5109 ULPFEC repair data under a single RTP payload type.
/// </summary>
/// <remarks>
/// <para>
/// A RED payload is a run of block headers followed by the block bodies, in the same order. Every
/// block but the last carries a four-octet redundant header; the last carries a one-octet primary
/// header. The high bit of the first header octet — the F bit — is set on every redundant header and
/// clear on the primary header, so a decoder walks the headers until it meets a clear F bit:
/// </para>
/// <code>
/// Redundant block header (F = 1)          Primary block header (F = 0)
///  0                   1                    0
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 ...     0 1 2 3 4 5 6 7
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+        +-+-+-+-+-+-+-+-+
/// |1|   block PT  |  timestamp off  |      |0|   block PT  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+      +-+-+-+-+-+-+-+-+
/// |   ... offset  |   block length  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// </code>
/// <para>
/// The timestamp offset is the primary packet's RTP timestamp minus the redundant block's, a 14-bit
/// unsigned value; the block length is a 10-bit octet count. The primary block has no length — it runs
/// to the end of the payload — and no timestamp offset, since it is the reference the offsets are
/// measured against.
/// </para>
/// <para>
/// This type holds only the payload-format helpers, like <see cref="RtxPacket"/>; the bodies alias the
/// caller's buffer and nothing here allocates.
/// </para>
/// </remarks>
public static class RedPacket
{
    /// <summary>Length in bytes of a redundant block header (RFC 2198 §3): F, PT, timestamp offset, length.</summary>
    public const int RedundantHeaderLength = 4;

    /// <summary>Length in bytes of the primary block header (RFC 2198 §3): F and PT only.</summary>
    public const int PrimaryHeaderLength = 1;

    /// <summary>Largest block body a redundant header can describe; the length field is ten bits wide.</summary>
    public const int MaxRedundantBlockLength = 0x3FF;

    /// <summary>Largest timestamp offset a redundant header can carry; the field is fourteen bits wide.</summary>
    public const int MaxTimestampOffset = 0x3FFF;

    private const byte FBit = 0x80;
    private const byte PayloadTypeMask = 0x7F;

    /// <summary>
    /// Writes a RED payload carrying only a primary block: a one-octet header naming the block's payload
    /// type, then the block body verbatim. This is the encapsulation Keryx uses to wrap both media and
    /// ULPFEC packets, each under its own inner payload type.
    /// </summary>
    /// <param name="primaryPayloadType">The inner payload type of the block, 0–127.</param>
    /// <param name="primaryData">The block body — the media or FEC payload being wrapped.</param>
    /// <param name="destination">
    /// Buffer receiving the RED payload. May overlap <paramref name="primaryData"/>; the body is moved
    /// before the header is written.
    /// </param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The payload type does not fit seven bits.</exception>
    /// <exception cref="ByteBufferException">The destination cannot hold the header plus the body.</exception>
    public static int WritePrimaryOnly(byte primaryPayloadType, ReadOnlySpan<byte> primaryData, Span<byte> destination)
    {
        ArgumentOutOfRangeException.ThrowIfGreaterThan(primaryPayloadType, (byte)127);

        var required = PrimaryHeaderLength + primaryData.Length;
        if (destination.Length < required)
        {
            throw new ByteBufferException(
                $"A RED payload of {required} byte(s) does not fit a {destination.Length}-byte destination.");
        }

        primaryData.CopyTo(destination[PrimaryHeaderLength..]);
        destination[0] = (byte)(primaryPayloadType & PayloadTypeMask);
        return required;
    }

    /// <summary>
    /// Writes a RED payload carrying one redundant block ahead of the primary block: the four-octet
    /// redundant header, the one-octet primary header, then the two bodies in that order (RFC 2198 §3).
    /// </summary>
    /// <param name="redundantPayloadType">Inner payload type of the redundant block, 0–127.</param>
    /// <param name="timestampOffset">
    /// Primary timestamp minus the redundant block's timestamp, 0–<see cref="MaxTimestampOffset"/>.
    /// </param>
    /// <param name="redundantData">The redundant block body; its length must not exceed <see cref="MaxRedundantBlockLength"/>.</param>
    /// <param name="primaryPayloadType">Inner payload type of the primary block, 0–127.</param>
    /// <param name="primaryData">The primary block body.</param>
    /// <param name="destination">Buffer receiving the RED payload. Must not overlap either body.</param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="ArgumentOutOfRangeException">A payload type, the timestamp offset, or the redundant length is out of range.</exception>
    /// <exception cref="ByteBufferException">The destination cannot hold the payload.</exception>
    public static int WriteWithSingleRedundancy(
        byte redundantPayloadType,
        ushort timestampOffset,
        ReadOnlySpan<byte> redundantData,
        byte primaryPayloadType,
        ReadOnlySpan<byte> primaryData,
        Span<byte> destination)
    {
        ArgumentOutOfRangeException.ThrowIfGreaterThan(redundantPayloadType, (byte)127);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(primaryPayloadType, (byte)127);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(timestampOffset, (ushort)MaxTimestampOffset);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(redundantData.Length, MaxRedundantBlockLength);

        var writer = new ByteWriter(destination);
        writer.WriteU8((byte)(FBit | (redundantPayloadType & PayloadTypeMask)));

        // 14-bit timestamp offset then 10-bit block length, packed big-endian across three octets.
        var packed = ((uint)timestampOffset << 10) | (uint)(redundantData.Length & MaxRedundantBlockLength);
        writer.WriteU24(packed);

        writer.WriteU8((byte)(primaryPayloadType & PayloadTypeMask));
        writer.WriteBytes(redundantData);
        writer.WriteBytes(primaryData);
        return writer.Position;
    }

    /// <summary>
    /// Reads the primary block — the last block — from a RED payload, skipping any redundant blocks.
    /// </summary>
    /// <param name="redPayload">The RED payload, headers included.</param>
    /// <param name="primaryPayloadType">On success, the primary block's inner payload type.</param>
    /// <param name="primaryData">On success, the primary block body; it aliases <paramref name="redPayload"/>.</param>
    /// <returns><see langword="false"/> when the payload is truncated or its block lengths run past the end.</returns>
    public static bool TryReadPrimary(
        ReadOnlySpan<byte> redPayload,
        out byte primaryPayloadType,
        out ReadOnlySpan<byte> primaryData)
    {
        primaryPayloadType = 0;
        primaryData = default;

        // Enumerate through the local directly rather than foreach: the enumerator is a ref struct whose
        // GetEnumerator returns a copy, so IsComplete must be read from the same instance MoveNext advanced.
        var enumerator = new RedBlockEnumerator(redPayload);
        var valid = false;
        while (enumerator.MoveNext())
        {
            if (enumerator.Current.IsPrimary)
            {
                primaryPayloadType = enumerator.Current.PayloadType;
                primaryData = enumerator.Current.Data;
                valid = true;
            }
        }

        // A well-formed payload always ends on the primary block; if enumeration stopped early on a
        // malformed header, IsComplete stays false.
        return valid && enumerator.IsComplete;
    }

    /// <summary>Enumerates the blocks of a RED payload in wire order (redundant blocks, then the primary).</summary>
    /// <param name="redPayload">The RED payload, headers included.</param>
    /// <returns>An allocation-free enumerator usable directly in <see langword="foreach"/>.</returns>
    public static RedBlockEnumerator GetBlocks(ReadOnlySpan<byte> redPayload) => new(redPayload);
}
