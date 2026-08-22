using System.Buffers.Binary;
using Keryx.Core;

namespace Keryx.Rtp;

/// <summary>
/// The RTP retransmission payload format of RFC 4588 §4.
/// </summary>
/// <remarks>
/// <para>
/// An RTX packet repeats an original packet under a <em>separate</em> RTP stream: its own SSRC, its
/// own payload type and — importantly — its own sequence-number space, so the retransmission stream
/// stays gap-free even though it carries packets out of the original stream's order. The RTP
/// timestamp is copied verbatim from the original packet, and the payload is the two-octet original
/// sequence number (OSN) followed by the original packet's payload:
/// </para>
/// <code>
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            OSN                |                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
/// |                  original RTP packet payload                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// </code>
/// <para>
/// This type holds only the payload-format helpers. <see cref="RtxRetransmitter"/> composes them with
/// an <see cref="RtpStreamSender"/> to produce complete RTX packets.
/// </para>
/// </remarks>
public static class RtxPacket
{
    /// <summary>Length in bytes of the OSN field that opens every RTX payload (RFC 4588 §4).</summary>
    public const int OriginalSequenceNumberLength = 2;

    /// <summary>
    /// Writes an RTX payload: the original sequence number in network byte order, then the original
    /// packet's payload.
    /// </summary>
    /// <param name="originalSequenceNumber">The sequence number the original packet carried.</param>
    /// <param name="originalPayload">The original packet's payload, header excluded.</param>
    /// <param name="destination">
    /// Buffer receiving the RTX payload. May overlap <paramref name="originalPayload"/>; the payload
    /// is moved before the OSN is written.
    /// </param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="ByteBufferException">The destination cannot hold the OSN plus the payload.</exception>
    public static int WritePayload(
        ushort originalSequenceNumber,
        ReadOnlySpan<byte> originalPayload,
        Span<byte> destination)
    {
        var required = OriginalSequenceNumberLength + originalPayload.Length;
        if (destination.Length < required)
        {
            throw new ByteBufferException(
                $"An RTX payload of {required} byte(s) does not fit a {destination.Length}-byte destination.");
        }

        originalPayload.CopyTo(destination[OriginalSequenceNumberLength..]);
        BinaryPrimitives.WriteUInt16BigEndian(destination, originalSequenceNumber);
        return required;
    }

    /// <summary>Reads the OSN from the front of an RTX payload.</summary>
    /// <param name="rtxPayload">The RTX payload, OSN included.</param>
    /// <param name="originalSequenceNumber">On success, the original packet's sequence number.</param>
    /// <returns><see langword="false"/> when the payload is shorter than the OSN field.</returns>
    public static bool TryReadOriginalSequenceNumber(ReadOnlySpan<byte> rtxPayload, out ushort originalSequenceNumber)
    {
        if (rtxPayload.Length < OriginalSequenceNumberLength)
        {
            originalSequenceNumber = 0;
            return false;
        }

        originalSequenceNumber = BinaryPrimitives.ReadUInt16BigEndian(rtxPayload);
        return true;
    }

    /// <summary>
    /// Reconstructs the original RTP packet from an RTX packet (the inverse of RFC 4588 §4): the OSN
    /// becomes the sequence number, and the caller supplies the original stream's SSRC and payload
    /// type, which the RTX packet does not carry.
    /// </summary>
    /// <param name="rtxPacket">A complete RTX packet, RTP header included.</param>
    /// <param name="originalSsrc">SSRC of the stream being repaired, from <c>a=ssrc-group:FID</c>.</param>
    /// <param name="originalPayloadType">Payload type of the stream being repaired, from the rtx <c>apt</c>.</param>
    /// <param name="destination">Buffer receiving the reconstructed packet. Must not overlap <paramref name="rtxPacket"/>.</param>
    /// <param name="length">On success, the reconstructed packet's length in bytes.</param>
    /// <param name="originalSequenceNumber">On success, the OSN the RTX packet carried.</param>
    /// <returns>
    /// <see langword="false"/> when the buffer is not a well-formed RTP packet, its payload is shorter
    /// than the OSN field, or the destination is too small.
    /// </returns>
    public static bool TryDecapsulate(
        ReadOnlySpan<byte> rtxPacket,
        uint originalSsrc,
        byte originalPayloadType,
        Span<byte> destination,
        out int length,
        out ushort originalSequenceNumber)
    {
        length = 0;
        originalSequenceNumber = 0;

        if (!RtpPacket.TryParse(rtxPacket, out var parsed)
            || !TryReadOriginalSequenceNumber(parsed.Payload, out originalSequenceNumber))
        {
            return false;
        }

        var payload = parsed.Payload[OriginalSequenceNumberLength..];
        var header = parsed.Header;
        header.PayloadType = originalPayloadType;
        header.SequenceNumber = originalSequenceNumber;
        header.Ssrc = originalSsrc;
        header.HasPadding = false;

        if (!header.TryWriteTo(destination, out var headerLength)
            || destination.Length < headerLength + payload.Length)
        {
            return false;
        }

        payload.CopyTo(destination[headerLength..]);
        length = headerLength + payload.Length;
        return true;
    }
}
