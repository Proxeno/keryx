using System.Buffers.Binary;
using Keryx.Core;

namespace Keryx.Rtp;

/// <summary>
/// Wire encoding for the transport-wide congestion-control header extension
/// (<c>draft-holmer-rmcat-transport-wide-cc-extensions-01</c> §2): a two-octet, monotonically
/// increasing sequence number carried as an RFC 8285 §4.2 one-byte-header extension element.
/// </summary>
/// <remarks>
/// Stamping this element on every outbound RTP packet is what lets the remote endpoint return
/// <see cref="Rtcp.RtcpTransportCcFeedback"/>; the value has no per-stream meaning and is allocated
/// from a single transport-wide counter shared by every SSRC on the connection.
/// </remarks>
public static class TransportCcExtension
{
    /// <summary>
    /// Length in bytes of the one-byte-header element body once padded to the RFC 3550 §5.3.1 four-byte
    /// boundary: the <c>id|len</c> octet plus the two sequence-number octets, padded up from three to four.
    /// </summary>
    public const int OneByteBodyLength = 4;

    /// <summary>
    /// Total bytes a stamped extension adds to an RTP header: the four-byte <c>0xBEDE</c> profile and
    /// word-count prefix plus the padded <see cref="OneByteBodyLength"/> body.
    /// </summary>
    public const int OneByteHeaderOverhead = 4 + OneByteBodyLength;

    /// <summary>
    /// Writes the one-byte-header extension body (excluding the profile/word-count prefix) carrying
    /// <paramref name="sequenceNumber"/> under the negotiated element identifier.
    /// </summary>
    /// <param name="destination">Buffer receiving the body; must hold at least <see cref="OneByteBodyLength"/> bytes.</param>
    /// <param name="id">The element identifier (1–14) negotiated via <c>a=extmap</c>.</param>
    /// <param name="sequenceNumber">The transport-wide sequence number, written big-endian.</param>
    /// <returns>The body length in bytes, always <see cref="OneByteBodyLength"/>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The identifier is outside 1–14.</exception>
    /// <exception cref="ByteBufferException">The destination cannot hold the body.</exception>
    public static int WriteOneByteBody(Span<byte> destination, byte id, ushort sequenceNumber)
    {
        if (id is < 1 or > 14)
        {
            throw new ArgumentOutOfRangeException(nameof(id), id, "One-byte-header element identifiers are 1–14.");
        }

        if (destination.Length < OneByteBodyLength)
        {
            throw new ByteBufferException(
                $"A transport-wide CC extension body needs {OneByteBodyLength} byte(s) but the destination holds {destination.Length}.");
        }

        // RFC 8285 §4.2: header octet is ID (4 bits) | len-1 (4 bits); the value is two octets, so len-1
        // is 1. The three used bytes are padded up to the four-byte boundary RFC 3550 §5.3.1 requires.
        destination[0] = (byte)((id << 4) | 0x01);
        BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(1, 2), sequenceNumber);
        destination[3] = 0;
        return OneByteBodyLength;
    }

    /// <summary>
    /// Reads the transport-wide sequence number from a parsed header, if the negotiated element is present.
    /// </summary>
    /// <param name="header">A parsed RTP header.</param>
    /// <param name="id">The element identifier (1–14) negotiated via <c>a=extmap</c>.</param>
    /// <param name="sequenceNumber">On success, the decoded sequence number.</param>
    /// <returns>
    /// <see langword="true"/> when a two-octet element with that identifier is present; never throws for
    /// malformed or truncated extensions.
    /// </returns>
    public static bool TryRead(in RtpHeader header, byte id, out ushort sequenceNumber)
    {
        if (header.TryGetExtension(id, out var data) && data.Length == 2)
        {
            sequenceNumber = BinaryPrimitives.ReadUInt16BigEndian(data);
            return true;
        }

        sequenceNumber = 0;
        return false;
    }
}
