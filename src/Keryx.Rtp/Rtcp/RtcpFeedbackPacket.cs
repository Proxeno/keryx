namespace Keryx.Rtp.Rtcp;

/// <summary>
/// Base for the RTP feedback packets of RFC 4585 §6.1: packet types 205 and 206 share a 12-byte
/// header (common header, sender SSRC, media source SSRC) followed by a feedback control information
/// (FCI) block whose layout depends on the feedback message type.
/// </summary>
public abstract class RtcpFeedbackPacket : RtcpPacket
{
    /// <summary>Length in bytes of the common feedback header, including the four-byte RTCP header.</summary>
    public const int FeedbackHeaderLength = 12;

    /// <summary>SSRC of the endpoint sending the feedback.</summary>
    public uint SenderSsrc { get; set; }

    /// <summary>SSRC of the media source the feedback is about.</summary>
    public uint MediaSsrc { get; set; }

    /// <summary>The feedback message type written into the count field of the common header.</summary>
    public abstract byte FeedbackMessageType { get; }

    /// <summary>Serialized length in bytes of the FCI block that follows the feedback header.</summary>
    protected abstract int FeedbackControlInformationLength { get; }

    /// <inheritdoc />
    public override int Length => FeedbackHeaderLength + FeedbackControlInformationLength;

    /// <inheritdoc />
    public override int WriteTo(Span<byte> destination)
    {
        var offset = WriteCommonHeader(destination, FeedbackMessageType);
        var writer = new Core.ByteWriter(destination[offset..]);
        writer.WriteU32(SenderSsrc);
        writer.WriteU32(MediaSsrc);
        offset += writer.Position;
        return offset + WriteFeedbackControlInformation(destination[offset..]);
    }

    /// <summary>Serializes the FCI block.</summary>
    /// <param name="destination">Buffer positioned immediately after the feedback header.</param>
    /// <returns>The number of bytes written.</returns>
    protected abstract int WriteFeedbackControlInformation(Span<byte> destination);

    /// <summary>
    /// Validates the common feedback header and hands back the FCI bytes.
    /// </summary>
    /// <param name="buffer">The complete packet, common header included.</param>
    /// <param name="packetType">Expected RTCP packet type (205 or 206).</param>
    /// <param name="feedbackMessageType">Expected feedback message type.</param>
    /// <param name="senderSsrc">On success, the feedback sender's SSRC.</param>
    /// <param name="mediaSsrc">On success, the media source SSRC.</param>
    /// <param name="fci">On success, the feedback control information block.</param>
    /// <returns><see langword="false"/> when the header does not match or the packet is truncated.</returns>
    protected static bool TryReadFeedbackHeader(
        ReadOnlySpan<byte> buffer,
        RtcpPacketType packetType,
        byte feedbackMessageType,
        out uint senderSsrc,
        out uint mediaSsrc,
        out ReadOnlySpan<byte> fci)
    {
        senderSsrc = 0;
        mediaSsrc = 0;
        fci = default;

        if (!RtcpPacketHeader.TryParse(buffer, out var header)
            || header.PacketType != packetType
            || header.Count != feedbackMessageType
            || header.PacketLength < FeedbackHeaderLength
            || header.PacketLength > buffer.Length)
        {
            return false;
        }

        var packet = buffer[..header.PacketLength];
        var reader = new Core.ByteReader(packet);
        reader.Skip(RtcpPacketHeader.Length);
        senderSsrc = reader.ReadU32();
        mediaSsrc = reader.ReadU32();
        fci = packet[FeedbackHeaderLength..];
        return true;
    }
}
