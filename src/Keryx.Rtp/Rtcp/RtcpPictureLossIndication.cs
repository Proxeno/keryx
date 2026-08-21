namespace Keryx.Rtp.Rtcp;

/// <summary>
/// Picture loss indication (PLI), RFC 4585 §6.3.1: payload-specific feedback, FMT 1, with no FCI.
/// A receiver sends it to ask the encoder for a new decoder refresh point.
/// </summary>
public sealed class RtcpPictureLossIndication : RtcpFeedbackPacket
{
    /// <summary>Creates an empty PLI.</summary>
    public RtcpPictureLossIndication()
    {
    }

    /// <summary>Creates a PLI.</summary>
    /// <param name="senderSsrc">SSRC of the endpoint requesting the refresh.</param>
    /// <param name="mediaSsrc">SSRC of the video stream that needs refreshing.</param>
    public RtcpPictureLossIndication(uint senderSsrc, uint mediaSsrc)
    {
        SenderSsrc = senderSsrc;
        MediaSsrc = mediaSsrc;
    }

    /// <inheritdoc />
    public override RtcpPacketType PacketType => RtcpPacketType.PayloadSpecificFeedback;

    /// <inheritdoc />
    public override byte FeedbackMessageType => (byte)RtcpPayloadFeedbackType.PictureLossIndication;

    /// <inheritdoc />
    protected override int FeedbackControlInformationLength => 0;

    /// <summary>Parses a PLI.</summary>
    /// <param name="buffer">The complete packet, common header included.</param>
    /// <param name="packet">On success, the parsed packet.</param>
    /// <returns><see langword="false"/> when the packet is not a well-formed PLI.</returns>
    public static bool TryParse(ReadOnlySpan<byte> buffer, out RtcpPictureLossIndication? packet)
    {
        packet = null;
        if (!TryReadFeedbackHeader(
                buffer,
                RtcpPacketType.PayloadSpecificFeedback,
                (byte)RtcpPayloadFeedbackType.PictureLossIndication,
                out var senderSsrc,
                out var mediaSsrc,
                out _))
        {
            return false;
        }

        packet = new RtcpPictureLossIndication(senderSsrc, mediaSsrc);
        return true;
    }

    /// <inheritdoc />
    protected override int WriteFeedbackControlInformation(Span<byte> destination) => 0;
}
