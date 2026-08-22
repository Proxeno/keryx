using Keryx.Core;

namespace Keryx.Rtp.Rtcp;

/// <summary>
/// Receiver Estimated Maximum Bitrate (REMB), <c>draft-alvestrand-rmcat-remb-03</c> §2.2: an
/// application-layer feedback message (payload-specific feedback, FMT 15) whose FCI starts with the
/// ASCII identifier <c>REMB</c> and carries a 6-bit exponent / 18-bit mantissa bitrate estimate.
/// </summary>
/// <remarks>
/// REMB predates transport-wide congestion control and is still emitted by older endpoints. Keryx
/// parses it so a bandwidth estimator can consume it; new senders should prefer
/// <see cref="RtcpTransportCcFeedback"/>.
/// </remarks>
public sealed class RtcpReceiverEstimatedMaxBitrate : RtcpFeedbackPacket
{
    /// <summary>The four ASCII bytes that identify a REMB message: <c>R</c>, <c>E</c>, <c>M</c>, <c>B</c>.</summary>
    public const uint Identifier = 0x52_45_4D_42;

    /// <summary>Largest mantissa the 18-bit field can hold.</summary>
    public const uint MaxMantissa = (1u << 18) - 1;

    private readonly List<uint> _ssrcs = [];

    /// <summary>Creates an empty REMB message.</summary>
    public RtcpReceiverEstimatedMaxBitrate()
    {
    }

    /// <summary>Creates a REMB message for a single stream.</summary>
    /// <param name="senderSsrc">SSRC of the receiver making the estimate.</param>
    /// <param name="bitrateBitsPerSecond">The estimated available bitrate.</param>
    /// <param name="ssrcs">The SSRCs the estimate applies to.</param>
    /// <exception cref="ArgumentNullException"><paramref name="ssrcs"/> is <see langword="null"/>.</exception>
    public RtcpReceiverEstimatedMaxBitrate(uint senderSsrc, ulong bitrateBitsPerSecond, params uint[] ssrcs)
    {
        ArgumentNullException.ThrowIfNull(ssrcs);
        SenderSsrc = senderSsrc;
        MediaSsrc = 0;
        BitrateBitsPerSecond = bitrateBitsPerSecond;
        _ssrcs.AddRange(ssrcs);
    }

    /// <summary>The estimated available bitrate, in bits per second.</summary>
    public ulong BitrateBitsPerSecond { get; set; }

    /// <summary>The SSRCs this estimate applies to.</summary>
    public IList<uint> Ssrcs => _ssrcs;

    /// <inheritdoc />
    public override RtcpPacketType PacketType => RtcpPacketType.PayloadSpecificFeedback;

    /// <inheritdoc />
    public override byte FeedbackMessageType => (byte)RtcpPayloadFeedbackType.ApplicationLayerFeedback;

    /// <inheritdoc />
    protected override int FeedbackControlInformationLength => 8 + (_ssrcs.Count * 4);

    /// <summary>Parses a REMB message.</summary>
    /// <param name="buffer">The complete packet, common header included.</param>
    /// <param name="packet">On success, the parsed message.</param>
    /// <returns>
    /// <see langword="false"/> when the packet is not application-layer feedback, does not carry the
    /// <c>REMB</c> identifier, or declares more SSRCs than the FCI holds.
    /// </returns>
    public static bool TryParse(ReadOnlySpan<byte> buffer, out RtcpReceiverEstimatedMaxBitrate? packet)
    {
        packet = null;
        if (!TryReadFeedbackHeader(
                buffer,
                RtcpPacketType.PayloadSpecificFeedback,
                (byte)RtcpPayloadFeedbackType.ApplicationLayerFeedback,
                out var senderSsrc,
                out var mediaSsrc,
                out var fci)
            || fci.Length < 8)
        {
            return false;
        }

        var reader = new ByteReader(fci);
        if (reader.ReadU32() != Identifier)
        {
            return false;
        }

        var ssrcCount = reader.ReadU8();
        var packed = reader.ReadU24();
        var exponent = (int)(packed >> 18);
        var mantissa = packed & MaxMantissa;

        if (reader.Remaining < ssrcCount * 4)
        {
            return false;
        }

        var parsed = new RtcpReceiverEstimatedMaxBitrate
        {
            SenderSsrc = senderSsrc,
            MediaSsrc = mediaSsrc,
            BitrateBitsPerSecond = (ulong)mantissa << exponent,
        };

        for (var i = 0; i < ssrcCount; i++)
        {
            parsed._ssrcs.Add(reader.ReadU32());
        }

        packet = parsed;
        return true;
    }

    /// <inheritdoc />
    protected override int WriteFeedbackControlInformation(Span<byte> destination)
    {
        var mantissa = BitrateBitsPerSecond;
        var exponent = 0;
        while (mantissa > MaxMantissa && exponent < 63)
        {
            mantissa >>= 1;
            exponent++;
        }

        var writer = new ByteWriter(destination);
        writer.WriteU32(Identifier);
        writer.WriteU8((byte)_ssrcs.Count);
        writer.WriteU24(((uint)exponent << 18) | ((uint)mantissa & MaxMantissa));
        foreach (var ssrc in _ssrcs)
        {
            writer.WriteU32(ssrc);
        }

        return writer.Position;
    }
}
