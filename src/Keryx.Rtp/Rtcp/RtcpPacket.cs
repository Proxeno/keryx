namespace Keryx.Rtp.Rtcp;

/// <summary>
/// Base class for the typed RTCP packets Keryx understands. Every packet knows its own on-the-wire
/// length and can serialize itself into a caller-supplied buffer.
/// </summary>
/// <remarks>
/// RTCP is not on the per-packet hot path — a handful of packets per second per stream — so the typed
/// model favours clarity over avoiding the one small allocation per parsed packet. The zero-allocation
/// path for scanning a compound packet is <see cref="RtcpCompoundReader"/>.
/// </remarks>
public abstract class RtcpPacket
{
    /// <summary>The RTCP packet type written into the common header.</summary>
    public abstract RtcpPacketType PacketType { get; }

    /// <summary>Total serialized length in bytes, including the four-byte common header.</summary>
    public abstract int Length { get; }

    /// <summary>Serializes the packet, common header included.</summary>
    /// <param name="destination">Buffer of at least <see cref="Length"/> bytes.</param>
    /// <returns>The number of bytes written, equal to <see cref="Length"/>.</returns>
    public abstract int WriteTo(Span<byte> destination);

    /// <summary>Serializes the packet into a freshly allocated array. Convenience for tests and tooling.</summary>
    /// <returns>The serialized packet.</returns>
    public byte[] ToByteArray()
    {
        var buffer = new byte[Length];
        WriteTo(buffer);
        return buffer;
    }

    /// <summary>
    /// Parses one RTCP packet from the front of <paramref name="buffer"/>, dispatching on packet type
    /// and, for feedback packets, on the feedback message type.
    /// </summary>
    /// <param name="buffer">Buffer positioned at an RTCP packet; may contain trailing packets.</param>
    /// <param name="packet">
    /// On success, the parsed packet. Types Keryx does not model are returned as
    /// <see cref="RtcpUnknownPacket"/> rather than failing, so a compound packet stays parseable.
    /// </param>
    /// <returns><see langword="false"/> when the header is malformed or the packet body is inconsistent.</returns>
    public static bool TryParse(ReadOnlySpan<byte> buffer, out RtcpPacket? packet)
    {
        packet = null;
        if (!RtcpPacketHeader.TryParse(buffer, out var header))
        {
            return false;
        }

        if (header.PacketLength > buffer.Length)
        {
            return false;
        }

        var span = buffer[..header.PacketLength];

        switch (header.PacketType)
        {
            case RtcpPacketType.SenderReport:
                return Wrap(RtcpSenderReport.TryParse(span, out var sr), sr, out packet);
            case RtcpPacketType.ReceiverReport:
                return Wrap(RtcpReceiverReport.TryParse(span, out var rr), rr, out packet);
            case RtcpPacketType.SourceDescription:
                return Wrap(RtcpSourceDescription.TryParse(span, out var sdes), sdes, out packet);
            case RtcpPacketType.Goodbye:
                return Wrap(RtcpGoodbye.TryParse(span, out var bye), bye, out packet);
            case RtcpPacketType.TransportLayerFeedback:
                switch ((RtcpTransportFeedbackType)header.Count)
                {
                    case RtcpTransportFeedbackType.GenericNack:
                        return Wrap(RtcpGenericNack.TryParse(span, out var nack), nack, out packet);
                    case RtcpTransportFeedbackType.TransportCc:
                        return Wrap(RtcpTransportCcFeedback.TryParse(span, out var twcc), twcc, out packet);
                    default:
                        return Unknown(header, span, out packet);
                }

            case RtcpPacketType.PayloadSpecificFeedback:
                switch ((RtcpPayloadFeedbackType)header.Count)
                {
                    case RtcpPayloadFeedbackType.PictureLossIndication:
                        return Wrap(RtcpPictureLossIndication.TryParse(span, out var pli), pli, out packet);
                    case RtcpPayloadFeedbackType.FullIntraRequest:
                        return Wrap(RtcpFullIntraRequest.TryParse(span, out var fir), fir, out packet);
                    case RtcpPayloadFeedbackType.ApplicationLayerFeedback
                        when RtcpReceiverEstimatedMaxBitrate.TryParse(span, out var remb):
                        packet = remb;
                        return true;
                    default:
                        return Unknown(header, span, out packet);
                }

            default:
                return Unknown(header, span, out packet);
        }
    }

    /// <summary>
    /// Parses every packet of a compound RTCP buffer (RFC 3550 §6.1), skipping over any sub-packet
    /// whose body cannot be interpreted.
    /// </summary>
    /// <param name="compound">The decrypted compound RTCP buffer.</param>
    /// <returns>The packets in wire order; empty when nothing could be parsed.</returns>
    public static IReadOnlyList<RtcpPacket> ParseCompound(ReadOnlySpan<byte> compound)
    {
        var packets = new List<RtcpPacket>();
        var reader = new RtcpCompoundReader(compound);
        while (reader.MoveNext())
        {
            if (TryParse(reader.Current.Packet, out var parsed) && parsed is not null)
            {
                packets.Add(parsed);
            }
        }

        return packets;
    }

    /// <summary>Serializes several RTCP packets back to back to form a compound packet.</summary>
    /// <param name="packets">The packets, in the order required by RFC 3550 §6.1.</param>
    /// <param name="destination">Destination buffer.</param>
    /// <returns>The total number of bytes written.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="packets"/> is <see langword="null"/>.</exception>
    public static int WriteCompound(IReadOnlyList<RtcpPacket> packets, Span<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(packets);
        var offset = 0;
        for (var i = 0; i < packets.Count; i++)
        {
            offset += packets[i].WriteTo(destination[offset..]);
        }

        return offset;
    }

    /// <summary>Writes the common header for a packet of this type.</summary>
    /// <param name="destination">Destination buffer.</param>
    /// <param name="count">Reception report count, source count, or feedback message type.</param>
    /// <returns>The number of bytes written, always <see cref="RtcpPacketHeader.Length"/>.</returns>
    protected int WriteCommonHeader(Span<byte> destination, byte count) =>
        RtcpPacketHeader.FromByteLength(count, PacketType, Length).WriteTo(destination);

    private static bool Wrap<T>(bool success, T? parsed, out RtcpPacket? packet)
        where T : RtcpPacket
    {
        packet = success ? parsed : null;
        return success && parsed is not null;
    }

    private static bool Unknown(RtcpPacketHeader header, ReadOnlySpan<byte> span, out RtcpPacket? packet)
    {
        packet = new RtcpUnknownPacket(header, span[RtcpPacketHeader.Length..]);
        return true;
    }
}

/// <summary>
/// An RTCP packet whose type (or feedback message type) Keryx does not model. It preserves the header
/// and body verbatim so a compound packet can be traversed, logged, and re-serialized without loss.
/// </summary>
public sealed class RtcpUnknownPacket : RtcpPacket
{
    private readonly RtcpPacketHeader _header;

    /// <summary>Creates an unknown packet from a parsed header and its body.</summary>
    /// <param name="header">The common header as received.</param>
    /// <param name="body">The packet body, excluding the common header.</param>
    public RtcpUnknownPacket(RtcpPacketHeader header, ReadOnlySpan<byte> body)
    {
        _header = header;
        Body = body.ToArray();
    }

    /// <inheritdoc />
    public override RtcpPacketType PacketType => _header.PacketType;

    /// <summary>The five-bit count/FMT field from the common header.</summary>
    public byte Count => _header.Count;

    /// <summary>The packet body, excluding the common header.</summary>
    public byte[] Body { get; }

    /// <inheritdoc />
    public override int Length => RtcpPacketHeader.Length + Body.Length;

    /// <inheritdoc />
    public override int WriteTo(Span<byte> destination)
    {
        var written = _header.WriteTo(destination);
        Body.CopyTo(destination[written..]);
        return written + Body.Length;
    }
}
