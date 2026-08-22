using Keryx.Core;

namespace Keryx.Rtp.Rtcp;

/// <summary>One FIR request entry: the target SSRC and the request sequence number (RFC 5104 §4.3.1.1).</summary>
public readonly struct RtcpFullIntraRequestEntry
{
    /// <summary>Length of one FIR FCI entry in bytes.</summary>
    public const int Length = 8;

    /// <summary>Creates an entry.</summary>
    /// <param name="ssrc">SSRC of the media sender that must send an intra frame.</param>
    /// <param name="sequenceNumber">Command sequence number; incremented for each new request.</param>
    public RtcpFullIntraRequestEntry(uint ssrc, byte sequenceNumber)
    {
        Ssrc = ssrc;
        SequenceNumber = sequenceNumber;
    }

    /// <summary>SSRC of the media sender that must send an intra frame.</summary>
    public uint Ssrc { get; }

    /// <summary>
    /// Command sequence number. Repeating a request with the same number is a retransmission and must
    /// not trigger a second intra frame (RFC 5104 §4.3.1.2).
    /// </summary>
    public byte SequenceNumber { get; }
}

/// <summary>
/// Full intra request (FIR), RFC 5104 §4.3.1: payload-specific feedback, FMT 4, whose FCI is a list
/// of (SSRC, sequence number) entries.
/// </summary>
public sealed class RtcpFullIntraRequest : RtcpFeedbackPacket
{
    private readonly List<RtcpFullIntraRequestEntry> _entries = [];

    /// <summary>Creates an empty FIR.</summary>
    public RtcpFullIntraRequest()
    {
    }

    /// <summary>Creates a FIR with a single request entry.</summary>
    /// <param name="senderSsrc">SSRC of the endpoint requesting the intra frame.</param>
    /// <param name="mediaSsrc">SSRC of the media source; per RFC 5104 §4.3.1.2 this is normally zero.</param>
    /// <param name="targetSsrc">SSRC of the media sender that must send an intra frame.</param>
    /// <param name="sequenceNumber">Command sequence number.</param>
    public RtcpFullIntraRequest(uint senderSsrc, uint mediaSsrc, uint targetSsrc, byte sequenceNumber)
    {
        SenderSsrc = senderSsrc;
        MediaSsrc = mediaSsrc;
        _entries.Add(new RtcpFullIntraRequestEntry(targetSsrc, sequenceNumber));
    }

    /// <summary>The request entries carried in the FCI.</summary>
    public IList<RtcpFullIntraRequestEntry> Entries => _entries;

    /// <inheritdoc />
    public override RtcpPacketType PacketType => RtcpPacketType.PayloadSpecificFeedback;

    /// <inheritdoc />
    public override byte FeedbackMessageType => (byte)RtcpPayloadFeedbackType.FullIntraRequest;

    /// <inheritdoc />
    protected override int FeedbackControlInformationLength => _entries.Count * RtcpFullIntraRequestEntry.Length;

    /// <summary>Parses a FIR.</summary>
    /// <param name="buffer">The complete packet, common header included.</param>
    /// <param name="packet">On success, the parsed packet.</param>
    /// <returns><see langword="false"/> when the packet is not a well-formed FIR.</returns>
    public static bool TryParse(ReadOnlySpan<byte> buffer, out RtcpFullIntraRequest? packet)
    {
        packet = null;
        if (!TryReadFeedbackHeader(
                buffer,
                RtcpPacketType.PayloadSpecificFeedback,
                (byte)RtcpPayloadFeedbackType.FullIntraRequest,
                out var senderSsrc,
                out var mediaSsrc,
                out var fci)
            || fci.Length % RtcpFullIntraRequestEntry.Length != 0)
        {
            return false;
        }

        var parsed = new RtcpFullIntraRequest { SenderSsrc = senderSsrc, MediaSsrc = mediaSsrc };
        var reader = new ByteReader(fci);
        while (reader.Remaining >= RtcpFullIntraRequestEntry.Length)
        {
            var ssrc = reader.ReadU32();
            var sequenceNumber = reader.ReadU8();
            reader.Skip(3);
            parsed._entries.Add(new RtcpFullIntraRequestEntry(ssrc, sequenceNumber));
        }

        packet = parsed;
        return true;
    }

    /// <inheritdoc />
    protected override int WriteFeedbackControlInformation(Span<byte> destination)
    {
        var writer = new ByteWriter(destination);
        foreach (var entry in _entries)
        {
            writer.WriteU32(entry.Ssrc);
            writer.WriteU8(entry.SequenceNumber);
            writer.WriteZero(3);
        }

        return writer.Position;
    }
}
