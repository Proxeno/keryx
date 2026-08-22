using Keryx.Core;

namespace Keryx.Rtp.Rtcp;

/// <summary>
/// One generic NACK FCI entry (RFC 4585 §6.2.1): a packet identifier plus a 16-bit bitmask naming the
/// 16 sequence numbers that follow it.
/// </summary>
public readonly struct RtcpNackEntry
{
    /// <summary>Length of one NACK FCI entry in bytes.</summary>
    public const int Length = 4;

    /// <summary>Creates an entry.</summary>
    /// <param name="packetId">The lowest missing sequence number covered by this entry.</param>
    /// <param name="bitmask">
    /// Bit <c>i</c> set means <c>packetId + i + 1</c> is also reported missing.
    /// </param>
    public RtcpNackEntry(ushort packetId, ushort bitmask)
    {
        PacketId = packetId;
        Bitmask = bitmask;
    }

    /// <summary>The PID field: the lowest missing sequence number covered by this entry.</summary>
    public ushort PacketId { get; }

    /// <summary>The BLP field: bit <c>i</c> reports <c>PacketId + i + 1</c> as lost.</summary>
    public ushort Bitmask { get; }

    /// <summary>Number of sequence numbers this entry reports, including the PID itself.</summary>
    public int Count => 1 + System.Numerics.BitOperations.PopCount(Bitmask);
}

/// <summary>
/// Generic NACK, RFC 4585 §6.2.1: transport-layer feedback, FMT 1, requesting retransmission of the
/// RTP sequence numbers named by its FCI entries.
/// </summary>
public sealed class RtcpGenericNack : RtcpFeedbackPacket
{
    private readonly List<RtcpNackEntry> _entries = [];

    /// <summary>Creates an empty NACK.</summary>
    public RtcpGenericNack()
    {
    }

    /// <summary>Creates a NACK, packing the lost sequence numbers into FCI entries.</summary>
    /// <param name="senderSsrc">SSRC of the receiver requesting retransmission.</param>
    /// <param name="mediaSsrc">SSRC of the stream whose packets are missing.</param>
    /// <param name="lostSequenceNumbers">
    /// The missing sequence numbers. They are sorted and packed greedily: each entry covers a PID and
    /// the next 16 sequence numbers.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="lostSequenceNumbers"/> is <see langword="null"/>.</exception>
    public RtcpGenericNack(uint senderSsrc, uint mediaSsrc, IEnumerable<ushort> lostSequenceNumbers)
    {
        ArgumentNullException.ThrowIfNull(lostSequenceNumbers);
        SenderSsrc = senderSsrc;
        MediaSsrc = mediaSsrc;

        var sorted = new List<ushort>(lostSequenceNumbers);
        sorted.Sort();

        var index = 0;
        while (index < sorted.Count)
        {
            var pid = sorted[index];
            ushort bitmask = 0;
            index++;
            while (index < sorted.Count)
            {
                var delta = sorted[index] - pid;
                if (delta is < 1 or > 16)
                {
                    break;
                }

                bitmask |= (ushort)(1 << (delta - 1));
                index++;
            }

            _entries.Add(new RtcpNackEntry(pid, bitmask));
        }
    }

    /// <summary>The FCI entries carried by this NACK.</summary>
    public IList<RtcpNackEntry> Entries => _entries;

    /// <inheritdoc />
    public override RtcpPacketType PacketType => RtcpPacketType.TransportLayerFeedback;

    /// <inheritdoc />
    public override byte FeedbackMessageType => (byte)RtcpTransportFeedbackType.GenericNack;

    /// <inheritdoc />
    protected override int FeedbackControlInformationLength => _entries.Count * RtcpNackEntry.Length;

    /// <summary>
    /// Expands every FCI entry into the individual RTP sequence numbers being NACKed, in wire order:
    /// the PID first, then each sequence number whose BLP bit is set (RFC 4585 §6.2.1).
    /// </summary>
    /// <remarks>Sequence numbers wrap at 65535, so an entry may report numbers that appear to precede its PID.</remarks>
    public IReadOnlyList<ushort> ExpandedSequenceNumbers
    {
        get
        {
            var total = 0;
            foreach (var entry in _entries)
            {
                total += entry.Count;
            }

            var result = new ushort[total];
            WriteExpandedSequenceNumbers(result);
            return result;
        }
    }

    /// <summary>
    /// Writes the expanded sequence numbers into a caller-supplied span, avoiding the allocation that
    /// <see cref="ExpandedSequenceNumbers"/> makes.
    /// </summary>
    /// <param name="destination">Destination span; must hold every reported sequence number.</param>
    /// <returns>The number of sequence numbers written.</returns>
    /// <exception cref="ArgumentException">The destination is too small.</exception>
    public int WriteExpandedSequenceNumbers(Span<ushort> destination)
    {
        var count = 0;
        foreach (var entry in _entries)
        {
            if (count >= destination.Length)
            {
                throw new ArgumentException("The destination cannot hold every reported sequence number.", nameof(destination));
            }

            destination[count++] = entry.PacketId;
            for (var bit = 0; bit < 16; bit++)
            {
                if ((entry.Bitmask & (1 << bit)) == 0)
                {
                    continue;
                }

                if (count >= destination.Length)
                {
                    throw new ArgumentException("The destination cannot hold every reported sequence number.", nameof(destination));
                }

                destination[count++] = (ushort)(entry.PacketId + bit + 1);
            }
        }

        return count;
    }

    /// <summary>Parses a generic NACK.</summary>
    /// <param name="buffer">The complete packet, common header included.</param>
    /// <param name="packet">On success, the parsed packet.</param>
    /// <returns><see langword="false"/> when the packet is not a well-formed NACK.</returns>
    public static bool TryParse(ReadOnlySpan<byte> buffer, out RtcpGenericNack? packet)
    {
        packet = null;
        if (!TryReadFeedbackHeader(
                buffer,
                RtcpPacketType.TransportLayerFeedback,
                (byte)RtcpTransportFeedbackType.GenericNack,
                out var senderSsrc,
                out var mediaSsrc,
                out var fci)
            || fci.Length == 0
            || fci.Length % RtcpNackEntry.Length != 0)
        {
            return false;
        }

        var parsed = new RtcpGenericNack { SenderSsrc = senderSsrc, MediaSsrc = mediaSsrc };
        var reader = new ByteReader(fci);
        while (reader.Remaining >= RtcpNackEntry.Length)
        {
            parsed._entries.Add(new RtcpNackEntry(reader.ReadU16(), reader.ReadU16()));
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
            writer.WriteU16(entry.PacketId);
            writer.WriteU16(entry.Bitmask);
        }

        return writer.Position;
    }
}
