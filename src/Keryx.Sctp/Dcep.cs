using System.Text;
using Keryx.Core;

namespace Keryx.Sctp;

/// <summary>Message types of the Data Channel Establishment Protocol (RFC 8832 §8.2.1).</summary>
public enum DcepMessageType : byte
{
    /// <summary>DATA_CHANNEL_ACK — acknowledges an open request.</summary>
    DataChannelAck = 0x02,

    /// <summary>DATA_CHANNEL_OPEN — requests a channel on the stream it is sent on.</summary>
    DataChannelOpen = 0x03,
}

/// <summary>Channel types of the Data Channel Establishment Protocol (RFC 8832 §8.2.1).</summary>
public enum DcepChannelType : byte
{
    /// <summary>Ordered and fully reliable.</summary>
    Reliable = 0x00,

    /// <summary>Ordered, with delivery abandoned after a maximum number of retransmissions.</summary>
    PartialReliableRexmit = 0x01,

    /// <summary>Ordered, with delivery abandoned after a lifetime in milliseconds.</summary>
    PartialReliableTimed = 0x02,

    /// <summary>Unordered and fully reliable.</summary>
    ReliableUnordered = 0x80,

    /// <summary>Unordered, with delivery abandoned after a maximum number of retransmissions.</summary>
    PartialReliableRexmitUnordered = 0x81,

    /// <summary>Unordered, with delivery abandoned after a lifetime in milliseconds.</summary>
    PartialReliableTimedUnordered = 0x82,
}

/// <summary>
/// A DATA_CHANNEL_OPEN message (RFC 8832 §5.1). Sent with PPID 50 on the stream the channel will
/// use, always with ordered delivery even when the channel itself is unordered.
/// </summary>
public sealed class DcepOpenMessage
{
    /// <summary>Creates an open message.</summary>
    /// <param name="channelType">Reliability and ordering profile.</param>
    /// <param name="label">Channel label; encoded as UTF-8.</param>
    /// <param name="protocol">Sub-protocol name; encoded as UTF-8.</param>
    /// <param name="priority">Channel priority. Keryx does not schedule by priority; the value is carried through.</param>
    /// <param name="reliabilityParameter">Retransmission count or lifetime, depending on <paramref name="channelType"/>.</param>
    public DcepOpenMessage(
        DcepChannelType channelType,
        string label,
        string protocol = "",
        ushort priority = 0,
        uint reliabilityParameter = 0)
    {
        ArgumentNullException.ThrowIfNull(label);
        ArgumentNullException.ThrowIfNull(protocol);
        ChannelType = channelType;
        Label = label;
        Protocol = protocol;
        Priority = priority;
        ReliabilityParameter = reliabilityParameter;
    }

    /// <summary>Reliability and ordering profile.</summary>
    public DcepChannelType ChannelType { get; }

    /// <summary>Channel label.</summary>
    public string Label { get; }

    /// <summary>Sub-protocol name.</summary>
    public string Protocol { get; }

    /// <summary>Channel priority as sent on the wire.</summary>
    public ushort Priority { get; }

    /// <summary>Retransmission count or message lifetime, per <see cref="ChannelType"/>.</summary>
    public uint ReliabilityParameter { get; }

    /// <summary>True when the channel type selects unordered delivery (high bit of the channel type).</summary>
    public bool Unordered => ((byte)ChannelType & 0x80) != 0;

    /// <summary>
    /// The maximum retransmission count when the channel type is a retransmit-limited profile,
    /// otherwise null.
    /// </summary>
    public ushort? MaxRetransmits =>
        ((byte)ChannelType & 0x7F) == (byte)DcepChannelType.PartialReliableRexmit
            ? (ushort)Math.Min(ReliabilityParameter, ushort.MaxValue)
            : null;

    /// <summary>Encodes the message.</summary>
    /// <returns>The wire representation, to be sent with PPID 50.</returns>
    public byte[] Encode()
    {
        var label = Encoding.UTF8.GetBytes(Label);
        var protocol = Encoding.UTF8.GetBytes(Protocol);
        var buffer = new byte[12 + label.Length + protocol.Length];
        var writer = new ByteWriter(buffer);
        writer.WriteU8((byte)DcepMessageType.DataChannelOpen);
        writer.WriteU8((byte)ChannelType);
        writer.WriteU16(Priority);
        writer.WriteU32(ReliabilityParameter);
        writer.WriteU16((ushort)label.Length);
        writer.WriteU16((ushort)protocol.Length);
        writer.WriteBytes(label);
        writer.WriteBytes(protocol);
        return buffer;
    }

    /// <summary>Parses a DATA_CHANNEL_OPEN message.</summary>
    /// <param name="message">The DCEP payload, starting at the message type byte.</param>
    /// <returns>The parsed message.</returns>
    /// <exception cref="ByteBufferException">The payload is truncated or is not an open message.</exception>
    public static DcepOpenMessage Parse(ReadOnlySpan<byte> message)
    {
        var reader = new ByteReader(message);
        var type = reader.ReadU8();
        if (type != (byte)DcepMessageType.DataChannelOpen)
        {
            throw new ByteBufferException($"Expected DCEP message type 0x03 (DATA_CHANNEL_OPEN) but got 0x{type:X2}.");
        }

        var channelType = (DcepChannelType)reader.ReadU8();
        var priority = reader.ReadU16();
        var reliability = reader.ReadU32();
        var labelLength = reader.ReadU16();
        var protocolLength = reader.ReadU16();
        var label = Encoding.UTF8.GetString(reader.ReadBytes(labelLength));
        var protocol = Encoding.UTF8.GetString(reader.ReadBytes(protocolLength));
        return new DcepOpenMessage(channelType, label, protocol, priority, reliability);
    }

    /// <summary>The encoded DATA_CHANNEL_ACK message — a single byte, 0x02.</summary>
    /// <returns>A fresh one-byte array.</returns>
    public static byte[] EncodeAck() => new[] { (byte)DcepMessageType.DataChannelAck };

    /// <summary>Maps ordering and retransmission settings onto a DCEP channel type.</summary>
    /// <param name="ordered">Whether the channel preserves message order.</param>
    /// <param name="maxRetransmits">Retransmission limit, or null for full reliability.</param>
    /// <returns>The channel type to advertise.</returns>
    public static DcepChannelType ChannelTypeFor(bool ordered, ushort? maxRetransmits)
    {
        var baseType = maxRetransmits.HasValue
            ? DcepChannelType.PartialReliableRexmit
            : DcepChannelType.Reliable;
        return ordered ? baseType : (DcepChannelType)((byte)baseType | 0x80);
    }
}
