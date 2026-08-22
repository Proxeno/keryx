using System.Text;
using Keryx.Core;

namespace Keryx.Rtp.Rtcp;

/// <summary>SDES item types (RFC 3550 §6.5).</summary>
public enum RtcpSdesItemType : byte
{
    /// <summary>Terminates the item list of a chunk.</summary>
    End = 0,

    /// <summary>Canonical end-point identifier, RFC 3550 §6.5.1. The only item WebRTC requires.</summary>
    Cname = 1,

    /// <summary>User name, RFC 3550 §6.5.2.</summary>
    Name = 2,

    /// <summary>Electronic mail address, RFC 3550 §6.5.3.</summary>
    Email = 3,

    /// <summary>Phone number, RFC 3550 §6.5.4.</summary>
    Phone = 4,

    /// <summary>Geographic location, RFC 3550 §6.5.5.</summary>
    Location = 5,

    /// <summary>Application or tool name, RFC 3550 §6.5.6.</summary>
    Tool = 6,

    /// <summary>Notice/status, RFC 3550 §6.5.7.</summary>
    Note = 7,

    /// <summary>Private extension, RFC 3550 §6.5.8.</summary>
    Private = 8,
}

/// <summary>One SDES item: a type and its UTF-8 text (RFC 3550 §6.5).</summary>
public sealed class RtcpSdesItem
{
    /// <summary>Largest item body length; the length field is one byte.</summary>
    public const int MaxValueLength = 255;

    /// <summary>Creates an item.</summary>
    /// <param name="type">The item type.</param>
    /// <param name="value">The item text; must encode to at most 255 UTF-8 bytes.</param>
    /// <exception cref="ArgumentException">The encoded text is too long.</exception>
    public RtcpSdesItem(RtcpSdesItemType type, string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (Encoding.UTF8.GetByteCount(value) > MaxValueLength)
        {
            throw new ArgumentException("An SDES item value must encode to at most 255 UTF-8 bytes.", nameof(value));
        }

        Type = type;
        Value = value;
    }

    /// <summary>The item type.</summary>
    public RtcpSdesItemType Type { get; }

    /// <summary>The item text.</summary>
    public string Value { get; }

    /// <summary>Serialized length of this item in bytes, including its two-byte type/length prefix.</summary>
    public int Length => 2 + Encoding.UTF8.GetByteCount(Value);
}

/// <summary>One SDES chunk: an SSRC and the items describing it (RFC 3550 §6.5).</summary>
public sealed class RtcpSdesChunk
{
    private readonly List<RtcpSdesItem> _items = [];

    /// <summary>Creates a chunk for <paramref name="ssrc"/>.</summary>
    /// <param name="ssrc">The source this chunk describes.</param>
    public RtcpSdesChunk(uint ssrc) => Ssrc = ssrc;

    /// <summary>The source (or contributing source) this chunk describes.</summary>
    public uint Ssrc { get; set; }

    /// <summary>The items in this chunk.</summary>
    public IList<RtcpSdesItem> Items => _items;

    /// <summary>
    /// Serialized length in bytes: the SSRC, the items, one terminating null octet, and enough
    /// additional null octets to reach a 32-bit boundary (RFC 3550 §6.5).
    /// </summary>
    public int Length
    {
        get
        {
            var items = 0;
            foreach (var item in _items)
            {
                items += item.Length;
            }

            return 4 + items + (4 - (items % 4));
        }
    }

    /// <summary>The value of the first CNAME item, or <see langword="null"/> when the chunk has none.</summary>
    public string? Cname
    {
        get
        {
            foreach (var item in _items)
            {
                if (item.Type == RtcpSdesItemType.Cname)
                {
                    return item.Value;
                }
            }

            return null;
        }
    }
}

/// <summary>Source description packet, RFC 3550 §6.5.</summary>
public sealed class RtcpSourceDescription : RtcpPacket
{
    /// <summary>Maximum number of chunks; the SC field is five bits wide.</summary>
    public const int MaxChunks = 31;

    private readonly List<RtcpSdesChunk> _chunks = [];

    /// <summary>The chunks carried by this packet.</summary>
    public IList<RtcpSdesChunk> Chunks => _chunks;

    /// <inheritdoc />
    public override RtcpPacketType PacketType => RtcpPacketType.SourceDescription;

    /// <inheritdoc />
    public override int Length
    {
        get
        {
            var total = RtcpPacketHeader.Length;
            foreach (var chunk in _chunks)
            {
                total += chunk.Length;
            }

            return total;
        }
    }

    /// <summary>
    /// Builds the minimal SDES packet WebRTC endpoints are required to send: one chunk carrying one
    /// CNAME item (RFC 3550 §6.5.1).
    /// </summary>
    /// <param name="ssrc">The source the CNAME belongs to.</param>
    /// <param name="cname">The canonical end-point identifier.</param>
    /// <returns>The packet.</returns>
    public static RtcpSourceDescription CreateCname(uint ssrc, string cname)
    {
        var chunk = new RtcpSdesChunk(ssrc);
        chunk.Items.Add(new RtcpSdesItem(RtcpSdesItemType.Cname, cname));
        var packet = new RtcpSourceDescription();
        packet.Chunks.Add(chunk);
        return packet;
    }

    /// <summary>Parses a source description packet.</summary>
    /// <param name="buffer">The complete packet, common header included.</param>
    /// <param name="packet">On success, the parsed packet.</param>
    /// <returns><see langword="false"/> when the packet is truncated or a chunk is malformed.</returns>
    public static bool TryParse(ReadOnlySpan<byte> buffer, out RtcpSourceDescription? packet)
    {
        packet = null;
        if (!RtcpPacketHeader.TryParse(buffer, out var header)
            || header.PacketType != RtcpPacketType.SourceDescription
            || header.PacketLength > buffer.Length)
        {
            return false;
        }

        try
        {
            var reader = new ByteReader(buffer[..header.PacketLength]);
            reader.Skip(RtcpPacketHeader.Length);
            var parsed = new RtcpSourceDescription();

            for (var i = 0; i < header.Count; i++)
            {
                var chunk = new RtcpSdesChunk(reader.ReadU32());
                var itemBytes = 0;

                while (true)
                {
                    var type = reader.ReadU8();
                    itemBytes++;
                    if (type == (byte)RtcpSdesItemType.End)
                    {
                        break;
                    }

                    var length = reader.ReadU8();
                    var value = reader.ReadBytes(length);
                    itemBytes += 1 + length;
                    chunk.Items.Add(new RtcpSdesItem((RtcpSdesItemType)type, Encoding.UTF8.GetString(value)));
                }

                // The terminating null was counted above; skip to the next 32-bit boundary.
                var consumed = itemBytes;
                var padding = (4 - (consumed % 4)) % 4;
                reader.Skip(padding);
                parsed._chunks.Add(chunk);
            }

            packet = parsed;
            return true;
        }
        catch (ByteBufferException)
        {
            packet = null;
            return false;
        }
        catch (ArgumentException)
        {
            packet = null;
            return false;
        }
    }

    /// <inheritdoc />
    public override int WriteTo(Span<byte> destination)
    {
        if (_chunks.Count > MaxChunks)
        {
            throw new InvalidOperationException($"An SDES packet carries at most {MaxChunks} chunks.");
        }

        var offset = WriteCommonHeader(destination, (byte)_chunks.Count);
        var writer = new ByteWriter(destination[offset..]);

        foreach (var chunk in _chunks)
        {
            writer.WriteU32(chunk.Ssrc);
            var itemBytes = 0;
            foreach (var item in chunk.Items)
            {
                var encoded = Encoding.UTF8.GetBytes(item.Value);
                writer.WriteU8((byte)item.Type);
                writer.WriteU8((byte)encoded.Length);
                writer.WriteBytes(encoded);
                itemBytes += 2 + encoded.Length;
            }

            writer.WriteZero(4 - (itemBytes % 4));
        }

        return offset + writer.Position;
    }
}
