using System.Text;
using Keryx.Core;

namespace Keryx.Rtp.Rtcp;

/// <summary>Goodbye packet, RFC 3550 §6.6.</summary>
public sealed class RtcpGoodbye : RtcpPacket
{
    /// <summary>Maximum number of sources; the SC field is five bits wide.</summary>
    public const int MaxSources = 31;

    private readonly List<uint> _sources = [];
    private string? _reason;

    /// <summary>Creates an empty goodbye packet.</summary>
    public RtcpGoodbye()
    {
    }

    /// <summary>Creates a goodbye packet for a single source.</summary>
    /// <param name="ssrc">The departing source.</param>
    /// <param name="reason">Optional human-readable reason for leaving.</param>
    public RtcpGoodbye(uint ssrc, string? reason = null)
    {
        _sources.Add(ssrc);
        Reason = reason;
    }

    /// <summary>The sources that are leaving.</summary>
    public IList<uint> Sources => _sources;

    /// <summary>Optional reason for leaving; must encode to at most 255 UTF-8 bytes.</summary>
    /// <exception cref="ArgumentException">The encoded reason is too long.</exception>
    public string? Reason
    {
        get => _reason;
        set
        {
            if (value is not null && Encoding.UTF8.GetByteCount(value) > 255)
            {
                throw new ArgumentException("A BYE reason must encode to at most 255 UTF-8 bytes.", nameof(value));
            }

            _reason = value;
        }
    }

    /// <inheritdoc />
    public override RtcpPacketType PacketType => RtcpPacketType.Goodbye;

    /// <inheritdoc />
    public override int Length
    {
        get
        {
            var total = RtcpPacketHeader.Length + (_sources.Count * 4);
            if (_reason is not null)
            {
                var reasonBytes = 1 + Encoding.UTF8.GetByteCount(_reason);
                total += reasonBytes + ((4 - (reasonBytes % 4)) % 4);
            }

            return total;
        }
    }

    /// <summary>Parses a goodbye packet.</summary>
    /// <param name="buffer">The complete packet, common header included.</param>
    /// <param name="packet">On success, the parsed packet.</param>
    /// <returns><see langword="false"/> when the packet is truncated.</returns>
    public static bool TryParse(ReadOnlySpan<byte> buffer, out RtcpGoodbye? packet)
    {
        packet = null;
        if (!RtcpPacketHeader.TryParse(buffer, out var header)
            || header.PacketType != RtcpPacketType.Goodbye
            || header.PacketLength > buffer.Length)
        {
            return false;
        }

        try
        {
            var reader = new ByteReader(buffer[..header.PacketLength]);
            reader.Skip(RtcpPacketHeader.Length);
            var parsed = new RtcpGoodbye();
            for (var i = 0; i < header.Count; i++)
            {
                parsed._sources.Add(reader.ReadU32());
            }

            if (reader.Remaining > 0)
            {
                var length = reader.ReadU8();
                parsed._reason = Encoding.UTF8.GetString(reader.ReadBytes(length));
            }

            packet = parsed;
            return true;
        }
        catch (ByteBufferException)
        {
            packet = null;
            return false;
        }
    }

    /// <inheritdoc />
    public override int WriteTo(Span<byte> destination)
    {
        if (_sources.Count > MaxSources)
        {
            throw new InvalidOperationException($"A BYE packet carries at most {MaxSources} sources.");
        }

        var offset = WriteCommonHeader(destination, (byte)_sources.Count);
        var writer = new ByteWriter(destination[offset..]);
        foreach (var ssrc in _sources)
        {
            writer.WriteU32(ssrc);
        }

        if (_reason is not null)
        {
            var encoded = Encoding.UTF8.GetBytes(_reason);
            writer.WriteU8((byte)encoded.Length);
            writer.WriteBytes(encoded);
            writer.WriteZero((4 - ((1 + encoded.Length) % 4)) % 4);
        }

        return offset + writer.Position;
    }
}
