using System.Buffers.Binary;
using Keryx.Core;

namespace Keryx.Sctp;

/// <summary>
/// An SCTP packet: the twelve-byte common header (source port, destination port, verification tag,
/// CRC-32C checksum) followed by one or more chunks (RFC 9260 §3.1).
/// </summary>
/// <remarks>
/// The checksum is computed over the whole packet with the checksum field treated as zero and is
/// then stored <em>little-endian</em> in that field — the byte order every SCTP implementation
/// uses in practice (RFC 9260 Appendix A's reference code byte-swaps the finalized CRC).
/// </remarks>
public sealed class SctpPacket
{
    /// <summary>Length of the SCTP common header in bytes.</summary>
    public const int CommonHeaderLength = 12;

    /// <summary>Byte offset of the checksum field within the common header.</summary>
    public const int ChecksumOffset = 8;

    /// <summary>Creates an empty packet.</summary>
    /// <param name="sourcePort">Source port (WebRTC uses 5000).</param>
    /// <param name="destinationPort">Destination port (WebRTC uses 5000).</param>
    /// <param name="verificationTag">Verification tag expected by the peer.</param>
    public SctpPacket(ushort sourcePort, ushort destinationPort, uint verificationTag)
    {
        SourcePort = sourcePort;
        DestinationPort = destinationPort;
        VerificationTag = verificationTag;
    }

    /// <summary>Source port.</summary>
    public ushort SourcePort { get; set; }

    /// <summary>Destination port.</summary>
    public ushort DestinationPort { get; set; }

    /// <summary>Verification tag.</summary>
    public uint VerificationTag { get; set; }

    /// <summary>The chunks carried by this packet, in wire order.</summary>
    public List<SctpChunk> Chunks { get; } = new();

    /// <summary>
    /// Total encoded length in bytes. Every chunk but the last is padded to a four-byte boundary;
    /// padding after the final chunk is omitted, which RFC 9260 §3.2 permits.
    /// </summary>
    public int Length
    {
        get
        {
            var length = CommonHeaderLength;
            for (var i = 0; i < Chunks.Count; i++)
            {
                length += i == Chunks.Count - 1 ? Chunks[i].Length : Chunks[i].PaddedLength;
            }

            return length;
        }
    }

    /// <summary>Encodes the packet, including its checksum, into <paramref name="destination"/>.</summary>
    /// <param name="destination">Buffer to write into; must be at least <see cref="Length"/> bytes.</param>
    /// <returns>The number of bytes written.</returns>
    public int WriteTo(Span<byte> destination)
    {
        var writer = new ByteWriter(destination);
        writer.WriteU16(SourcePort);
        writer.WriteU16(DestinationPort);
        writer.WriteU32(VerificationTag);
        writer.WriteU32(0);
        for (var i = 0; i < Chunks.Count; i++)
        {
            Chunks[i].WriteTo(ref writer, includePadding: i != Chunks.Count - 1);
        }

        var written = writer.Written;
        var checksum = Crc32c.Compute(written);
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(ChecksumOffset, 4), checksum);
        return written.Length;
    }

    /// <summary>Encodes the packet, including its checksum, into a newly allocated array.</summary>
    /// <returns>The encoded packet.</returns>
    public byte[] ToArray()
    {
        var buffer = new byte[Length];
        WriteTo(buffer);
        return buffer;
    }

    /// <summary>Recomputes the CRC-32C a packet buffer should carry, ignoring its current checksum field.</summary>
    /// <param name="packet">The complete packet, at least <see cref="CommonHeaderLength"/> bytes long.</param>
    /// <returns>The finalized CRC-32C value.</returns>
    public static uint ComputeChecksum(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < CommonHeaderLength)
        {
            throw new ByteBufferException($"SCTP packet must be at least {CommonHeaderLength} bytes; got {packet.Length}.");
        }

        Span<byte> zeros = stackalloc byte[4];
        zeros.Clear();
        var state = Crc32c.Update(Crc32c.Seed, packet[..ChecksumOffset]);
        state = Crc32c.Update(state, zeros);
        state = Crc32c.Update(state, packet[(ChecksumOffset + 4)..]);
        return Crc32c.Finish(state);
    }

    /// <summary>Reads the checksum field carried by a packet buffer.</summary>
    /// <param name="packet">The complete packet.</param>
    /// <returns>The stored checksum value.</returns>
    public static uint ReadChecksum(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < CommonHeaderLength)
        {
            throw new ByteBufferException($"SCTP packet must be at least {CommonHeaderLength} bytes; got {packet.Length}.");
        }

        return BinaryPrimitives.ReadUInt32LittleEndian(packet.Slice(ChecksumOffset, 4));
    }

    /// <summary>Parses a packet.</summary>
    /// <param name="datagram">The received datagram.</param>
    /// <param name="verifyChecksum">When true, a checksum mismatch throws.</param>
    /// <returns>The parsed packet.</returns>
    /// <exception cref="ByteBufferException">The datagram is truncated, malformed, or fails checksum verification.</exception>
    public static SctpPacket Parse(ReadOnlySpan<byte> datagram, bool verifyChecksum = true)
    {
        if (datagram.Length < CommonHeaderLength)
        {
            throw new ByteBufferException($"SCTP packet must be at least {CommonHeaderLength} bytes; got {datagram.Length}.");
        }

        if (verifyChecksum)
        {
            var expected = ComputeChecksum(datagram);
            var actual = ReadChecksum(datagram);
            if (expected != actual)
            {
                throw new ByteBufferException($"SCTP checksum mismatch: computed 0x{expected:X8}, packet carried 0x{actual:X8}.");
            }
        }

        var reader = new ByteReader(datagram);
        var packet = new SctpPacket(reader.ReadU16(), reader.ReadU16(), reader.ReadU32());
        reader.Skip(4);

        while (reader.Remaining >= 4)
        {
            var type = reader.ReadU8();
            var flags = reader.ReadU8();
            var length = reader.ReadU16();
            if (length < 4)
            {
                throw new ByteBufferException($"Chunk type {type} declares an invalid length of {length}.");
            }

            var bodyLength = length - 4;
            if (bodyLength > reader.Remaining)
            {
                throw new ByteBufferException(
                    $"Chunk type {type} declares a body of {bodyLength} byte(s) but only {reader.Remaining} remain.");
            }

            var body = reader.ReadBytes(bodyLength);
            packet.Chunks.Add(SctpChunk.Parse(type, flags, body));

            // Skip alignment padding. The final chunk of a packet may omit it, so clamp.
            var padding = ((length + 3) & ~3) - length;
            reader.Skip(Math.Min(padding, reader.Remaining));
        }

        return packet;
    }
}
