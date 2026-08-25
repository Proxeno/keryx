using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Keryx.ScalingSpike;

/// <summary>The single synthetic 720p ingest packet every fan-out lever re-encrypts or copies.</summary>
internal static class Packets
{
    public const int PacketSize = 1200;
    public const int HeaderLength = 12;
    private const byte VideoPayloadType = 96;

    /// <summary>Builds a complete, well-formed RTP packet (12-byte header + random payload).</summary>
    public static byte[] BuildRtpPacket(uint ssrc, ushort sequenceNumber, uint timestamp)
    {
        var packet = new byte[PacketSize];
        packet[0] = 0x80; // version 2, no padding/extension/CSRC.
        packet[1] = VideoPayloadType; // marker bit clear.
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), sequenceNumber);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(4, 4), timestamp);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(8, 4), ssrc);
        RandomNumberGenerator.Fill(packet.AsSpan(HeaderLength));
        return packet;
    }

    /// <summary>Overwrites the sequence number in place so a reused buffer advances its packet index.</summary>
    public static void SetSequence(byte[] packet, ushort sequenceNumber) =>
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), sequenceNumber);
}
