using System.Buffers.Binary;
using System.Security.Cryptography;
using Keryx.Srtp;

namespace Keryx.Benchmarks;

/// <summary>
/// Shared builders for the synthetic RTP packets and SRTP contexts every benchmark works on. The
/// target profile is a 720p H.264 stream at ~2 Mbps: ~1200-byte packets (12-byte RTP header plus a
/// ~1188-byte payload), the size that dominates the fan-out cost.
/// </summary>
internal static class BenchPackets
{
    /// <summary>Total RTP packet size in bytes for the modelled 720p video payload.</summary>
    public const int VideoPacketSize = 1200;

    /// <summary>Fixed RTP header length (no CSRCs, no extension) used by the synthetic packets.</summary>
    public const int HeaderLength = 12;

    /// <summary>Dynamic payload type used for the synthetic H.264 video stream.</summary>
    public const byte VideoPayloadType = 96;

    /// <summary>Builds one well-formed plaintext RTP packet with a filled random payload.</summary>
    public static byte[] BuildRtpPacket(uint ssrc, ushort sequenceNumber, uint timestamp, int totalSize)
    {
        var packet = new byte[totalSize];
        packet[0] = 0x80; // version 2, no padding, no extension, no CSRC.
        packet[1] = VideoPayloadType; // marker clear.
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), sequenceNumber);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(4, 4), timestamp);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(8, 4), ssrc);
        RandomNumberGenerator.Fill(packet.AsSpan(HeaderLength));
        return packet;
    }

    /// <summary>Random master keying material sized for <paramref name="profile"/>.</summary>
    public static SrtpSessionKeys NewKeys(SrtpProtectionProfile profile)
    {
        var key = new byte[profile.MasterKeyLength];
        var salt = new byte[profile.MasterSaltLength];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(salt);
        return new SrtpSessionKeys(key, salt);
    }
}
