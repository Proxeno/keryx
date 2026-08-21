using System.Buffers.Binary;

namespace Keryx.Srtp.Tests;

/// <summary>Minimal RTP/RTCP packet builders so the SRTP tests do not depend on Keryx.Rtp.</summary>
internal static class TestPackets
{
    public static byte[] Rtp(uint ssrc, ushort sequenceNumber, uint timestamp, ReadOnlySpan<byte> payload, byte payloadType = 96)
    {
        var packet = new byte[12 + payload.Length];
        packet[0] = 0x80;                    // V=2, P=0, X=0, CC=0
        packet[1] = payloadType;             // M=0
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), sequenceNumber);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(4, 4), timestamp);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(8, 4), ssrc);
        payload.CopyTo(packet.AsSpan(12));
        return packet;
    }

    /// <summary>An RTP packet with two CSRCs and a one-word header extension.</summary>
    public static byte[] RtpWithCsrcsAndExtension(uint ssrc, ushort sequenceNumber, ReadOnlySpan<byte> payload)
    {
        const int csrcCount = 2;
        const int extensionWords = 1;
        var headerLength = 12 + (csrcCount * 4) + 4 + (extensionWords * 4);
        var packet = new byte[headerLength + payload.Length];
        packet[0] = (byte)(0x80 | 0x10 | csrcCount); // V=2, X=1, CC=2
        packet[1] = 96;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), sequenceNumber);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(4, 4), 0xDEADBEEF);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(8, 4), ssrc);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(12, 4), 0x11111111);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(16, 4), 0x22222222);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(20, 2), 0xBEDE);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22, 2), extensionWords);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(24, 4), 0x33445566);
        payload.CopyTo(packet.AsSpan(headerLength));
        return packet;
    }

    /// <summary>A minimal RTCP receiver report (PT=201) with a trailing body.</summary>
    public static byte[] Rtcp(uint ssrc, ReadOnlySpan<byte> body)
    {
        var packet = new byte[8 + body.Length];
        packet[0] = 0x80;                    // V=2, P=0, RC=0
        packet[1] = 201;                     // PT = RR
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), (ushort)((packet.Length / 4) - 1));
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(4, 4), ssrc);
        body.CopyTo(packet.AsSpan(8));
        return packet;
    }

    public static byte[] RandomBytes(Random random, int length)
    {
        var bytes = new byte[length];
        random.NextBytes(bytes);
        return bytes;
    }

    /// <summary>A deterministic 60-byte DTLS-SRTP exporter block for the AES-CM profile.</summary>
    public static byte[] KeyingMaterial(int seed, SrtpProtectionProfile profile)
    {
        var length = DtlsSrtpKeyMaterial.RequiredLength(profile);
        var block = new byte[length];
        for (var i = 0; i < length; i++)
        {
            block[i] = (byte)((i * 7) + seed);
        }

        return block;
    }
}
