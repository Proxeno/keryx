using System.Buffers.Binary;
using FluentAssertions;
using Xunit;

namespace Keryx.Srtp.Tests;

/// <summary>SRTCP behaviour per RFC 3711 Section 3.4 (and RFC 7714 Section 9 for the AEAD profile).</summary>
public class SrtcpRoundTripTests
{
    public static TheoryData<SrtpProtectionProfileKind> Profiles => new()
    {
        SrtpProtectionProfileKind.Aes128CmHmacSha1_80,
        SrtpProtectionProfileKind.Aes128CmHmacSha1_32,
        SrtpProtectionProfileKind.AeadAes128Gcm,
        SrtpProtectionProfileKind.AeadAes256Gcm,
    };

    private static (SrtpEncryptContext Sender, SrtpDecryptContext Receiver) CreatePair(
        SrtpProtectionProfileKind kind,
        int seed = 5)
    {
        var profile = SrtpProtectionProfile.ForKind(kind);
        var keys = DtlsSrtpKeyMaterial.Split(profile, TestPackets.KeyingMaterial(seed, profile), DtlsSrtpRole.Client);
        return (new SrtpEncryptContext(profile, keys.Local), new SrtpDecryptContext(profile, keys.Local));
    }

    [Theory]
    [MemberData(nameof(Profiles))]
    public void ProtectThenUnprotect_RecoversTheOriginalPacket(SrtpProtectionProfileKind kind)
    {
        var (sender, receiver) = CreatePair(kind);
        using var s = sender;
        using var r = receiver;

        var random = new Random(99);
        for (var i = 0; i < 32; i++)
        {
            var body = TestPackets.RandomBytes(random, 4 * random.Next(1, 20));
            var packet = TestPackets.Rtcp(0xCAFEBABE, body);

            var buffer = new byte[packet.Length + s.Profile.RtcpOverhead];
            var protectedLength = s.ProtectRtcp(packet, buffer);
            protectedLength.Should().Be(packet.Length + s.Profile.RtcpOverhead);

            // RFC 3711 Section 3.4: the encrypted portion starts at the ninth octet, so the RTCP
            // header and sender SSRC stay in the clear.
            buffer.AsSpan(0, 8).ToArray().Should().Equal(packet.AsSpan(0, 8).ToArray());
            buffer.AsSpan(8, body.Length).ToArray().Should().NotEqual(body);

            var output = new byte[protectedLength];
            r.TryUnprotectRtcp(buffer.AsSpan(0, protectedLength), output, out var length).Should().BeTrue();
            output.AsSpan(0, length).ToArray().Should().Equal(packet);
        }
    }

    [Theory]
    [MemberData(nameof(Profiles))]
    public void ProtectedPacket_CarriesTheEncryptFlagAndAnIncrementingIndex(SrtpProtectionProfileKind kind)
    {
        var (sender, receiver) = CreatePair(kind);
        using var s = sender;
        using var r = receiver;

        var profile = s.Profile;
        for (uint expectedIndex = 0; expectedIndex < 8; expectedIndex++)
        {
            var packet = TestPackets.Rtcp(0x1234_5678, [0, 0, 0, (byte)expectedIndex]);
            var buffer = new byte[packet.Length + profile.RtcpOverhead];
            var protectedLength = s.ProtectRtcp(packet, buffer);

            // The AES-CM profiles put the E/index word before the tag (RFC 3711 Figure 2); the AEAD
            // profiles put it at the very end (RFC 7714 Section 17).
            var wordOffset = kind is SrtpProtectionProfileKind.Aes128CmHmacSha1_80 or SrtpProtectionProfileKind.Aes128CmHmacSha1_32
                ? protectedLength - profile.TagLength - SrtpProtectionProfile.SrtcpIndexLength
                : protectedLength - SrtpProtectionProfile.SrtcpIndexLength;
            var word = BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(wordOffset, 4));

            (word & 0x8000_0000).Should().Be(0x8000_0000, "SRTCP is always encrypted here");
            (word & 0x7FFF_FFFF).Should().Be(expectedIndex);

            var output = new byte[protectedLength];
            r.TryUnprotectRtcp(buffer.AsSpan(0, protectedLength), output, out _).Should().BeTrue();
        }
    }

    [Theory]
    [MemberData(nameof(Profiles))]
    public void TamperedPacket_IsRejected(SrtpProtectionProfileKind kind)
    {
        var (sender, receiver) = CreatePair(kind);
        using var s = sender;
        using var r = receiver;

        var packet = TestPackets.Rtcp(0xFEEDFACE, TestPackets.RandomBytes(new Random(17), 24));
        var buffer = new byte[packet.Length + s.Profile.RtcpOverhead];
        var protectedLength = s.ProtectRtcp(packet, buffer);
        var wire = buffer.AsSpan(0, protectedLength).ToArray();

        int[] positions = [0, 5, 12, protectedLength - 1, protectedLength - 5];
        foreach (var position in positions)
        {
            var tampered = (byte[])wire.Clone();
            tampered[position] ^= 0x02;

            var output = new byte[tampered.Length];
            r.TryUnprotectRtcp(tampered, output, out _)
                .Should().BeFalse($"flipping a bit at offset {position} must fail authentication");
        }

        var clean = new byte[wire.Length];
        r.TryUnprotectRtcp(wire, clean, out var length).Should().BeTrue();
        clean.AsSpan(0, length).ToArray().Should().Equal(packet);
    }

    /// <summary>RFC 3711 Section 3.4: SRTCP keeps its own replay list, keyed on the SRTCP index.</summary>
    [Theory]
    [MemberData(nameof(Profiles))]
    public void ReplayedPacket_IsRejected(SrtpProtectionProfileKind kind)
    {
        var (sender, receiver) = CreatePair(kind);
        using var s = sender;
        using var r = receiver;

        var packet = TestPackets.Rtcp(0x0101_0101, [1, 2, 3, 4]);
        var buffer = new byte[packet.Length + s.Profile.RtcpOverhead];
        var protectedLength = s.ProtectRtcp(packet, buffer);
        var wire = buffer.AsSpan(0, protectedLength).ToArray();

        var output = new byte[wire.Length];
        r.TryUnprotectRtcp(wire, output, out _).Should().BeTrue();
        r.TryUnprotectRtcp(wire, output, out _).Should().BeFalse();
    }

    [Theory]
    [MemberData(nameof(Profiles))]
    public void OutOfOrderPackets_AreAcceptedWithinTheWindow(SrtpProtectionProfileKind kind)
    {
        var (sender, receiver) = CreatePair(kind);
        using var s = sender;
        using var r = receiver;

        var wire = new List<byte[]>();
        for (var i = 0; i < 8; i++)
        {
            var packet = TestPackets.Rtcp(0x2020_2020, [(byte)i, 0, 0, 0]);
            var buffer = new byte[packet.Length + s.Profile.RtcpOverhead];
            var protectedLength = s.ProtectRtcp(packet, buffer);
            wire.Add(buffer.AsSpan(0, protectedLength).ToArray());
        }

        int[] order = [3, 0, 7, 1, 6, 2, 5, 4];
        var output = new byte[64];
        foreach (var i in order)
        {
            r.TryUnprotectRtcp(wire[i], output, out _).Should().BeTrue($"index {i} has not been seen yet");
        }

        foreach (var i in order)
        {
            r.TryUnprotectRtcp(wire[i], output, out _).Should().BeFalse($"index {i} is now a replay");
        }
    }

    [Theory]
    [MemberData(nameof(Profiles))]
    public void DistinctSsrcs_KeepIndependentSrtcpIndices(SrtpProtectionProfileKind kind)
    {
        var (sender, receiver) = CreatePair(kind);
        using var s = sender;
        using var r = receiver;

        for (var i = 0; i < 4; i++)
        {
            foreach (var ssrc in new uint[] { 0xAAAA_AAAA, 0xBBBB_BBBB })
            {
                var packet = TestPackets.Rtcp(ssrc, [(byte)i, 0, 0, 0]);
                var buffer = new byte[packet.Length + s.Profile.RtcpOverhead];
                var protectedLength = s.ProtectRtcp(packet, buffer);

                var output = new byte[protectedLength];
                r.TryUnprotectRtcp(buffer.AsSpan(0, protectedLength), output, out var length)
                    .Should().BeTrue($"SSRC 0x{ssrc:x8} packet {i}");
                output.AsSpan(0, length).ToArray().Should().Equal(packet);
            }
        }
    }

    [Theory]
    [MemberData(nameof(Profiles))]
    public void ProtectThenUnprotect_WorksInPlace(SrtpProtectionProfileKind kind)
    {
        var (sender, receiver) = CreatePair(kind);
        using var s = sender;
        using var r = receiver;

        var packet = TestPackets.Rtcp(0x3333_3333, TestPackets.RandomBytes(new Random(21), 40));
        var buffer = new byte[packet.Length + s.Profile.RtcpOverhead];
        packet.CopyTo(buffer, 0);

        var protectedLength = s.ProtectRtcp(buffer.AsSpan(0, packet.Length), buffer);
        r.TryUnprotectRtcp(buffer.AsSpan(0, protectedLength), buffer, out var length).Should().BeTrue();
        buffer.AsSpan(0, length).ToArray().Should().Equal(packet);
    }
}

/// <summary>
/// RFC 3711 Section 3.4 allows an SRTCP packet to be authenticated but not encrypted (E = 0). The
/// public API always encrypts, but the receive path must handle a peer that does not.
/// </summary>
public class SrtcpUnencryptedTests
{
    public static TheoryData<SrtpProtectionProfileKind> Profiles => new()
    {
        SrtpProtectionProfileKind.Aes128CmHmacSha1_80,
        SrtpProtectionProfileKind.Aes128CmHmacSha1_32,
        SrtpProtectionProfileKind.AeadAes128Gcm,
        SrtpProtectionProfileKind.AeadAes256Gcm,
    };

    [Theory]
    [MemberData(nameof(Profiles))]
    public void PacketWithTheEFlagClear_IsAuthenticatedAndPassedThroughInTheClear(SrtpProtectionProfileKind kind)
    {
        var profile = SrtpProtectionProfile.ForKind(kind);
        var keys = DtlsSrtpKeyMaterial.Split(profile, TestPackets.KeyingMaterial(31, profile), DtlsSrtpRole.Client);
        using var sender = new SrtpEncryptContext(profile, keys.Local);
        using var receiver = new SrtpDecryptContext(profile, keys.Local);

        var body = TestPackets.RandomBytes(new Random(66), 32);
        var packet = TestPackets.Rtcp(0x5151_5151, body);

        var buffer = new byte[packet.Length + profile.RtcpOverhead];
        var protectedLength = sender.ProtectRtcpWithoutEncryption(packet, buffer);
        protectedLength.Should().Be(packet.Length + profile.RtcpOverhead);

        // With E = 0 the body travels in the clear.
        buffer.AsSpan(0, packet.Length).ToArray().Should().Equal(packet);

        var wordOffset = kind is SrtpProtectionProfileKind.Aes128CmHmacSha1_80 or SrtpProtectionProfileKind.Aes128CmHmacSha1_32
            ? protectedLength - profile.TagLength - SrtpProtectionProfile.SrtcpIndexLength
            : protectedLength - SrtpProtectionProfile.SrtcpIndexLength;
        var word = BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(wordOffset, 4));
        (word & 0x8000_0000).Should().Be(0u, "the E flag must be clear");

        var output = new byte[protectedLength];
        receiver.TryUnprotectRtcp(buffer.AsSpan(0, protectedLength), output, out var length).Should().BeTrue();
        output.AsSpan(0, length).ToArray().Should().Equal(packet);
    }

    [Theory]
    [MemberData(nameof(Profiles))]
    public void TamperedUnencryptedPacket_IsRejected(SrtpProtectionProfileKind kind)
    {
        var profile = SrtpProtectionProfile.ForKind(kind);
        var keys = DtlsSrtpKeyMaterial.Split(profile, TestPackets.KeyingMaterial(31, profile), DtlsSrtpRole.Client);
        using var sender = new SrtpEncryptContext(profile, keys.Local);
        using var receiver = new SrtpDecryptContext(profile, keys.Local);

        var packet = TestPackets.Rtcp(0x5151_5151, TestPackets.RandomBytes(new Random(67), 16));
        var buffer = new byte[packet.Length + profile.RtcpOverhead];
        var protectedLength = sender.ProtectRtcpWithoutEncryption(packet, buffer);
        var wire = buffer.AsSpan(0, protectedLength).ToArray();

        int[] positions = [1, 10, 20, protectedLength - 1];
        foreach (var position in positions)
        {
            var tampered = (byte[])wire.Clone();
            tampered[position] ^= 0x04;
            var output = new byte[tampered.Length];
            receiver.TryUnprotectRtcp(tampered, output, out _)
                .Should().BeFalse($"flipping a bit at offset {position} must fail authentication");
        }

        var clean = new byte[wire.Length];
        receiver.TryUnprotectRtcp(wire, clean, out var length).Should().BeTrue();
        clean.AsSpan(0, length).ToArray().Should().Equal(packet);
    }
}
