using FluentAssertions;
using Xunit;

namespace Keryx.Srtp.Tests;

/// <summary>
/// The published AEAD_AES_256_GCM test vectors from RFC 7714 Sections 16.2 and 17.2. These are the
/// same RTP/RTCP packets as <see cref="Rfc7714VectorTests"/>, keyed with a 32-octet session key
/// instead of 16, which is exactly the parameterization <see cref="SrtpAeadGcmTransform"/> already
/// supports.
/// </summary>
/// <remarks>
/// These vectors publish session keys and salts rather than master keys, so they exercise the
/// transform directly rather than through <see cref="SrtpEncryptContext"/>.
/// </remarks>
public class Rfc7714Aes256GcmVectorTests
{
    private const int TagLength = 16;

    // RFC 7714 Section 16.2: the 32-octet (256-bit) key is 00 01 02 ... 1f and the salt
    // (51756964 2070726f 2071756f) is the same "Quid pro quo" salt as the AES-128-GCM vectors.
    private const string SessionKey =
        "000102030405060708090a0b0c0d0e0f" +
        "101112131415161718191a1b1c1d1e1f";
    private const string SessionSalt = "51756964 2070726f 2071756f";

    private static SrtpAeadGcmTransform CreateTransform() => new(
        Hex.Parse(SessionKey),
        Hex.Parse(SessionSalt),
        Hex.Parse(SessionKey),
        Hex.Parse(SessionSalt),
        TagLength);

    // RFC 7714 Section 16.2, the same RTP packet as Section 16.1: a 12-octet header and the
    // 38-octet payload "Gallia est omnis divisa in partes tres".
    private const string RtpPacket =
        "8040f17b 8041f8d3 5501a0b2 47616c6c" +
        "69612065 7374206f 6d6e6973 20646976" +
        "69736120 696e2070 61727465 73207472" +
        "6573";

    // RFC 7714 Section 16.2.1, "Encrypted and tagged packet" (AEAD_AES_256_GCM).
    private const string ProtectedRtpPacket =
        "8040f17b 8041f8d3 5501a0b2 32b1de78" +
        "a822fe12 ef9f78fa 332e33aa b1801238" +
        "9a58e2f3 b50b2a02 76ffae0f 1ba63799" +
        "b87b7aa3 db36dfff d6b0f9bb 7878d7a7" +
        "6c13";

    private const uint RtpSsrc = 0x5501a0b2;
    private const ushort RtpSequenceNumber = 0xf17b;

    /// <summary>RFC 7714 Section 16.2.1, SRTP AEAD_AES_256_GCM Encryption.</summary>
    [Fact]
    public void Section16_2_1_ProtectRtp_MatchesPublishedVector()
    {
        using var transform = CreateTransform();
        var packet = Hex.Parse(RtpPacket);
        var output = new byte[packet.Length + TagLength];

        var length = transform.ProtectRtp(
            packet,
            headerLength: 12,
            RtpSsrc,
            rolloverCounter: 0,
            RtpSequenceNumber,
            output);

        Hex.ToString(output.AsSpan(0, length)).Should().Be(Hex.ToString(Hex.Parse(ProtectedRtpPacket)));
    }

    /// <summary>RFC 7714 Section 16.2.2, SRTP AEAD_AES_256_GCM Decryption.</summary>
    [Fact]
    public void Section16_2_2_UnprotectRtp_MatchesPublishedVector()
    {
        using var transform = CreateTransform();
        var wire = Hex.Parse(ProtectedRtpPacket);
        var output = new byte[wire.Length];

        transform.TryUnprotectRtp(
            wire,
            headerLength: 12,
            RtpSsrc,
            rolloverCounter: 0,
            RtpSequenceNumber,
            output,
            out var length).Should().BeTrue();

        Hex.ToString(output.AsSpan(0, length)).Should().Be(Hex.ToString(Hex.Parse(RtpPacket)));
    }

    [Fact]
    public void Section16_2_2_UnprotectRtp_RejectsATamperedVector()
    {
        using var transform = CreateTransform();
        var wire = Hex.Parse(ProtectedRtpPacket);
        wire[20] ^= 0x01;
        var output = new byte[wire.Length];

        transform.TryUnprotectRtp(wire, 12, RtpSsrc, 0, RtpSequenceNumber, output, out _).Should().BeFalse();
    }

    // RFC 7714 Section 17.2, the same RTCP packet as Section 17.1, with 31-bit SRTCP index 000005d4.
    private const string RtcpPacket =
        "81c8000d 4d617273 4e545031 4e545032" +
        "52545020 0000042a 0000e930 4c756e61" +
        "deadbeef deadbeef deadbeef deadbeef" +
        "deadbeef";

    // RFC 7714 Section 17.2, "Encrypted and tagged packet" (AEAD_AES_256_GCM).
    private const string ProtectedRtcpPacket =
        "81c8000d 4d617273 d50ae4d1 f5ce5d30" +
        "4ba297e4 7d470c28 2c3ece5d bffe0a50" +
        "a2eaa5c1 110555be 8415f658 c61de047" +
        "6f1b6fad 1d1eb30c 4446839f 57ff6f6c" +
        "b26ac3be 800005d4";

    private const uint RtcpSsrc = 0x4d617273;
    private const uint RtcpIndex = 0x5d4;

    /// <summary>RFC 7714 Section 17.2, SRTCP AEAD_AES_256_GCM Encryption and Tagging.</summary>
    [Fact]
    public void Section17_2_ProtectRtcp_MatchesPublishedVector()
    {
        using var transform = CreateTransform();
        var packet = Hex.Parse(RtcpPacket);
        var output = new byte[packet.Length + TagLength + SrtpProtectionProfile.SrtcpIndexLength];

        var length = transform.ProtectRtcp(packet, RtcpSsrc, RtcpIndex, encrypt: true, output);

        Hex.ToString(output.AsSpan(0, length)).Should().Be(Hex.ToString(Hex.Parse(ProtectedRtcpPacket)));
    }

    /// <summary>The reverse of Section 17.2: the published SRTCP packet must decrypt to the original.</summary>
    [Fact]
    public void Section17_2_UnprotectRtcp_MatchesPublishedVector()
    {
        using var transform = CreateTransform();
        var wire = Hex.Parse(ProtectedRtcpPacket);
        var output = new byte[wire.Length];

        transform.TryUnprotectRtcp(wire, RtcpSsrc, RtcpIndex, encrypted: true, output, out var length)
            .Should().BeTrue();

        Hex.ToString(output.AsSpan(0, length)).Should().Be(Hex.ToString(Hex.Parse(RtcpPacket)));
    }

    [Fact]
    public void Section17_2_UnprotectRtcp_RejectsATamperedVector()
    {
        using var transform = CreateTransform();
        var wire = Hex.Parse(ProtectedRtcpPacket);
        wire[30] ^= 0x08;
        var output = new byte[wire.Length];

        transform.TryUnprotectRtcp(wire, RtcpSsrc, RtcpIndex, encrypted: true, output, out _).Should().BeFalse();
    }

    /// <summary>Exercises the full key-derivation path from a 32-octet master key, not just the raw transform.</summary>
    [Fact]
    public void MasterKeyConstructor_DerivesA256BitSessionKeyAndRoundTrips()
    {
        var profile = SrtpProtectionProfile.AeadAes256Gcm;
        var masterKey = TestPackets.RandomBytes(new Random(256), profile.MasterKeyLength);
        var masterSalt = TestPackets.RandomBytes(new Random(257), profile.MasterSaltLength);
        var keys = new SrtpSessionKeys(masterKey, masterSalt);

        using var sender = new SrtpEncryptContext(profile, keys);
        using var receiver = new SrtpDecryptContext(profile, keys);

        var packet = TestPackets.Rtp(0x2A2A2A2A, 10, 960, TestPackets.RandomBytes(new Random(258), 64));
        var wire = new byte[packet.Length + profile.RtpOverhead];
        var protectedLength = sender.ProtectRtp(packet, wire);
        protectedLength.Should().Be(packet.Length + 16);

        var output = new byte[protectedLength];
        receiver.TryUnprotectRtp(wire.AsSpan(0, protectedLength), output, out var length).Should().BeTrue();
        output.AsSpan(0, length).ToArray().Should().Equal(packet);
    }
}
