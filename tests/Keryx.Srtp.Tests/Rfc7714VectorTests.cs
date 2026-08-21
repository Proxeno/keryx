using FluentAssertions;
using Xunit;

namespace Keryx.Srtp.Tests;

/// <summary>
/// The published AEAD_AES_128_GCM test vectors from RFC 7714 Sections 16 and 17.
/// </summary>
/// <remarks>
/// These vectors publish session keys and salts rather than master keys, so they exercise the
/// transform directly rather than through <see cref="SrtpEncryptContext"/>.
/// </remarks>
public class Rfc7714VectorTests
{
    private const int TagLength = 16;

    // RFC 7714 Section 16: "The 16-octet (128-bit) key is 00 01 02 ... 0f" and the salt
    // (51756964 2070726f 2071756f) comes from the ASCII string "Quid pro quo".
    private const string SessionKey = "000102030405060708090a0b0c0d0e0f";
    private const string SessionSalt = "51756964 2070726f 2071756f";

    private static SrtpAeadGcmTransform CreateTransform() => new(
        Hex.Parse(SessionKey),
        Hex.Parse(SessionSalt),
        Hex.Parse(SessionKey),
        Hex.Parse(SessionSalt),
        TagLength);

    // RFC 7714 Section 16, the RTP packet all the RTP examples are based on: a 12-octet header and
    // the 38-octet payload "Gallia est omnis divisa in partes tres".
    private const string RtpPacket =
        "8040f17b 8041f8d3 5501a0b2 47616c6c" +
        "69612065 7374206f 6d6e6973 20646976" +
        "69736120 696e2070 61727465 73207472" +
        "6573";

    // RFC 7714 Section 16.1.1, "Encrypted and tagged packet".
    private const string ProtectedRtpPacket =
        "8040f17b 8041f8d3 5501a0b2 f24de3a3" +
        "fb34de6c acba861c 9d7e4bca be633bd5" +
        "0d294e6f 42a5f47a 51c7d19b 36de3adf" +
        "8833899d 7f27beb1 6a9152cf 765ee439" +
        "0cce";

    private const uint RtpSsrc = 0x5501a0b2;
    private const ushort RtpSequenceNumber = 0xf17b;

    /// <summary>
    /// RFC 7714 Section 16: the IV is <c>(00 00 || SSRC || ROC || SEQ) XOR salt</c>, which for this
    /// packet gives 51 75 3c 65 80 c2 72 6f 20 71 84 14.
    /// </summary>
    [Fact]
    public void Section16_RtpNonce_MatchesPublishedIv()
    {
        Span<byte> nonce = stackalloc byte[SrtpAeadGcmTransform.NonceLength];
        SrtpAeadGcmTransform.BuildRtpNonce(
            Hex.Parse(SessionSalt),
            RtpSsrc,
            rolloverCounter: 0,
            RtpSequenceNumber,
            nonce);

        Hex.ToString(nonce).Should().Be("51753C6580C2726F20718414");
    }

    /// <summary>RFC 7714 Section 16.1.1, SRTP AEAD_AES_128_GCM Encryption.</summary>
    [Fact]
    public void Section16_1_1_ProtectRtp_MatchesPublishedVector()
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

    /// <summary>RFC 7714 Section 16.1.2, SRTP AEAD_AES_128_GCM Decryption.</summary>
    [Fact]
    public void Section16_1_2_UnprotectRtp_MatchesPublishedVector()
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
    public void Section16_1_2_UnprotectRtp_RejectsATamperedVector()
    {
        using var transform = CreateTransform();
        var wire = Hex.Parse(ProtectedRtpPacket);
        wire[20] ^= 0x01;
        var output = new byte[wire.Length];

        transform.TryUnprotectRtp(wire, 12, RtpSsrc, 0, RtpSequenceNumber, output, out _).Should().BeFalse();
    }

    // RFC 7714 Section 17.1, the RTCP packet being encrypted, with 31-bit SRTCP index 000005d4.
    private const string RtcpPacket =
        "81c8000d 4d617273 4e545031 4e545032" +
        "52545020 0000042a 0000e930 4c756e61" +
        "deadbeef deadbeef deadbeef deadbeef" +
        "deadbeef";

    // RFC 7714 Section 17.1, "Encrypted and tagged packet".
    private const string ProtectedRtcpPacket =
        "81c8000d 4d617273 63e94885 dcdab67c" +
        "a727d766 2f6b7e99 7ff5c0f7 6c06f32d" +
        "c676a5f1 730d6fda 4ce09b46 86303ded" +
        "0bb9275b c84aa458 96cf4d2f c5abf872" +
        "45d9eade 800005d4";

    private const uint RtcpSsrc = 0x4d617273;
    private const uint RtcpIndex = 0x5d4;

    /// <summary>
    /// RFC 7714 Section 17: the SRTCP IV is
    /// <c>(00 00 || SSRC || 00 00 || 0 || SRTCP index) XOR salt</c>, giving
    /// 51 75 24 05 52 03 72 6f 20 71 70 bb.
    /// </summary>
    [Fact]
    public void Section17_RtcpNonce_MatchesPublishedIv()
    {
        Span<byte> nonce = stackalloc byte[SrtpAeadGcmTransform.NonceLength];
        SrtpAeadGcmTransform.BuildRtcpNonce(Hex.Parse(SessionSalt), RtcpSsrc, RtcpIndex, nonce);

        Hex.ToString(nonce).Should().Be("517524055203726F207170BB");
    }

    /// <summary>RFC 7714 Section 17.1, SRTCP AEAD_AES_128_GCM Encryption and Tagging.</summary>
    [Fact]
    public void Section17_1_ProtectRtcp_MatchesPublishedVector()
    {
        using var transform = CreateTransform();
        var packet = Hex.Parse(RtcpPacket);
        var output = new byte[packet.Length + TagLength + SrtpProtectionProfile.SrtcpIndexLength];

        var length = transform.ProtectRtcp(packet, RtcpSsrc, RtcpIndex, encrypt: true, output);

        Hex.ToString(output.AsSpan(0, length)).Should().Be(Hex.ToString(Hex.Parse(ProtectedRtcpPacket)));
    }

    /// <summary>The reverse of Section 17.1: the published SRTCP packet must decrypt to the original.</summary>
    [Fact]
    public void Section17_1_UnprotectRtcp_MatchesPublishedVector()
    {
        using var transform = CreateTransform();
        var wire = Hex.Parse(ProtectedRtcpPacket);
        var output = new byte[wire.Length];

        transform.TryUnprotectRtcp(wire, RtcpSsrc, RtcpIndex, encrypted: true, output, out var length)
            .Should().BeTrue();

        Hex.ToString(output.AsSpan(0, length)).Should().Be(Hex.ToString(Hex.Parse(RtcpPacket)));
    }

    [Fact]
    public void Section17_1_UnprotectRtcp_RejectsATamperedVector()
    {
        using var transform = CreateTransform();
        var wire = Hex.Parse(ProtectedRtcpPacket);
        wire[30] ^= 0x08;
        var output = new byte[wire.Length];

        transform.TryUnprotectRtcp(wire, RtcpSsrc, RtcpIndex, encrypted: true, output, out _).Should().BeFalse();
    }

    /// <summary>The AEAD binds the SRTCP index through the IV and the ESRTCP word in the AAD.</summary>
    [Fact]
    public void Section17_1_UnprotectRtcp_RejectsAnAlteredIndex()
    {
        using var transform = CreateTransform();
        var wire = Hex.Parse(ProtectedRtcpPacket);
        var output = new byte[wire.Length];

        transform.TryUnprotectRtcp(wire, RtcpSsrc, RtcpIndex + 1, encrypted: true, output, out _)
            .Should().BeFalse();
    }
}
