using FluentAssertions;
using Xunit;

namespace Keryx.Srtp.Tests;

/// <summary>
/// Whole-packet cross-checks for SRTP_AES128_CM_HMAC_SHA1_80.
/// </summary>
/// <remarks>
/// RFC 3711 Appendix B publishes only the keystream and key derivation vectors, never a complete
/// protected packet, so these use the reference vectors carried in libsrtp's <c>srtp_driver.c</c>
/// (<c>srtp_plaintext_ref</c> / <c>srtp_ciphertext</c> and <c>rtcp_plaintext_ref</c> /
/// <c>srtcp_ciphertext</c>). They are keyed with the same master key and master salt as
/// RFC 3711 Appendix B.3, and they pin the pieces the RFC's own vectors cannot: the packet IV
/// built from the real SSRC and index, the placement of the encrypted portion, the
/// <c>M = packet || ROC</c> authentication input, and the SRTCP E-flag/index word.
/// </remarks>
public class SrtpInteropVectorTests
{
    // The RFC 3711 Appendix B.3 master key and master salt.
    private const string MasterKey = "e1f97a0d3e018be0d64fa32c06de4139";
    private const string MasterSalt = "0ec675ad498afeebb6960b3aabe6";

    private static SrtpSessionKeys Keys() => new(Hex.Parse(MasterKey), Hex.Parse(MasterSalt));

    // libsrtp srtp_plaintext_ref: V=2 PT=15 SEQ=0x1234 TS=0xdecafbad SSRC=0xcafebabe, payload 0xab x16.
    private const string RtpPlaintext = "800f1234 decafbad cafebabe abababab abababab abababab abababab";

    private const string RtpCiphertext =
        "800f1234 decafbad cafebabe 4e55dc4c" +
        "e79978d8 8ca4d215 949d2402 b78d6acc" +
        "99ea179b 8dbb";

    [Fact]
    public void ProtectRtp_MatchesTheLibsrtpReferenceVector()
    {
        using var sender = new SrtpEncryptContext(SrtpProtectionProfile.Aes128CmHmacSha1_80, Keys());
        var packet = Hex.Parse(RtpPlaintext);
        var output = new byte[packet.Length + sender.Profile.RtpOverhead];

        var length = sender.ProtectRtp(packet, output);

        length.Should().Be(38);
        Hex.ToString(output.AsSpan(0, length)).Should().Be(Hex.ToString(Hex.Parse(RtpCiphertext)));
    }

    [Fact]
    public void UnprotectRtp_RecoversTheLibsrtpReferenceVector()
    {
        using var receiver = new SrtpDecryptContext(SrtpProtectionProfile.Aes128CmHmacSha1_80, Keys());
        var wire = Hex.Parse(RtpCiphertext);
        var output = new byte[wire.Length];

        receiver.TryUnprotectRtp(wire, output, out var length).Should().BeTrue();
        Hex.ToString(output.AsSpan(0, length)).Should().Be(Hex.ToString(Hex.Parse(RtpPlaintext)));
    }

    // libsrtp rtcp_plaintext_ref: an RR header with SSRC 0xcafebabe and a 16-octet body of 0xab.
    private const string RtcpPlaintext = "81c8000b cafebabe abababab abababab abababab abababab";

    // libsrtp srtcp_ciphertext, which carries SRTCP index 1 with the E flag set (0x80000001).
    private const string RtcpCiphertext =
        "81c8000b cafebabe 7128035b e487b9bd" +
        "bef89041 f977a5a8 80000001 993e08cd" +
        "54d6c123 0798";

    [Fact]
    public void ProtectRtcp_MatchesTheLibsrtpReferenceVector()
    {
        using var sender = new SrtpEncryptContext(SrtpProtectionProfile.Aes128CmHmacSha1_80, Keys());
        sender.SetNextSrtcpIndex(0xcafebabe, 1);

        var packet = Hex.Parse(RtcpPlaintext);
        var output = new byte[packet.Length + sender.Profile.RtcpOverhead];

        var length = sender.ProtectRtcp(packet, output);

        length.Should().Be(38);
        Hex.ToString(output.AsSpan(0, length)).Should().Be(Hex.ToString(Hex.Parse(RtcpCiphertext)));
    }

    [Fact]
    public void UnprotectRtcp_RecoversTheLibsrtpReferenceVector()
    {
        using var receiver = new SrtpDecryptContext(SrtpProtectionProfile.Aes128CmHmacSha1_80, Keys());
        var wire = Hex.Parse(RtcpCiphertext);
        var output = new byte[wire.Length];

        receiver.TryUnprotectRtcp(wire, output, out var length).Should().BeTrue();
        Hex.ToString(output.AsSpan(0, length)).Should().Be(Hex.ToString(Hex.Parse(RtcpPlaintext)));
    }

    /// <summary>
    /// The full session key set the RFC 3711 Appendix B.3 master material expands into for the
    /// mandatory profile: a 16-octet cipher key, a 20-octet HMAC-SHA1 key and a 14-octet salt.
    /// </summary>
    [Fact]
    public void SrtpSessionKeys_DeriveToTheAppendixB3Material()
    {
        var masterKey = Hex.Parse(MasterKey);
        var masterSalt = Hex.Parse(MasterSalt);

        Span<byte> cipherKey = stackalloc byte[16];
        Span<byte> authKey = stackalloc byte[20];
        Span<byte> salt = stackalloc byte[14];

        SrtpKeyDerivation.Derive(masterKey, masterSalt, SrtpKeyDerivation.SrtpEncryptionLabel, 0, 0, cipherKey);
        SrtpKeyDerivation.Derive(masterKey, masterSalt, SrtpKeyDerivation.SrtpAuthenticationLabel, 0, 0, authKey);
        SrtpKeyDerivation.Derive(masterKey, masterSalt, SrtpKeyDerivation.SrtpSaltLabel, 0, 0, salt);

        // The first 16, 20 and 14 octets of the Appendix B.3 cipher key, auth key and cipher salt.
        Hex.ToString(cipherKey).Should().Be("C61E7A93744F39EE10734AFE3FF7A087");
        Hex.ToString(authKey).Should().Be("CEBE321F6FF7716B6FD4AB49AF256A156D38BAA4");
        Hex.ToString(salt).Should().Be("30CBBC08863D8C85D49DB34A9AE1");
    }
}
