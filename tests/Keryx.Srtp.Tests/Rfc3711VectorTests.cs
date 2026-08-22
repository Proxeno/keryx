using Xunit;
using FluentAssertions;

namespace Keryx.Srtp.Tests;

/// <summary>
/// The published test vectors from RFC 3711 Appendix B, byte for byte.
/// </summary>
public class Rfc3711VectorTests
{
    // RFC 3711 Appendix B.2, "AES-CM Test Vectors":
    //   Session Key:      2B7E151628AED2A6ABF7158809CF4F3C
    //   Rollover Counter: 00000000
    //   Sequence Number:  0000
    //   SSRC:             00000000
    //   Session Salt:     F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000 (already shifted)
    //   Offset:           F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000
    private const string B2SessionKey = "2B7E151628AED2A6ABF7158809CF4F3C";
    private const string B2SessionSalt = "F0F1F2F3F4F5F6F7F8F9FAFBFCFD";
    private const string B2Offset = "F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000";

    /// <summary>
    /// RFC 3711 Appendix B.2: with ROC = 0, SEQ = 0 and SSRC = 0 the IV
    /// <c>(k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)</c> collapses to the published offset.
    /// </summary>
    [Fact]
    public void B2_PacketIv_MatchesPublishedOffset()
    {
        Span<byte> iv = stackalloc byte[AesCounterMode.BlockSize];
        AesCounterMode.BuildPacketIv(Hex.Parse(B2SessionSalt), ssrc: 0, packetIndex: 0, iv);

        Hex.ToString(iv).Should().Be(B2Offset);
    }

    /// <summary>
    /// RFC 3711 Appendix B.2. The published keystream segment is 1 044 512 octets
    /// (65 282 = 0xFF02 AES blocks); the RFC lists the blocks produced at counters 0, 1, 2, 0xFEFF,
    /// 0xFF00 and 0xFF01. The tail deliberately coincides with NIST SP 800-38A Section F.5.1.
    /// </summary>
    [Theory]
    [InlineData(0x0000, "E03EAD0935C95E80E166B16DD92B4EB4")]
    [InlineData(0x0001, "D23513162B02D0F72A43A2FE4A5F97AB")]
    [InlineData(0x0002, "41E95B3BB0A2E8DD477901E4FCA894C0")]
    [InlineData(0xFEFF, "EC8CDF7398607CB0F2D21675EA9EA1E4")]
    [InlineData(0xFF00, "362B7C3C6773516318A077D7FC5073AE")]
    [InlineData(0xFF01, "6A2CC3787889374FBEB4C81B17BA6C44")]
    public void B2_KeystreamSegment_MatchesPublishedBlocks(int blockIndex, string expected)
    {
        const int segmentBlocks = 0xFF02;
        const int segmentLength = segmentBlocks * AesCounterMode.BlockSize; // 1 044 512 octets

        using var cipher = new AesCounterMode(Hex.Parse(B2SessionKey));
        var keystream = new byte[segmentLength];
        cipher.GenerateKeystream(Hex.Parse(B2Offset), keystream);

        var block = keystream.AsSpan(blockIndex * AesCounterMode.BlockSize, AesCounterMode.BlockSize);
        Hex.ToString(block).Should().Be(expected);
    }

    // RFC 3711 Appendix B.3, "Key Derivation Test Vectors":
    //   master key:  E1F97A0D3E018BE0D64FA32C06DE4139
    //   master salt: 0EC675AD498AFEEBB6960B3AABE6
    private const string B3MasterKey = "E1F97A0D3E018BE0D64FA32C06DE4139";
    private const string B3MasterSalt = "0EC675AD498AFEEBB6960B3AABE6";

    /// <summary>
    /// RFC 3711 Appendix B.3, cipher key: label 0x00, index DIV kdr = 000000000000, giving
    /// AES-CM input 0EC675AD498AFEEBB6960B3AABE60000 and output
    /// C61E7A93744F39EE10734AFE3FF7A087.
    /// </summary>
    [Fact]
    public void B3_CipherKey_MatchesPublishedVector()
    {
        Span<byte> cipherKey = stackalloc byte[16];
        SrtpKeyDerivation.Derive(
            Hex.Parse(B3MasterKey),
            Hex.Parse(B3MasterSalt),
            SrtpKeyDerivation.SrtpEncryptionLabel,
            index: 0,
            keyDerivationRate: 0,
            cipherKey);

        Hex.ToString(cipherKey).Should().Be("C61E7A93744F39EE10734AFE3FF7A087");
    }

    /// <summary>
    /// RFC 3711 Appendix B.3, cipher salt: label 0x02, AES-CM input
    /// 0EC675AD498AFEE9B6960B3AABE60000, AES-CM output 30CBBC08863D8C85D49DB34A9AE17AC6,
    /// truncated to the 14-octet cipher salt 30CBBC08863D8C85D49DB34A9AE1.
    /// </summary>
    [Fact]
    public void B3_CipherSalt_MatchesPublishedVector()
    {
        Span<byte> full = stackalloc byte[16];
        SrtpKeyDerivation.Derive(
            Hex.Parse(B3MasterKey),
            Hex.Parse(B3MasterSalt),
            SrtpKeyDerivation.SrtpSaltLabel,
            index: 0,
            keyDerivationRate: 0,
            full);

        Hex.ToString(full).Should().Be("30CBBC08863D8C85D49DB34A9AE17AC6");
        Hex.ToString(full[..14]).Should().Be("30CBBC08863D8C85D49DB34A9AE1");
    }

    /// <summary>
    /// RFC 3711 Appendix B.3, auth key: label 0x01 expanded to 94 octets across the six AES input
    /// blocks 0EC675AD498AFEEAB6960B3AABE60000 .. ...0005.
    /// </summary>
    [Fact]
    public void B3_AuthKey_MatchesPublishedVector()
    {
        const string expected =
            "CEBE321F6FF7716B6FD4AB49AF256A15" +
            "6D38BAA48F0A0ACF3C34E2359E6CDBCE" +
            "E049646C43D9327AD175578EF7227098" +
            "6371C10C9A369AC2F94A8C5FBCDDDC25" +
            "6D6E919A48B610EF17C2041E47403576" +
            "6B68642C59BBFC2F34DB60DBDFB2";

        Span<byte> authKey = stackalloc byte[94];
        SrtpKeyDerivation.Derive(
            Hex.Parse(B3MasterKey),
            Hex.Parse(B3MasterSalt),
            SrtpKeyDerivation.SrtpAuthenticationLabel,
            index: 0,
            keyDerivationRate: 0,
            authKey);

        Hex.ToString(authKey).Should().Be(expected);
    }

    /// <summary>
    /// RFC 3711 Appendix B.3 also publishes the AES-CM input blocks (<c>x * 2^16</c>). Feeding them
    /// to the raw PRF must give the same material the key derivation produces, which pins the
    /// <c>x = (label || r) XOR master_salt</c> construction and not just the AES step.
    /// </summary>
    [Theory]
    [InlineData("0EC675AD498AFEEBB6960B3AABE60000", "C61E7A93744F39EE10734AFE3FF7A087")]
    [InlineData("0EC675AD498AFEEAB6960B3AABE60000", "CEBE321F6FF7716B6FD4AB49AF256A15")]
    [InlineData("0EC675AD498AFEE9B6960B3AABE60000", "30CBBC08863D8C85D49DB34A9AE17AC6")]
    public void B3_PrfInputBlocks_ProducePublishedOutput(string inputBlock, string expected)
    {
        using var prf = new AesCounterMode(Hex.Parse(B3MasterKey));
        Span<byte> output = stackalloc byte[16];
        prf.GenerateKeystream(Hex.Parse(inputBlock), output);

        Hex.ToString(output).Should().Be(expected);
    }

    /// <summary>
    /// The SRTCP labels of RFC 3711 Section 4.3.2 (0x03, 0x04, 0x05) flip different bits of octet 7
    /// of the PRF input, so they must yield material distinct from the SRTP labels.
    /// </summary>
    [Fact]
    public void SrtcpLabels_DeriveDistinctMaterial()
    {
        var masterKey = Hex.Parse(B3MasterKey);
        var masterSalt = Hex.Parse(B3MasterSalt);
        var derived = new List<string>();
        Span<byte> material = stackalloc byte[16];

        foreach (var label in new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 })
        {
            SrtpKeyDerivation.Derive(masterKey, masterSalt, label, 0, 0, material);
            derived.Add(Hex.ToString(material));
        }

        derived.Should().OnlyHaveUniqueItems();
    }
}
