using FluentAssertions;
using Xunit;

namespace Keryx.Srtp.Tests;

/// <summary>Shape and behaviour of the public surface.</summary>
public class SrtpApiTests
{
    [Fact]
    public void Aes128CmProfile_HasTheRfc3711Parameters()
    {
        var profile = SrtpProtectionProfile.Aes128CmHmacSha1_80;

        profile.Kind.Should().Be(SrtpProtectionProfileKind.Aes128CmHmacSha1_80);
        profile.Name.Should().Be("SRTP_AES128_CM_HMAC_SHA1_80");
        profile.MasterKeyLength.Should().Be(16);
        profile.MasterSaltLength.Should().Be(14, "RFC 3711 Section 5.2 specifies a 112-bit master salt");
        profile.SessionSaltLength.Should().Be(14);
        profile.AuthenticationKeyLength.Should().Be(20, "HMAC-SHA1 takes a 160-bit session auth key");
        profile.TagLength.Should().Be(10, "the tag is HMAC-SHA1 truncated to 80 bits");
        profile.RtpOverhead.Should().Be(10);
        profile.RtcpOverhead.Should().Be(14, "4 octets of E-flag/index word plus the 10-octet tag");
    }

    [Fact]
    public void AeadGcmProfile_HasTheRfc7714Parameters()
    {
        var profile = SrtpProtectionProfile.AeadAes128Gcm;

        profile.Kind.Should().Be(SrtpProtectionProfileKind.AeadAes128Gcm);
        profile.Name.Should().Be("SRTP_AEAD_AES_128_GCM");
        profile.MasterKeyLength.Should().Be(16);
        profile.MasterSaltLength.Should().Be(12, "RFC 7714 Table 2 specifies a 96-bit master salt");
        profile.AuthenticationKeyLength.Should().Be(0, "AEAD authenticates with the cipher itself");
        profile.TagLength.Should().Be(16);
        profile.RtpOverhead.Should().Be(16);
        profile.RtcpOverhead.Should().Be(20);
    }

    /// <summary>The enum values are the DTLS-SRTP code points from the IANA registry.</summary>
    [Fact]
    public void ProfileKinds_UseTheIanaCodePoints()
    {
        ((int)SrtpProtectionProfileKind.Aes128CmHmacSha1_80).Should().Be(0x0001);
        ((int)SrtpProtectionProfileKind.AeadAes128Gcm).Should().Be(0x0007);
    }

    [Fact]
    public void ForKind_RejectsUnknownProfiles()
    {
        var act = () => SrtpProtectionProfile.ForKind((SrtpProtectionProfileKind)0x1234);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void SessionKeys_CopyTheirInputAndCompareByValue()
    {
        var key = new byte[16];
        var salt = new byte[14];
        key[0] = 1;

        var keys = new SrtpSessionKeys(key, salt);
        key[0] = 2; // mutating the caller's array must not affect the stored copy.

        keys.MasterKey.Span[0].Should().Be(1);
        keys.Should().Be(new SrtpSessionKeys(new byte[16] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, salt));
        keys.Should().NotBe(new SrtpSessionKeys(new byte[16], salt));
    }

    [Fact]
    public void SessionKeys_NeverRenderKeyBytes()
    {
        var keys = new SrtpSessionKeys(new byte[16], new byte[14]);
        keys.ToString().Should().Be("SrtpSessionKeys { MasterKey = 16 bytes, MasterSalt = 14 bytes }");
    }

    [Fact]
    public void SessionKeys_RejectEmptyMaterial()
    {
        var keyAct = () => new SrtpSessionKeys([], new byte[14]);
        keyAct.Should().Throw<ArgumentException>();

        var saltAct = () => new SrtpSessionKeys(new byte[16], []);
        saltAct.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void SrtpContext_ExposesBothDirectionsAndDelegatesToThem()
    {
        var profile = SrtpProtectionProfile.Aes128CmHmacSha1_80;
        var block = TestPackets.KeyingMaterial(3, profile);

        using var context = SrtpContext.CreateFromDtlsKeyingMaterial(profile, block, DtlsSrtpRole.Client);

        context.Profile.Should().BeSameAs(profile);
        context.Outbound.Profile.Should().BeSameAs(profile);
        context.Inbound.Profile.Should().BeSameAs(profile);

        var packet = TestPackets.Rtp(0x1234, 5, 0, [7, 7, 7, 7]);
        var wire = new byte[packet.Length + profile.RtpOverhead];
        var protectedLength = context.ProtectRtp(packet, wire);

        // The context protects with the local keys, so its own inbound side must reject the result.
        var output = new byte[protectedLength];
        context.TryUnprotectRtp(wire.AsSpan(0, protectedLength), output, out _).Should().BeFalse();

        using var peer = SrtpContext.CreateFromDtlsKeyingMaterial(profile, block, DtlsSrtpRole.Server);
        peer.TryUnprotectRtp(wire.AsSpan(0, protectedLength), output, out var length).Should().BeTrue();
        output.AsSpan(0, length).ToArray().Should().Equal(packet);
    }

    [Fact]
    public void KeyDerivation_RejectsAnOversizedMasterSalt()
    {
        var act = () =>
        {
            Span<byte> output = new byte[16];
            SrtpKeyDerivation.Derive(new byte[16], new byte[15], 0, 0, 0, output);
        };
        act.Should().Throw<ArgumentException>();
    }

    /// <summary>
    /// RFC 3711 Section 4.3.1 defines <c>r = index DIV key_derivation_rate</c> with
    /// <c>a DIV 0 = 0</c>, so a non-zero rate must change the derived material once the index
    /// crosses it while a zero rate never does.
    /// </summary>
    [Fact]
    public void KeyDerivation_HonoursTheKeyDerivationRate()
    {
        var masterKey = Hex.Parse("e1f97a0d3e018be0d64fa32c06de4139");
        var masterSalt = Hex.Parse("0ec675ad498afeebb6960b3aabe6");

        Span<byte> atRateZero = stackalloc byte[16];
        Span<byte> atRateZeroLater = stackalloc byte[16];
        Span<byte> firstInterval = stackalloc byte[16];
        Span<byte> secondInterval = stackalloc byte[16];

        SrtpKeyDerivation.Derive(masterKey, masterSalt, 0, index: 0, keyDerivationRate: 0, atRateZero);
        SrtpKeyDerivation.Derive(masterKey, masterSalt, 0, index: 1_000_000, keyDerivationRate: 0, atRateZeroLater);
        SrtpKeyDerivation.Derive(masterKey, masterSalt, 0, index: 1023, keyDerivationRate: 1024, firstInterval);
        SrtpKeyDerivation.Derive(masterKey, masterSalt, 0, index: 1024, keyDerivationRate: 1024, secondInterval);

        Hex.ToString(atRateZeroLater).Should().Be(Hex.ToString(atRateZero));
        Hex.ToString(firstInterval).Should().Be(Hex.ToString(atRateZero));
        Hex.ToString(secondInterval).Should().NotBe(Hex.ToString(atRateZero));
    }

    [Fact]
    public void AesCounterMode_ValidatesItsArguments()
    {
        using var cipher = new AesCounterMode(new byte[16]);

        var badIv = () =>
        {
            Span<byte> output = new byte[16];
            cipher.Transform(new byte[15], new byte[16], output);
        };
        badIv.Should().Throw<ArgumentException>();

        var shortDestination = () =>
        {
            Span<byte> output = new byte[8];
            cipher.Transform(new byte[16], new byte[16], output);
        };
        shortDestination.Should().Throw<ArgumentException>();

        cipher.Dispose();
        var afterDispose = () =>
        {
            Span<byte> output = new byte[16];
            cipher.Transform(new byte[16], new byte[16], output);
        };
        afterDispose.Should().Throw<ObjectDisposedException>();
    }

    /// <summary>
    /// Counter-mode encryption is its own inverse, and a 128-bit counter must carry correctly
    /// across a block boundary rather than repeating keystream.
    /// </summary>
    [Fact]
    public void AesCounterMode_IsItsOwnInverseAndProducesDistinctBlocks()
    {
        using var cipher = new AesCounterMode(Hex.Parse("000102030405060708090a0b0c0d0e0f"));
        var iv = Hex.Parse("00000000000000000000000000000000");

        var keystream = new byte[16 * 300];
        cipher.GenerateKeystream(iv, keystream);

        var blocks = new HashSet<string>();
        for (var i = 0; i < 300; i++)
        {
            blocks.Add(Hex.ToString(keystream.AsSpan(i * 16, 16))).Should().BeTrue();
        }

        var plaintext = TestPackets.RandomBytes(new Random(8), 1500);
        var ciphertext = new byte[plaintext.Length];
        var roundTrip = new byte[plaintext.Length];
        cipher.Transform(iv, plaintext, ciphertext);
        cipher.Transform(iv, ciphertext, roundTrip);

        ciphertext.Should().NotEqual(plaintext);
        roundTrip.Should().Equal(plaintext);
    }
}
