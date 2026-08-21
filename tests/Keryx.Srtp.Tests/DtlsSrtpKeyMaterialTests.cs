using FluentAssertions;
using Xunit;

namespace Keryx.Srtp.Tests;

/// <summary>
/// The DTLS-SRTP exporter split of RFC 5764 Section 4.2, and the end-to-end session it keys.
/// </summary>
public class DtlsSrtpKeyMaterialTests
{
    /// <summary>
    /// RFC 5764 Section 4.2: the exporter produces
    /// <c>2 * (master_key_len + master_salt_len)</c> bytes, i.e. 60 for
    /// SRTP_AES128_CM_HMAC_SHA1_80 and 56 for SRTP_AEAD_AES_128_GCM.
    /// </summary>
    [Theory]
    [InlineData(SrtpProtectionProfileKind.Aes128CmHmacSha1_80, 60)]
    [InlineData(SrtpProtectionProfileKind.AeadAes128Gcm, 56)]
    public void RequiredLength_MatchesTheProfile(SrtpProtectionProfileKind kind, int expected)
    {
        DtlsSrtpKeyMaterial.RequiredLength(SrtpProtectionProfile.ForKind(kind)).Should().Be(expected);
    }

    /// <summary>
    /// RFC 5764 Section 4.2 ordering:
    /// <c>client_write_SRTP_master_key || server_write_SRTP_master_key ||
    /// client_write_SRTP_master_salt || server_write_SRTP_master_salt</c>.
    /// </summary>
    [Fact]
    public void Split_UsesTheRfc5764Ordering()
    {
        var profile = SrtpProtectionProfile.Aes128CmHmacSha1_80;
        var block = new byte[60];
        for (var i = 0; i < block.Length; i++)
        {
            block[i] = (byte)i;
        }

        var clientKey = block.AsSpan(0, 16).ToArray();
        var serverKey = block.AsSpan(16, 16).ToArray();
        var clientSalt = block.AsSpan(32, 14).ToArray();
        var serverSalt = block.AsSpan(46, 14).ToArray();

        var asClient = DtlsSrtpKeyMaterial.Split(profile, block, DtlsSrtpRole.Client);
        asClient.Local.MasterKey.ToArray().Should().Equal(clientKey);
        asClient.Local.MasterSalt.ToArray().Should().Equal(clientSalt);
        asClient.Remote.MasterKey.ToArray().Should().Equal(serverKey);
        asClient.Remote.MasterSalt.ToArray().Should().Equal(serverSalt);

        var asServer = DtlsSrtpKeyMaterial.Split(profile, block, DtlsSrtpRole.Server);
        asServer.Local.MasterKey.ToArray().Should().Equal(serverKey);
        asServer.Local.MasterSalt.ToArray().Should().Equal(serverSalt);
        asServer.Remote.MasterKey.ToArray().Should().Equal(clientKey);
        asServer.Remote.MasterSalt.ToArray().Should().Equal(clientSalt);
    }

    [Fact]
    public void Split_RejectsAKeyingBlockOfTheWrongLength()
    {
        var profile = SrtpProtectionProfile.Aes128CmHmacSha1_80;
        var act = () => DtlsSrtpKeyMaterial.Split(profile, new byte[59], DtlsSrtpRole.Client);
        act.Should().Throw<ArgumentException>();
    }

    /// <summary>
    /// The DTLS-shaped end to end: one 60-byte exporter block, two peers that split it with
    /// opposite roles, and traffic in both directions. Each peer must decrypt only what the other
    /// sent, which is what proves the client/server key assignment of RFC 5764 Section 4.2.
    /// </summary>
    [Theory]
    [InlineData(SrtpProtectionProfileKind.Aes128CmHmacSha1_80)]
    [InlineData(SrtpProtectionProfileKind.AeadAes128Gcm)]
    public void TwoPeersKeyedFromOneExporterBlock_TalkToEachOther(SrtpProtectionProfileKind kind)
    {
        var profile = SrtpProtectionProfile.ForKind(kind);
        var exporterBlock = TestPackets.KeyingMaterial(0x5A, profile);

        using var client = SrtpContext.CreateFromDtlsKeyingMaterial(profile, exporterBlock, DtlsSrtpRole.Client);
        using var server = SrtpContext.CreateFromDtlsKeyingMaterial(profile, exporterBlock, DtlsSrtpRole.Server);

        var random = new Random(555);
        for (ushort seq = 1; seq <= 40; seq++)
        {
            Exchange(client, server, 0xC11E_0000u, seq, random);
            Exchange(server, client, 0x5E27_0000u, seq, random);
        }

        // RTCP travels the same path, including the rtcp-mux case of several SSRCs per direction.
        for (var i = 0; i < 5; i++)
        {
            ExchangeRtcp(client, server, 0xC11E_0000u, random);
            ExchangeRtcp(server, client, 0x5E27_0000u, random);
        }
    }

    private static void Exchange(SrtpContext from, SrtpContext to, uint ssrc, ushort sequenceNumber, Random random)
    {
        var payload = TestPackets.RandomBytes(random, random.Next(1, 300));
        var packet = TestPackets.Rtp(ssrc, sequenceNumber, sequenceNumber * 960u, payload);

        var wire = new byte[packet.Length + from.Profile.RtpOverhead];
        var protectedLength = from.ProtectRtp(packet, wire);

        var output = new byte[protectedLength];
        to.TryUnprotectRtp(wire.AsSpan(0, protectedLength), output, out var length).Should().BeTrue();
        output.AsSpan(0, length).ToArray().Should().Equal(packet);

        // The sender cannot unprotect its own traffic: the two directions use different keys.
        var selfOutput = new byte[protectedLength];
        from.TryUnprotectRtp(wire.AsSpan(0, protectedLength), selfOutput, out _).Should().BeFalse();
    }

    private static void ExchangeRtcp(SrtpContext from, SrtpContext to, uint ssrc, Random random)
    {
        var packet = TestPackets.Rtcp(ssrc, TestPackets.RandomBytes(random, 4 * random.Next(1, 8)));

        var wire = new byte[packet.Length + from.Profile.RtcpOverhead];
        var protectedLength = from.ProtectRtcp(packet, wire);

        var output = new byte[protectedLength];
        to.TryUnprotectRtcp(wire.AsSpan(0, protectedLength), output, out var length).Should().BeTrue();
        output.AsSpan(0, length).ToArray().Should().Equal(packet);

        var selfOutput = new byte[protectedLength];
        from.TryUnprotectRtcp(wire.AsSpan(0, protectedLength), selfOutput, out _).Should().BeFalse();
    }
}
