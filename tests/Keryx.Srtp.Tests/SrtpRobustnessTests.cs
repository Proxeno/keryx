using FluentAssertions;
using Keryx.Core;
using Xunit;

namespace Keryx.Srtp.Tests;

/// <summary>
/// Wire data must never produce an exception: every malformed, truncated or forged packet has to
/// come back as <see langword="false"/>.
/// </summary>
public class SrtpRobustnessTests
{
    public static TheoryData<SrtpProtectionProfileKind> Profiles => new()
    {
        SrtpProtectionProfileKind.Aes128CmHmacSha1_80,
        SrtpProtectionProfileKind.AeadAes128Gcm,
    };

    private static SrtpDecryptContext CreateReceiver(SrtpProtectionProfileKind kind, IKeryxLogger? logger = null)
    {
        var profile = SrtpProtectionProfile.ForKind(kind);
        var keys = DtlsSrtpKeyMaterial.Split(profile, TestPackets.KeyingMaterial(9, profile), DtlsSrtpRole.Client);
        return new SrtpDecryptContext(profile, keys.Local, logger);
    }

    [Theory]
    [MemberData(nameof(Profiles))]
    public void TruncatedAndMalformedPackets_ReturnFalseWithoutThrowing(SrtpProtectionProfileKind kind)
    {
        using var receiver = CreateReceiver(kind);
        var random = new Random(4242);

        for (var length = 0; length <= 80; length++)
        {
            var packet = TestPackets.RandomBytes(random, length);
            var output = new byte[Math.Max(length, 1)];

            var rtp = () => receiver.TryUnprotectRtp(packet, output, out _);
            rtp.Should().NotThrow().Which.Should().BeFalse();

            var rtcp = () => receiver.TryUnprotectRtcp(packet, output, out _);
            rtcp.Should().NotThrow().Which.Should().BeFalse();
        }
    }

    /// <summary>
    /// A header extension whose length field runs past the end of the packet must be rejected
    /// rather than crash the parser.
    /// </summary>
    [Theory]
    [MemberData(nameof(Profiles))]
    public void RtpPacketWithAnOversizedHeaderExtension_IsRejected(SrtpProtectionProfileKind kind)
    {
        using var receiver = CreateReceiver(kind);

        var packet = new byte[40];
        packet[0] = 0x90; // V=2, X=1, CC=0
        packet[1] = 96;
        packet[12] = 0xBE;
        packet[13] = 0xDE;
        packet[14] = 0xFF;  // extension length = 0xFFFF words
        packet[15] = 0xFF;

        var output = new byte[packet.Length];
        receiver.TryUnprotectRtp(packet, output, out _).Should().BeFalse();
    }

    [Theory]
    [MemberData(nameof(Profiles))]
    public void PacketsWithTheWrongRtpVersion_AreRejected(SrtpProtectionProfileKind kind)
    {
        using var receiver = CreateReceiver(kind);

        var packet = new byte[60];
        packet[0] = 0x40; // version 1
        var output = new byte[packet.Length];

        receiver.TryUnprotectRtp(packet, output, out _).Should().BeFalse();
        receiver.TryUnprotectRtcp(packet, output, out _).Should().BeFalse();
    }

    /// <summary>Rejections are reported at Debug level and never escalate to an exception.</summary>
    [Fact]
    public void RejectionsAreLoggedAtDebug()
    {
        var writer = new StringWriter();
        var logger = new TextWriterLogger(writer, KeryxLogLevel.Debug, "srtp-test");

        var profile = SrtpProtectionProfile.Aes128CmHmacSha1_80;
        var keys = DtlsSrtpKeyMaterial.Split(profile, TestPackets.KeyingMaterial(9, profile), DtlsSrtpRole.Client);
        using var sender = new SrtpEncryptContext(profile, keys.Local, logger);
        using var receiver = new SrtpDecryptContext(profile, keys.Local, logger);

        var packet = TestPackets.Rtp(0x1234, 1, 0, [1, 2, 3, 4]);
        var wire = new byte[packet.Length + profile.RtpOverhead];
        var protectedLength = sender.ProtectRtp(packet, wire);
        wire[13] ^= 0x40;

        var output = new byte[protectedLength];
        receiver.TryUnprotectRtp(wire.AsSpan(0, protectedLength), output, out _).Should().BeFalse();

        writer.ToString().Should().Contain("[Debug]").And.Contain("authentication failed");
    }

    [Theory]
    [MemberData(nameof(Profiles))]
    public void UndersizedOutputBuffer_IsACallerErrorAndThrows(SrtpProtectionProfileKind kind)
    {
        var profile = SrtpProtectionProfile.ForKind(kind);
        var keys = DtlsSrtpKeyMaterial.Split(profile, TestPackets.KeyingMaterial(9, profile), DtlsSrtpRole.Client);
        using var sender = new SrtpEncryptContext(profile, keys.Local);
        using var receiver = new SrtpDecryptContext(profile, keys.Local);

        var packet = TestPackets.Rtp(0x1234, 1, 0, [1, 2, 3, 4]);

        var protectAct = () =>
        {
            Span<byte> tooSmall = new byte[packet.Length + profile.RtpOverhead - 1];
            sender.ProtectRtp(packet, tooSmall);
        };
        protectAct.Should().Throw<ArgumentException>();

        var unprotectAct = () =>
        {
            Span<byte> tooSmall = new byte[packet.Length - 1];
            receiver.TryUnprotectRtp(packet, tooSmall, out _);
        };
        unprotectAct.Should().Throw<ArgumentException>();
    }

    [Theory]
    [MemberData(nameof(Profiles))]
    public void ProtectingAMalformedPacket_IsACallerErrorAndThrows(SrtpProtectionProfileKind kind)
    {
        var profile = SrtpProtectionProfile.ForKind(kind);
        var keys = DtlsSrtpKeyMaterial.Split(profile, TestPackets.KeyingMaterial(9, profile), DtlsSrtpRole.Client);
        using var sender = new SrtpEncryptContext(profile, keys.Local);

        var rtpAct = () =>
        {
            Span<byte> output = new byte[64];
            sender.ProtectRtp(new byte[8], output);
        };
        rtpAct.Should().Throw<ArgumentException>();

        var rtcpAct = () =>
        {
            Span<byte> output = new byte[64];
            sender.ProtectRtcp(new byte[4], output);
        };
        rtcpAct.Should().Throw<ArgumentException>();
    }

    [Theory]
    [MemberData(nameof(Profiles))]
    public void UsingADisposedContext_Throws(SrtpProtectionProfileKind kind)
    {
        var profile = SrtpProtectionProfile.ForKind(kind);
        var keys = DtlsSrtpKeyMaterial.Split(profile, TestPackets.KeyingMaterial(9, profile), DtlsSrtpRole.Client);
        var sender = new SrtpEncryptContext(profile, keys.Local);
        sender.Dispose();
        sender.Dispose(); // idempotent

        var act = () =>
        {
            Span<byte> output = new byte[64];
            sender.ProtectRtp(TestPackets.Rtp(1, 1, 1, [1]), output);
        };
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void KeyMaterialOfTheWrongSize_IsRejected()
    {
        var profile = SrtpProtectionProfile.Aes128CmHmacSha1_80;
        var badKey = new SrtpSessionKeys(new byte[15], new byte[14]);
        var badSalt = new SrtpSessionKeys(new byte[16], new byte[12]);

        var keyAct = () => new SrtpEncryptContext(profile, badKey);
        keyAct.Should().Throw<ArgumentException>();

        var saltAct = () => new SrtpDecryptContext(profile, badSalt);
        saltAct.Should().Throw<ArgumentException>();
    }
}
