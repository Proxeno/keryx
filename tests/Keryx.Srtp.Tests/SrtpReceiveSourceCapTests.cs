using FluentAssertions;
using Xunit;

namespace Keryx.Srtp.Tests;

/// <summary>
/// The SRTP master key authenticates any SSRC, so a peer that has completed the DTLS handshake can
/// stamp a fresh SSRC on every packet. Each distinct authenticated SSRC would otherwise pin a
/// per-stream replay window and rollover counter forever, so an authenticated flood grows the
/// receiver's per-SSRC maps without bound — a remote out-of-memory DoS. These tests pin the cap that
/// bounds that state (refuse-new-past-cap), and that a legitimate few-SSRC session is unaffected.
/// </summary>
public class SrtpReceiveSourceCapTests
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
        int maxReceiveSources)
    {
        var profile = SrtpProtectionProfile.ForKind(kind);
        var keys = DtlsSrtpKeyMaterial.Split(profile, TestPackets.KeyingMaterial(11, profile), DtlsSrtpRole.Client);
        return (
            new SrtpEncryptContext(profile, keys.Local),
            new SrtpDecryptContext(profile, keys.Local, logger: null, maxReceiveSources));
    }

    private static byte[] ProtectRtp(SrtpEncryptContext sender, uint ssrc, ushort seq)
    {
        var packet = TestPackets.Rtp(ssrc, seq, seq, [1, 2, 3, 4]);
        var wire = new byte[packet.Length + sender.Profile.RtpOverhead];
        var written = sender.ProtectRtp(packet, wire);
        return wire.AsSpan(0, written).ToArray();
    }

    private static byte[] ProtectRtcp(SrtpEncryptContext sender, uint ssrc)
    {
        var packet = TestPackets.Rtcp(ssrc, [5, 6, 7, 8]);
        var wire = new byte[packet.Length + sender.Profile.RtcpOverhead];
        var written = sender.ProtectRtcp(packet, wire);
        return wire.AsSpan(0, written).ToArray();
    }

    /// <summary>
    /// A flood of <em>authenticated</em> packets, each with a distinct SSRC, must not grow the
    /// per-SSRC RTP state past the cap. Without the cap this map would reach 400 entries; the
    /// assertion below is what fails on an unbounded implementation.
    /// </summary>
    [Theory]
    [MemberData(nameof(Profiles))]
    public void AuthenticatedRtpSsrcFlood_IsBoundedByTheCap(SrtpProtectionProfileKind kind)
    {
        const int cap = 8;
        var (sender, receiver) = CreatePair(kind, cap);
        using var s = sender;
        using var r = receiver;

        var output = new byte[256];
        var accepted = 0;
        for (uint ssrc = 0x4000_0000; ssrc < 0x4000_0190; ssrc++) // 400 distinct SSRCs
        {
            if (receiver.TryUnprotectRtp(ProtectRtp(s, ssrc, 1), output, out _))
            {
                accepted++;
            }
        }

        accepted.Should().Be(cap, "only the first cap distinct SSRCs are admitted");
        receiver.TrackedStreamCount.Should().Be(cap, "an authenticated SSRC flood must not grow state past the cap");
    }

    /// <summary>The SRTCP path keeps its own per-SSRC replay map and must be bounded the same way.</summary>
    [Theory]
    [MemberData(nameof(Profiles))]
    public void AuthenticatedSrtcpSsrcFlood_IsBoundedByTheCap(SrtpProtectionProfileKind kind)
    {
        const int cap = 8;
        var (sender, receiver) = CreatePair(kind, cap);
        using var s = sender;
        using var r = receiver;

        var output = new byte[256];
        var accepted = 0;
        for (uint ssrc = 0x5000_0000; ssrc < 0x5000_0190; ssrc++)
        {
            if (receiver.TryUnprotectRtcp(ProtectRtcp(s, ssrc), output, out _))
            {
                accepted++;
            }
        }

        accepted.Should().Be(cap);
        receiver.TrackedStreamCount.Should().Be(cap);
    }

    /// <summary>
    /// SSRCs admitted before the cap keep working after it is reached: refusing new sources must not
    /// disturb the streams already being tracked, and a packet from a capped-out SSRC is dropped
    /// (returns false) rather than throwing.
    /// </summary>
    [Theory]
    [MemberData(nameof(Profiles))]
    public void TrackedSourcesKeepWorkingAfterTheCapIsReached(SrtpProtectionProfileKind kind)
    {
        const int cap = 4;
        var (sender, receiver) = CreatePair(kind, cap);
        using var s = sender;
        using var r = receiver;

        var output = new byte[256];
        var tracked = new uint[cap];
        for (var i = 0; i < cap; i++)
        {
            tracked[i] = 0x6000_0000 + (uint)i;
            receiver.TryUnprotectRtp(ProtectRtp(s, tracked[i], 1), output, out _).Should().BeTrue();
        }

        // A new SSRC is now refused, without throwing.
        var newSource = ProtectRtp(s, 0x6000_00FF, 1);
        var refuse = () => receiver.TryUnprotectRtp(newSource, output, out _);
        refuse.Should().NotThrow().Which.Should().BeFalse("a new SSRC past the cap is dropped");

        // Every already-tracked SSRC still advances normally (seq 2), and replays (seq 1) are refused.
        foreach (var ssrc in tracked)
        {
            receiver.TryUnprotectRtp(ProtectRtp(s, ssrc, 2), output, out _)
                .Should().BeTrue("a tracked SSRC keeps working after the cap is reached");
        }

        receiver.TrackedStreamCount.Should().Be(cap);
    }

    /// <summary>A realistic session with a handful of SSRCs is nowhere near the default cap.</summary>
    [Theory]
    [MemberData(nameof(Profiles))]
    public void ALegitimateFewSourceSession_IsUnaffected(SrtpProtectionProfileKind kind)
    {
        var (sender, receiver) = CreatePair(kind, SrtpDecryptContext.DefaultMaxReceiveSources);
        using var s = sender;
        using var r = receiver;

        var output = new byte[256];
        uint[] sources = [0xAAAA_0001, 0xAAAA_0002, 0xAAAA_0003];
        foreach (var ssrc in sources)
        {
            for (ushort seq = 1; seq <= 20; seq++)
            {
                receiver.TryUnprotectRtp(ProtectRtp(s, ssrc, seq), output, out _)
                    .Should().BeTrue($"SSRC 0x{ssrc:x8} seq {seq} is legitimate traffic");
            }
        }

        receiver.TrackedStreamCount.Should().Be(sources.Length);
    }

    [Fact]
    public void ANonPositiveCap_IsRejected()
    {
        var profile = SrtpProtectionProfile.Aes128CmHmacSha1_80;
        var keys = DtlsSrtpKeyMaterial.Split(profile, TestPackets.KeyingMaterial(1, profile), DtlsSrtpRole.Client);

        var zero = () => new SrtpDecryptContext(profile, keys.Local, logger: null, maxReceiveSources: 0);
        zero.Should().Throw<ArgumentOutOfRangeException>();

        var negative = () => new SrtpDecryptContext(profile, keys.Local, logger: null, maxReceiveSources: -1);
        negative.Should().Throw<ArgumentOutOfRangeException>();
    }
}
