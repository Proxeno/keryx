using FluentAssertions;
using Xunit;

namespace Keryx.Srtp.Tests;

/// <summary>
/// Adversarial probes for the two failure modes that turn a media-path bug into a remote exploit:
/// accepting a forged or blanked authentication tag (fail-open), and letting a packet that failed
/// authentication mutate replay / rollover state (state poisoning). RFC 3711 Section 3.3 fixes the
/// order as "check replay, verify the tag, and only then update state"; these tests pin that a
/// rejected packet leaves nothing behind.
/// </summary>
public class SrtpAdversarialTests
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
        int seed = 31)
    {
        var profile = SrtpProtectionProfile.ForKind(kind);
        var keys = DtlsSrtpKeyMaterial.Split(profile, TestPackets.KeyingMaterial(seed, profile), DtlsSrtpRole.Client);
        return (new SrtpEncryptContext(profile, keys.Local), new SrtpDecryptContext(profile, keys.Local));
    }

    private static byte[] ProtectRtp(SrtpEncryptContext sender, uint ssrc, ushort seq, byte[] payload)
    {
        var packet = TestPackets.Rtp(ssrc, seq, seq, payload);
        var wire = new byte[packet.Length + sender.Profile.RtpOverhead];
        var written = sender.ProtectRtp(packet, wire);
        return wire.AsSpan(0, written).ToArray();
    }

    private static byte[] ProtectRtcp(SrtpEncryptContext sender, uint ssrc, byte[] body)
    {
        var packet = TestPackets.Rtcp(ssrc, body);
        var wire = new byte[packet.Length + sender.Profile.RtcpOverhead];
        var written = sender.ProtectRtcp(packet, wire);
        return wire.AsSpan(0, written).ToArray();
    }

    /// <summary>
    /// The RTP authentication tag is the trailing <see cref="SrtpProtectionProfile.TagLength"/> bytes
    /// in every profile here. Blanking it to zero, setting it to all-ones, or flipping a single bit
    /// must all fail: an implementation that treated a zero tag as "no tag supplied" and skipped the
    /// check would silently accept forgeries.
    /// </summary>
    [Theory]
    [MemberData(nameof(Profiles))]
    public void ForgedOrBlankedRtpTag_IsRejected(SrtpProtectionProfileKind kind)
    {
        var (sender, receiver) = CreatePair(kind);
        using var s = sender;
        using var r = receiver;

        var genuine = ProtectRtp(s, 0x1234_5678, 4001, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
        var tagLength = s.Profile.TagLength;
        var output = new byte[genuine.Length];

        // All-zero tag.
        var zeroed = (byte[])genuine.Clone();
        Array.Clear(zeroed, zeroed.Length - tagLength, tagLength);
        receiver.TryUnprotectRtp(zeroed, output, out _).Should().BeFalse("a blanked (all-zero) tag must not authenticate");

        // All-ones tag.
        var ones = (byte[])genuine.Clone();
        for (var i = ones.Length - tagLength; i < ones.Length; i++)
        {
            ones[i] = 0xFF;
        }

        receiver.TryUnprotectRtp(ones, output, out _).Should().BeFalse("an all-ones tag must not authenticate");

        // Single-bit flip in the tag.
        var flipped = (byte[])genuine.Clone();
        flipped[^1] ^= 0x01;
        receiver.TryUnprotectRtp(flipped, output, out _).Should().BeFalse("a one-bit tag change must not authenticate");

        // The pristine packet still authenticates, so the receiver was not simply rejecting everything.
        receiver.TryUnprotectRtp(genuine, output, out var length).Should().BeTrue();
        length.Should().Be(17);
    }

    /// <summary>
    /// Truncating the tag, or stripping it entirely, must be rejected rather than read past the end
    /// of the datagram or accept a short tag.
    /// </summary>
    [Theory]
    [MemberData(nameof(Profiles))]
    public void TruncatedRtpTag_IsRejected(SrtpProtectionProfileKind kind)
    {
        var (sender, receiver) = CreatePair(kind);
        using var s = sender;
        using var r = receiver;

        var genuine = ProtectRtp(s, 0x2222_3333, 4002, [1, 2, 3, 4, 5, 6, 7, 8]);

        for (var drop = 1; drop <= s.Profile.TagLength; drop++)
        {
            var truncated = genuine.AsSpan(0, genuine.Length - drop).ToArray();
            var output = new byte[Math.Max(truncated.Length, 1)];
            var act = () => receiver.TryUnprotectRtp(truncated, output, out _);
            act.Should().NotThrow().Which.Should().BeFalse($"dropping {drop} tag byte(s) must be rejected");
        }
    }

    /// <summary>
    /// A packet that fails authentication must not advance the replay window. Otherwise an attacker
    /// who can predict the next index could inject a forgery at that index and have the receiver drop
    /// the genuine packet that follows as a "replay" — a remote denial of the media stream without
    /// ever holding the key. RFC 3711 Section 3.3 commits replay state only after the tag verifies.
    /// </summary>
    [Theory]
    [MemberData(nameof(Profiles))]
    public void AFailedRtpAuthentication_DoesNotBurnTheReplayIndex(SrtpProtectionProfileKind kind)
    {
        var (sender, receiver) = CreatePair(kind);
        using var s = sender;
        using var r = receiver;

        const uint ssrc = 0x0BAD_C0DE;
        var output = new byte[512];

        // Establish the stream with a genuine packet.
        receiver.TryUnprotectRtp(ProtectRtp(s, ssrc, 5000, [9, 9, 9, 9]), output, out _).Should().BeTrue();

        // The sender's next real packet is seq 5001. Build it, then inject a corrupted copy first:
        // same index, broken tag. If the receiver committed the index on failure, the genuine copy
        // below would be rejected as a replay.
        var genuineNext = ProtectRtp(s, ssrc, 5001, [8, 8, 8, 8]);
        var corrupted = (byte[])genuineNext.Clone();
        corrupted[^1] ^= 0xFF;
        receiver.TryUnprotectRtp(corrupted, output, out _).Should().BeFalse("the forged copy must fail authentication");

        receiver.TryUnprotectRtp(genuineNext, output, out var length)
            .Should()
            .BeTrue("a failed authentication must not burn the index of the genuine packet");
        output.AsSpan(12, length - 12).ToArray().Should().Equal(8, 8, 8, 8);

        // And the genuine packet, now committed, is itself a replay the second time.
        receiver.TryUnprotectRtp(genuineNext, output, out _).Should().BeFalse("the committed index is now a replay");
    }

    /// <summary>
    /// The same property for a not-yet-seen SSRC: a forged first packet must create no state, so the
    /// stream's genuine first packet still authenticates and is not pre-empted.
    /// </summary>
    [Theory]
    [MemberData(nameof(Profiles))]
    public void AForgedFirstPacket_DoesNotPreemptTheGenuineStream(SrtpProtectionProfileKind kind)
    {
        var (sender, receiver) = CreatePair(kind);
        using var s = sender;
        using var r = receiver;

        const uint ssrc = 0x0011_2233;
        var genuineFirst = ProtectRtp(s, ssrc, 100, [4, 5, 6, 7]);
        var output = new byte[512];

        var corrupted = (byte[])genuineFirst.Clone();
        corrupted[^2] ^= 0x80;
        receiver.TryUnprotectRtp(corrupted, output, out _).Should().BeFalse();
        receiver.TrackedStreamCount.Should().Be(0, "a forged first packet must leave no per-SSRC state");

        receiver.TryUnprotectRtp(genuineFirst, output, out _).Should().BeTrue();
        receiver.TrackedStreamCount.Should().Be(1);
    }

    /// <summary>
    /// SRTCP analogue of the replay-index probe: a corrupted SRTCP packet must not commit its index,
    /// so the genuine packet at that index still authenticates.
    /// </summary>
    [Theory]
    [MemberData(nameof(Profiles))]
    public void AFailedSrtcpAuthentication_DoesNotBurnTheSrtcpIndex(SrtpProtectionProfileKind kind)
    {
        var (sender, receiver) = CreatePair(kind);
        using var s = sender;
        using var r = receiver;

        const uint ssrc = 0x5151_5151;
        var output = new byte[512];

        var genuine = ProtectRtcp(s, ssrc, [1, 2, 3, 4]);
        var corrupted = (byte[])genuine.Clone();
        corrupted[^1] ^= 0xFF; // trailing byte: tag (CM-HMAC) or SRTCP index low byte (GCM); either fails auth
        receiver.TryUnprotectRtcp(corrupted, output, out _).Should().BeFalse();

        receiver.TryUnprotectRtcp(genuine, output, out var length)
            .Should()
            .BeTrue("a failed SRTCP authentication must not burn the genuine packet's index");
        output.AsSpan(0, length).ToArray().Should().Equal(TestPackets.Rtcp(ssrc, [1, 2, 3, 4]));

        receiver.TryUnprotectRtcp(genuine, output, out _).Should().BeFalse("the committed index is now a replay");
    }

    /// <summary>
    /// Flipping the SRTCP E (encryption) bit in the index word must fail authentication: the whole
    /// index word is inside the authenticated portion (RFC 3711 Section 3.4 / RFC 7714 Section 17), so
    /// a receiver cannot be tricked into treating an encrypted packet's ciphertext as cleartext.
    /// </summary>
    [Theory]
    [MemberData(nameof(Profiles))]
    public void FlippingTheSrtcpEncryptionBit_IsRejected(SrtpProtectionProfileKind kind)
    {
        var (sender, receiver) = CreatePair(kind);
        using var s = sender;
        using var r = receiver;

        const uint ssrc = 0x7788_99AA;
        var genuine = ProtectRtcp(s, ssrc, [0x10, 0x20, 0x30, 0x40]);
        var profile = s.Profile;

        // CM-HMAC lays the packet out as [rtcp | index-word(4) | tag]; GCM as [rtcp | tag | index-word(4)].
        // The E bit is the top bit of the first index-word byte in both.
        var indexWordStart = profile.Kind is SrtpProtectionProfileKind.AeadAes128Gcm or SrtpProtectionProfileKind.AeadAes256Gcm
            ? genuine.Length - SrtpProtectionProfile.SrtcpIndexLength
            : genuine.Length - profile.TagLength - SrtpProtectionProfile.SrtcpIndexLength;

        var tampered = (byte[])genuine.Clone();
        tampered[indexWordStart] ^= 0x80; // flip E
        var output = new byte[genuine.Length];
        receiver.TryUnprotectRtcp(tampered, output, out _).Should().BeFalse("flipping the E bit must fail authentication");
    }
}
