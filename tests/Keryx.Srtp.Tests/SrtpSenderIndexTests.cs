using FluentAssertions;
using Xunit;

namespace Keryx.Srtp.Tests;

/// <summary>
/// RFC 3711 §3.3.1 and §9.1: the SRTP packet index <c>i = 2^16 * ROC + SEQ</c> must never be reused
/// with one master key. The index is the only thing that varies in the AES-CM IV (§4.1.1) and in the
/// RFC 7714 §8.1 GCM nonce, so a reused index is a reused keystream under AES-CM and a reused GCM
/// nonce — the latter leaking the GHASH subkey and with it the ability to forge arbitrary packets.
/// These tests attack the <em>sender</em>, which is where index reuse is created.
/// </summary>
public class SrtpSenderIndexTests
{
    public static TheoryData<SrtpProtectionProfileKind> Profiles => new()
    {
        SrtpProtectionProfileKind.Aes128CmHmacSha1_80,
        SrtpProtectionProfileKind.AeadAes128Gcm,
    };

    private static SrtpEncryptContext CreateSender(SrtpProtectionProfileKind kind)
    {
        var profile = SrtpProtectionProfile.ForKind(kind);
        var keys = DtlsSrtpKeyMaterial.Split(profile, TestPackets.KeyingMaterial(1, profile), DtlsSrtpRole.Client);
        return new SrtpEncryptContext(profile, keys.Local);
    }

    private static byte[] Protect(SrtpEncryptContext sender, uint ssrc, ushort seq, byte[] payload)
    {
        var packet = TestPackets.Rtp(ssrc, seq, seq * 960u, payload);
        var buffer = new byte[packet.Length + sender.Profile.RtpOverhead];
        var written = sender.ProtectRtp(packet, buffer);
        return buffer.AsSpan(0, written).ToArray();
    }

    /// <summary>
    /// Protecting the same SSRC and sequence number twice reuses the packet index and therefore the
    /// keystream. Two ciphertexts under one keystream are a two-time pad: XOR-ing them yields the XOR
    /// of the two plaintexts, so anyone on the wire recovers both given a guess at either. The sender
    /// must refuse instead.
    /// </summary>
    [Theory]
    [MemberData(nameof(Profiles))]
    public void Protecting_the_same_sequence_number_twice_is_refused(SrtpProtectionProfileKind kind)
    {
        using var sender = CreateSender(kind);
        const uint Ssrc = 0x0BADF00D;

        var first = new byte[64];
        var second = new byte[64];
        first.AsSpan().Fill(0xAA);
        second.AsSpan().Fill(0x55);

        _ = Protect(sender, Ssrc, 5000, first);

        var again = () => Protect(sender, Ssrc, 5000, second);
        again.Should().Throw<InvalidOperationException>()
            .WithMessage("*index*", "reusing an SRTP index is a two-time pad under AES-CM and a repeated GCM nonce");
    }

    /// <summary>
    /// The sender used the receiver-side RFC 3711 Appendix A rollover estimator, which is specified
    /// for receivers only. After a genuine wrap, a forward sequence jump larger than 32768 made the
    /// estimator answer <c>ROC-1</c> — rewinding the packet index by 2^16 and re-entering an index
    /// range the session had already used. Traced: seq 40000 (index 40000), 65000, 0 (ROC becomes 1,
    /// index 65536), then 40000 again — which the estimator resolves back to ROC 0 and index 40000.
    /// </summary>
    [Theory]
    [MemberData(nameof(Profiles))]
    public void A_forward_jump_after_a_wrap_cannot_rewind_the_packet_index(SrtpProtectionProfileKind kind)
    {
        using var sender = CreateSender(kind);
        const uint Ssrc = 0x5EEDCAFE;

        var payload = new byte[48];
        payload.AsSpan().Fill(0xAA);

        var firstAt40000 = Protect(sender, Ssrc, 40000, payload);
        _ = Protect(sender, Ssrc, 65000, payload);
        _ = Protect(sender, Ssrc, 0, payload);
        var secondAt40000 = Protect(sender, Ssrc, 40000, payload);

        // Identical plaintext, so an identical index would produce an identical encrypted payload.
        // Correctly counted, the second packet sits at index 2^16 + 40000, not back at 40000.
        firstAt40000.AsSpan(12, payload.Length).ToArray()
            .Should().NotEqual(
                secondAt40000.AsSpan(12, payload.Length).ToArray(),
                "the packet index must never rewind into a range the session has already used");
    }

    /// <summary>
    /// The legitimate case must keep working: sequence numbers that wrap normally advance the ROC and
    /// keep the index strictly increasing.
    /// </summary>
    [Theory]
    [MemberData(nameof(Profiles))]
    public void A_normal_sequence_number_wrap_still_protects(SrtpProtectionProfileKind kind)
    {
        using var sender = CreateSender(kind);
        const uint Ssrc = 0x11223344;
        var payload = new byte[32];

        ushort[] order = [65533, 65534, 65535, 0, 1, 2];
        var seen = new List<byte[]>();
        foreach (var seq in order)
        {
            var act = () => seen.Add(Protect(sender, Ssrc, seq, payload));
            act.Should().NotThrow($"sequence number {seq} advances the index legitimately");
        }

        seen.Should().HaveCount(order.Length);
        seen.Distinct(new ByteArrayComparer()).Should().HaveCount(order.Length, "every packet must be distinct");
    }

    private sealed class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        public bool Equals(byte[]? x, byte[]? y) => x is not null && y is not null && x.AsSpan().SequenceEqual(y);

        public int GetHashCode(byte[] obj) => obj.Length == 0 ? 0 : (obj[0] << 8) | obj[^1];
    }

    /// <summary>
    /// RFC 3711 Section 9.2 caps one master key at 2^31 SRTCP packets, which is the capacity of the
    /// 31-bit index field. Wrapping past it restarts the index at 0 and repeats every SRTCP nonce the
    /// session has already used, so the sender must stop rather than wrap.
    /// </summary>
    [Theory]
    [MemberData(nameof(Profiles))]
    public void The_srtcp_index_stops_at_the_rfc3711_limit_rather_than_wrapping(SrtpProtectionProfileKind kind)
    {
        using var sender = CreateSender(kind);
        const uint Ssrc = 0x0BADF00D;

        var packet = TestPackets.Rtcp(Ssrc, [1, 2, 3, 4]);
        var buffer = new byte[packet.Length + sender.Profile.RtcpOverhead];

        // Position the counter on the last index the 31-bit field can represent.
        sender.SetNextSrtcpIndex(Ssrc, SrtcpIndexWord.IndexMask);

        var last = () => sender.ProtectRtcp(packet, buffer);
        last.Should().NotThrow("2^31-1 is still a usable index");

        var overflow = () => sender.ProtectRtcp(packet, buffer);
        overflow.Should().Throw<InvalidOperationException>()
            .WithMessage("*2^31*", "wrapping the SRTCP index would repeat a nonce");
    }

    /// <summary>
    /// RFC 3711 Section 3.3.2: the replay list must not be updated by a packet that failed
    /// authentication. If it were, an attacker could inject a forged packet carrying a far-future
    /// sequence number, slide the receiver's window past everything the real sender is about to
    /// emit, and silently kill the stream without ever knowing a key.
    /// </summary>
    [Theory]
    [MemberData(nameof(Profiles))]
    public void A_forged_packet_with_a_far_future_sequence_number_does_not_slide_the_window(
        SrtpProtectionProfileKind kind)
    {
        var profile = SrtpProtectionProfile.ForKind(kind);
        var keys = DtlsSrtpKeyMaterial.Split(profile, TestPackets.KeyingMaterial(1, profile), DtlsSrtpRole.Client);
        using var sender = new SrtpEncryptContext(profile, keys.Local);
        using var receiver = new SrtpDecryptContext(profile, keys.Local);
        const uint Ssrc = 0x0BADF00D;
        var payload = new byte[32];

        // Establish the stream at sequence number 100.
        var opening = Protect(sender, Ssrc, 100, payload);
        var scratch = new byte[opening.Length];
        receiver.TryUnprotectRtp(opening, scratch, out _).Should().BeTrue();

        // Forge: take a real packet and rewrite only its sequence number to something far ahead.
        // The tag no longer covers the packet, so it must be rejected — and must leave no trace.
        var forged = Protect(sender, Ssrc, 101, payload);
        forged[2] = 0xF0;
        forged[3] = 0x00;
        var forgedOut = new byte[forged.Length];
        receiver.TryUnprotectRtp(forged, forgedOut, out _)
            .Should().BeFalse("the authentication tag does not cover the rewritten sequence number");

        // The real sender carries on from 102. Every one of these must still authenticate.
        for (ushort seq = 102; seq < 112; seq++)
        {
            var good = Protect(sender, Ssrc, seq, payload);
            var output = new byte[good.Length];
            receiver.TryUnprotectRtp(good, output, out var written)
                .Should().BeTrue($"sequence number {seq} must survive the forgery attempt");
            output.AsSpan(0, written).ToArray().Should().Equal(
                TestPackets.Rtp(Ssrc, seq, seq * 960u, payload));
        }
    }

    /// <summary>
    /// The SSRC is read straight off the wire before anything is authenticated. Creating per-SSRC
    /// cryptographic state at that point lets anyone who can reach the media socket pin one
    /// SrtpStreamState plus a dictionary entry per forged SSRC — never evicted, across a 2^32 space —
    /// for the price of one small datagram each. State must not exist until a packet authenticates.
    /// </summary>
    [Theory]
    [MemberData(nameof(Profiles))]
    public void Forged_packets_do_not_create_per_ssrc_state(SrtpProtectionProfileKind kind)
    {
        var profile = SrtpProtectionProfile.ForKind(kind);
        var keys = DtlsSrtpKeyMaterial.Split(profile, TestPackets.KeyingMaterial(1, profile), DtlsSrtpRole.Client);
        using var receiver = new SrtpDecryptContext(profile, keys.Local);

        receiver.TrackedStreamCount.Should().Be(0);

        var payload = new byte[32];
        for (uint ssrc = 0x1000_0000; ssrc < 0x1000_0400; ssrc++)
        {
            var rtp = TestPackets.Rtp(ssrc, 7, 700, payload);
            var forgedRtp = new byte[rtp.Length + profile.RtpOverhead];
            rtp.CopyTo(forgedRtp, 0); // garbage where the tag belongs: cannot authenticate
            var rtpOut = new byte[forgedRtp.Length];
            receiver.TryUnprotectRtp(forgedRtp, rtpOut, out _).Should().BeFalse();

            var rtcp = TestPackets.Rtcp(ssrc, [1, 2, 3, 4]);
            var forgedRtcp = new byte[rtcp.Length + profile.RtcpOverhead];
            rtcp.CopyTo(forgedRtcp, 0);
            var rtcpOut = new byte[forgedRtcp.Length];
            receiver.TryUnprotectRtcp(forgedRtcp, rtcpOut, out _).Should().BeFalse();
        }

        receiver.TrackedStreamCount.Should().Be(
            0,
            "1024 distinct forged SSRCs must leave no cryptographic state behind");
    }

    /// <summary>The counterpart: a packet that authenticates does create state, so the guard above
    /// is not simply disabling stream tracking.</summary>
    [Theory]
    [MemberData(nameof(Profiles))]
    public void An_authenticated_packet_does_create_per_ssrc_state(SrtpProtectionProfileKind kind)
    {
        var profile = SrtpProtectionProfile.ForKind(kind);
        var keys = DtlsSrtpKeyMaterial.Split(profile, TestPackets.KeyingMaterial(1, profile), DtlsSrtpRole.Client);
        using var sender = new SrtpEncryptContext(profile, keys.Local);
        using var receiver = new SrtpDecryptContext(profile, keys.Local);

        var good = Protect(sender, 0x0BADF00D, 7, new byte[32]);
        var output = new byte[good.Length];
        receiver.TryUnprotectRtp(good, output, out _).Should().BeTrue();

        receiver.TrackedStreamCount.Should().Be(1);
    }
}
