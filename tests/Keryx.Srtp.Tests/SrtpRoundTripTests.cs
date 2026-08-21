using FluentAssertions;
using Xunit;

namespace Keryx.Srtp.Tests;

/// <summary>
/// End-to-end protect/unprotect behaviour for both profiles: identity, packet index handling
/// across sequence-number wrap, tamper detection, replay rejection and per-SSRC independence.
/// </summary>
public class SrtpRoundTripTests
{
    public static TheoryData<SrtpProtectionProfileKind> Profiles => new()
    {
        SrtpProtectionProfileKind.Aes128CmHmacSha1_80,
        SrtpProtectionProfileKind.AeadAes128Gcm,
    };

    private static (SrtpEncryptContext Sender, SrtpDecryptContext Receiver) CreatePair(
        SrtpProtectionProfileKind kind,
        int seed = 1)
    {
        var profile = SrtpProtectionProfile.ForKind(kind);
        var keys = DtlsSrtpKeyMaterial.Split(profile, TestPackets.KeyingMaterial(seed, profile), DtlsSrtpRole.Client);
        return (new SrtpEncryptContext(profile, keys.Local), new SrtpDecryptContext(profile, keys.Local));
    }

    [Theory]
    [MemberData(nameof(Profiles))]
    public void ProtectThenUnprotect_RecoversTheOriginalPacket(SrtpProtectionProfileKind kind)
    {
        var (sender, receiver) = CreatePair(kind);
        using var s = sender;
        using var r = receiver;

        var random = new Random(1234);
        for (ushort seq = 1000; seq < 1064; seq++)
        {
            var payload = TestPackets.RandomBytes(random, random.Next(0, 400));
            var packet = TestPackets.Rtp(0x0BADF00D, seq, seq * 960u, payload);

            var protectedBuffer = new byte[packet.Length + s.Profile.RtpOverhead];
            var protectedLength = s.ProtectRtp(packet, protectedBuffer);
            protectedLength.Should().Be(packet.Length + s.Profile.RtpOverhead);

            // The RTP header must survive in the clear; the payload must not.
            protectedBuffer.AsSpan(0, 12).ToArray().Should().Equal(packet.AsSpan(0, 12).ToArray());
            if (payload.Length > 0)
            {
                protectedBuffer.AsSpan(12, payload.Length).ToArray().Should().NotEqual(payload);
            }

            var output = new byte[protectedLength];
            r.TryUnprotectRtp(protectedBuffer.AsSpan(0, protectedLength), output, out var length).Should().BeTrue();
            output.AsSpan(0, length).ToArray().Should().Equal(packet);
        }
    }

    [Theory]
    [MemberData(nameof(Profiles))]
    public void ProtectThenUnprotect_WorksInPlace(SrtpProtectionProfileKind kind)
    {
        var (sender, receiver) = CreatePair(kind);
        using var s = sender;
        using var r = receiver;

        var payload = TestPackets.RandomBytes(new Random(7), 200);
        var packet = TestPackets.Rtp(0x11223344, 4242, 96000, payload);

        var buffer = new byte[packet.Length + s.Profile.RtpOverhead];
        packet.CopyTo(buffer, 0);

        var protectedLength = s.ProtectRtp(buffer.AsSpan(0, packet.Length), buffer);
        r.TryUnprotectRtp(buffer.AsSpan(0, protectedLength), buffer, out var length).Should().BeTrue();
        buffer.AsSpan(0, length).ToArray().Should().Equal(packet);
    }

    [Theory]
    [MemberData(nameof(Profiles))]
    public void HeaderExtensionAndCsrcs_AreAuthenticatedButNotEncrypted(SrtpProtectionProfileKind kind)
    {
        var (sender, receiver) = CreatePair(kind);
        using var s = sender;
        using var r = receiver;

        var payload = TestPackets.RandomBytes(new Random(11), 64);
        var packet = TestPackets.RtpWithCsrcsAndExtension(0xABCDEF01, 9, payload);
        const int headerLength = 12 + 8 + 4 + 4;

        var buffer = new byte[packet.Length + s.Profile.RtpOverhead];
        var protectedLength = s.ProtectRtp(packet, buffer);

        // RFC 3711 Section 3.1: the header extension is inside the authenticated portion but
        // outside the encrypted portion.
        buffer.AsSpan(0, headerLength).ToArray().Should().Equal(packet.AsSpan(0, headerLength).ToArray());
        buffer.AsSpan(headerLength, payload.Length).ToArray().Should().NotEqual(payload);

        var output = new byte[protectedLength];
        r.TryUnprotectRtp(buffer.AsSpan(0, protectedLength), output, out var length).Should().BeTrue();
        output.AsSpan(0, length).ToArray().Should().Equal(packet);
    }

    /// <summary>
    /// RFC 3711 Section 3.3.1: the sender increments the ROC when SEQ wraps and the receiver
    /// re-derives the same index from s_l alone. Protecting 65534, 65535, 0, 1 and unprotecting
    /// them in the same order must round-trip; if the ROC were not carried into the IV and the
    /// authentication tag, the packets after the wrap would fail.
    /// </summary>
    [Theory]
    [MemberData(nameof(Profiles))]
    public void SequenceNumberWrap_RollsTheRolloverCounterOnBothSides(SrtpProtectionProfileKind kind)
    {
        var (sender, receiver) = CreatePair(kind);
        using var s = sender;
        using var r = receiver;

        ushort[] sequence = [65534, 65535, 0, 1, 2];
        foreach (var seq in sequence)
        {
            var packet = TestPackets.Rtp(0x5EEDCAFE, seq, seq * 90u, [(byte)seq, 0x01, 0x02, 0x03]);
            var buffer = new byte[packet.Length + s.Profile.RtpOverhead];
            var protectedLength = s.ProtectRtp(packet, buffer);

            var output = new byte[protectedLength];
            r.TryUnprotectRtp(buffer.AsSpan(0, protectedLength), output, out var length)
                .Should().BeTrue($"sequence number {seq} should authenticate");
            output.AsSpan(0, length).ToArray().Should().Equal(packet);
        }
    }

    /// <summary>
    /// The same wrap, but delivered out of order: 65535 arrives after 0 and 1, which forces the
    /// receiver down the "v = ROC - 1" branch of RFC 3711 Appendix A.
    /// </summary>
    [Theory]
    [MemberData(nameof(Profiles))]
    public void SequenceNumberWrap_HandlesOutOfOrderDelivery(SrtpProtectionProfileKind kind)
    {
        var (sender, receiver) = CreatePair(kind);
        using var s = sender;
        using var r = receiver;

        ushort[] sendOrder = [65533, 65534, 65535, 0, 1, 2];
        var wire = new Dictionary<ushort, (byte[] Plain, byte[] Protected)>();
        foreach (var seq in sendOrder)
        {
            var packet = TestPackets.Rtp(0x5EEDCAFE, seq, seq * 90u, [(byte)(seq >> 8), (byte)seq, 0xAA, 0xBB]);
            var buffer = new byte[packet.Length + s.Profile.RtpOverhead];
            var protectedLength = s.ProtectRtp(packet, buffer);
            wire[seq] = (packet, buffer.AsSpan(0, protectedLength).ToArray());
        }

        // 65535 is reordered to arrive after the wrap.
        ushort[] receiveOrder = [65533, 65534, 0, 65535, 1, 2];
        foreach (var seq in receiveOrder)
        {
            var (plain, wrapped) = wire[seq];
            var output = new byte[wrapped.Length];
            r.TryUnprotectRtp(wrapped, output, out var length)
                .Should().BeTrue($"sequence number {seq} should authenticate when delivered out of order");
            output.AsSpan(0, length).ToArray().Should().Equal(plain);
        }
    }

    [Theory]
    [MemberData(nameof(Profiles))]
    public void TamperedPacket_IsRejected(SrtpProtectionProfileKind kind)
    {
        var (sender, receiver) = CreatePair(kind);
        using var s = sender;
        using var r = receiver;

        var packet = TestPackets.Rtp(0x0A0B0C0D, 77, 1000, TestPackets.RandomBytes(new Random(3), 100));
        var buffer = new byte[packet.Length + s.Profile.RtpOverhead];
        var protectedLength = s.ProtectRtp(packet, buffer);
        var wire = buffer.AsSpan(0, protectedLength).ToArray();

        // Flip one bit in the payload, one in the header and one in the tag.
        int[] positions = [1, 20, protectedLength - 1];
        foreach (var position in positions)
        {
            var tampered = (byte[])wire.Clone();
            tampered[position] ^= 0x01;

            var output = new byte[tampered.Length];
            r.TryUnprotectRtp(tampered, output, out _)
                .Should().BeFalse($"flipping a bit at offset {position} must fail authentication");
        }

        // The untouched packet still verifies: the rejections above left no poisoned state.
        var clean = new byte[wire.Length];
        r.TryUnprotectRtp(wire, clean, out var length).Should().BeTrue();
        clean.AsSpan(0, length).ToArray().Should().Equal(packet);
    }

    /// <summary>RFC 3711 Section 3.3.2: an already-accepted index must not be accepted again.</summary>
    [Theory]
    [MemberData(nameof(Profiles))]
    public void ReplayedPacket_IsRejected(SrtpProtectionProfileKind kind)
    {
        var (sender, receiver) = CreatePair(kind);
        using var s = sender;
        using var r = receiver;

        var packet = TestPackets.Rtp(0x7777, 500, 1000, [1, 2, 3, 4, 5, 6, 7, 8]);
        var buffer = new byte[packet.Length + s.Profile.RtpOverhead];
        var protectedLength = s.ProtectRtp(packet, buffer);
        var wire = buffer.AsSpan(0, protectedLength).ToArray();

        var output = new byte[wire.Length];
        r.TryUnprotectRtp(wire, output, out _).Should().BeTrue();
        r.TryUnprotectRtp(wire, output, out _).Should().BeFalse("the packet is an exact replay");
        r.TryUnprotectRtp(wire, output, out _).Should().BeFalse();
    }

    /// <summary>A packet older than the replay window is dropped even though it authenticates.</summary>
    [Theory]
    [MemberData(nameof(Profiles))]
    public void PacketOlderThanTheReplayWindow_IsRejected(SrtpProtectionProfileKind kind)
    {
        var (sender, receiver) = CreatePair(kind);
        using var s = sender;
        using var r = receiver;

        var wire = new List<byte[]>();
        for (ushort seq = 100; seq < 400; seq++)
        {
            var packet = TestPackets.Rtp(0x9999, seq, seq * 10u, [(byte)seq]);
            var buffer = new byte[packet.Length + s.Profile.RtpOverhead];
            var protectedLength = s.ProtectRtp(packet, buffer);
            wire.Add(buffer.AsSpan(0, protectedLength).ToArray());
        }

        var output = new byte[64];
        foreach (var wrapped in wire)
        {
            r.TryUnprotectRtp(wrapped, output, out _).Should().BeTrue();
        }

        // Index 100 is 299 behind the highest accepted index, far outside the 128-entry window.
        r.TryUnprotectRtp(wire[0], output, out _).Should().BeFalse();
    }

    [Theory]
    [MemberData(nameof(Profiles))]
    public void DistinctSsrcs_KeepIndependentState(SrtpProtectionProfileKind kind)
    {
        var (sender, receiver) = CreatePair(kind);
        using var s = sender;
        using var r = receiver;

        const uint first = 0x1111_1111;
        const uint second = 0x2222_2222;

        // Interleave two streams that both wrap, each starting from its own sequence number.
        ushort[] firstSequence = [65534, 65535, 0, 1];
        ushort[] secondSequence = [10, 11, 12, 13];

        for (var i = 0; i < firstSequence.Length; i++)
        {
            foreach (var (ssrc, seq) in new[] { (first, firstSequence[i]), (second, secondSequence[i]) })
            {
                var packet = TestPackets.Rtp(ssrc, seq, seq * 20u, [(byte)i, (byte)seq]);
                var buffer = new byte[packet.Length + s.Profile.RtpOverhead];
                var protectedLength = s.ProtectRtp(packet, buffer);

                var output = new byte[protectedLength];
                r.TryUnprotectRtp(buffer.AsSpan(0, protectedLength), output, out var length)
                    .Should().BeTrue($"SSRC 0x{ssrc:x8} seq {seq}");
                output.AsSpan(0, length).ToArray().Should().Equal(packet);
            }
        }

        // The second stream never wrapped, so sequence 0 is unseen there even though the first
        // stream has already consumed it. Independent replay lists must let it through.
        var freshPacket = TestPackets.Rtp(second, 0, 0, [9, 9]);
        var freshBuffer = new byte[freshPacket.Length + s.Profile.RtpOverhead];
        var freshLength = s.ProtectRtp(freshPacket, freshBuffer);
        var freshOutput = new byte[freshLength];
        r.TryUnprotectRtp(freshBuffer.AsSpan(0, freshLength), freshOutput, out var freshWritten)
            .Should().BeTrue("the two SSRCs must not share a replay list");
        freshOutput.AsSpan(0, freshWritten).ToArray().Should().Equal(freshPacket);
    }

    /// <summary>A packet protected with one key must never verify under a different key.</summary>
    [Theory]
    [MemberData(nameof(Profiles))]
    public void PacketFromAnotherKey_IsRejected(SrtpProtectionProfileKind kind)
    {
        var (sender, _) = CreatePair(kind, seed: 1);
        var (_, foreignReceiver) = CreatePair(kind, seed: 2);
        using var s = sender;
        using var r = foreignReceiver;

        var packet = TestPackets.Rtp(0x4242, 1, 0, [0xDE, 0xAD, 0xBE, 0xEF]);
        var buffer = new byte[packet.Length + s.Profile.RtpOverhead];
        var protectedLength = s.ProtectRtp(packet, buffer);

        var output = new byte[protectedLength];
        r.TryUnprotectRtp(buffer.AsSpan(0, protectedLength), output, out _).Should().BeFalse();
    }
}
