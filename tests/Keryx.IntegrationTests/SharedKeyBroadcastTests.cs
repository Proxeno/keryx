using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using FluentAssertions;
using Keryx.Broadcast;
using Keryx.Dtls;
using Keryx.Rtp;
using Keryx.Rtp.Simulcast;
using Keryx.Sdp;
using Keryx.Srtp;
using Xunit;
using SrtpProtectionProfile = Keryx.Srtp.SrtpProtectionProfile;

namespace Keryx.IntegrationTests;

/// <summary>
/// Shared-key encrypt-once public-broadcast mode (<c>broadcast-scale.md</c> §5). These tests pin the two
/// things the owner sign-off is for: the O(N)→O(1) crypto property (the SFU encrypts ONE ciphertext that
/// every viewer decrypts with the installed shared key), and the security boundary — enrollment throws
/// for any session that could receive/send media under the shared key, and there is no path to the mode
/// on a private room. Wrong/absent keys fail; epoch rotation switches cleanly.
/// </summary>
public sealed class SharedKeyBroadcastTests
{
    private static readonly SimulcastLayerId Hi = SimulcastLayerId.Parse("hi");
    private const uint IngestSsrc = 0x1234_5678u;
    private const uint BroadcastSsrc = 0x0BEE_F000u;
    private static SrtpProtectionProfile Profile => SrtpProtectionProfile.AeadAes128Gcm;

    // -------------------------------------------------------------------------------------------------
    // The O(1) crypto lever: encrypt once, every viewer decrypts the byte-identical ciphertext.
    // -------------------------------------------------------------------------------------------------

    /// <summary>
    /// The whole point of §5: the SFU SRTP-encrypts a broadcast packet exactly ONCE, and every one of the
    /// N enrolled viewers receives the <b>byte-identical ciphertext</b> — the same backing memory, not N
    /// copies — which each viewer decrypts with the installed shared key to recover the original media.
    /// </summary>
    [Fact]
    public void EncryptOnce_DeliversByteIdenticalCiphertext_EveryViewerDecrypts()
    {
        const int viewers = 16;
        using var key = PublicBroadcastKey.CreateForPublicContent(Profile);
        using var harness = new ViewerHarness(viewers);
        using var tier = new SharedKeyBroadcastTier(key, BroadcastSsrc);
        harness.EnrollAll(tier);
        tier.SelectTier(Hi);

        // One decrypt context per viewer, all built from the SAME exported shared key (as the client's
        // InstallPublicBroadcastReceiveKey would build it).
        var decryptors = CreateDecryptors(key.Export(), viewers);
        var datagrams = new List<BroadcastDatagram>();
        var recovered = new byte[2048];

        try
        {
            for (var packet = 0; packet < 40; packet++)
            {
                var payload = PacketPayload(packet);
                var ingest = BuildIngestPacket((ushort)packet, (uint)(packet * 3000), payload);

                var produced = tier.Fanout(Classification(), ingest, canStartLayer: packet == 0, datagrams);
                produced.Should().Be(viewers, "one datagram per enrolled viewer");

                // O(1) crypto, proven structurally: every datagram points at the identical backing array
                // and offset — there is exactly one ciphertext, replicated by reference, not re-encrypted.
                MemoryMarshal.TryGetArray(datagrams[0].Payload, out var firstSeg).Should().BeTrue();
                for (var i = 1; i < datagrams.Count; i++)
                {
                    MemoryMarshal.TryGetArray(datagrams[i].Payload, out var seg).Should().BeTrue();
                    seg.Array.Should().BeSameAs(firstSeg.Array, "all viewers share one ciphertext buffer");
                    seg.Offset.Should().Be(firstSeg.Offset);
                    seg.Count.Should().Be(firstSeg.Count);
                }

                // Every viewer decrypts that one ciphertext and recovers the ingest media on the broadcast SSRC.
                for (var i = 0; i < viewers; i++)
                {
                    datagrams[i].Destination.Should().Be(harness.Endpoint(i));
                    decryptors[i].TryUnprotectRtp(datagrams[i].Payload.Span, recovered, out var length)
                        .Should().BeTrue("viewer {0} packet {1} must authenticate under the shared key", i, packet);
                    RtpHeader.TryParse(recovered.AsSpan(0, length), out var header).Should().BeTrue();
                    header.Ssrc.Should().Be(BroadcastSsrc);
                    recovered.AsSpan(header.HeaderLength, length - header.HeaderLength).ToArray()
                        .Should().Equal(payload, "the recovered payload is the ingest media verbatim");
                }
            }
        }
        finally
        {
            foreach (var d in decryptors)
            {
                d.Dispose();
            }
        }
    }

    // -------------------------------------------------------------------------------------------------
    // THE SECURITY BOUNDARY (spec §5.4) — the fable-reviewed invariants.
    // -------------------------------------------------------------------------------------------------

    /// <summary>
    /// Invariant 2: a session with ANY receiving media m-line can never be enrolled. A viewer that could
    /// send media (recvonly/sendrecv from the SFU's view) would, under the shared key every viewer holds,
    /// be a cross-viewer forgery vector. Enrollment throws.
    /// </summary>
    [Theory]
    [InlineData(MediaDirection.RecvOnly)]
    [InlineData(MediaDirection.SendRecv)]
    public void Enroll_Throws_WhenSessionHasReceivingMLine(MediaDirection receiving)
    {
        using var key = PublicBroadcastKey.CreateForPublicContent(Profile);
        using var harness = new ViewerHarness(0);
        using var tier = new SharedKeyBroadcastTier(key, BroadcastSsrc);

        var session = harness.CreateSession(0, pc => pc.AddTransceiver(MediaKind.Video, receiving));

        var act = () => tier.Enroll(session);
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*receiving direction*", "the boundary refuses any receive m-line");
        tier.ViewerCount.Should().Be(0);
    }

    /// <summary>A send-only viewer (SFU→viewer, the only legitimate broadcast leg) enrolls cleanly.</summary>
    [Fact]
    public void Enroll_Succeeds_ForSendOnlyViewer()
    {
        using var key = PublicBroadcastKey.CreateForPublicContent(Profile);
        using var harness = new ViewerHarness(0);
        using var tier = new SharedKeyBroadcastTier(key, BroadcastSsrc);

        // A default viewer connection's legacy transceivers are send-only (SFU sends to the viewer).
        var session = harness.CreateSession(0);
        tier.Enroll(session);
        tier.ViewerCount.Should().Be(1);
    }

    /// <summary>
    /// Invariant: a session belongs to exactly one broadcast's shared key. Enrolling it into a second
    /// broadcast throws, so a viewer never holds two broadcasts' keys through this path.
    /// </summary>
    [Fact]
    public void Enroll_Throws_WhenSessionAlreadyInAnotherBroadcast()
    {
        using var keyA = PublicBroadcastKey.CreateForPublicContent(Profile);
        using var keyB = PublicBroadcastKey.CreateForPublicContent(Profile);
        using var harness = new ViewerHarness(0);
        using var tierA = new SharedKeyBroadcastTier(keyA, BroadcastSsrc);
        using var tierB = new SharedKeyBroadcastTier(keyB, 0x0BEE_F111u);

        var session = harness.CreateSession(0);
        tierA.Enroll(session);

        var act = () => tierB.Enroll(session);
        act.Should().Throw<InvalidOperationException>().WithMessage("*already enrolled*");
    }

    /// <summary>
    /// Invariant 3, structural: <see cref="PublicBroadcastKey"/> has no public constructor — the only way
    /// to obtain one is the factory whose name asserts public content. There is no way to build the key
    /// from a per-connection secret, and no general constructor a private room could reach.
    /// </summary>
    [Fact]
    public void PublicBroadcastKey_HasNoPublicConstructor_OnlyTheNamedFactory()
    {
        typeof(PublicBroadcastKey).GetConstructors(
            System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance)
            .Should().BeEmpty("the key must be unconstructable except through CreateForPublicContent");

        typeof(PublicBroadcastKey).GetMethod("CreateForPublicContent")
            .Should().NotBeNull("the sole mint path names 'public content' at every call site");
    }

    // -------------------------------------------------------------------------------------------------
    // Crypto correctness: wrong / absent key fails.
    // -------------------------------------------------------------------------------------------------

    /// <summary>A viewer holding the wrong shared key cannot decrypt the broadcast ciphertext.</summary>
    [Fact]
    public void WrongKey_FailsToDecrypt()
    {
        using var key = PublicBroadcastKey.CreateForPublicContent(Profile);
        using var wrongKey = PublicBroadcastKey.CreateForPublicContent(Profile);
        using var harness = new ViewerHarness(1);
        using var tier = new SharedKeyBroadcastTier(key, BroadcastSsrc);
        harness.EnrollAll(tier);
        tier.SelectTier(Hi);

        var datagrams = new List<BroadcastDatagram>();
        tier.Fanout(Classification(), BuildIngestPacket(0, 0, PacketPayload(0)), canStartLayer: true, datagrams);
        datagrams.Should().HaveCount(1);

        using var right = new SrtpDecryptContext(Profile, key.Export().ToSessionKeys());
        using var wrong = new SrtpDecryptContext(Profile, wrongKey.Export().ToSessionKeys());
        var recovered = new byte[2048];

        // A fresh context is needed per attempt (replay state); assert the wrong key fails, the right one works.
        wrong.TryUnprotectRtp(datagrams[0].Payload.Span, recovered, out _).Should().BeFalse("the wrong key must not authenticate");
        right.TryUnprotectRtp(datagrams[0].Payload.Span, recovered, out _).Should().BeTrue("the right key authenticates");
    }

    // -------------------------------------------------------------------------------------------------
    // Epoch rotation.
    // -------------------------------------------------------------------------------------------------

    /// <summary>
    /// Epoch rotation (spec §5.1): the tier mints a new random key and switches to it. Pre-rotation
    /// ciphertext decrypts only under the old epoch; post-rotation ciphertext only under the new epoch. A
    /// viewer that holds BOTH epochs (as the receive path does across a switch) decrypts either.
    /// </summary>
    [Fact]
    public void EpochRotation_SwitchesToNewKey_ClientHoldsBothEpochs()
    {
        using var key = PublicBroadcastKey.CreateForPublicContent(Profile);
        using var harness = new ViewerHarness(1);
        using var tier = new SharedKeyBroadcastTier(key, BroadcastSsrc);
        harness.EnrollAll(tier);
        tier.SelectTier(Hi);

        var epoch0 = tier.ExportKey();
        epoch0.Epoch.Should().Be(0);

        var datagrams = new List<BroadcastDatagram>();
        tier.Fanout(Classification(), BuildIngestPacket(0, 0, PacketPayload(0)), canStartLayer: true, datagrams);
        var beforeRotation = datagrams[0].Payload.ToArray();

        var epoch1 = tier.RotateEpoch();
        epoch1.Epoch.Should().Be(1);
        tier.Epoch.Should().Be(1);

        tier.Fanout(Classification(), BuildIngestPacket(1, 3000, PacketPayload(1)), canStartLayer: false, datagrams);
        var afterRotation = datagrams[0].Payload.ToArray();

        var recovered = new byte[2048];

        // The pre-rotation packet authenticates only under epoch 0; the post-rotation packet only under epoch 1.
        using (var d0 = new SrtpDecryptContext(Profile, epoch0.ToSessionKeys()))
        {
            d0.TryUnprotectRtp(beforeRotation, recovered, out _).Should().BeTrue();
        }

        using (var d0 = new SrtpDecryptContext(Profile, epoch0.ToSessionKeys()))
        {
            d0.TryUnprotectRtp(afterRotation, recovered, out _).Should().BeFalse("epoch 0 cannot read epoch 1 media");
        }

        using (var d1 = new SrtpDecryptContext(Profile, epoch1.ToSessionKeys()))
        {
            d1.TryUnprotectRtp(afterRotation, recovered, out _).Should().BeTrue();
        }

        // The receive-side manager holds both epochs and decrypts across the switch, keyed by SSRC.
        using var receiver = new PublicBroadcastReceiveKeysHarness(BroadcastSsrc);
        receiver.Install(epoch0);
        receiver.Install(epoch1);
        receiver.TryUnprotect(BroadcastSsrc, beforeRotation).Should().Be(PublicBroadcastReceiveKeys.Outcome.Unprotected);
        receiver.TryUnprotect(BroadcastSsrc, afterRotation).Should().Be(PublicBroadcastReceiveKeys.Outcome.Unprotected);
    }

    // -------------------------------------------------------------------------------------------------
    // Client-side receive routing: SSRC-scoped, the structural client boundary.
    // -------------------------------------------------------------------------------------------------

    /// <summary>
    /// The client applies the shared key ONLY to the enumerated broadcast SSRC(s); any other SSRC (a
    /// private m-line) is reported NotBroadcast so it keeps the connection's own DTLS keys. A broadcast
    /// SSRC whose packet does not authenticate is Failed, never falling through to the private keys.
    /// </summary>
    [Fact]
    public void ReceiveKeys_AreSsrcScoped_PrivateSsrcNeverUsesSharedKey()
    {
        using var key = PublicBroadcastKey.CreateForPublicContent(Profile);
        using var harness = new ViewerHarness(1);
        using var tier = new SharedKeyBroadcastTier(key, BroadcastSsrc);
        harness.EnrollAll(tier);
        tier.SelectTier(Hi);

        var datagrams = new List<BroadcastDatagram>();
        tier.Fanout(Classification(), BuildIngestPacket(0, 0, PacketPayload(0)), canStartLayer: true, datagrams);
        var ciphertext = datagrams[0].Payload.ToArray();

        using var receiver = new PublicBroadcastReceiveKeysHarness(BroadcastSsrc);
        receiver.Install(key.Export());

        // Broadcast SSRC → decrypts under the shared key.
        receiver.TryUnprotect(BroadcastSsrc, ciphertext).Should().Be(PublicBroadcastReceiveKeys.Outcome.Unprotected);
        // A different (e.g. private) SSRC → not our concern, use DTLS keys.
        receiver.TryUnprotect(0xAAAA_BBBBu, ciphertext).Should().Be(PublicBroadcastReceiveKeys.Outcome.NotBroadcast);
        // A broadcast SSRC with a corrupted body → Failed, never a DTLS fallthrough.
        var tampered = (byte[])ciphertext.Clone();
        tampered[^1] ^= 0xFF;
        receiver.TryUnprotect(BroadcastSsrc, tampered).Should().Be(PublicBroadcastReceiveKeys.Outcome.Failed);
    }

    /// <summary>The documented client entry point records the install on the config with its SSRC scope.</summary>
    [Fact]
    public void InstallPublicBroadcastReceiveKey_OnConfig_RecordsScopedInstall()
    {
        using var key = PublicBroadcastKey.CreateForPublicContent(Profile);
        var config = new PeerConnectionConfig();
        config.InstallPublicBroadcastReceiveKey(key.Export(), BroadcastSsrc);

        config.BroadcastReceiveInstalls.Should().ContainSingle();
        config.BroadcastReceiveInstalls[0].BroadcastSsrcs.Should().Equal(BroadcastSsrc);

        var empty = () => new PeerConnectionConfig().InstallPublicBroadcastReceiveKey(key.Export());
        empty.Should().Throw<ArgumentException>("a receive key must be scoped to at least one SSRC");
    }

    // -------------------------------------------------------------------------------------------------
    // Key distribution message (over the DTLS-authenticated data channel).
    // -------------------------------------------------------------------------------------------------

    /// <summary>The Keryx-defined key control message round-trips epoch, profile, SSRC scope and material.</summary>
    [Fact]
    public void KeyMessage_RoundTrips_AndRejectsForeignFrames()
    {
        using var key = PublicBroadcastKey.CreateForPublicContent(Profile);
        var export = key.Export();
        var frame = PublicBroadcastKeyMessage.Encode(export, [BroadcastSsrc, 0x0BEE_F111u]);

        PublicBroadcastKeyMessage.TryDecode(frame, out var decoded, out var ssrcs).Should().BeTrue();
        decoded!.Epoch.Should().Be(export.Epoch);
        decoded.ProfileKind.Should().Be(Profile.Kind);
        ssrcs.Should().Equal(BroadcastSsrc, 0x0BEE_F111u);
        decoded.ToSessionKeys().Should().Be(export.ToSessionKeys());

        // Arbitrary application data on the same channel is not mistaken for a key message.
        PublicBroadcastKeyMessage.TryDecode("hello, this is app data"u8, out _, out _).Should().BeFalse();
        PublicBroadcastKeyMessage.TryDecode(ReadOnlySpan<byte>.Empty, out _, out _).Should().BeFalse();
    }

    // -------------------------------------------------------------------------------------------------
    // NACK verbatim resend from the one shared history.
    // -------------------------------------------------------------------------------------------------

    /// <summary>
    /// A NACK is served by verbatim resend (spec §5.2): the tier returns the identical stored ciphertext
    /// for the requested broadcast sequence number, to only the viewer that asked. Unknown/aged sequence
    /// numbers return false.
    /// </summary>
    [Fact]
    public void TryResend_ReturnsVerbatimStoredCiphertext_ToOnlyTheAskingViewer()
    {
        using var key = PublicBroadcastKey.CreateForPublicContent(Profile);
        using var harness = new ViewerHarness(2);
        using var tier = new SharedKeyBroadcastTier(
            key, BroadcastSsrc, new SharedKeyBroadcastTierOptions { RetransmitHistoryDepth = 8 });
        harness.EnrollAll(tier);
        tier.SelectTier(Hi);

        var datagrams = new List<BroadcastDatagram>();
        byte[]? sentForSeqZero = null;
        ushort broadcastSeqZero = 0;

        for (var packet = 0; packet < 4; packet++)
        {
            tier.Fanout(Classification(), BuildIngestPacket((ushort)packet, (uint)(packet * 3000), PacketPayload(packet)), packet == 0, datagrams);
            if (packet == 0)
            {
                sentForSeqZero = datagrams[0].Payload.ToArray();
                RtpHeader.TryParse(DecryptWithKey(key, datagrams[0].Payload.Span), out var header).Should().BeTrue();
                broadcastSeqZero = header.SequenceNumber;
            }
        }

        // Resend the first broadcast packet to viewer 1 only: identical ciphertext, that viewer's endpoint.
        tier.TryResend(broadcastSeqZero, harness.Endpoint(1), out var resent).Should().BeTrue();
        resent.Payload.ToArray().Should().Equal(sentForSeqZero!, "the resend is the verbatim stored ciphertext");
        resent.Destination.Should().Be(harness.Endpoint(1));

        // A sequence number that was never sent is not in the history.
        tier.TryResend(60000, harness.Endpoint(0), out _).Should().BeFalse();
    }

    /// <summary>A fan-out with no enrolled viewers produces nothing and does not throw.</summary>
    [Fact]
    public void Fanout_WithNoViewers_IsANoOp()
    {
        using var key = PublicBroadcastKey.CreateForPublicContent(Profile);
        using var tier = new SharedKeyBroadcastTier(key, BroadcastSsrc);
        tier.SelectTier(Hi);
        var datagrams = new List<BroadcastDatagram>();
        tier.Fanout(Classification(), BuildIngestPacket(0, 0, PacketPayload(0)), canStartLayer: true, datagrams)
            .Should().Be(0);
        datagrams.Should().BeEmpty();
    }

    // -------------------------------------------------------------------------------------------------
    // Helpers.
    // -------------------------------------------------------------------------------------------------

    private static RtpLayerClassification Classification() =>
        new(Hi, IngestSsrc, IsRepair: false, RtpLayerClassificationSource.RidExtension);

    private static SrtpDecryptContext[] CreateDecryptors(PublicBroadcastKeyExport export, int count)
    {
        var contexts = new SrtpDecryptContext[count];
        for (var i = 0; i < count; i++)
        {
            contexts[i] = new SrtpDecryptContext(export.Profile, export.ToSessionKeys());
        }

        return contexts;
    }

    private static byte[] DecryptWithKey(PublicBroadcastKey key, ReadOnlySpan<byte> ciphertext)
    {
        using var context = new SrtpDecryptContext(Profile, key.Export().ToSessionKeys());
        var recovered = new byte[2048];
        context.TryUnprotectRtp(ciphertext, recovered, out var length).Should().BeTrue();
        return recovered.AsSpan(0, length).ToArray();
    }

    private static byte[] BuildIngestPacket(ushort sequenceNumber, uint timestamp, byte[] payload)
    {
        var header = new RtpHeader
        {
            Version = 2,
            PayloadType = 96,
            Ssrc = IngestSsrc,
            SequenceNumber = sequenceNumber,
            Timestamp = timestamp,
            Marker = false,
        };

        var buffer = new byte[header.HeaderLength + payload.Length];
        var written = header.WriteTo(buffer);
        payload.CopyTo(buffer.AsSpan(written));
        return buffer;
    }

    private static byte[] PacketPayload(int packet)
    {
        var payload = new byte[1000];
        for (var i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)((packet * 31) + (i * 7));
        }

        return payload;
    }

    /// <summary>A set of send-only viewer sessions with bound loopback endpoints, for enrollment.</summary>
    private sealed class ViewerHarness : IDisposable
    {
        private readonly DtlsCertificate _certificate = DtlsCertificate.GenerateSelfSigned();
        private readonly List<PeerConnection> _connections = [];
        private readonly List<ViewerSession> _sessions = [];
        private readonly List<IPEndPoint> _endpoints = [];

        public ViewerHarness(int viewers)
        {
            for (var i = 0; i < viewers; i++)
            {
                CreateSession(i);
            }
        }

        public ViewerSession CreateSession(int index, Action<PeerConnection>? configure = null)
        {
            var config = new PeerConnectionConfig { Certificate = _certificate };
            var connection = new PeerConnection(config);
            configure?.Invoke(connection);

            var endpoint = new IPEndPoint(IPAddress.Loopback, 40000 + index);
            var session = new ViewerSession($"viewer-{index}", connection, $"ufrag{index}");
            session.NoteBoundEndPoint(endpoint);

            _connections.Add(connection);
            _sessions.Add(session);
            _endpoints.Add(endpoint);
            return session;
        }

        public IPEndPoint Endpoint(int index) => _endpoints[index];

        public void EnrollAll(SharedKeyBroadcastTier tier)
        {
            foreach (var session in _sessions)
            {
                tier.Enroll(session);
            }
        }

        public void Dispose()
        {
            foreach (var connection in _connections)
            {
                connection.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }

            _certificate.Dispose();
        }
    }

    /// <summary>Drives the internal receive-key manager exactly as the connection's RTP path does.</summary>
    private sealed class PublicBroadcastReceiveKeysHarness : IDisposable
    {
        private readonly PublicBroadcastReceiveKeys _keys = new(Keryx.Core.NullLogger.Instance);
        private readonly uint[] _ssrcs;
        private readonly byte[] _recovered = new byte[2048];

        public PublicBroadcastReceiveKeysHarness(params uint[] ssrcs) => _ssrcs = ssrcs;

        public void Install(PublicBroadcastKeyExport export) => _keys.Install(export, _ssrcs);

        public PublicBroadcastReceiveKeys.Outcome TryUnprotect(uint ssrc, ReadOnlySpan<byte> packet) =>
            _keys.TryUnprotectRtp(ssrc, packet, _recovered, out _);

        public void Dispose() => _keys.Dispose();
    }
}
