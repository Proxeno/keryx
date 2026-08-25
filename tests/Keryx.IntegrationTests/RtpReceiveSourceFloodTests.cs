using FluentAssertions;
using Keryx;
using Keryx.Rtp;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// Adversarial coverage for the inbound per-source memory bound. A peer authenticated to the SRTP
/// context can stamp an arbitrary SSRC on every packet it sends; without a cap, each unseen value
/// allocates per-source receive state (RFC 3550 reception statistics, and — when enabled — a jitter
/// buffer) that is never evicted, so an SSRC flood would pin unbounded memory. This is the RTP analogue
/// of the bounded SCTP reassembly path.
/// </summary>
/// <remarks>
/// The flood is driven through <see cref="PeerConnection.DeliverDecryptedRtpForTest"/>, the post-SRTP
/// receive entry point, so the test crafts hostile already-decrypted packets deterministically without
/// standing up a transport or holding the session key. Routes are wired by applying a remote offer.
/// </remarks>
public sealed class RtpReceiveSourceFloodTests
{
    private const byte VideoPayloadType = 96;

    private static CancellationToken TestTimeout() =>
        new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;

    // A minimal BUNDLE offer with one audio (Opus, pt 111) and one video (H.264, pt 96) section, enough
    // for the receiver to publish a route table that resolves the video payload type to a 90 kHz video
    // route — so a flooded packet is fully tracked (stats, jitter, NACK) rather than skipped as unknown.
    private static readonly string RemoteOffer = string.Join("\r\n",
        "v=0",
        "o=- 4611731400430051336 2 IN IP4 127.0.0.1",
        "s=-",
        "t=0 0",
        "a=group:BUNDLE 0 1",
        "a=extmap-allow-mixed",
        "a=msid-semantic: WMS stream",
        "m=audio 9 UDP/TLS/RTP/SAVPF 111",
        "c=IN IP4 0.0.0.0",
        "a=rtcp:9 IN IP4 0.0.0.0",
        "a=ice-ufrag:hT7a",
        "a=ice-pwd:XKQVjJ9wRVWy3zNsL6mQ0pTb",
        "a=ice-options:trickle",
        "a=fingerprint:sha-256 75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24",
        "a=setup:actpass",
        "a=mid:0",
        "a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid",
        "a=sendrecv",
        "a=rtcp-mux",
        "a=rtpmap:111 opus/48000/2",
        "a=ssrc:1657320245 cname:JnQ3z0",
        "m=video 9 UDP/TLS/RTP/SAVPF 96",
        "c=IN IP4 0.0.0.0",
        "a=rtcp:9 IN IP4 0.0.0.0",
        "a=ice-ufrag:hT7a",
        "a=ice-pwd:XKQVjJ9wRVWy3zNsL6mQ0pTb",
        "a=ice-options:trickle",
        "a=fingerprint:sha-256 75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24",
        "a=setup:actpass",
        "a=mid:1",
        "a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid",
        "a=sendrecv",
        "a=rtcp-mux",
        "a=rtpmap:96 H264/90000",
        "a=rtcp-fb:96 nack",
        "a=ssrc:3204773231 cname:JnQ3z0",
        "");

    private static byte[] BuildVideoPacket(uint ssrc, ushort sequenceNumber)
    {
        var header = new RtpHeader
        {
            Version = 2,
            PayloadType = VideoPayloadType,
            Ssrc = ssrc,
            SequenceNumber = sequenceNumber,
            Timestamp = 90000u,
            Marker = true,
        };

        // A single-NAL H.264 payload (type 1, non-IDR slice) so any downstream depacketizer is happy; the
        // bound under test is about source count, not payload shape.
        var payload = new byte[] { 0x01, 0xAA, 0xBB, 0xCC };
        var packet = new byte[RtpHeader.FixedLength + payload.Length];
        var written = header.WriteTo(packet);
        payload.CopyTo(packet.AsSpan(written));
        return packet;
    }

    [Fact]
    public async Task An_ssrc_flood_cannot_grow_the_reception_statistics_table_without_bound()
    {
        var config = TestSupport.NewConfig();
        config.MaxReceiveSources = 8;

        await using var receiver = new PeerConnection(config);
        await receiver.SetRemoteDescriptionAsync(RemoteOffer, SdpType.Offer, TestTimeout());

        var delivered = 0;
        receiver.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            if (info.Kind == MediaKind.Video)
            {
                Interlocked.Increment(ref delivered);
            }
        };

        const int floodSize = 500;
        for (var i = 0; i < floodSize; i++)
        {
            // A fresh, well-formed SSRC on every packet — the withheld-source flood.
            var ssrc = 0x1000_0000u + (uint)i;
            receiver.DeliverDecryptedRtpForTest(BuildVideoPacket(ssrc, sequenceNumber: 1000));
        }

        // The retained per-source statistics table is capped, not grown to one entry per invented SSRC.
        receiver.ReceiveSourceStatCountForTest.Should().Be(8);

        // Delivery is never gated by the cap: every packet still reached the handler in arrival order.
        delivered.Should().Be(floodSize);
    }

    [Fact]
    public async Task An_ssrc_flood_cannot_grow_the_jitter_buffer_table_without_bound()
    {
        var config = TestSupport.NewConfig();
        config.MaxReceiveSources = 8;
        config.EnableReceiveJitterBuffer = true;

        // No reordering wait: a lone packet per source releases immediately, so the drain fires the
        // handler synchronously and the test stays deterministic without a clock.
        config.ReceiveJitterBuffer.MaxWait = TimeSpan.Zero;

        await using var receiver = new PeerConnection(config);
        await receiver.SetRemoteDescriptionAsync(RemoteOffer, SdpType.Offer, TestTimeout());

        var delivered = 0;
        receiver.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            if (info.Kind == MediaKind.Video)
            {
                Interlocked.Increment(ref delivered);
            }
        };

        const int floodSize = 500;
        for (var i = 0; i < floodSize; i++)
        {
            var ssrc = 0x2000_0000u + (uint)i;
            receiver.DeliverDecryptedRtpForTest(BuildVideoPacket(ssrc, sequenceNumber: 1000));
        }

        // At most MaxReceiveSources jitter buffers are ever allocated, however many SSRCs the peer invents.
        receiver.ReceiveStreamCountForTest.Should().Be(8);
        receiver.ReceiveSourceStatCountForTest.Should().Be(8);

        // Sources past the cap fall back to arrival-order delivery rather than being dropped, so every
        // packet is still surfaced to the application.
        delivered.Should().Be(floodSize);
    }

    [Fact]
    public async Task A_legitimate_handful_of_sources_is_fully_tracked_and_buffers_are_reused()
    {
        var config = TestSupport.NewConfig();
        config.EnableReceiveJitterBuffer = true;
        config.ReceiveJitterBuffer.MaxWait = TimeSpan.Zero;

        await using var receiver = new PeerConnection(config);
        await receiver.SetRemoteDescriptionAsync(RemoteOffer, SdpType.Offer, TestTimeout());

        var delivered = 0;
        receiver.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            if (info.Kind == MediaKind.Video)
            {
                Interlocked.Increment(ref delivered);
            }
        };

        // Three real sources, each sending a contiguous run of packets. The per-source state is created
        // once per SSRC and reused for every subsequent packet — the tables track exactly three sources.
        var ssrcs = new uint[] { 0x0A, 0x0B, 0x0C };
        foreach (var ssrc in ssrcs)
        {
            for (ushort seq = 100; seq < 140; seq++)
            {
                receiver.DeliverDecryptedRtpForTest(BuildVideoPacket(ssrc, seq));
            }
        }

        receiver.ReceiveStreamCountForTest.Should().Be(ssrcs.Length);
        receiver.ReceiveSourceStatCountForTest.Should().Be(ssrcs.Length);
        delivered.Should().Be(ssrcs.Length * 40);
    }
}
