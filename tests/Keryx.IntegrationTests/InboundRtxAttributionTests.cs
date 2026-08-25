using System.Collections.Concurrent;
using FluentAssertions;
using Keryx.Rtp;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// Coverage for the mid-first attribution of a recovered RFC 4588 RTX packet when several same-kind
/// transceivers are negotiated and the repair carries no <c>a=ssrc-group:FID</c> association. The
/// no-FID fallback in the inbound RTX path must attribute the repair to the media source of the
/// transceiver the repair route demuxed to (mid-first), not to whichever same-kind transceiver happens
/// to be first — otherwise a repair for the second video m-line would be reconstructed onto the first
/// m-line's media SSRC and delivered as the wrong source's media.
/// </summary>
/// <remarks>
/// Driven through <see cref="PeerConnection.DeliverDecryptedRtpForTest"/>, the post-SRTP receive entry
/// point, so the test crafts already-decrypted media and repair packets deterministically. The remote
/// offer declares two video m-lines that share the H.264 (96) and rtx (97) payload types but carry no
/// <c>a=ssrc</c> or FID lines, so an inbound repair takes the no-FID fallback and demuxes by its MID.
/// </remarks>
public sealed class InboundRtxAttributionTests
{
    private const byte VideoPayloadType = 96;
    private const byte RtxPayloadType = 97;
    private const byte MidExtensionId = 3;

    private const uint FirstMediaSsrc = 0x1111_1111;
    private const uint SecondMediaSsrc = 0x2222_2222;
    private const uint RepairSsrc = 0x3333_3333;

    private static CancellationToken TestTimeout() =>
        new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;

    // Two video m-lines (mid "0" and "2") sharing pt 96 (H.264) and pt 97 (rtx, apt=96), with the MID
    // header extension but no a=ssrc / a=ssrc-group lines — so a repair packet has no FID association and
    // must be attributed by the mid it demuxes to. Mid "2" (not "1") avoids colliding with the default
    // send-only audio transceiver the receiver pins to mid "1".
    private static readonly string RemoteOffer = string.Join("\r\n",
        "v=0",
        "o=- 4611731400430051336 2 IN IP4 127.0.0.1",
        "s=-",
        "t=0 0",
        "a=group:BUNDLE 0 2",
        "a=extmap-allow-mixed",
        "a=msid-semantic: WMS stream",
        VideoSection("0"),
        VideoSection("2"),
        "");

    private static string VideoSection(string mid) => string.Join("\r\n",
        "m=video 9 UDP/TLS/RTP/SAVPF 96 97",
        "c=IN IP4 0.0.0.0",
        "a=rtcp:9 IN IP4 0.0.0.0",
        "a=ice-ufrag:hT7a",
        "a=ice-pwd:XKQVjJ9wRVWy3zNsL6mQ0pTb",
        "a=ice-options:trickle",
        "a=fingerprint:sha-256 75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24",
        "a=setup:actpass",
        $"a=mid:{mid}",
        "a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid",
        "a=sendrecv",
        "a=rtcp-mux",
        "a=rtpmap:96 H264/90000",
        "a=rtcp-fb:96 nack",
        "a=rtpmap:97 rtx/90000",
        "a=fmtp:97 apt=96");

    private static byte[] MediaPacket(string mid, uint ssrc, ushort sequenceNumber)
    {
        Span<byte> extBody = stackalloc byte[16];
        var writer = new RtpOneByteExtensionWriter(extBody);
        writer.TryAppend(MidExtensionId, System.Text.Encoding.ASCII.GetBytes(mid));
        var extLength = writer.Finish();

        var header = new RtpHeader
        {
            Version = 2,
            PayloadType = VideoPayloadType,
            Ssrc = ssrc,
            SequenceNumber = sequenceNumber,
            Timestamp = 90000u,
            Marker = true,
            HasExtension = true,
            ExtensionProfile = RtpHeaderExtension.OneByteProfile,
            ExtensionData = extBody[..extLength],
        };

        var payload = new byte[] { 0x01, 0xAA, 0xBB, 0xCC };
        var packet = new byte[header.HeaderLength + payload.Length];
        var written = header.WriteTo(packet);
        payload.CopyTo(packet.AsSpan(written));
        return packet;
    }

    private static byte[] RtxPacket(string mid, uint ssrc, ushort rtxSequenceNumber, ushort originalSequenceNumber, byte[] originalPayload)
    {
        Span<byte> extBody = stackalloc byte[16];
        var writer = new RtpOneByteExtensionWriter(extBody);
        writer.TryAppend(MidExtensionId, System.Text.Encoding.ASCII.GetBytes(mid));
        var extLength = writer.Finish();

        var rtxPayload = new byte[Keryx.Rtp.RtxPacket.OriginalSequenceNumberLength + originalPayload.Length];
        Keryx.Rtp.RtxPacket.WritePayload(originalSequenceNumber, originalPayload, rtxPayload);

        var header = new RtpHeader
        {
            Version = 2,
            PayloadType = RtxPayloadType,
            Ssrc = ssrc,
            SequenceNumber = rtxSequenceNumber,
            Timestamp = 90000u,
            HasExtension = true,
            ExtensionProfile = RtpHeaderExtension.OneByteProfile,
            ExtensionData = extBody[..extLength],
        };

        var packet = new byte[header.HeaderLength + rtxPayload.Length];
        var written = header.WriteTo(packet);
        rtxPayload.CopyTo(packet.AsSpan(written));
        return packet;
    }

    [Fact]
    public async Task A_repair_without_an_fid_association_is_attributed_to_the_media_source_of_its_own_mid()
    {
        await using var receiver = new PeerConnection(TestSupport.NewConfig());
        await receiver.SetRemoteDescriptionAsync(RemoteOffer, SdpType.Offer, TestTimeout());

        // Two video transceivers were created from the offer's two m-lines.
        receiver.Transceivers.Count(t => t.Kind == MediaKind.Video).Should().Be(2);

        var delivered = new ConcurrentQueue<(ushort Seq, uint Ssrc, byte PayloadType)>();
        receiver.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            if (info.Kind == MediaKind.Video)
            {
                delivered.Enqueue((info.SequenceNumber, info.Ssrc, info.PayloadType));
            }
        };

        // Teach each transceiver its own remote media SSRC: mid "0" -> FirstMediaSsrc (also first-of-kind),
        // mid "2" -> SecondMediaSsrc. A first-of-kind attribution would therefore pick FirstMediaSsrc.
        receiver.DeliverDecryptedRtpForTest(MediaPacket("0", FirstMediaSsrc, sequenceNumber: 100));
        receiver.DeliverDecryptedRtpForTest(MediaPacket("2", SecondMediaSsrc, sequenceNumber: 200));

        // A repair for the *second* m-line (mid "2"), on a repair SSRC with no FID association. The
        // recovered media packet must carry the second m-line's media SSRC.
        var recoveredPayload = new byte[] { 0x01, 0xDE, 0xAD, 0xBE, 0xEF };
        receiver.DeliverDecryptedRtpForTest(
            RtxPacket("2", RepairSsrc, rtxSequenceNumber: 7, originalSequenceNumber: 250, recoveredPayload));

        var recovered = delivered.Should().ContainSingle(d => d.Seq == 250).Subject;
        recovered.Ssrc.Should().Be(SecondMediaSsrc, "the repair demuxed to mid \"2\", whose learned media SSRC is SecondMediaSsrc");
        recovered.Ssrc.Should().NotBe(FirstMediaSsrc, "a first-of-kind attribution would wrongly pick the first video transceiver's SSRC");
        recovered.PayloadType.Should().Be(VideoPayloadType, "the repair was decapsulated back to its media payload type");
    }
}
