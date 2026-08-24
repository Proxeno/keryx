using System.Buffers.Binary;
using System.Collections.Concurrent;
using FluentAssertions;
using Keryx.Rtp;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// The public transceiver API (Epic D, PR 3): <see cref="PeerConnection.AddTransceiver"/> /
/// <see cref="PeerConnection.AddTrack"/> offer N m-lines of any kind, the answerer binds or auto-creates
/// per RFC 8829 §5.10 firing <see cref="PeerConnection.OnTransceiver"/>, the offer carries the MID
/// header extension on every RTP m-line, a recvonly transceiver ingests as the offerer, and
/// <see cref="PeerConnection.GetStats"/> reports one entry per transceiver — all additive over the
/// unchanged single-per-kind path.
/// </summary>
public sealed class PublicTransceiverApiTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    private static CancellationToken TestTimeout(int seconds = 60) =>
        new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    [Fact]
    public async Task DefaultOffer_HasNoMidExtmap_AndOneVideoOneAudio()
    {
        await using var peer = new PeerConnection(TestSupport.NewConfig());
        var offer = SessionDescription.Parse(await peer.CreateOfferAsync(TestTimeout()));

        var rtp = offer.MediaDescriptions.Where(m => m.Media is "video" or "audio").ToList();
        rtp.Should().HaveCount(2);
        foreach (var media in rtp)
        {
            media.GetExtMaps().Should().NotContain(
                e => string.Equals(e.Uri, RtpHeaderExtensionUri.Mid, StringComparison.Ordinal),
                "the pure legacy config must not offer the MID extmap (byte-identical offer)");
        }

        peer.Transceivers.Should().HaveCount(2);
        peer.Transceivers.Select(t => t.Kind).Should().Equal(MediaKind.Video, MediaKind.Audio);
    }

    [Fact]
    public async Task AddTransceiver_MultipleSameKind_OffersMidExtmapOnEveryRtpMLine()
    {
        await using var peer = new PeerConnection(TestSupport.NewConfig());
        peer.AddTransceiver(MediaKind.Video, MediaDirection.SendOnly);

        var offer = SessionDescription.Parse(await peer.CreateOfferAsync(TestTimeout()));
        var rtp = offer.MediaDescriptions.Where(m => m.Media is "video" or "audio").ToList();

        rtp.Where(m => m.Media == "video").Should().HaveCount(2, "the default video plus the added one");
        foreach (var media in rtp)
        {
            media.GetExtMaps().Should().Contain(
                e => string.Equals(e.Uri, RtpHeaderExtensionUri.Mid, StringComparison.Ordinal),
                "every RTP m-line carries the MID extmap once the transceiver API is used (§3.5)");
        }

        // Mids are allocated in insertion order, skipping the pinned legacy and application mids.
        peer.Transceivers.Should().HaveCount(3);
        peer.Transceivers.Select(t => t.Mid).Should().Equal("0", "1", "3");
        offer.MediaDescriptions.Select(m => m.Mid).Should().Equal("0", "1", "3", "2");
    }

    [Fact]
    public async Task Answerer_AutoCreatesTransceiver_AndRaisesOnTransceiver()
    {
        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        offerer.AddTransceiver(MediaKind.Video, MediaDirection.SendOnly); // a second video m-line
        var offer = await offerer.CreateOfferAsync(TestTimeout());

        await using var answerer = new PeerConnection(TestSupport.NewConfig());
        var created = new List<RtpTransceiver>();
        answerer.OnTransceiver += (_, t) => created.Add(t);

        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, TestTimeout());

        // The offer's third m-line (a second video) has no local transceiver to bind to, so one is
        // auto-created and OnTransceiver fires exactly once for it, before the answer is built.
        created.Should().HaveCount(1);
        created[0].Kind.Should().Be(MediaKind.Video);
        answerer.Transceivers.Should().HaveCount(3);
        answerer.Transceivers.Count(t => t.Kind == MediaKind.Video).Should().Be(2);

        // The auto-created transceiver defaults to the complement of the offered sendonly: recvonly.
        var answer = SessionDescription.Parse(await answerer.CreateAnswerAsync(TestTimeout()));
        answer.MediaDescriptions.Where(m => m.Media == "video")
            .Should().OnlyContain(m => m.DirectionOrDefault == MediaDirection.RecvOnly);
    }

    [Fact]
    public async Task Answerer_OnTransceiverHandler_MaySetDirectionBeforeAnswer()
    {
        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        offerer.AddTransceiver(MediaKind.Video, MediaDirection.SendOnly);
        var offer = await offerer.CreateOfferAsync(TestTimeout());

        await using var answerer = new PeerConnection(TestSupport.NewConfig());
        answerer.OnTransceiver += (_, t) => t.Direction = MediaDirection.Inactive;
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, TestTimeout());

        var answer = SessionDescription.Parse(await answerer.CreateAnswerAsync(TestTimeout()));
        // The handler forced the auto-created transceiver inactive; the negotiated direction follows.
        answer.MediaDescriptions.Count(m => m.Media == "video" && m.DirectionOrDefault == MediaDirection.Inactive)
            .Should().Be(1);
    }

    [Fact]
    public async Task AddTransceiver_AfterDescription_Throws()
    {
        await using var peer = new PeerConnection(TestSupport.NewConfig());
        _ = await peer.CreateOfferAsync(TestTimeout());

        var act = () => peer.AddTransceiver(MediaKind.Video);
        act.Should().Throw<InvalidOperationException>("adding a transceiver mid-session is not supported yet");
    }

    [Fact]
    public async Task MultipleSameKindTransceivers_FlowAndDemuxByTheirOwnMids()
    {
        var cancellationToken = TestTimeout();

        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        var secondVideo = offerer.AddTransceiver(MediaKind.Video, MediaDirection.SendOnly);
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        var byMid = new ConcurrentDictionary<string, ConcurrentDictionary<uint, bool>>();
        answerer.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            if (info.Kind == MediaKind.Video && info.Mid is { } mid)
            {
                byMid.GetOrAdd(mid, _ => new ConcurrentDictionary<uint, bool>())[info.Ssrc] = true;
            }
        };

        await ConnectAsync(offerer, answerer, cancellationToken);

        var videoTransceivers = offerer.Transceivers.Where(t => t.Kind == MediaKind.Video).ToList();
        videoTransceivers.Should().HaveCount(2);
        videoTransceivers.Select(t => t.Sender.Ssrc).Distinct().Should().HaveCount(2, "each video sender owns a distinct SSRC");

        // Forward already-packetized payloads on each video sender directly (the RtpSender IS the
        // forwarder). They carry pt 96 but distinct SSRCs, so the answerer must demux by SSRC→mid.
        foreach (var transceiver in videoTransceivers)
        {
            var pt = transceiver.Sender.PayloadType;
            pt.Should().NotBeNull("each sendonly video transceiver negotiated a send codec");
            for (var i = 0; i < 30; i++)
            {
                var payload = new byte[80];
                Random.Shared.NextBytes(payload);
                transceiver.Sender.TryForwardRtp(payload, 1000u + ((uint)i * 3000u), marker: i == 29, pt!.Value)
                    .Should().BeTrue();
                await Task.Delay(2, cancellationToken);
            }
        }

        (await TestSupport.WaitForAsync(() => byMid.Count >= 2)).Should().BeTrue(
            "packets from two same-kind m-lines must demux to two distinct mids");

        // Each mid received exactly its own sender's SSRC, never the other's.
        foreach (var transceiver in videoTransceivers)
        {
            var mid = transceiver.Mid!;
            byMid.Should().ContainKey(mid);
            byMid[mid].Keys.Should().Equal(transceiver.Sender.Ssrc);
        }

        // The answerer's per-transceiver receiver learned its OWN sender's SSRC — the multi-same-kind
        // case this API exists for. A first-of-kind write would flip-flop one and leave the other null.
        answerer.Transceivers.Count(t => t.Kind == MediaKind.Video).Should().Be(2);
        foreach (var offererVideo in videoTransceivers)
        {
            var answererVideo = answerer.GetTransceiver(offererVideo.Mid!);
            answererVideo.Should().NotBeNull();
            answererVideo!.Receiver.Ssrc.Should().Be(
                offererVideo.Sender.Ssrc,
                "receiver on mid {0} must learn its own m-line's remote SSRC",
                offererVideo.Mid);
        }

        // Per-transceiver stats are populated (§2.2): two video + one audio, the video senders sending.
        var stats = offerer.GetStats();
        stats.Transceivers.Should().NotBeNull();
        stats.Transceivers.Should().HaveCount(3);
        stats.Transceivers.Count(t => t.Kind == MediaKind.Video).Should().Be(2);
        foreach (var t in stats.Transceivers.Where(t => t.Kind == MediaKind.Video))
        {
            t.CurrentDirection.Should().Be(MediaDirection.SendOnly);
            t.SenderPayloadType.Should().NotBeNull();
            t.Send.Should().NotBeNull();
            t.Send!.Value.PacketsSent.Should().BeGreaterThan(0);
        }

        secondVideo.CurrentDirection.Should().Be(MediaDirection.SendOnly);
    }

    [Fact]
    public async Task RecvOnlyVideoTransceiver_IngestsAsOfferer_WithoutTheRecvonlyOfferTrick()
    {
        var cancellationToken = TestTimeout();

        // The offerer publishes nothing; it adds a single recvonly video transceiver and offers it. The
        // answerer (a default sender) answers sendonly by the complement rule and streams into it.
        var offererConfig = TestSupport.NewConfig();
        offererConfig.VideoCodecs.Clear();
        offererConfig.AudioCodecs.Clear();
        await using var offerer = new PeerConnection(offererConfig);

        var init = new RtpTransceiverInit();
        init.Codecs.Add(SdpCodec.H264());
        var recv = offerer.AddTransceiver(MediaKind.Video, MediaDirection.RecvOnly, init);

        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        var frames = 0;
        offerer.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            if (info.Kind == MediaKind.Video && string.Equals(info.Mid, recv.Mid, StringComparison.Ordinal))
            {
                Interlocked.Increment(ref frames);
            }
        };

        await ConnectAsync(offerer, answerer, cancellationToken);

        // The offerer offered recvonly and settled recvonly; it wired no send track.
        recv.CurrentDirection.Should().Be(MediaDirection.RecvOnly);
        recv.Receiver.PayloadTypes.Should().NotBeEmpty("the offerer negotiated a receive codec");

        var accessUnits = H264TestStream.ReadAccessUnits(60);
        var timestamp = 90_000u;
        foreach (var accessUnit in accessUnits)
        {
            answerer.SendVideoFrame(accessUnit, timestamp);
            timestamp += 3000;
            await Task.Delay(5, cancellationToken);
        }

        (await TestSupport.WaitForAsync(() => Volatile.Read(ref frames) > 0)).Should().BeTrue(
            "the recvonly transceiver must ingest the answerer's stream as the offerer");
        recv.Receiver.Ssrc.Should().Be(answerer.VideoSsrc);
    }

    private static async Task ConnectAsync(
        PeerConnection offerer,
        PeerConnection answerer,
        CancellationToken cancellationToken)
    {
        offerer.OnLocalIceCandidate += (_, e) => answerer.AddIceCandidate(e.Candidate, e.SdpMid);
        answerer.OnLocalIceCandidate += (_, e) => offerer.AddIceCandidate(e.Candidate, e.SdpMid);

        var offer = await offerer.CreateOfferAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await answerer.CreateAnswerAsync(cancellationToken);
        await offerer.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        (await offerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
    }
}
