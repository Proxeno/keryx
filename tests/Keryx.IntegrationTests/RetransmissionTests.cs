using System.Collections.Concurrent;
using FluentAssertions;
using Keryx.Rtp;
using Keryx.Rtp.Rtcp;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// End-to-end coverage for sender-side resilience: RFC 4588 RTX negotiation against a browser-shaped
/// answer, real NACK-driven retransmission over UDP, and the link-quality surface reception reports
/// feed.
/// </summary>
public sealed class RetransmissionTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    private static CancellationToken TestTimeout() =>
        new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    /// <summary>
    /// Rewrites the Chrome answer fixture so that every m-section answers the offer it is given: same
    /// mids, same media types, and the payload types the offer actually proposed.
    /// </summary>
    private static string ChromeStyleAnswer(string offerSdp, bool keepRtx)
    {
        var offer = SessionDescription.Parse(offerSdp);
        var answer = new SessionDescription
        {
            Version = 0,
            Origin = new SdpOrigin("-", "1092376891452871093", "3", "IN", "IP4", "127.0.0.1"),
            SessionName = "-",
        };
        answer.Timings.Add(new SdpTiming("0", "0"));
        answer.SetBundleGroup(offer.GetBundleGroup());
        answer.SetWmsStreamIds();

        foreach (var offered in offer.MediaDescriptions)
        {
            var media = new MediaDescription
            {
                Media = offered.Media,
                Port = 9,
                Protocol = offered.Protocol,
                Connection = SdpConnection.WebRtcPlaceholder,
            };

            media.AddAttribute(SdpAttributeNames.IceUfrag, "4ZcD");
            media.AddAttribute(SdpAttributeNames.IcePwd, "2/1muCWoOi3uLifh0NuRHlZ6cKr");
            media.AddAttribute(SdpAttributeNames.IceOptions, "trickle");
            media.AddAttribute(
                SdpAttributeNames.Fingerprint,
                "sha-256 EE:2D:1B:70:1C:0F:39:A6:1D:47:23:8A:41:66:9C:0B:5F:AE:2C:73:88:14:D5:6E:9A:B1:03:F7:52:C4:60:1A");
            media.AddAttribute(SdpAttributeNames.Setup, "active");
            media.AddAttribute(SdpAttributeNames.Mid, offered.Mid!);

            if (offered.SctpPort is { } sctpPort)
            {
                media.Formats.Add(SdpMediaOffer.DataChannelFormat);
                media.AddAttribute(SdpAttributeNames.SctpPort, sctpPort.ToString(null as IFormatProvider));
                media.AddAttribute(SdpAttributeNames.MaxMessageSize, "262144");
                answer.MediaDescriptions.Add(media);
                continue;
            }

            media.AddAttribute(MediaDirection.RecvOnly.ToAttributeName());
            media.AddAttribute(SdpAttributeNames.RtcpMux);

            foreach (var payloadType in offered.GetPayloadTypes())
            {
                var rtpMap = offered.GetRtpMap(payloadType)!;
                var isRtx = string.Equals(rtpMap.EncodingName, "rtx", StringComparison.OrdinalIgnoreCase);
                if (isRtx && !keepRtx)
                {
                    continue;
                }

                media.Formats.Add(payloadType.ToString(null as IFormatProvider));
                media.SetRtpMap(rtpMap);
                foreach (var feedback in offered.GetRtcpFeedback(payloadType))
                {
                    media.AddRtcpFeedback(payloadType, feedback);
                }

                if (offered.GetFmtp(payloadType) is { } fmtp)
                {
                    media.SetFmtp(payloadType, fmtp);
                }
            }

            answer.MediaDescriptions.Add(media);
        }

        return answer.ToSdpString();
    }

    [Fact]
    public async Task ABrowserShapedAnswerKeepingRtxNegotiatesRetransmission()
    {
        await using var peer = new PeerConnection(TestSupport.NewConfig());
        var offer = await peer.CreateOfferAsync(TestTimeout());
        var answer = ChromeStyleAnswer(offer, keepRtx: true);

        answer.Should().Contain("a=rtpmap:97 rtx/90000").And.Contain("a=fmtp:97 apt=96");
        await peer.SetRemoteDescriptionAsync(answer, SdpType.Answer, TestTimeout());

        peer.NegotiatedVideoRtxPayloadType.Should().Be(97);
    }

    [Fact]
    public async Task AnAnswerThatDropsRtxDisablesRetransmissionRatherThanPromisingIt()
    {
        await using var peer = new PeerConnection(TestSupport.NewConfig());
        var offer = await peer.CreateOfferAsync(TestTimeout());
        var answer = ChromeStyleAnswer(offer, keepRtx: false);

        // The answer still echoes bare a=rtcp-fb:96 nack, which on its own must not be read as a
        // negotiated repair stream: RFC 4588 needs the rtx codec and its own SSRC.
        answer.Should().Contain("a=rtcp-fb:96 nack").And.NotContain("rtx/90000");
        await peer.SetRemoteDescriptionAsync(answer, SdpType.Answer, TestTimeout());

        peer.NegotiatedVideoRtxPayloadType.Should().BeNull();
    }

    [Fact]
    public async Task AReceptionReportBecomesTheOutboundLinkQualitySnapshot()
    {
        await using var peer = new PeerConnection(TestSupport.NewConfig());

        // RFC 3550 §6.4.1: RTT = (arrival - DLSR - LSR), all in compact NTP form. A report that says
        // the last sender report reached the peer 100 ms ago and sat there for 20 ms describes an
        // 80 ms round trip.
        var receivedAt = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var lastSenderReport = NtpTime.ToCompact(NtpTime.FromDateTimeOffset(receivedAt.AddMilliseconds(-100)));
        var delay = (uint)(0.020 * 65536);

        var report = new RtcpReceiverReport { SenderSsrc = 0x1234 };
        report.ReportBlocks.Add(new RtcpReportBlock(
            peer.VideoSsrc,
            fractionLost: 64,
            cumulativePacketsLost: 137,
            extendedHighestSequenceNumber: 0x0001_2345,
            jitter: 900,
            lastSenderReport: lastSenderReport,
            delaySinceLastSenderReport: delay));
        report.ReportBlocks.Add(new RtcpReportBlock(
            peer.AudioSsrc,
            fractionLost: 0,
            cumulativePacketsLost: 0,
            extendedHighestSequenceNumber: 42,
            jitter: 12,
            lastSenderReport: 0,
            delaySinceLastSenderReport: 0));
        report.ReportBlocks.Add(new RtcpReportBlock(
            0xDEAD_BEEF,
            fractionLost: 255,
            cumulativePacketsLost: -1,
            extendedHighestSequenceNumber: 1,
            jitter: 1,
            lastSenderReport: 1,
            delaySinceLastSenderReport: 1));

        peer.DispatchRtcp(report, receivedAt);

        var stats = peer.GetStats();
        stats.Feedback.ReceiverReports.Should().Be(1);

        var video = stats.Video!.Value.Quality!;
        video.Ssrc.Should().Be(peer.VideoSsrc);
        video.FractionLost.Should().BeApproximately(0.25, 1e-9);
        video.CumulativePacketsLost.Should().Be(137);
        video.ExtendedHighestSequenceNumber.Should().Be(0x0001_2345);
        video.Jitter.Should().Be(900);
        video.RoundTripTime.Should().NotBeNull();
        video.RoundTripTime!.Value.TotalMilliseconds.Should().BeApproximately(80, 2);
        video.ReportedAt.Should().Be(receivedAt);

        var audio = stats.Audio!.Value.Quality!;
        audio.Ssrc.Should().Be(peer.AudioSsrc);
        audio.FractionLost.Should().Be(0);

        // No sender report has reached the peer for the audio stream, so there is no RTT to report.
        audio.RoundTripTime.Should().BeNull();

        // A block about a source that is not ours is ignored entirely.
        stats.Video!.Value.Quality!.FractionLost.Should().BeApproximately(0.25, 1e-9);
    }

    [Fact]
    public async Task ANackOverRealUdpIsServedAsAnRtxPacket()
    {
        var cancellationToken = TestTimeout();
        var senderConfig = TestSupport.NewConfig();

        // Pin the resend rate limit far above anything this test can take, so the suppression
        // assertion below depends on the limit and not on how fast the machine happens to be.
        senderConfig.Retransmission.MinimumResendInterval = TimeSpan.FromSeconds(30);

        await using var offerer = new PeerConnection(senderConfig);
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        var videoSequenceNumbers = new ConcurrentQueue<ushort>();
        var deliveries = new ConcurrentDictionary<ushort, int>();

        offerer.OnLocalIceCandidate += (_, e) => answerer.AddIceCandidate(e.Candidate, e.SdpMid);
        answerer.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            if (info.Kind != MediaKind.Video)
            {
                return;
            }

            // The receiver decapsulates RTX itself now: a repair arrives as ordinary media on its
            // original sequence number and the media payload type, never as a raw rtx-payload-type
            // packet, so a NACKed packet already delivered once is simply delivered again.
            deliveries.AddOrUpdate(info.SequenceNumber, 1, (_, count) => count + 1);
            videoSequenceNumbers.Enqueue(info.SequenceNumber);
        };

        var offer = await offerer.CreateOfferAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await answerer.CreateAnswerAsync(cancellationToken);

        // Keryx answering Keryx keeps the rtx codec, because its apt names a codec it accepted.
        answer.Should().Contain("rtx/90000").And.Contain("apt=96");
        await offerer.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        (await offerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        offerer.NegotiatedVideoRtxPayloadType.Should().Be(97);

        var accessUnits = H264TestStream.ReadAccessUnits(10);
        for (var i = 0; i < accessUnits.Count; i++)
        {
            offerer.SendVideoFrame(accessUnits[i], (uint)(i * 3000));
        }

        (await TestSupport.WaitForAsync(() => videoSequenceNumbers.Count >= 5)).Should().BeTrue();

        // Ask for three packets the receiver did in fact get: the sender cannot tell the difference,
        // and this keeps the test independent of whether the loopback ever loses anything.
        var seen = videoSequenceNumbers.Distinct().ToArray();
        var wanted = new[] { seen[0], seen[1], seen[3] };
        answerer.SendNack(offerer.VideoSsrc, wanted).Should().BeTrue();

        // The sender served each NACKed packet as an RTX repair and the answerer decapsulated it back to
        // the original media packet: every one, already delivered once directly, is delivered a second
        // time on its original sequence number.
        (await TestSupport.WaitForAsync(() => wanted.All(seq => deliveries.GetValueOrDefault(seq) >= 2)))
            .Should().BeTrue();

        var retransmission = offerer.GetStats().Video!.Value.Retransmission!.Value;
        retransmission.RtxSsrc.Should().Be(offerer.VideoRtxSsrc);
        retransmission.RtxPayloadType.Should().Be(97);
        retransmission.NacksReceived.Should().BeGreaterThanOrEqualTo(1);
        retransmission.NackRequestedPackets.Should().BeGreaterThanOrEqualTo(3);
        retransmission.PacketsRetransmitted.Should().BeGreaterThanOrEqualTo(3);
        retransmission.BytesRetransmitted.Should().BeGreaterThan(0);

        // A sequence number that was never sent cannot be served out of the history.
        answerer.SendNack(offerer.VideoSsrc, [(ushort)(seen[0] + 30_000)]).Should().BeTrue();
        (await TestSupport.WaitForAsync(
                () => offerer.GetStats().Video!.Value.Retransmission!.Value.HistoryMisses > 0))
            .Should().BeTrue();

        // Repeating the same NACK inside the minimum interval is suppressed by the resend rate limit.
        answerer.SendNack(offerer.VideoSsrc, wanted).Should().BeTrue();
        (await TestSupport.WaitForAsync(
                () => offerer.GetStats().Video!.Value.Retransmission!.Value.Suppressed >= 3))
            .Should().BeTrue();

        // A NACK naming a stream we do not send is ignored rather than answered from the wrong stream.
        var before = offerer.GetStats().Video!.Value.Retransmission!.Value.NackRequestedPackets;
        answerer.SendNack(0xFEED_FACE, wanted).Should().BeTrue();
        await Task.Delay(200, cancellationToken);
        offerer.GetStats().Video!.Value.Retransmission!.Value.NackRequestedPackets.Should().Be(before);

        await offerer.CloseAsync();
        await answerer.CloseAsync();
    }
}
