using FluentAssertions;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// Adversarial coverage of the media-section cap (<see cref="PeerConnectionConfig.MaxMediaSections"/>),
/// the bound on peer-reachable transceiver / m-line growth. The append-only transceiver set, the inbound
/// route table and the local-SSRC ownership map are all keyed by bound m-sections, so without a cap a
/// remote peer could grow them without bound with one enormous offer or an ever-growing renegotiation.
/// The guarantees under test: an offer that presents more RTP m-sections than the cap has the sections
/// within the cap negotiated (and carrying media), each excess offered section answered rejected (port 0,
/// RFC 8843) with no transceiver / route / SSRC state allocated for it, the agent never faulting; and the
/// application's own <see cref="PeerConnection.AddTransceiver"/> throwing clearly once the set is full.
/// </summary>
public sealed class MediaSectionCapTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    private static CancellationToken TestTimeout(int seconds = 40) =>
        new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    private static int CountRejectedRtpSections(string sdp)
    {
        var parsed = SessionDescription.Parse(sdp);
        return parsed.MediaDescriptions.Count(m =>
            (string.Equals(m.Media, "audio", StringComparison.Ordinal)
                || string.Equals(m.Media, "video", StringComparison.Ordinal))
            && m.Port == 0);
    }

    private static int CountLiveRtpSections(string sdp)
    {
        var parsed = SessionDescription.Parse(sdp);
        return parsed.MediaDescriptions.Count(m =>
            (string.Equals(m.Media, "audio", StringComparison.Ordinal)
                || string.Equals(m.Media, "video", StringComparison.Ordinal))
            && m.Port != 0);
    }

    /// <summary>
    /// A single offer that presents far more RTP m-sections than the answerer's cap must leave the
    /// answerer's transceiver set, inbound route table and local-SSRC map all bounded by the cap, must
    /// answer the excess sections rejected (port 0), and must not fault: the offer stays answerable.
    /// </summary>
    [Fact]
    public async Task OverLargeOffer_BoundsAnswererState_AndRejectsExcessInAnswer()
    {
        var cancellationToken = TestTimeout();

        // The offerer is allowed a large set so it can present a flood; the answerer is capped small.
        var offererConfig = TestSupport.NewConfig();
        offererConfig.MaxMediaSections = 128;
        await using var offerer = new PeerConnection(offererConfig);

        const int cap = 4;
        var answererConfig = TestSupport.NewConfig();
        answererConfig.MaxMediaSections = cap;
        await using var answerer = new PeerConnection(answererConfig);

        // Legacy video(0) + audio(1) + 14 extra video = 16 offered RTP m-sections, four times the cap.
        for (var i = 0; i < 14; i++)
        {
            offerer.AddTransceiver(MediaKind.Video, MediaDirection.SendOnly);
        }

        var offer = await offerer.CreateOfferAsync(cancellationToken);
        var offeredRtp = CountLiveRtpSections(offer);
        offeredRtp.Should().Be(16, "the flood offer carries sixteen live RTP m-sections");

        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);

        // The agent did not fault on the flood: it landed cleanly in HaveRemoteOffer.
        answerer.SignalingState.Should().Be(SignalingState.HaveRemoteOffer);

        // Every peer-reachable state keyed by m-section is bounded by the cap.
        answerer.Transceivers.Count.Should().Be(cap, "the transceiver set never grows past MaxMediaSections");
        answerer.InboundRouteMidCountForTest.Should().BeLessThanOrEqualTo(cap,
            "the inbound route table only carries routes for bound (within-cap) sections");
        answerer.LocalSsrcOwnerCountForTest.Should().BeLessThanOrEqualTo(cap * 2,
            "the local-SSRC map only owns SSRCs for bound sections (media + rtx per video)");

        // The answer negotiates the within-cap sections and rejects each excess section (port 0), keeping
        // the m-line slots index-aligned per RFC 8843.
        var answer = await answerer.CreateAnswerAsync(cancellationToken);
        CountLiveRtpSections(answer).Should().Be(cap, "only the within-cap sections answer live");
        CountRejectedRtpSections(answer).Should().Be(offeredRtp - cap, "every excess offered section is rejected");

        answerer.SignalingState.Should().Be(SignalingState.Stable, "answering the flood settles back to Stable");
    }

    /// <summary>
    /// When an offer exceeds the answerer's cap, the within-cap audio and video sections must still
    /// negotiate and carry real media end to end over a live loopback transport — the excess rejected
    /// sections do not disturb the connection.
    /// </summary>
    [Fact]
    public async Task WithinCapSections_StillNegotiateAndCarryMedia_WhenOfferExceedsCap()
    {
        var cancellationToken = TestTimeout(60);

        var offererConfig = TestSupport.NewConfig();
        offererConfig.MaxMediaSections = 64;
        await using var offerer = new PeerConnection(offererConfig);

        const int cap = 3;
        var answererConfig = TestSupport.NewConfig();
        answererConfig.MaxMediaSections = cap;
        await using var answerer = new PeerConnection(answererConfig);

        offerer.OnLocalIceCandidate += (_, e) => answerer.AddIceCandidate(e.Candidate, e.SdpMid);
        answerer.OnLocalIceCandidate += (_, e) => offerer.AddIceCandidate(e.Candidate, e.SdpMid);

        var videoPacketsReceived = 0;
        var audioPacketsReceived = 0;
        uint videoSsrcSeen = 0;
        answerer.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            switch (info.Kind)
            {
                case MediaKind.Video:
                    Volatile.Write(ref videoSsrcSeen, info.Ssrc);
                    Interlocked.Increment(ref videoPacketsReceived);
                    break;
                case MediaKind.Audio:
                    Interlocked.Increment(ref audioPacketsReceived);
                    break;
                default:
                    break;
            }
        };

        // Offer six RTP m-sections (legacy video/audio + four extra video) into a cap of three.
        for (var i = 0; i < 4; i++)
        {
            offerer.AddTransceiver(MediaKind.Video, MediaDirection.SendOnly);
        }

        var offer = await offerer.CreateOfferAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        answerer.Transceivers.Count.Should().Be(cap, "the answerer bound exactly the cap and rejected the rest");
        var answer = await answerer.CreateAnswerAsync(cancellationToken);
        CountRejectedRtpSections(answer).Should().Be(3, "the three sections beyond the cap answer rejected");
        await offerer.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        // The transport for the surviving sections still comes up despite the rejected sections.
        (await offerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        // Media flows on the within-cap video and audio sections (mid 0 and mid 1).
        for (var i = 0; i < 40; i++)
        {
            offerer.SendVideoFrame(new byte[] { 0, 0, 0, 1, 0x65, 0x11, 0x22, 0x33 }, (uint)(i * 3000))
                .Should().BeGreaterThan(0);
            offerer.SendAudioFrame(new byte[] { 0xFC, 1, 2, 3 }, (uint)(i * 960)).Should().Be(1);
            await Task.Delay(3, cancellationToken);
        }

        (await TestSupport.WaitForAsync(() => Volatile.Read(ref videoPacketsReceived) >= 20)).Should().BeTrue(
            "video on the within-cap section must reach the answerer");
        (await TestSupport.WaitForAsync(() => Volatile.Read(ref audioPacketsReceived) >= 20)).Should().BeTrue(
            "audio on the within-cap section must reach the answerer");
        Volatile.Read(ref videoSsrcSeen).Should().Be(offerer.VideoSsrc, "the received video is the first video section's stream");
    }

    /// <summary>
    /// A renegotiation that keeps adding m-sections past the cap must keep the answerer's state bounded and
    /// never fault the live session: the flood round is answered, the excess rejected, and the connection
    /// stays usable.
    /// </summary>
    [Fact]
    public async Task RenegotiationGrowingMLines_StaysBoundedAndDoesNotFault()
    {
        var cancellationToken = TestTimeout(60);

        var offererConfig = TestSupport.NewConfig();
        offererConfig.MaxMediaSections = 128;
        await using var offerer = new PeerConnection(offererConfig);

        const int cap = 4;
        var answererConfig = TestSupport.NewConfig();
        answererConfig.MaxMediaSections = cap;
        await using var answerer = new PeerConnection(answererConfig);

        offerer.OnLocalIceCandidate += (_, e) => answerer.AddIceCandidate(e.Candidate, e.SdpMid);
        answerer.OnLocalIceCandidate += (_, e) => offerer.AddIceCandidate(e.Candidate, e.SdpMid);

        // Round 1: an ordinary two-section negotiation connects.
        var offer1 = await offerer.CreateOfferAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(offer1, SdpType.Offer, cancellationToken);
        var answer1 = await answerer.CreateAnswerAsync(cancellationToken);
        await offerer.SetRemoteDescriptionAsync(answer1, SdpType.Answer, cancellationToken);
        (await offerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        answerer.Transceivers.Count.Should().Be(2, "the first negotiation binds only the legacy pair");

        // Round 2: the peer renegotiates with a flood of new m-sections.
        for (var i = 0; i < 30; i++)
        {
            offerer.AddTransceiver(MediaKind.Video, MediaDirection.SendOnly);
        }

        var offer2 = await offerer.CreateOfferAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(offer2, SdpType.Offer, cancellationToken);

        // The renegotiation flood is absorbed: state stays bounded by the cap and the agent does not fault.
        answerer.SignalingState.Should().Be(SignalingState.HaveRemoteOffer);
        answerer.Transceivers.Count.Should().Be(cap, "renegotiation never grows the set past the cap");
        answerer.InboundRouteMidCountForTest.Should().BeLessThanOrEqualTo(cap);
        answerer.LocalSsrcOwnerCountForTest.Should().BeLessThanOrEqualTo(cap * 2);

        var answer2 = await answerer.CreateAnswerAsync(cancellationToken);
        CountLiveRtpSections(answer2).Should().Be(cap, "only the within-cap sections stay live across the renegotiation");
        await offerer.SetRemoteDescriptionAsync(answer2, SdpType.Answer, cancellationToken);

        // The live session survived the flood.
        offerer.SignalingState.Should().Be(SignalingState.Stable);
        answerer.SignalingState.Should().Be(SignalingState.Stable);
    }

    /// <summary>
    /// The application's own <see cref="PeerConnection.AddTransceiver"/> must throw a clear exception once
    /// the transceiver set has reached the cap, rather than growing it without bound.
    /// </summary>
    [Fact]
    public async Task AddTransceiver_PastCap_ThrowsClearly()
    {
        // Cap of three, and the legacy pair already occupies two slots.
        var config = TestSupport.NewConfig();
        config.MaxMediaSections = 3;
        await using var peer = new PeerConnection(config);

        peer.Transceivers.Count.Should().Be(2, "the legacy video/audio pair occupies two of the three slots");

        // The third slot is fillable...
        peer.AddTransceiver(MediaKind.Video, MediaDirection.SendOnly);
        peer.Transceivers.Count.Should().Be(3);

        // ...the fourth is refused with a clear message naming the cap.
        var act = () => peer.AddTransceiver(MediaKind.Audio, MediaDirection.SendOnly);
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*MaxMediaSections*3*", "the exception names the cap it hit");

        peer.Transceivers.Count.Should().Be(3, "the refused add left the set unchanged");
    }
}
