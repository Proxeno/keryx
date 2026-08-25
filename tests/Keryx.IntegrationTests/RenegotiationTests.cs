using System.Collections.Concurrent;
using FluentAssertions;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// Epic D PR 5 (session-model.md §4.2/§4.3): a repeat offer/answer from <see cref="SignalingState.Stable"/>
/// that adds, removes or repoints m-lines, keeping the session identity constant while the o= version
/// increments, reusing the existing ICE transport (no restart) and — the load-bearing guarantee — never
/// re-deriving or rekeying the SRTP context. Both peers run on real UDP loopback.
/// </summary>
public sealed class RenegotiationTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    private static CancellationToken TestTimeout() =>
        new CancellationTokenSource(TimeSpan.FromSeconds(50)).Token;

    /// <summary>
    /// The §4.3 proof: establish a session, add a second video transceiver mid-session, renegotiate, and
    /// assert (a) the SRTP context object is the same instance on both peers (unchanged, not rekeyed),
    /// (b) both video senders stream and the answerer receives both SSRCs, and (c) the o= session id is
    /// unchanged while the version incremented — plus the mid/ordering, ICE-reuse, negotiation-needed and
    /// signaling-state guarantees.
    /// </summary>
    [Fact]
    public async Task AddSecondVideoMidSession_SrtpContextUnchanged_BothStream_SessionVersionBumps()
    {
        var cancellationToken = TestTimeout();

        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        offerer.OnLocalIceCandidate += (_, e) => answerer.AddIceCandidate(e.Candidate, e.SdpMid);
        answerer.OnLocalIceCandidate += (_, e) => offerer.AddIceCandidate(e.Candidate, e.SdpMid);

        var videoSsrcsSeen = new ConcurrentDictionary<uint, bool>();
        answerer.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            if (info.Kind == MediaKind.Video)
            {
                videoSsrcsSeen[info.Ssrc] = true;
            }
        };

        var negotiationNeeded = 0;
        offerer.OnNegotiationNeeded += (_, _) => Interlocked.Increment(ref negotiationNeeded);

        // ---------------------------------------------------------------- initial negotiation
        var offer1 = SessionDescription.Parse(await offerer.CreateOfferAsync(cancellationToken));
        await answerer.SetRemoteDescriptionAsync(offer1.ToSdpString(), SdpType.Offer, cancellationToken);
        var answer1 = await answerer.CreateAnswerAsync(cancellationToken);
        await offerer.SetRemoteDescriptionAsync(answer1, SdpType.Answer, cancellationToken);

        (await offerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        var offererSrtpBefore = offerer.SrtpContextForTest;
        var answererSrtpBefore = answerer.SrtpContextForTest;
        offererSrtpBefore.Should().NotBeNull("the DTLS handshake derived an SRTP context");
        answererSrtpBefore.Should().NotBeNull();

        var sessionIdBefore = offer1.Origin.SessionId;
        var versionBefore = long.Parse(offer1.Origin.SessionVersion);
        var iceUfragBefore = offer1.MediaDescriptions[0].IceUfrag;
        var icePwdBefore = offer1.MediaDescriptions[0].IcePwd;

        var firstVideo = offerer.Transceivers.Single(t => t.Kind == MediaKind.Video);
        var firstVideoSsrc = firstVideo.Sender.Ssrc;

        // Stream on the first video before renegotiation, so its sender is live with real sequence state.
        await StreamVideoAsync(firstVideo.Sender, 20, cancellationToken);
        (await TestSupport.WaitForAsync(() => videoSsrcsSeen.ContainsKey(firstVideoSsrc))).Should().BeTrue(
            "the first video stream must reach the answerer before renegotiation");

        // ---------------------------------------------------------------- mid-session add
        Interlocked.Exchange(ref negotiationNeeded, 0);
        var secondVideo = offerer.AddTransceiver(MediaKind.Video, MediaDirection.SendOnly);

        (await TestSupport.WaitForAsync(() => Volatile.Read(ref negotiationNeeded) >= 1)).Should().BeTrue(
            "adding a transceiver mid-session fires OnNegotiationNeeded");
        offerer.SignalingState.Should().Be(SignalingState.Stable);

        // ---------------------------------------------------------------- renegotiation
        var offer2 = SessionDescription.Parse(await offerer.CreateOfferAsync(cancellationToken));
        await answerer.SetRemoteDescriptionAsync(offer2.ToSdpString(), SdpType.Offer, cancellationToken);
        var answer2 = await answerer.CreateAnswerAsync(cancellationToken);
        await offerer.SetRemoteDescriptionAsync(answer2, SdpType.Answer, cancellationToken);

        offerer.SignalingState.Should().Be(SignalingState.Stable, "the repeat offer/answer returns to Stable");
        answerer.SignalingState.Should().Be(SignalingState.Stable);

        // (a) The SRTP context object is the SAME instance — an ordinary renegotiation never rekeys (§4.3).
        ReferenceEquals(offerer.SrtpContextForTest, offererSrtpBefore).Should().BeTrue(
            "the offerer's SRTP context must not be re-derived by a plain renegotiation");
        ReferenceEquals(answerer.SrtpContextForTest, answererSrtpBefore).Should().BeTrue(
            "the answerer's SRTP context must not be re-derived by a plain renegotiation");

        // (c) The o= session id is unchanged; the version incremented.
        offer2.Origin.SessionId.Should().Be(sessionIdBefore, "the session identity stays constant (§4.2)");
        long.Parse(offer2.Origin.SessionVersion).Should().BeGreaterThan(versionBefore, "the o= version bumps per description");

        // No ICE restart: the credentials are re-emitted unchanged (a plain renegotiation reuses the transport).
        offer2.MediaDescriptions[0].IceUfrag.Should().Be(iceUfragBefore, "a plain renegotiation is not an ICE restart");
        offer2.MediaDescriptions[0].IcePwd.Should().Be(icePwdBefore);

        // Existing mids keep their positions; the added transceiver got a fresh mid (JSEP no-reorder).
        offer2.MediaDescriptions[0].Mid.Should().Be("0", "the first video keeps its mid and index");
        offer2.MediaDescriptions[1].Mid.Should().Be("1", "the audio keeps its mid and index");
        secondVideo.Mid.Should().NotBeNull().And.NotBe("0").And.NotBe("1");
        offer2.MediaDescriptions.Select(m => m.Mid).Should().Contain(secondVideo.Mid);

        // (b) Both video senders now negotiated a send codec and stream; the answerer receives both SSRCs.
        firstVideo.Sender.PayloadType.Should().NotBeNull();
        secondVideo.Sender.PayloadType.Should().NotBeNull("the mid-session transceiver settled a send codec");
        secondVideo.CurrentDirection.Should().Be(MediaDirection.SendOnly);

        videoSsrcsSeen.Clear();
        for (var round = 0; round < 20; round++)
        {
            var frame = H264TestStream.ReadAccessUnits(1)[0];
            firstVideo.Sender.SendFrame(frame, 90_000u + ((uint)round * 3000u)).Should().BeGreaterThan(0);
            secondVideo.Sender.SendFrame(frame, 90_000u + ((uint)round * 3000u)).Should().BeGreaterThan(0);
            await Task.Delay(5, cancellationToken);
        }

        (await TestSupport.WaitForAsync(() =>
            videoSsrcsSeen.ContainsKey(firstVideo.Sender.Ssrc) && videoSsrcsSeen.ContainsKey(secondVideo.Sender.Ssrc)))
            .Should().BeTrue("both video senders must stream to the answerer after renegotiation");

        // The mid-session add left no pending negotiation-needed behind: re-running the check is a no-op.
        Interlocked.Exchange(ref negotiationNeeded, 0);
        offerer.RaiseNegotiationNeeded();
        Volatile.Read(ref negotiationNeeded).Should().Be(0, "the renegotiation cleared the negotiation-needed flag");
    }

    /// <summary>
    /// A stopped/removed transceiver is re-emitted as a rejected (port-0) m-line at its fixed index and
    /// mid, while every other m-line keeps its position (session-model.md §3.3/§4.2), and stopping fires
    /// OnNegotiationNeeded.
    /// </summary>
    [Fact]
    public async Task StoppedTransceiver_IsReEmittedAsRejectedPort0MLine_OthersRetained()
    {
        var cancellationToken = TestTimeout();

        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        offerer.OnLocalIceCandidate += (_, e) => answerer.AddIceCandidate(e.Candidate, e.SdpMid);
        answerer.OnLocalIceCandidate += (_, e) => offerer.AddIceCandidate(e.Candidate, e.SdpMid);

        // A second video transceiver added before connect, so there is one to stop mid-session.
        var extraVideo = offerer.AddTransceiver(MediaKind.Video, MediaDirection.SendOnly);

        var offer1 = await offerer.CreateOfferAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(offer1, SdpType.Offer, cancellationToken);
        var answer1 = await answerer.CreateAnswerAsync(cancellationToken);
        await offerer.SetRemoteDescriptionAsync(answer1, SdpType.Answer, cancellationToken);

        (await offerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        var extraMid = extraVideo.Mid;
        extraMid.Should().NotBeNull();

        var negotiationNeeded = 0;
        offerer.OnNegotiationNeeded += (_, _) => Interlocked.Increment(ref negotiationNeeded);

        // ---------------------------------------------------------------- stop + renegotiate
        extraVideo.Stop();
        extraVideo.Stopped.Should().BeTrue();
        (await TestSupport.WaitForAsync(() => Volatile.Read(ref negotiationNeeded) >= 1)).Should().BeTrue(
            "stopping a transceiver fires OnNegotiationNeeded");

        var offer2 = SessionDescription.Parse(await offerer.CreateOfferAsync(cancellationToken));

        var rejected = offer2.MediaDescriptions.Single(m => m.Mid == extraMid);
        rejected.Port.Should().Be(0, "a stopped transceiver is re-emitted as a rejected port-0 section");

        // The live video and audio keep their mids and positions; the rejected slot is not reordered.
        offer2.MediaDescriptions[0].Mid.Should().Be("0");
        offer2.MediaDescriptions[1].Mid.Should().Be("1");
        offer2.MediaDescriptions.Where(m => m.Media == "video").Should().HaveCount(2, "the stopped slot is kept, not removed");

        // The answerer mirrors the rejection.
        await answerer.SetRemoteDescriptionAsync(offer2.ToSdpString(), SdpType.Offer, cancellationToken);
        var answer2 = SessionDescription.Parse(await answerer.CreateAnswerAsync(cancellationToken));
        answer2.MediaDescriptions.Single(m => m.Mid == extraMid).Port.Should().Be(0,
            "the answerer answers a rejected section rejected");
    }

    private static async Task StreamVideoAsync(RtpSender sender, int frames, CancellationToken cancellationToken)
    {
        var accessUnits = H264TestStream.ReadAccessUnits(frames);
        var timestamp = 0u;
        foreach (var accessUnit in accessUnits)
        {
            sender.SendFrame(accessUnit, timestamp);
            timestamp += 3000;
            await Task.Delay(5, cancellationToken);
        }
    }
}
