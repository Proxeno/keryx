using System.Collections.Concurrent;
using System.Text;
using FluentAssertions;
using Keryx.Sctp;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// ICE restart (RFC 8445 §9, session-model.md §7): a re-offer from <see cref="SignalingState.Stable"/>
/// that carries fresh ICE credentials and re-emitted candidates, triggering a new connectivity-check
/// phase on both peers and switching the selected pair, after which media and data resume. Both peers run
/// on real UDP loopback.
/// <para>
/// This exercises the ICE-transport layer of a restart. The DTLS/SRTP context is deliberately preserved
/// across the restart (RFC 8842) — a fresh DTLS handshake with re-derived SRTP keys is the deferred
/// follow-on (session-model.md §7), so the SRTP-context-is-unchanged assertion here is the current
/// contract, the opposite of what a full DTLS-rehandshake restart would assert.
/// </para>
/// </summary>
public sealed class IceRestartTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    private static CancellationToken TestTimeout() =>
        new CancellationTokenSource(TimeSpan.FromSeconds(50)).Token;

    /// <summary>
    /// Establish a session with media and a data channel flowing, restart ICE mid-session, and assert:
    /// fresh ufrag/pwd offered and answered, candidates re-emitted, a new selected candidate pair on both
    /// peers, media and data flow again over the re-validated transport, the SRTP context is unchanged
    /// (rekey deferred), and both peers return to <see cref="SignalingState.Stable"/>.
    /// </summary>
    [Fact]
    public async Task RestartIceMidSession_FreshCredentials_NewPair_MediaAndDataResume()
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

        var atAnswerer = new ConcurrentQueue<string>();
        answerer.OnDataChannel += (_, channel) =>
            channel.OnMessage += (binary, payload) =>
            {
                if (!binary)
                {
                    atAnswerer.Enqueue(Encoding.UTF8.GetString(payload));
                }
            };

        var channelTask = offerer.CreateDataChannel("control");

        // ---------------------------------------------------------------- initial negotiation + connect
        var offer1 = SessionDescription.Parse(await offerer.CreateOfferAsync(cancellationToken));
        offer1.MediaDescriptions[0].GetCandidates().Should().NotBeEmpty("the first offer carries gathered candidates");
        await answerer.SetRemoteDescriptionAsync(offer1.ToSdpString(), SdpType.Offer, cancellationToken);
        var answer1 = SessionDescription.Parse(await answerer.CreateAnswerAsync(cancellationToken));
        await offerer.SetRemoteDescriptionAsync(answer1.ToSdpString(), SdpType.Answer, cancellationToken);

        (await offerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        var channel = await channelTask.WaitAsync(ConnectTimeout, cancellationToken);
        (await TestSupport.WaitForAsync(() => channel.State == DataChannelState.Open)).Should().BeTrue();

        // Media flows before the restart.
        var firstVideo = offerer.Transceivers.Single(t => t.Kind == MediaKind.Video);
        await StreamVideoAsync(firstVideo.Sender, 20, cancellationToken);
        (await TestSupport.WaitForAsync(() => videoSsrcsSeen.ContainsKey(firstVideo.Sender.Ssrc))).Should().BeTrue(
            "video must reach the answerer before the restart");

        // Data flows before the restart.
        channel.SendText("before restart");
        (await TestSupport.WaitForAsync(() => atAnswerer.Contains("before restart"))).Should().BeTrue(
            "the data channel must carry a message before the restart");

        // ---------------------------------------------------------------- capture pre-restart state
        var offerUfragBefore = offer1.MediaDescriptions[0].IceUfrag;
        var offerPwdBefore = offer1.MediaDescriptions[0].IcePwd;
        var answerUfragBefore = answer1.MediaDescriptions[0].IceUfrag;
        var sessionIdBefore = offer1.Origin.SessionId;

        var offererSrtpBefore = offerer.SrtpContextForTest;
        var answererSrtpBefore = answerer.SrtpContextForTest;
        var offererPairBefore = offerer.SelectedIceCandidatePairForTest;
        var answererPairBefore = answerer.SelectedIceCandidatePairForTest;
        offererPairBefore.Should().NotBeNull("a pair was selected on the initial connect");
        answererPairBefore.Should().NotBeNull();

        // ---------------------------------------------------------------- ICE restart
        // Arm via the browser-shaped RestartIce(); it does not itself produce an offer.
        offerer.RestartIce();
        offerer.SignalingState.Should().Be(SignalingState.Stable, "arming a restart does not move the signaling state");

        var offer2 = SessionDescription.Parse(await offerer.CreateOfferAsync(cancellationToken));
        offerer.SignalingState.Should().Be(SignalingState.HaveLocalOffer);

        // Fresh local ICE credentials (RFC 8445 §9), and candidates are re-emitted.
        offer2.MediaDescriptions[0].IceUfrag.Should().NotBe(offerUfragBefore, "an ICE restart offers a fresh ufrag");
        offer2.MediaDescriptions[0].IcePwd.Should().NotBe(offerPwdBefore, "an ICE restart offers a fresh pwd");
        offer2.MediaDescriptions[0].GetCandidates().Should().NotBeEmpty("the restart offer re-emits candidates");
        offer2.Origin.SessionId.Should().Be(sessionIdBefore, "the session identity stays constant across a restart");

        await answerer.SetRemoteDescriptionAsync(offer2.ToSdpString(), SdpType.Offer, cancellationToken);
        var answer2 = SessionDescription.Parse(await answerer.CreateAnswerAsync(cancellationToken));

        // The answerer likewise regenerates its credentials and re-emits candidates.
        answer2.MediaDescriptions[0].IceUfrag.Should().NotBe(answerUfragBefore, "the answerer answers a restart with a fresh ufrag");
        answer2.MediaDescriptions[0].GetCandidates().Should().NotBeEmpty("the restart answer re-emits candidates");

        await offerer.SetRemoteDescriptionAsync(answer2.ToSdpString(), SdpType.Answer, cancellationToken);

        offerer.SignalingState.Should().Be(SignalingState.Stable, "the restart offer/answer returns to Stable");
        answerer.SignalingState.Should().Be(SignalingState.Stable);

        // ---------------------------------------------------------------- new connectivity-check phase
        // A fresh phase nominates a NEW pair instance on both peers (the old ones were discarded).
        (await TestSupport.WaitForAsync(() =>
            offerer.SelectedIceCandidatePairForTest is { } op && !ReferenceEquals(op, offererPairBefore)))
            .Should().BeTrue("the offerer must select a new candidate pair after the restart");
        (await TestSupport.WaitForAsync(() =>
            answerer.SelectedIceCandidatePairForTest is { } ap && !ReferenceEquals(ap, answererPairBefore)))
            .Should().BeTrue("the answerer must select a new candidate pair after the restart");

        offerer.IceState.Should().Be(Ice.IceAgentState.Connected);
        answerer.IceState.Should().Be(Ice.IceAgentState.Connected);

        // The DTLS/SRTP context is preserved across the ICE restart (RFC 8842); rekey is deferred (§7).
        ReferenceEquals(offerer.SrtpContextForTest, offererSrtpBefore).Should().BeTrue(
            "an ICE restart preserves the SRTP context in this release (rekey deferred)");
        ReferenceEquals(answerer.SrtpContextForTest, answererSrtpBefore).Should().BeTrue();

        // ---------------------------------------------------------------- media + data resume
        videoSsrcsSeen.Clear();
        await StreamVideoAsync(firstVideo.Sender, 20, cancellationToken);
        (await TestSupport.WaitForAsync(() => videoSsrcsSeen.ContainsKey(firstVideo.Sender.Ssrc))).Should().BeTrue(
            "video must flow again over the restarted transport");

        channel.SendText("after restart");
        (await TestSupport.WaitForAsync(() => atAnswerer.Contains("after restart"))).Should().BeTrue(
            "the data channel must carry a message again after the restart");

        await offerer.CloseAsync();
        await answerer.CloseAsync();
    }

    /// <summary>
    /// A plain renegotiation is not an ICE restart: without <see cref="PeerConnection.RestartIce"/> or the
    /// <c>iceRestart</c> flag, a repeat offer re-emits the existing credentials unchanged and keeps the
    /// selected pair — guarding the golden no-change guarantee.
    /// </summary>
    [Fact]
    public async Task RepeatOfferWithoutRestart_KeepsCredentialsAndSelectedPair()
    {
        var cancellationToken = TestTimeout();

        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        offerer.OnLocalIceCandidate += (_, e) => answerer.AddIceCandidate(e.Candidate, e.SdpMid);
        answerer.OnLocalIceCandidate += (_, e) => offerer.AddIceCandidate(e.Candidate, e.SdpMid);

        var offer1 = SessionDescription.Parse(await offerer.CreateOfferAsync(cancellationToken));
        await answerer.SetRemoteDescriptionAsync(offer1.ToSdpString(), SdpType.Offer, cancellationToken);
        var answer1 = await answerer.CreateAnswerAsync(cancellationToken);
        await offerer.SetRemoteDescriptionAsync(answer1, SdpType.Answer, cancellationToken);

        (await offerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        var pairBefore = offerer.SelectedIceCandidatePairForTest;

        var offer2 = SessionDescription.Parse(await offerer.CreateOfferAsync(cancellationToken));
        offer2.MediaDescriptions[0].IceUfrag.Should().Be(offer1.MediaDescriptions[0].IceUfrag,
            "a plain renegotiation reuses the ICE credentials");
        offer2.MediaDescriptions[0].IcePwd.Should().Be(offer1.MediaDescriptions[0].IcePwd);

        await answerer.SetRemoteDescriptionAsync(offer2.ToSdpString(), SdpType.Offer, cancellationToken);
        var answer2 = await answerer.CreateAnswerAsync(cancellationToken);
        await offerer.SetRemoteDescriptionAsync(answer2, SdpType.Answer, cancellationToken);

        // No restart: the selected pair is undisturbed.
        ReferenceEquals(offerer.SelectedIceCandidatePairForTest, pairBefore).Should().BeTrue(
            "a plain renegotiation does not re-run connectivity checks");

        await offerer.CloseAsync();
        await answerer.CloseAsync();
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
