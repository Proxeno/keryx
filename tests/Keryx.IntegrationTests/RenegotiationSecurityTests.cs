using FluentAssertions;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// Adversarial coverage of the JSEP signaling state machine and rollback (Epic D, PR 4-6) against a peer
/// that drives an illegal or hostile offer/answer/rollback sequence: out-of-order descriptions, repeated
/// offers, glare loops, and rollback churn. The load-bearing security guarantees are that every illegal
/// transition <b>throws rather than silently corrupting</b> the transceiver set, that a rollback leaves no
/// residue in the lock-free receive snapshot / inbound route table / SSRC ownership that a later packet
/// could resolve against, and that repeated renegotiation from a fixed offer does not accumulate state.
/// </summary>
public sealed class RenegotiationSecurityTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    private static CancellationToken TestTimeout(int seconds = 40) =>
        new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    // ---------------------------------------------------------------- illegal transitions throw

    /// <summary>
    /// A peer that answers when it is <i>our</i> turn to answer (we hold their offer) drives an answer into
    /// HaveRemoteOffer. That is illegal (an answer is only valid while a local offer is pending) and must
    /// throw without disturbing the pending remote offer, which stays answerable.
    /// </summary>
    [Fact]
    public async Task ApplyAnswer_InHaveRemoteOffer_Throws_AndRemoteOfferStaysAnswerable()
    {
        var cancellationToken = TestTimeout();
        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        var offer = await offerer.CreateOfferAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        answerer.SignalingState.Should().Be(SignalingState.HaveRemoteOffer);

        // A well-formed answer, injected where an answer has no business being applied.
        await using var third = new PeerConnection(TestSupport.NewConfig());
        await third.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var strayAnswer = await third.CreateAnswerAsync(cancellationToken);

        var act = () => answerer.SetRemoteDescriptionAsync(strayAnswer, SdpType.Answer, cancellationToken);
        await act.Should().ThrowAsync<InvalidOperationException>(
            "an answer is only valid while a local offer is pending, not in HaveRemoteOffer");

        // The rejected answer left the pending remote offer intact — we can still answer it.
        answerer.SignalingState.Should().Be(SignalingState.HaveRemoteOffer);
        var answer = await answerer.CreateAnswerAsync(cancellationToken);
        answer.Should().NotBeNullOrEmpty();
        answerer.SignalingState.Should().Be(SignalingState.Stable);
    }

    /// <summary>
    /// A peer that fires two offers back-to-back without waiting for an answer must have the second rejected
    /// (a remote offer is already pending). The first offer's bound transceiver set must be untouched, so
    /// the machine can still answer the first offer.
    /// </summary>
    [Fact]
    public async Task SecondRemoteOffer_InHaveRemoteOffer_Throws_AndFirstOfferSurvives()
    {
        var cancellationToken = TestTimeout();
        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        offerer.AddTransceiver(MediaKind.Video, MediaDirection.SendOnly); // 2 video + 1 audio m-lines
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        var offer1 = await offerer.CreateOfferAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(offer1, SdpType.Offer, cancellationToken);
        answerer.SignalingState.Should().Be(SignalingState.HaveRemoteOffer);
        var boundCount = answerer.Transceivers.Count;

        // A second, differently-shaped offer arriving before we answer.
        await using var other = new PeerConnection(TestSupport.NewConfig());
        var offer2 = await other.CreateOfferAsync(cancellationToken);

        var act = () => answerer.SetRemoteDescriptionAsync(offer2, SdpType.Offer, cancellationToken);
        await act.Should().ThrowAsync<InvalidOperationException>("a remote offer is already pending");

        // The rejected second offer neither advanced the state nor mutated the transceiver set bound by the
        // first offer, so the first offer remains answerable.
        answerer.SignalingState.Should().Be(SignalingState.HaveRemoteOffer);
        answerer.Transceivers.Count.Should().Be(boundCount, "the rejected second offer must not bind or auto-create anything");
        var answer = await answerer.CreateAnswerAsync(cancellationToken);
        answer.Should().NotBeNullOrEmpty();
    }

    /// <summary>An offer is illegal while a remote offer is pending; it must not be silently accepted.</summary>
    [Fact]
    public async Task CreateOffer_InHaveLocalOffer_Throws_WithoutRecapturingRollbackState()
    {
        var cancellationToken = TestTimeout();
        await using var peer = new PeerConnection(TestSupport.NewConfig());
        var added = peer.AddTransceiver(MediaKind.Video, MediaDirection.SendOnly);

        _ = await peer.CreateOfferAsync(cancellationToken);
        peer.SignalingState.Should().Be(SignalingState.HaveLocalOffer);

        var act = () => peer.CreateOfferAsync(cancellationToken);
        await act.Should().ThrowAsync<InvalidOperationException>("only one local offer may be outstanding");

        // The rejected second offer did not clobber the captured rollback snapshot: a rollback still
        // restores the original pre-offer shape (added transceiver detached, legacy pair pinned).
        peer.SignalingState.Should().Be(SignalingState.HaveLocalOffer);
        peer.Rollback();
        peer.SignalingState.Should().Be(SignalingState.Stable);
        added.Mid.Should().BeNull("rollback after a rejected re-offer still reverts the provisional mid");
        peer.Transceivers.Should().Contain(added);
    }

    // ---------------------------------------------------------------- operations after close

    [Fact]
    public async Task Rollback_AfterClose_ThrowsObjectDisposed()
    {
        var cancellationToken = TestTimeout();
        var peer = new PeerConnection(TestSupport.NewConfig());
        _ = await peer.CreateOfferAsync(cancellationToken);
        await peer.CloseAsync();

        var act = peer.Rollback;
        act.Should().Throw<ObjectDisposedException>("a closed connection rejects a rollback");
    }

    [Fact]
    public async Task RemoteRollback_AfterClose_ThrowsObjectDisposed()
    {
        var cancellationToken = TestTimeout();
        var peer = new PeerConnection(TestSupport.NewConfig());
        await peer.CloseAsync();

        var act = () => peer.SetRemoteDescriptionAsync(string.Empty, SdpType.Rollback, cancellationToken);
        await act.Should().ThrowAsync<ObjectDisposedException>("a closed connection rejects a remote-offer rollback");
    }

    // ---------------------------------------------------------------- glare loop

    /// <summary>
    /// A hostile peer repeatedly wins glare: every time we propose a local offer, its offer arrives first
    /// and rolls ours back. Drive several rounds (each glare resolved by then rolling the remote offer back,
    /// so no driver side effects accumulate) and assert the machine never corrupts — each glare lands
    /// cleanly in HaveRemoteOffer, returns to Stable, and after the loop a normal exchange still converges
    /// to a connected session.
    /// </summary>
    [Fact]
    public async Task RepeatedGlare_StaysConsistent_AndStillConverges()
    {
        var cancellationToken = TestTimeout(60);
        await using var local = new PeerConnection(TestSupport.NewConfig());
        await using var remote = new PeerConnection(TestSupport.NewConfig());

        for (var round = 0; round < 5; round++)
        {
            // We propose an offer...
            _ = await local.CreateOfferAsync(cancellationToken);
            local.SignalingState.Should().Be(SignalingState.HaveLocalOffer);

            // ...but the peer's offer arrives first: glare. Our offer rolls back, the remote offer wins.
            await using var glarePeer = new PeerConnection(TestSupport.NewConfig());
            var remoteOffer = await glarePeer.CreateOfferAsync(cancellationToken);
            await local.SetRemoteDescriptionAsync(remoteOffer, SdpType.Offer, cancellationToken);
            local.SignalingState.Should().Be(SignalingState.HaveRemoteOffer, $"glare round {round} must land in HaveRemoteOffer");

            // Discard the winning offer with a remote rollback, returning to Stable without starting the
            // driver, so the loop stays a pure signaling-state exercise.
            await local.SetRemoteDescriptionAsync(string.Empty, SdpType.Rollback, cancellationToken);
            local.SignalingState.Should().Be(SignalingState.Stable, $"glare round {round} must settle back to Stable");
            local.Transceivers.Should().HaveCount(2, "repeated glare must not accumulate transceivers");
        }

        // After the glare storm, a clean negotiation with a fresh partner still connects.
        local.OnLocalIceCandidate += (_, e) => remote.AddIceCandidate(e.Candidate, e.SdpMid);
        remote.OnLocalIceCandidate += (_, e) => local.AddIceCandidate(e.Candidate, e.SdpMid);

        var offer = await local.CreateOfferAsync(cancellationToken);
        await remote.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await remote.CreateAnswerAsync(cancellationToken);
        await local.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        (await local.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await remote.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
    }

    // ---------------------------------------------------------------- rollback residue

    /// <summary>
    /// After a remote-offer rollback, the auto-created transceiver's mid must not linger in the lock-free
    /// receive snapshot (<see cref="PeerConnection.GetTransceiver"/>) and the inbound route table must be
    /// fully restored to its pre-offer value — otherwise a packet the peer times to the rollback window
    /// could resolve against a transceiver that no longer exists.
    /// </summary>
    [Fact]
    public async Task RemoteOfferRollback_LeavesNoResidueInSnapshotOrRouteTable()
    {
        var cancellationToken = TestTimeout();
        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        offerer.AddTransceiver(MediaKind.Video, MediaDirection.SendOnly); // extra video -> answerer auto-creates
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        // Pre-offer the inbound route table is the shared Empty instance and no auto-created mid exists.
        ReferenceEquals(answerer.InboundRoutes, PeerConnection.RouteTable.Empty).Should().BeTrue(
            "no offer has been applied, so the inbound route table is still Empty");

        RtpTransceiver? autoCreated = null;
        answerer.OnTransceiver += (_, t) => autoCreated = t;

        var offer = await offerer.CreateOfferAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        autoCreated.Should().NotBeNull();
        var autoMid = autoCreated!.Mid;
        autoMid.Should().NotBeNull();
        answerer.GetTransceiver(autoMid!).Should().BeSameAs(autoCreated, "the auto-created transceiver is resolvable while the offer is pending");
        ReferenceEquals(answerer.InboundRoutes, PeerConnection.RouteTable.Empty).Should().BeFalse(
            "applying the offer published a populated route table");

        await answerer.SetRemoteDescriptionAsync(string.Empty, SdpType.Rollback, cancellationToken);
        answerer.SignalingState.Should().Be(SignalingState.Stable);

        // Residue checks: the dropped transceiver is unreachable through the lock-free snapshot, and the
        // route table is restored to the exact pre-offer instance (no dangling route survives).
        answerer.GetTransceiver(autoMid!).Should().BeNull("the rolled-back auto-created transceiver must leave the receive snapshot");
        answerer.Transceivers.Should().HaveCount(2, "rollback drops the auto-created transceiver");
        ReferenceEquals(answerer.InboundRoutes, PeerConnection.RouteTable.Empty).Should().BeTrue(
            "rollback restores the pre-offer (Empty) inbound route table with no residual routes");
    }

    /// <summary>
    /// Repeated apply-offer/rollback churn from a hostile peer must not accumulate transceivers, routes or
    /// SSRC-ownership entries: every round returns to exactly the pre-offer shape.
    /// </summary>
    [Fact]
    public async Task RemoteOfferRollbackChurn_DoesNotAccumulateState()
    {
        var cancellationToken = TestTimeout();
        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        offerer.AddTransceiver(MediaKind.Video, MediaDirection.SendOnly);
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        var offer = await offerer.CreateOfferAsync(cancellationToken);

        for (var round = 0; round < 25; round++)
        {
            await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
            answerer.SignalingState.Should().Be(SignalingState.HaveRemoteOffer);
            answerer.Transceivers.Should().HaveCount(3, $"round {round}: applying the offer auto-creates exactly one transceiver");

            await answerer.SetRemoteDescriptionAsync(string.Empty, SdpType.Rollback, cancellationToken);
            answerer.SignalingState.Should().Be(SignalingState.Stable);
            answerer.Transceivers.Should().HaveCount(2, $"round {round}: rollback returns to the pre-offer transceiver set");
            ReferenceEquals(answerer.InboundRoutes, PeerConnection.RouteTable.Empty).Should().BeTrue(
                $"round {round}: rollback restores the Empty route table, so nothing accumulates");
        }
    }

    // ---------------------------------------------------------------- mid-session attribution

    /// <summary>
    /// A mid-session add that appends a transceiver to the lock-free snapshot must not disturb the mid→
    /// transceiver attribution of the already-negotiated transceivers: after renegotiation the original
    /// mids still resolve to the original transceivers, and the new mid resolves to the new transceiver —
    /// so an inbound packet is never demuxed to the wrong receiver.
    /// </summary>
    [Fact]
    public async Task MidSessionAdd_PreservesExistingMidAttribution()
    {
        var cancellationToken = TestTimeout(60);
        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        offerer.OnLocalIceCandidate += (_, e) => answerer.AddIceCandidate(e.Candidate, e.SdpMid);
        answerer.OnLocalIceCandidate += (_, e) => offerer.AddIceCandidate(e.Candidate, e.SdpMid);

        var offer1 = await offerer.CreateOfferAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(offer1, SdpType.Offer, cancellationToken);
        var answer1 = await answerer.CreateAnswerAsync(cancellationToken);
        await offerer.SetRemoteDescriptionAsync(answer1, SdpType.Answer, cancellationToken);
        (await offerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        var video0 = offerer.GetTransceiver("0");
        var audio1 = offerer.GetTransceiver("1");
        video0.Should().NotBeNull();
        audio1.Should().NotBeNull();

        // Mid-session add + renegotiate.
        var added = offerer.AddTransceiver(MediaKind.Video, MediaDirection.SendOnly);
        var offer2 = await offerer.CreateOfferAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(offer2, SdpType.Offer, cancellationToken);
        var answer2 = await answerer.CreateAnswerAsync(cancellationToken);
        await offerer.SetRemoteDescriptionAsync(answer2, SdpType.Answer, cancellationToken);

        // The append must not have re-pointed any existing mid.
        offerer.GetTransceiver("0").Should().BeSameAs(video0, "the append must not steal mid 0 from the first video");
        offerer.GetTransceiver("1").Should().BeSameAs(audio1, "the append must not steal mid 1 from the audio");
        added.Mid.Should().NotBeNull().And.NotBe("0").And.NotBe("1");
        offerer.GetTransceiver(added.Mid!).Should().BeSameAs(added, "the new mid resolves to the newly added transceiver");
    }

    /// <summary>
    /// Rolling back a local offer <i>mid-session</i> (on a live, connected peer) must not tear down or
    /// re-key the running SRTP context, and must revert the provisional mid of the just-added transceiver —
    /// the rollback window touches only signaling state, never the live media transport.
    /// </summary>
    [Fact]
    public async Task LocalOfferRollback_MidSession_DoesNotDisturbLiveSrtpContext()
    {
        var cancellationToken = TestTimeout(60);
        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        offerer.OnLocalIceCandidate += (_, e) => answerer.AddIceCandidate(e.Candidate, e.SdpMid);
        answerer.OnLocalIceCandidate += (_, e) => offerer.AddIceCandidate(e.Candidate, e.SdpMid);

        var offer1 = await offerer.CreateOfferAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(offer1, SdpType.Offer, cancellationToken);
        var answer1 = await answerer.CreateAnswerAsync(cancellationToken);
        await offerer.SetRemoteDescriptionAsync(answer1, SdpType.Answer, cancellationToken);
        (await offerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        var srtpBefore = offerer.SrtpContextForTest;
        var routesBefore = offerer.InboundRoutes;
        srtpBefore.Should().NotBeNull();

        // Propose a mid-session offer that adds a transceiver, then roll it back.
        var added = offerer.AddTransceiver(MediaKind.Video, MediaDirection.SendOnly);
        _ = await offerer.CreateOfferAsync(cancellationToken);
        offerer.SignalingState.Should().Be(SignalingState.HaveLocalOffer);
        added.Mid.Should().NotBeNull("building the offer provisionally assigned a mid");

        offerer.Rollback();

        offerer.SignalingState.Should().Be(SignalingState.Stable);
        added.Mid.Should().BeNull("rollback reverts the provisional mid of the added transceiver");
        ReferenceEquals(offerer.SrtpContextForTest, srtpBefore).Should().BeTrue(
            "a mid-session rollback must never re-derive or rekey the live SRTP context");
        ReferenceEquals(offerer.InboundRoutes, routesBefore).Should().BeTrue(
            "a local-offer rollback touches only signaling state, not the inbound route table");

        // The live session is undisturbed: a subsequent clean renegotiation still settles the added track.
        var offer2 = await offerer.CreateOfferAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(offer2, SdpType.Offer, cancellationToken);
        var answer2 = await answerer.CreateAnswerAsync(cancellationToken);
        await offerer.SetRemoteDescriptionAsync(answer2, SdpType.Answer, cancellationToken);
        offerer.SignalingState.Should().Be(SignalingState.Stable);
        added.Mid.Should().NotBeNull("the fresh offer re-assigns the added transceiver a mid");
    }
}
