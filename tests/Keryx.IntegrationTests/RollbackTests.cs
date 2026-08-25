using FluentAssertions;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// SDP rollback (Epic D, PR 6, JSEP §4.1.8.2, session-model.md §4.4): a proposed-but-not-yet-answered
/// local offer (<see cref="PeerConnection.Rollback"/>) or remote offer
/// (<see cref="PeerConnection.SetRemoteDescriptionAsync"/> with <see cref="SdpType.Rollback"/>) can be
/// discarded, returning <see cref="SignalingState"/> to <see cref="SignalingState.Stable"/> and restoring
/// the transceiver set to its pre-offer shape. Covers the local and remote paths, the JSEP no-rollback-from-
/// stable rule, glare resolution, and that a fresh negotiation succeeds after a rollback.
/// </summary>
public sealed class RollbackTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    private static CancellationToken TestTimeout(int seconds = 30) =>
        new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    [Fact]
    public async Task LocalRollback_ReturnsToStable_DetachesAddedTransceiver_AndFreshOfferWorks()
    {
        var cancellationToken = TestTimeout();
        await using var peer = new PeerConnection(TestSupport.NewConfig());

        var states = new List<SignalingState>();
        peer.OnSignalingStateChanged += (_, s) => states.Add(s);

        // An application-added video transceiver on top of the legacy video+audio pair.
        var added = peer.AddTransceiver(MediaKind.Video, MediaDirection.SendOnly);

        var offer1 = await peer.CreateOfferAsync(cancellationToken);
        peer.SignalingState.Should().Be(SignalingState.HaveLocalOffer);
        added.Mid.Should().NotBeNull("building the offer provisionally assigns the added transceiver a mid");
        var assignedMid = added.Mid;

        // Roll the pending local offer back.
        peer.Rollback();

        peer.SignalingState.Should().Be(SignalingState.Stable);
        states.Should().Equal(SignalingState.HaveLocalOffer, SignalingState.Stable);

        // The application-added transceiver is kept (JSEP does not destroy app-added transceivers) but is
        // detached: its provisional mid is reverted so it is no longer associated with an m-line.
        peer.Transceivers.Should().Contain(added);
        added.Mid.Should().BeNull("rollback reverts the provisionally assigned mid");

        // The legacy pair keeps its pinned mids and directions.
        var legacyVideo = peer.Transceivers.First(t => t.Kind == MediaKind.Video && !ReferenceEquals(t, added));
        var legacyAudio = peer.Transceivers.Single(t => t.Kind == MediaKind.Audio);
        legacyVideo.Mid.Should().Be("0");
        legacyAudio.Mid.Should().Be("1");

        // A subsequent fresh offer works and re-includes the (still-present) added transceiver.
        var offer2 = SessionDescription.Parse(await peer.CreateOfferAsync(cancellationToken));
        peer.SignalingState.Should().Be(SignalingState.HaveLocalOffer);
        added.Mid.Should().NotBeNull().And.Be(assignedMid, "the fresh offer re-assigns the same free mid");
        offer2.MediaDescriptions.Where(m => m.Media == "video").Should().HaveCount(2, "both video m-lines are re-offered");
        offer2.MediaDescriptions.Select(m => m.Mid).Should().Contain(added.Mid);

        _ = offer1;
    }

    [Fact]
    public async Task RemoteRollback_ReturnsToStable_RemovesAutoCreatedTransceiver_AndRevertsBoundOnes()
    {
        var cancellationToken = TestTimeout();

        // The offerer offers two video m-lines plus audio; the answerer has only the legacy video+audio
        // pair, so the second video auto-creates on the answerer.
        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        offerer.AddTransceiver(MediaKind.Video, MediaDirection.SendOnly);
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        var states = new List<SignalingState>();
        answerer.OnSignalingStateChanged += (_, s) => states.Add(s);

        RtpTransceiver? autoCreated = null;
        answerer.OnTransceiver += (_, t) => autoCreated = t;

        var offer = await offerer.CreateOfferAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);

        answerer.SignalingState.Should().Be(SignalingState.HaveRemoteOffer);
        autoCreated.Should().NotBeNull("the extra offered video m-line auto-creates a transceiver");
        answerer.Transceivers.Should().Contain(autoCreated!);
        answerer.Transceivers.Should().HaveCount(3);

        // The legacy video bound to the offered sendonly m-line and took the complement direction.
        var legacyVideo = answerer.Transceivers.First(t => t.Kind == MediaKind.Video && !ReferenceEquals(t, autoCreated));
        legacyVideo.Direction.Should().Be(MediaDirection.RecvOnly, "binding a sendonly offer makes this side the receiver");

        // Roll the pending remote offer back (the SDP text is ignored for a rollback).
        await answerer.SetRemoteDescriptionAsync(string.Empty, SdpType.Rollback, cancellationToken);

        answerer.SignalingState.Should().Be(SignalingState.Stable);
        states.Should().Equal(SignalingState.HaveRemoteOffer, SignalingState.Stable);

        // The auto-created transceiver is gone; the legacy pair survives with its pre-offer direction restored.
        answerer.Transceivers.Should().NotContain(autoCreated!);
        answerer.Transceivers.Should().HaveCount(2);
        legacyVideo.Direction.Should().Be(MediaDirection.SendOnly, "rollback restores the pre-offer direction");

        // A fresh negotiation succeeds after the rollback: re-apply the offerer's still-pending offer and
        // answer it. The auto-created transceiver is re-created, and binding/answering proceeds cleanly.
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        answerer.SignalingState.Should().Be(SignalingState.HaveRemoteOffer);
        answerer.Transceivers.Should().HaveCount(3, "re-applying the offer re-creates the extra video transceiver");
        var answer2 = await answerer.CreateAnswerAsync(cancellationToken);
        answer2.Should().NotBeNullOrEmpty();
        answerer.SignalingState.Should().Be(SignalingState.Stable);
    }

    [Fact]
    public async Task LocalRollback_FromStable_Throws()
    {
        await using var peer = new PeerConnection(TestSupport.NewConfig());

        var act = peer.Rollback;
        act.Should().Throw<InvalidOperationException>("JSEP rejects a rollback from the stable state");
        peer.SignalingState.Should().Be(SignalingState.Stable);
    }

    [Fact]
    public async Task RemoteRollback_FromStable_Throws()
    {
        var cancellationToken = TestTimeout();
        await using var peer = new PeerConnection(TestSupport.NewConfig());

        var act = () => peer.SetRemoteDescriptionAsync(string.Empty, SdpType.Rollback, cancellationToken);
        await act.Should().ThrowAsync<InvalidOperationException>("a remote-offer rollback needs a remote offer pending");
        peer.SignalingState.Should().Be(SignalingState.Stable);
    }

    [Fact]
    public async Task LocalRollback_InHaveRemoteOffer_Throws()
    {
        var cancellationToken = TestTimeout();
        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        var offer = await offerer.CreateOfferAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        answerer.SignalingState.Should().Be(SignalingState.HaveRemoteOffer);

        // Rollback() rolls back a local offer; a pending remote offer must use SetRemoteDescription(rollback).
        var act = answerer.Rollback;
        act.Should().Throw<InvalidOperationException>();
        answerer.SignalingState.Should().Be(SignalingState.HaveRemoteOffer);
    }

    [Fact]
    public async Task LocalRollback_ThenFreshNegotiation_Connects()
    {
        var cancellationToken = TestTimeout(60);
        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        offerer.OnLocalIceCandidate += (_, e) => answerer.AddIceCandidate(e.Candidate, e.SdpMid);
        answerer.OnLocalIceCandidate += (_, e) => offerer.AddIceCandidate(e.Candidate, e.SdpMid);

        // Propose, then abandon, a first offer.
        _ = await offerer.CreateOfferAsync(cancellationToken);
        offerer.Rollback();
        offerer.SignalingState.Should().Be(SignalingState.Stable);

        // A completely fresh offer/answer from the rolled-back state connects normally.
        var offer = await offerer.CreateOfferAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await answerer.CreateAnswerAsync(cancellationToken);
        await offerer.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        (await offerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        offerer.SignalingState.Should().Be(SignalingState.Stable);
        answerer.SignalingState.Should().Be(SignalingState.Stable);
    }

    [Fact]
    public async Task RemoteRollback_ThenReofferSameOffer_ReAppliesCleanly()
    {
        var cancellationToken = TestTimeout();
        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        var offer = await offerer.CreateOfferAsync(cancellationToken);

        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        answerer.SignalingState.Should().Be(SignalingState.HaveRemoteOffer);

        await answerer.SetRemoteDescriptionAsync(string.Empty, SdpType.Rollback, cancellationToken);
        answerer.SignalingState.Should().Be(SignalingState.Stable);

        // Applying the very same offer again after the rollback binds cleanly and can be answered.
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        answerer.SignalingState.Should().Be(SignalingState.HaveRemoteOffer);
        var answer = await answerer.CreateAnswerAsync(cancellationToken);
        answer.Should().NotBeNullOrEmpty();
        answerer.SignalingState.Should().Be(SignalingState.Stable);
    }
}
