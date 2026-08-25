using FluentAssertions;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// The JSEP signaling state machine (Epic D, PR 4, session-model.md §4.1): <see cref="SignalingState"/>
/// replaces the historical <c>_isOfferer</c> bool, tracked on the existing create-offer / create-answer
/// / apply-offer / apply-answer methods (no public <c>SetLocalDescription</c>). Covers the offerer and
/// answerer walks, that invalid transitions throw, and that <see cref="PeerConnection.OnNegotiationNeeded"/>
/// fires (coalesced) on an add-transceiver-before-connect and not for a no-op.
/// </summary>
public sealed class SignalingStateMachineTests
{
    private static CancellationToken TestTimeout(int seconds = 30) =>
        new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    [Fact]
    public async Task NewConnection_IsStable()
    {
        await using var peer = new PeerConnection(TestSupport.NewConfig());
        peer.SignalingState.Should().Be(SignalingState.Stable);
    }

    [Fact]
    public async Task OffererFlow_WalksStableHaveLocalOfferStable()
    {
        var cancellationToken = TestTimeout();
        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        var states = new List<SignalingState>();
        offerer.OnSignalingStateChanged += (_, s) => states.Add(s);

        var offer = await offerer.CreateOfferAsync(cancellationToken);
        offerer.SignalingState.Should().Be(SignalingState.HaveLocalOffer);

        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await answerer.CreateAnswerAsync(cancellationToken);

        await offerer.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);
        offerer.SignalingState.Should().Be(SignalingState.Stable);

        states.Should().Equal(SignalingState.HaveLocalOffer, SignalingState.Stable);
    }

    [Fact]
    public async Task AnswererFlow_WalksStableHaveRemoteOfferStable()
    {
        var cancellationToken = TestTimeout();
        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        var states = new List<SignalingState>();
        answerer.OnSignalingStateChanged += (_, s) => states.Add(s);

        var offer = await offerer.CreateOfferAsync(cancellationToken);

        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        answerer.SignalingState.Should().Be(SignalingState.HaveRemoteOffer);

        _ = await answerer.CreateAnswerAsync(cancellationToken);
        answerer.SignalingState.Should().Be(SignalingState.Stable);

        states.Should().Equal(SignalingState.HaveRemoteOffer, SignalingState.Stable);
    }

    [Fact]
    public async Task SecondCreateOffer_InHaveLocalOffer_Throws()
    {
        var cancellationToken = TestTimeout();
        await using var peer = new PeerConnection(TestSupport.NewConfig());
        _ = await peer.CreateOfferAsync(cancellationToken);

        var act = () => peer.CreateOfferAsync(cancellationToken);
        await act.Should().ThrowAsync<InvalidOperationException>(
            "a second local offer while one is pending is invalid until rollback lands");
        peer.SignalingState.Should().Be(SignalingState.HaveLocalOffer);
    }

    [Fact]
    public async Task CreateAnswer_InStable_Throws()
    {
        var cancellationToken = TestTimeout();
        await using var peer = new PeerConnection(TestSupport.NewConfig());

        var act = () => peer.CreateAnswerAsync(cancellationToken);
        await act.Should().ThrowAsync<InvalidOperationException>(
            "answering requires a remote offer to have been applied");
        peer.SignalingState.Should().Be(SignalingState.Stable);
    }

    [Fact]
    public async Task CreateAnswer_InHaveLocalOffer_Throws()
    {
        var cancellationToken = TestTimeout();
        await using var peer = new PeerConnection(TestSupport.NewConfig());
        _ = await peer.CreateOfferAsync(cancellationToken);

        var act = () => peer.CreateAnswerAsync(cancellationToken);
        await act.Should().ThrowAsync<InvalidOperationException>("the offerer cannot answer its own pending offer");
    }

    [Fact]
    public async Task ApplyAnswer_InStable_Throws()
    {
        var cancellationToken = TestTimeout();
        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        // Produce a real, well-formed answer, but try to apply it on a peer that never offered.
        var offer = await offerer.CreateOfferAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await answerer.CreateAnswerAsync(cancellationToken);

        await using var bystander = new PeerConnection(TestSupport.NewConfig());
        var act = () => bystander.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);
        await act.Should().ThrowAsync<InvalidOperationException>(
            "an answer is only valid while a local offer is pending");
        bystander.SignalingState.Should().Be(SignalingState.Stable);
    }

    [Fact]
    public async Task ApplyRemoteOffer_InHaveLocalOffer_ThrowsGlare()
    {
        var cancellationToken = TestTimeout();
        await using var a = new PeerConnection(TestSupport.NewConfig());
        await using var b = new PeerConnection(TestSupport.NewConfig());

        var offerA = await a.CreateOfferAsync(cancellationToken);
        var offerB = await b.CreateOfferAsync(cancellationToken);

        // a has a local offer pending; applying b's offer is glare, which needs rollback (not yet here).
        var act = () => a.SetRemoteDescriptionAsync(offerB, SdpType.Offer, cancellationToken);
        await act.Should().ThrowAsync<InvalidOperationException>("glare is rejected until rollback lands");
        a.SignalingState.Should().Be(SignalingState.HaveLocalOffer);
        _ = offerA;
    }

    [Fact]
    public async Task CreateOffer_InHaveRemoteOffer_Throws()
    {
        var cancellationToken = TestTimeout();
        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        var offer = await offerer.CreateOfferAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);

        var act = () => answerer.CreateOfferAsync(cancellationToken);
        await act.Should().ThrowAsync<InvalidOperationException>(
            "with a remote offer pending the peer must answer, not offer");
        answerer.SignalingState.Should().Be(SignalingState.HaveRemoteOffer);
    }

    [Fact]
    public async Task OnNegotiationNeeded_FiresOnAddTransceiverBeforeConnect()
    {
        await using var peer = new PeerConnection(TestSupport.NewConfig());
        var fired = 0;
        peer.OnNegotiationNeeded += (_, _) => Interlocked.Increment(ref fired);

        peer.AddTransceiver(MediaKind.Video, MediaDirection.SendOnly);

        fired.Should().Be(1, "adding a track before the first negotiation needs (re)negotiation");
    }

    [Fact]
    public async Task OnNegotiationNeeded_CoalescesMultipleAdds()
    {
        await using var peer = new PeerConnection(TestSupport.NewConfig());
        var fired = 0;
        peer.OnNegotiationNeeded += (_, _) => Interlocked.Increment(ref fired);

        peer.AddTransceiver(MediaKind.Video, MediaDirection.SendOnly);
        peer.AddTransceiver(MediaKind.Audio, MediaDirection.SendOnly);
        peer.AddTransceiver(MediaKind.Video, MediaDirection.SendOnly);

        fired.Should().Be(1, "a burst of adds in the stable state coalesces into one negotiation-needed event");
    }

    [Fact]
    public async Task OnNegotiationNeeded_DoesNotFireForLegacyNoOp()
    {
        var cancellationToken = TestTimeout();
        await using var peer = new PeerConnection(TestSupport.NewConfig());
        var fired = 0;
        peer.OnNegotiationNeeded += (_, _) => Interlocked.Increment(ref fired);

        // The pure legacy path adds no application transceiver: the constructor-built per-kind
        // transceivers are driven through the single-shot flow and must not raise negotiation-needed.
        _ = await peer.CreateOfferAsync(cancellationToken);

        fired.Should().Be(0, "a no-op change (no application track added) does not raise negotiation-needed");
    }

    [Fact]
    public async Task OnNegotiationNeeded_ClearedAfterOfferCovers_TheAddedTrack()
    {
        var cancellationToken = TestTimeout();
        await using var peer = new PeerConnection(TestSupport.NewConfig());
        var fired = 0;
        peer.OnNegotiationNeeded += (_, _) => Interlocked.Increment(ref fired);

        peer.AddTransceiver(MediaKind.Video, MediaDirection.SendOnly);
        fired.Should().Be(1);

        // Building the offer folds the added transceiver into the local description; the pending intent
        // clears, so returning to stable after the answer must not re-raise the event.
        await using var answerer = new PeerConnection(TestSupport.NewConfig());
        var offer = await peer.CreateOfferAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await answerer.CreateAnswerAsync(cancellationToken);
        await peer.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        peer.SignalingState.Should().Be(SignalingState.Stable);
        fired.Should().Be(1, "the added track was covered by the offer; no further negotiation-needed");
    }

    [Fact]
    public async Task SignalingState_IsStable_AfterCompletedNegotiationAndConnect()
    {
        var cancellationToken = TestTimeout(60);
        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        offerer.OnLocalIceCandidate += (_, e) => answerer.AddIceCandidate(e.Candidate, e.SdpMid);
        answerer.OnLocalIceCandidate += (_, e) => offerer.AddIceCandidate(e.Candidate, e.SdpMid);

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
    public async Task SignalingState_IsClosed_AfterClose()
    {
        var peer = new PeerConnection(TestSupport.NewConfig());
        var states = new List<SignalingState>();
        peer.OnSignalingStateChanged += (_, s) => states.Add(s);

        await peer.CloseAsync();

        peer.SignalingState.Should().Be(SignalingState.Closed);
        states.Should().Contain(SignalingState.Closed);
    }
}
