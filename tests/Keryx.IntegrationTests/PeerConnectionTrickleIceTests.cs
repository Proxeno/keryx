using FluentAssertions;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// Covers true outbound trickle ICE (RFC 8838): with
/// <see cref="PeerConnectionConfig.TrickleIceCandidates"/> set, <see cref="PeerConnection.CreateOfferAsync(System.Threading.CancellationToken)"/>
/// and <see cref="PeerConnection.CreateAnswerAsync"/> return before gathering completes and without
/// asserting <c>a=end-of-candidates</c>; candidates are surfaced incrementally through
/// <see cref="PeerConnection.OnLocalIceCandidate"/>; gathering-complete is signalled through
/// <see cref="PeerConnection.OnIceGatheringComplete"/>; and two trickle agents connect purely by
/// exchanging candidates out of band. The default (flag off) blocking path is asserted unchanged.
/// </summary>
public sealed class PeerConnectionTrickleIceTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    private static PeerConnectionConfig TrickleConfig()
    {
        var config = TestSupport.NewConfig();
        config.TrickleIceCandidates = true;
        return config;
    }

    private static int CountCandidateLines(string sdp) =>
        sdp.Split('\n').Count(line => line.TrimEnd('\r').StartsWith("a=candidate:", StringComparison.Ordinal));

    [Fact]
    public async Task TrickleOffer_ReturnsBeforeGatheringCompletes_WithoutEndOfCandidates()
    {
        var cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;
        await using var offerer = new PeerConnection(TrickleConfig());

        var surfaced = 0;
        var gatheringComplete = false;
        offerer.OnLocalIceCandidate += (_, _) => Interlocked.Increment(ref surfaced);
        offerer.OnIceGatheringComplete += (_, _) => Volatile.Write(ref gatheringComplete, true);

        _ = offerer.CreateDataChannel("d");
        var offer = await offerer.CreateOfferAsync(cancellationToken);

        // The offer advertises trickle but, having returned before gathering finished, must NOT yet
        // assert end-of-candidates — the JSEP/RFC 8838 contract that proves it did not block on the
        // full gather (contrast the default path, which always asserts it).
        offer.Should().Contain("a=ice-options:trickle");
        offer.Should().NotContain("a=end-of-candidates");

        // Gathering runs in the background; the terminal signal arrives after the offer was returned.
        (await TestSupport.WaitForAsync(() => Volatile.Read(ref gatheringComplete))).Should().BeTrue(
            "OnIceGatheringComplete is the end-of-candidates signal raised once background gathering finishes");

        // Candidates were surfaced incrementally for the consumer to trickle, and every one the offer
        // itself carried was also delivered through the event (the offer never carries more than the set).
        Volatile.Read(ref surfaced).Should().BeGreaterThan(0);
        CountCandidateLines(offer).Should().BeLessThanOrEqualTo(Volatile.Read(ref surfaced));
    }

    [Fact]
    public async Task TrickleAnswer_OmitsEndOfCandidates_AndSignalsGatheringComplete()
    {
        var cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;

        // A plain (blocking) offerer; only the answerer trickles.
        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        await using var answerer = new PeerConnection(TrickleConfig());

        var gatheringComplete = false;
        answerer.OnIceGatheringComplete += (_, _) => Volatile.Write(ref gatheringComplete, true);

        _ = offerer.CreateDataChannel("d");
        var offer = await offerer.CreateOfferAsync(cancellationToken);
        offer.Should().Contain("a=end-of-candidates", "the blocking offerer still gathers fully before offering");

        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await answerer.CreateAnswerAsync(cancellationToken);

        answer.Should().Contain("a=ice-options:trickle");
        answer.Should().NotContain("a=end-of-candidates");

        (await TestSupport.WaitForAsync(() => Volatile.Read(ref gatheringComplete))).Should().BeTrue();
    }

    [Fact]
    public async Task DefaultConfig_BlockingOffer_AssertsEndOfCandidates()
    {
        var cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;
        await using var offerer = new PeerConnection(TestSupport.NewConfig());

        _ = offerer.CreateDataChannel("d");
        var offer = await offerer.CreateOfferAsync(cancellationToken);

        // Flag off: the description is complete, carries its gathered candidates and asserts the
        // terminator — byte-for-byte the historical behaviour the goldens capture.
        offer.Should().Contain("a=ice-options:trickle");
        offer.Should().Contain("a=end-of-candidates");
        CountCandidateLines(offer).Should().BeGreaterThan(0, "a blocking offer embeds every gathered candidate");
    }

    [Fact]
    public async Task TwoTrickleAgents_ConnectByExchangingCandidatesAsTheyArrive()
    {
        var cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(50)).Token;

        await using var offerer = new PeerConnection(TrickleConfig());
        await using var answerer = new PeerConnection(TrickleConfig());

        var offererTrickled = 0;
        var answererTrickled = 0;

        // Each side trickles every gathered candidate to the peer as it arrives, then forwards an
        // end-of-candidates marker once gathering completes — exactly the WebRTC signalling contract.
        // Candidates that arrive before the peer's ICE agent exists are buffered by AddIceCandidate.
        offerer.OnLocalIceCandidate += (_, e) =>
        {
            Interlocked.Increment(ref offererTrickled);
            answerer.AddIceCandidate(e.Candidate, e.SdpMid);
        };
        offerer.OnIceGatheringComplete += (_, _) => answerer.AddIceCandidate("a=end-of-candidates", "0");

        answerer.OnLocalIceCandidate += (_, e) =>
        {
            Interlocked.Increment(ref answererTrickled);
            offerer.AddIceCandidate(e.Candidate, e.SdpMid);
        };
        answerer.OnIceGatheringComplete += (_, _) => offerer.AddIceCandidate("a=end-of-candidates", "0");

        _ = offerer.CreateDataChannel("d");

        var offer = await offerer.CreateOfferAsync(cancellationToken);
        offer.Should().NotContain("a=end-of-candidates", "the offer is emitted before gathering completes");

        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await answerer.CreateAnswerAsync(cancellationToken);
        answer.Should().NotContain("a=end-of-candidates");

        await offerer.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        // The connection must establish purely from the trickled candidates, without the full set having
        // been present in the offer/answer up front.
        (await offerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        Volatile.Read(ref offererTrickled).Should().BeGreaterThan(0);
        Volatile.Read(ref answererTrickled).Should().BeGreaterThan(0);
    }
}
