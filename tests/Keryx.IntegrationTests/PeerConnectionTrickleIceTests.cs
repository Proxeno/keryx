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

        // The deterministic, non-racy proof that the offer did not block on the full gather: trickle mode
        // omits a=end-of-candidates unconditionally (PeerConnection.AttachLocalCandidates ties it purely
        // to PeerConnectionConfig.TrickleIceCandidates, never to whether gathering happened to finish by
        // the time the offer was built), so this holds regardless of how fast gathering completes
        // (contrast the default path in DefaultConfig_BlockingOffer_AssertsEndOfCandidates, which always
        // asserts it). Deliberately not asserted here: that the offer "returned before gathering
        // completed" — on a fast loopback host, gathering can finish essentially synchronously, so any
        // wall-clock ordering check on that races.
        offer.Should().Contain("a=ice-options:trickle");
        offer.Should().NotContain("a=end-of-candidates");

        // Gathering runs in the background and its terminal signal must arrive regardless of whether it
        // finishes before or after CreateOfferAsync returns.
        (await TestSupport.WaitForAsync(() => Volatile.Read(ref gatheringComplete))).Should().BeTrue(
            "OnIceGatheringComplete is the end-of-candidates signal raised once background gathering finishes");

        // Every candidate the offer carries must eventually be surfaced through OnLocalIceCandidate too.
        // IceAgent adds a candidate to its internal list (which AttachLocalCandidates reads synchronously
        // from the CreateOfferAsync caller's thread) and only then enqueues/drains its event on the
        // gathering background thread, so sampling the surfaced count once, immediately after
        // CreateOfferAsync returns, races: on a fast loopback host the offer can already embed a
        // candidate whose event has not been drained yet. Poll instead of sampling once.
        var offerCandidateCount = CountCandidateLines(offer);
        (await TestSupport.WaitForAsync(() => Volatile.Read(ref surfaced) >= offerCandidateCount)).Should().BeTrue(
            "every candidate embedded in the offer must eventually be delivered through OnLocalIceCandidate");
        Volatile.Read(ref surfaced).Should().BeGreaterThan(0);
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
