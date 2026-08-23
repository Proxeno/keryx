using System.Linq;
using FluentAssertions;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// Covers <see cref="LocalIceCandidateEventArgs.SdpMLineIndex"/> (Epic D PR0): the JSEP
/// <c>sdpMLineIndex</c> a browser peer expects alongside <c>sdpMid</c> on a trickled candidate, added as
/// a new constructor overload so the existing two-parameter constructor stays binary compatible.
/// </summary>
public sealed class LocalIceCandidateMLineIndexTests
{
    [Fact]
    public void TwoParameterConstructor_StillWorks_AndDefaultsMLineIndexToZero()
    {
        var args = new LocalIceCandidateEventArgs("candidate:1 1 UDP 1 127.0.0.1 9 typ host", "0");

        args.Candidate.Should().Be("candidate:1 1 UDP 1 127.0.0.1 9 typ host");
        args.SdpMid.Should().Be("0");
        args.SdpMLineIndex.Should().Be(0);
    }

    [Fact]
    public void ThreeParameterConstructor_SetsExplicitMLineIndex()
    {
        var args = new LocalIceCandidateEventArgs("candidate:1 1 UDP 1 127.0.0.1 9 typ host", "2", 2);

        args.SdpMid.Should().Be("2");
        args.SdpMLineIndex.Should().Be(2);
    }

    [Fact]
    public async Task Offerer_RaisedCandidate_ReportsTheMLineIndexOfItsOwnMid()
    {
        var cancellationToken = TestTimeout();

        await using var offerer = new PeerConnection(TestSupport.NewConfig());

        LocalIceCandidateEventArgs? firstCandidate = null;
        offerer.OnLocalIceCandidate += (_, e) => firstCandidate ??= e;

        var offer = await offerer.CreateOfferAsync(cancellationToken);

        firstCandidate.Should().NotBeNull("a loopback-bound agent gathers at least a host candidate");

        // Cross-check the raised event against the offer's real m-section order: under max-bundle the
        // candidate is scoped to the whole bundled transport, so it is always reported against the
        // first m-line — video, per the default config's fixed mids ("0"/"1"/"2") — and the index must
        // match that mid's actual position in the built offer, not an assumed constant.
        var parsedOffer = SessionDescription.Parse(offer);
        var mids = parsedOffer.GetMids().ToList();
        mids.IndexOf(firstCandidate!.SdpMid).Should().Be(firstCandidate.SdpMLineIndex);

        firstCandidate.SdpMid.Should().Be("0");
        firstCandidate.SdpMLineIndex.Should().Be(0);
    }

    [Fact]
    public async Task DefaultOfferSdp_MidsAppearAtTheFixedConfigIndices()
    {
        // The fixed-mid legacy config offers video, audio, then the data channel, in that order — so
        // this is the m-section order SdpMLineIndex is computed structurally against for as long as
        // mids stay the "0"/"1"/"2" constants: video mid "0" at index 0, audio mid "1" at index 1,
        // application mid "2" at index 2.
        var cancellationToken = TestTimeout();

        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        var offer = await offerer.CreateOfferAsync(cancellationToken);

        var mids = SessionDescription.Parse(offer).GetMids().ToList();

        mids.IndexOf("0").Should().Be(0);
        mids.IndexOf("1").Should().Be(1);
        mids.IndexOf("2").Should().Be(2);
    }

    [Fact]
    public async Task Answerer_RaisedCandidate_ReportsMLineIndexZeroMirroringTheOfferedFirstMid()
    {
        var cancellationToken = TestTimeout();

        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        var offer = await offerer.CreateOfferAsync(cancellationToken);
        var offeredFirstMid = SessionDescription.Parse(offer).GetMids()[0];

        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);

        LocalIceCandidateEventArgs? firstCandidate = null;
        answerer.OnLocalIceCandidate += (_, e) => firstCandidate ??= e;

        // CreateAnswerAsync starts the connection driver once it returns; nothing here needs the
        // handshake to finish, only the candidates gathered while building the answer.
        _ = await answerer.CreateAnswerAsync(cancellationToken);

        firstCandidate.Should().NotBeNull();
        firstCandidate!.SdpMid.Should().Be(offeredFirstMid);
        firstCandidate.SdpMLineIndex.Should().Be(0);
    }

    private static CancellationToken TestTimeout() =>
        new CancellationTokenSource(TimeSpan.FromSeconds(20)).Token;
}
