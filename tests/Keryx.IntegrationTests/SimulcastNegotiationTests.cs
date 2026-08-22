using FluentAssertions;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// Exercises the simulcast answer path end to end on <see cref="PeerConnection"/>: a simulcast offer
/// is answered with a reversed <c>a=simulcast</c>, reversed <c>a=rid</c> lines, and the negotiated
/// RID / repaired-RID / MID <c>a=extmap</c>s, and the resolved header-extension ids are exposed.
/// </summary>
public sealed class SimulcastNegotiationTests
{
    private const byte MidExtId = 4;
    private const byte RidExtId = 5;
    private const byte RepairedRidExtId = 6;

    private static CancellationToken TestTimeout() =>
        new CancellationTokenSource(TimeSpan.FromSeconds(20)).Token;

    private static async Task<(string Offer, string VideoMid)> SimulcastOfferAsync(CancellationToken cancellationToken)
    {
        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        var baseOffer = await offerer.CreateOfferAsync(cancellationToken);

        // Turn the plain video section into a simulcast one by adding the RFC 8852 extmaps, the a=rid
        // declarations and the a=simulcast line, then re-serialize through the real writer.
        var parsed = SessionDescription.Parse(baseOffer);
        var video = parsed.MediaDescriptions.First(m => string.Equals(m.Media, "video", StringComparison.Ordinal));
        video.AddExtMap(new SdpExtMap(MidExtId, RtpHeaderExtensionUri.Mid));
        video.AddExtMap(new SdpExtMap(RidExtId, RtpHeaderExtensionUri.Rid));
        video.AddExtMap(new SdpExtMap(RepairedRidExtId, RtpHeaderExtensionUri.RepairedRid));
        video.AddRid(new SdpRid("hi", RidDirection.Send, new[] { new SdpRidRestriction("max-width", "1280") }));
        video.AddRid(new SdpRid("mid", RidDirection.Send));
        video.AddRid(new SdpRid("lo", RidDirection.Send));
        video.Simulcast = SdpSimulcast.SendOnly(
            new SdpSimulcastStream("hi"),
            new SdpSimulcastStream("mid"),
            new SdpSimulcastStream("lo"));

        return (parsed.ToSdpString(), video.Mid!);
    }

    [Fact]
    public async Task AnswerEchoesReversedSimulcastRidsAndExtmaps()
    {
        var cancellationToken = TestTimeout();
        var (offer, _) = await SimulcastOfferAsync(cancellationToken);

        await using var answerer = new PeerConnection(TestSupport.NewConfig());
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await answerer.CreateAnswerAsync(cancellationToken);

        // Directions reversed, RID order preserved.
        answer.Should().Contain("a=simulcast:recv hi;mid;lo");

        // a=rid lines flipped to recv, restrictions kept verbatim.
        answer.Should().Contain("a=rid:hi recv max-width=1280");
        answer.Should().Contain("a=rid:mid recv");
        answer.Should().Contain("a=rid:lo recv");

        // The stream-identifier extensions are negotiated with the offered ids.
        answer.Should().Contain($"a=extmap:{MidExtId} {RtpHeaderExtensionUri.Mid}");
        answer.Should().Contain($"a=extmap:{RidExtId} {RtpHeaderExtensionUri.Rid}");
        answer.Should().Contain($"a=extmap:{RepairedRidExtId} {RtpHeaderExtensionUri.RepairedRid}");
    }

    [Fact]
    public async Task AppliedOfferExposesResolvedHeaderExtensionIds()
    {
        var cancellationToken = TestTimeout();
        var (offer, videoMid) = await SimulcastOfferAsync(cancellationToken);

        await using var answerer = new PeerConnection(TestSupport.NewConfig());
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);

        answerer.SimulcastMids.Should().Contain(videoMid);

        answerer.TryGetSimulcastExtensions(videoMid, out var extensions).Should().BeTrue();
        extensions.MidId.Should().Be(MidExtId);
        extensions.RidId.Should().Be(RidExtId);
        extensions.RepairedRidId.Should().Be(RepairedRidExtId);
        extensions.HasRid.Should().BeTrue();

        // The classifier the peer connection drives for the section is available to the app.
        answerer.GetSimulcastClassifier(videoMid).Should().NotBeNull();
        answerer.GetSimulcastLayerStats(videoMid).Should().BeEmpty();
    }

    [Fact]
    public async Task SimulcastIsNotAnsweredWhenDisabled()
    {
        var cancellationToken = TestTimeout();
        var (offer, videoMid) = await SimulcastOfferAsync(cancellationToken);

        var config = TestSupport.NewConfig();
        config.EnableSimulcast = false;
        await using var answerer = new PeerConnection(config);
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await answerer.CreateAnswerAsync(cancellationToken);

        answer.Should().NotContain("a=simulcast");
        answer.Should().NotContain("a=rid:");
        answerer.SimulcastMids.Should().NotContain(videoMid);
    }
}
