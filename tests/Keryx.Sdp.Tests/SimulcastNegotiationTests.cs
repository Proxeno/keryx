using FluentAssertions;
using Xunit;

namespace Keryx.Sdp.Tests;

public class SimulcastNegotiationTests
{
    private static MediaDescription OfferedSimulcastVideo()
    {
        var media = new MediaDescription("video", 9, SdpMediaOffer.RtpProtocol, "96", "97");
        media.AddExtMap(new SdpExtMap(1, RtpHeaderExtensionUri.Mid));
        media.AddExtMap(new SdpExtMap(2, RtpHeaderExtensionUri.Rid));
        media.AddExtMap(new SdpExtMap(3, RtpHeaderExtensionUri.RepairedRid));
        media.AddExtMap(new SdpExtMap(5, RtpHeaderExtensionUri.AbsoluteSendTime));
        media.AddRid(new SdpRid("hi", RidDirection.Send, new[] { new SdpRidRestriction("max-width", "1280") }));
        media.AddRid(new SdpRid("mid", RidDirection.Send, new[] { new SdpRidRestriction("max-width", "640") }));
        media.AddRid(new SdpRid("lo", RidDirection.Send));
        media.Simulcast = SdpSimulcast.SendOnly(
            new SdpSimulcastStream("hi"),
            new SdpSimulcastStream("mid"),
            new SdpSimulcastStream("lo"));
        return media;
    }

    [Fact]
    public void AnswerSimulcast_ReversesDirectionAndKeepsRestrictions()
    {
        var answer = SdpNegotiator.AnswerSimulcast(OfferedSimulcastVideo());

        answer.Should().NotBeNull();

        // The offered send list becomes the answerer's recv list, in order.
        answer!.Simulcast.Send.Should().BeEmpty();
        answer.Simulcast.Recv.Should().HaveCount(3);
        answer.Simulcast.ToAttributeValue().Should().Be("recv hi;mid;lo");

        // Each a=rid flips send -> recv and keeps its restrictions verbatim.
        answer.Rids.Should().HaveCount(3);
        answer.Rids.Should().OnlyContain(r => r.Direction == RidDirection.Recv);
        answer.Rids[0].Id.Should().Be("hi");
        answer.Rids[0].Restrictions.Should().ContainSingle().Which.ToString().Should().Be("max-width=1280");
    }

    [Fact]
    public void AnswerSimulcast_NegotiatesRidMidAndRepairedRidExtmaps()
    {
        var answer = SdpNegotiator.AnswerSimulcast(OfferedSimulcastVideo());

        answer!.HeaderExtensions.Should().HaveCount(3);
        answer.HeaderExtensions.Should().Contain(e => e.Id == 1 && e.Uri == RtpHeaderExtensionUri.Mid);
        answer.HeaderExtensions.Should().Contain(e => e.Id == 2 && e.Uri == RtpHeaderExtensionUri.Rid);
        answer.HeaderExtensions.Should().Contain(e => e.Id == 3 && e.Uri == RtpHeaderExtensionUri.RepairedRid);

        // Non-stream-identifier extensions (abs-send-time) are not part of the simulcast answer.
        answer.HeaderExtensions.Should().NotContain(e => e.Uri == RtpHeaderExtensionUri.AbsoluteSendTime);
        answer.HasRidExtension.Should().BeTrue();
    }

    [Fact]
    public void AnswerSimulcast_PrunesRidsTheAnswererDoesNotAccept()
    {
        var answer = SdpNegotiator.AnswerSimulcast(
            OfferedSimulcastVideo(),
            acceptRid: id => id != "hi");

        answer!.Simulcast.ToAttributeValue().Should().Be("recv mid;lo");
        answer.Rids.Select(r => r.Id).Should().Equal("mid", "lo");
    }

    [Fact]
    public void AnswerSimulcast_ReturnsNullWhenNotSimulcast()
    {
        var media = new MediaDescription("video", 9, SdpMediaOffer.RtpProtocol, "96");
        SdpNegotiator.AnswerSimulcast(media).Should().BeNull();
    }

    [Fact]
    public void AnswerSimulcast_ReturnsNullWhenEveryRidIsPruned()
    {
        SdpNegotiator.AnswerSimulcast(OfferedSimulcastVideo(), acceptRid: _ => false).Should().BeNull();
    }

    [Fact]
    public void AnswerSimulcast_DropsAlternativesReferencingUndeclaredRids()
    {
        var media = new MediaDescription("video", 9, SdpMediaOffer.RtpProtocol, "96");
        media.AddExtMap(new SdpExtMap(2, RtpHeaderExtensionUri.Rid));
        media.AddRid(new SdpRid("hi", RidDirection.Send));
        // 'ghost' appears in a=simulcast but has no a=rid declaration.
        media.Simulcast = SdpSimulcast.SendOnly(new SdpSimulcastStream("hi"), new SdpSimulcastStream("ghost"));

        var answer = SdpNegotiator.AnswerSimulcast(media);

        answer!.Simulcast.ToAttributeValue().Should().Be("recv hi");
        answer.Rids.Select(r => r.Id).Should().Equal("hi");
    }

    [Theory]
    [InlineData("send")]
    [InlineData("send hi;;")]
    [InlineData("recv ~;,")]
    [InlineData("garbage nonsense tokens")]
    [InlineData("send hi mid lo")]
    public void AnswerSimulcast_NeverThrowsOnHostileSimulcastInput(string simulcastValue)
    {
        var media = new MediaDescription("video", 9, SdpMediaOffer.RtpProtocol, "96");
        media.AddExtMap(new SdpExtMap(2, RtpHeaderExtensionUri.Rid));
        media.AddRid(new SdpRid("hi", RidDirection.Send));
        media.AddAttribute(SdpAttributeNames.Simulcast, simulcastValue);
        media.AddAttribute(SdpAttributeNames.Rid, "!!! not a rid line ;;;");

        var act = () => SdpNegotiator.AnswerSimulcast(media);

        act.Should().NotThrow();
    }
}
