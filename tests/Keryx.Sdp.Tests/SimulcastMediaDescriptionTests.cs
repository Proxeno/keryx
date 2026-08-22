using FluentAssertions;
using Xunit;

namespace Keryx.Sdp.Tests;

public class SimulcastMediaDescriptionTests
{
    [Fact]
    public void AddRid_And_GetRids_RoundTrip()
    {
        var media = new MediaDescription("video", 9, SdpMediaOffer.RtpProtocol, "96");
        media.AddRid(new SdpRid("hi", RidDirection.Send, new[] { new SdpRidRestriction("max-width", "1280") }));
        media.AddRid(new SdpRid("lo", RidDirection.Send));

        var rids = media.GetRids();
        rids.Should().HaveCount(2);
        rids[0].Id.Should().Be("hi");
        rids[1].Id.Should().Be("lo");
    }

    [Fact]
    public void Simulcast_SetAndGet_RoundTrip()
    {
        var media = new MediaDescription("video", 9, SdpMediaOffer.RtpProtocol, "96")
        {
            Simulcast = SdpSimulcast.SendOnly(
                new SdpSimulcastStream("hi"),
                new SdpSimulcastStream("lo")),
        };

        media.Simulcast.Should().NotBeNull();
        media.Simulcast!.Send.Should().HaveCount(2);

        media.Simulcast = null;
        media.Simulcast.Should().BeNull();
        media.HasAttribute(SdpAttributeNames.Simulcast).Should().BeFalse();
    }

    [Fact]
    public void OfferBuilder_EmitsRidAndSimulcastLines()
    {
        var offer = SdpMediaOffer.Video("0", new SdpCodec(96, "H264", 90000));
        offer.HeaderExtensions.Add(new SdpExtMap(2, RtpHeaderExtensionUri.Rid, MediaDirection.SendOnly));
        offer.Rids.Add(new SdpRid("hi", RidDirection.Send));
        offer.Rids.Add(new SdpRid("lo", RidDirection.Send));
        offer.Simulcast = SdpSimulcast.SendOnly(new SdpSimulcastStream("hi"), new SdpSimulcastStream("lo"));

        var builder = new SdpOfferBuilder
        {
            IceCredentials = new SdpIceCredentials("ufrag", "a-very-long-ice-password-value"),
            Fingerprint = new SdpFingerprint("sha-256", "00:11:22:33:44:55:66:77"),
        };
        builder.AddMedia(offer);

        var media = builder.Build().MediaDescriptions.Should().ContainSingle().Subject;
        media.GetRids().Should().HaveCount(2);
        media.Simulcast!.Send.Should().HaveCount(2);
        media.GetExtMaps().Should().Contain(e => e.Uri == RtpHeaderExtensionUri.Rid);

        var text = media.ToSdpString();
        text.Should().Contain("a=rid:hi send");
        text.Should().Contain("a=simulcast:send hi;lo");
    }
}
