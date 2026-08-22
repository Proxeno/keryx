using FluentAssertions;
using Xunit;

namespace Keryx.Sdp.Tests;

public class SdpParserTests
{
    [Fact]
    public void Parse_ReadsSessionLevelFields()
    {
        var sdp = SessionDescription.Parse(SdpTestData.ChromeOffer);

        sdp.Version.Should().Be(0);
        sdp.Origin.Username.Should().Be("-");
        sdp.Origin.SessionId.Should().Be("4611731400430051336");
        sdp.Origin.SessionVersion.Should().Be("2");
        sdp.Origin.NetworkType.Should().Be("IN");
        sdp.Origin.AddressType.Should().Be("IP4");
        sdp.Origin.UnicastAddress.Should().Be("127.0.0.1");
        sdp.SessionName.Should().Be("-");
        sdp.Timings.Should().ContainSingle();
        sdp.Timings[0].Start.Should().Be("0");
        sdp.Timings[0].Stop.Should().Be("0");
    }

    [Fact]
    public void Parse_ReadsAllMediaSectionsInOrder()
    {
        var sdp = SessionDescription.Parse(SdpTestData.ChromeOffer);

        sdp.MediaDescriptions.Should().HaveCount(3);
        sdp.MediaDescriptions.Select(m => m.Media).Should().Equal("audio", "video", "application");
        sdp.GetMids().Should().Equal("0", "1", "2");
    }

    [Fact]
    public void Parse_ReadsMediaLineFields()
    {
        var video = SessionDescription.Parse(SdpTestData.ChromeOffer).MediaDescriptions[1];

        video.Media.Should().Be("video");
        video.Port.Should().Be(9);
        video.PortCount.Should().BeNull();
        video.Protocol.Should().Be("UDP/TLS/RTP/SAVPF");
        video.Formats.Should().Equal("96", "97", "102", "103");
        video.GetPayloadTypes().Should().Equal(96, 97, 102, 103);
        video.IsRtp.Should().BeTrue();
        video.IsRejected.Should().BeFalse();
    }

    [Fact]
    public void Parse_ReadsPerMediaConnectionAndBandwidth()
    {
        var sdp = SessionDescription.Parse(SdpTestData.ChromeOffer);

        sdp.Connection.Should().BeNull();
        sdp.MediaDescriptions[1].Connection.Should().Be(new SdpConnection("IN", "IP4", "0.0.0.0"));
        sdp.MediaDescriptions[1].Bandwidths.Should().Equal("AS:2000");
        sdp.MediaDescriptions[0].Bandwidths.Should().BeEmpty();
    }

    [Fact]
    public void Parse_PreservesAttributeOrderWithinASection()
    {
        var audio = SessionDescription.Parse(SdpTestData.ChromeOffer).MediaDescriptions[0];

        audio.Attributes.Take(8).Select(a => a.Name).Should().Equal(
            "rtcp", "ice-ufrag", "ice-pwd", "ice-options", "fingerprint", "setup", "mid", "extmap");
    }

    [Fact]
    public void Parse_PreservesUnknownAttributesVerbatim()
    {
        const string body = """
            v=0
            o=- 1 2 IN IP4 127.0.0.1
            s=-
            t=0 0
            a=x-vendor-thing:keep me exactly as-is
            m=audio 9 UDP/TLS/RTP/SAVPF 111
            a=x-flag
            """;

        var sdp = SessionDescription.Parse(SdpTestData.Crlf(body));

        sdp.FindAttribute("x-vendor-thing")!.Value.Should().Be("keep me exactly as-is");
        sdp.MediaDescriptions[0].FindAttribute("x-flag")!.IsFlag.Should().BeTrue();
    }

    [Fact]
    public void Parse_AcceptsBareLfLineEndings()
    {
        var fromLf = SessionDescription.Parse(SdpTestData.ChromeAnswerLf);
        var fromCrlf = SessionDescription.Parse(SdpTestData.ChromeAnswer);

        fromLf.ToSdpString().Should().Be(fromCrlf.ToSdpString());
    }

    [Fact]
    public void Parse_IgnoresGarbageLines()
    {
        const string body = """
            v=0
            this line is not sdp at all
            o=- 1 2 IN IP4 127.0.0.1

            =
            s=-
            t=0 0
            m=audio 9 UDP/TLS/RTP/SAVPF 111
            !
            a=mid:0
            """;

        var sdp = SessionDescription.Parse(SdpTestData.Crlf(body));

        sdp.Origin.SessionId.Should().Be("1");
        sdp.MediaDescriptions.Should().ContainSingle();
        sdp.MediaDescriptions[0].Mid.Should().Be("0");
    }

    [Fact]
    public void Parse_KeepsUnknownLineTypes()
    {
        const string body = """
            v=0
            o=- 1 2 IN IP4 127.0.0.1
            s=-
            t=0 0
            x=some future line
            m=audio 9 UDP/TLS/RTP/SAVPF 111
            """;

        var sdp = SessionDescription.Parse(SdpTestData.Crlf(body));

        sdp.UnknownLines.Should().Equal("x=some future line");
        sdp.ToSdpString().Should().Contain("x=some future line\r\n");
    }

    [Fact]
    public void Parse_EmptyString_ProducesDefaultDescription()
    {
        var sdp = SessionDescription.Parse(string.Empty);

        sdp.MediaDescriptions.Should().BeEmpty();
        sdp.Attributes.Should().BeEmpty();
        sdp.Origin.Should().Be(SdpOrigin.Default);
        sdp.ToSdpString().Should().Be("v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n");
    }

    [Fact]
    public void Parse_Null_Throws()
    {
        var parse = () => SessionDescription.Parse(null!);

        parse.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Parse_RejectedMediaSectionHasPortZero()
    {
        const string body = """
            v=0
            o=- 1 2 IN IP4 127.0.0.1
            s=-
            t=0 0
            m=video 0 UDP/TLS/RTP/SAVPF 96
            a=mid:1
            """;

        var media = SessionDescription.Parse(SdpTestData.Crlf(body)).MediaDescriptions[0];

        media.Port.Should().Be(0);
        media.IsRejected.Should().BeTrue();
    }

    [Fact]
    public void Parse_MediaLineWithPortCount()
    {
        const string body = """
            v=0
            o=- 1 2 IN IP4 127.0.0.1
            s=-
            t=0 0
            m=audio 49170/2 RTP/AVP 0
            """;

        var media = SessionDescription.Parse(SdpTestData.Crlf(body)).MediaDescriptions[0];

        media.Port.Should().Be(49170);
        media.PortCount.Should().Be(2);
        media.ToMediaLineValue().Should().Be("audio 49170/2 RTP/AVP 0");
    }

    [Fact]
    public void Parse_RepeatLineAttachesToPrecedingTiming()
    {
        const string body = """
            v=0
            o=- 1 2 IN IP4 127.0.0.1
            s=-
            t=3034423619 3042462419
            r=604800 3600 0 90000
            """;

        var sdp = SessionDescription.Parse(SdpTestData.Crlf(body));

        sdp.Timings.Should().ContainSingle();
        sdp.Timings[0].RepeatTimes.Should().Equal("604800 3600 0 90000");
    }

    [Fact]
    public void Parse_SessionLevelOptionalLines()
    {
        const string body = """
            v=0
            o=- 1 2 IN IP4 127.0.0.1
            s=A session
            i=Some info
            u=http://example.invalid/
            e=nobody@example.invalid
            p=+1 555 0100
            c=IN IP4 224.2.1.1/127
            b=AS:64
            t=0 0
            """;

        var sdp = SessionDescription.Parse(SdpTestData.Crlf(body));

        sdp.SessionName.Should().Be("A session");
        sdp.Information.Should().Be("Some info");
        sdp.Uri.Should().Be("http://example.invalid/");
        sdp.Emails.Should().Equal("nobody@example.invalid");
        sdp.PhoneNumbers.Should().Equal("+1 555 0100");
        sdp.Connection!.Address.Should().Be("224.2.1.1/127");
        sdp.Bandwidths.Should().Equal("AS:64");
    }
}
