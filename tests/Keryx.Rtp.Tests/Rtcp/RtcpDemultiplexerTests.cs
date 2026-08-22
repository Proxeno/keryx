using FluentAssertions;
using Keryx.Rtp.Rtcp;
using Xunit;

namespace Keryx.Rtp.Tests.Rtcp;

/// <summary>Coverage for the rtcp-mux demultiplexing rule of RFC 5761 §4.</summary>
public class RtcpDemultiplexerTests
{
    [Theory]
    [InlineData(200)] // SR
    [InlineData(201)] // RR
    [InlineData(202)] // SDES
    [InlineData(203)] // BYE
    [InlineData(204)] // APP
    [InlineData(205)] // RTPFB
    [InlineData(206)] // PSFB
    [InlineData(207)] // XR
    [InlineData(192)] // low edge of the reserved range
    [InlineData(223)] // high edge of the reserved range
    public void Classifies_the_reserved_range_as_rtcp(byte secondOctet)
    {
        RtcpDemultiplexer.IsRtcp([0x80, secondOctet, 0, 0]).Should().BeTrue();
    }

    [Theory]
    [InlineData(0x60)]  // M=0, PT=96
    [InlineData(0xE0)]  // M=1, PT=96 — just above the reserved range
    [InlineData(0x6F)]  // M=0, PT=111 (Opus)
    [InlineData(0xEF)]  // M=1, PT=111
    [InlineData(0x00)]  // M=0, PT=0  (PCMU)
    [InlineData(0x08)]  // M=0, PT=8  (PCMA)
    [InlineData(191)]   // just below the reserved range
    public void Classifies_everything_else_as_rtp(byte secondOctet)
    {
        var datagram = new byte[12];
        datagram[0] = 0x80;
        datagram[1] = secondOctet;
        RtcpDemultiplexer.IsRtcp(datagram).Should().BeFalse();
        RtcpDemultiplexer.IsRtp(datagram).Should().BeTrue();
    }

    [Fact]
    public void A_one_octet_datagram_is_neither()
    {
        RtcpDemultiplexer.IsRtcp([0x80]).Should().BeFalse();
        RtcpDemultiplexer.IsRtp([0x80]).Should().BeFalse();
    }
}
