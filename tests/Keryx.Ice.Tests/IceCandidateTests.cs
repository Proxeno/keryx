using System.Net;
using FluentAssertions;
using Xunit;

namespace Keryx.Ice.Tests;

/// <summary>
/// Parsing and formatting of the SDP <c>candidate</c> attribute (RFC 8839 section 5.1), checked
/// against candidate strings taken verbatim from Chrome.
/// </summary>
public sealed class IceCandidateTests
{
    [Theory]
    [InlineData("candidate:2905311565 1 udp 2122260223 192.168.1.7 61042 typ host generation 0")]
    [InlineData("candidate:842163049 1 udp 1677729535 203.0.113.5 51772 typ srflx raddr 192.168.1.7 rport 61042 generation 0 ufrag Jhc7 network-id 1 network-cost 10")]
    [InlineData("candidate:3593525017 1 udp 41885439 198.51.100.20 62134 typ relay raddr 203.0.113.5 rport 51772 generation 0 ufrag Jhc7 network-id 1")]
    [InlineData("candidate:1510613869 1 tcp 1518280447 192.168.1.7 9 typ host tcptype active generation 0 ufrag Jhc7 network-id 1")]
    [InlineData("candidate:1673975443 1 udp 2130706431 ::1 40678 typ host generation 0")]
    [InlineData("candidate:1 1 udp 2130706431 127.0.0.1 7900 typ host")]
    public void ChromeCandidateStrings_RoundTripExactly(string attribute)
    {
        var candidate = IceCandidate.Parse(attribute);

        candidate.ToAttributeString().Should().Be(attribute);
        candidate.ToString().Should().Be(attribute);
        candidate.ToValueString().Should().Be(attribute["candidate:".Length..]);
        candidate.ToSdpLine().Should().Be("a=" + attribute);
    }

    [Fact]
    public void Parse_ReadsEveryFieldOfAHostCandidate()
    {
        var candidate = IceCandidate.Parse(
            "candidate:2905311565 1 udp 2122260223 192.168.1.7 61042 typ host generation 0");

        candidate.Foundation.Should().Be("2905311565");
        candidate.Component.Should().Be(1);
        candidate.Transport.Should().Be("udp");
        candidate.IsUdp.Should().BeTrue();
        candidate.Priority.Should().Be(2122260223u);
        candidate.Address.Should().Be(IPAddress.Parse("192.168.1.7"));
        candidate.Port.Should().Be(61042);
        candidate.EndPoint.Should().Be(new IPEndPoint(IPAddress.Parse("192.168.1.7"), 61042));
        candidate.Type.Should().Be(IceCandidateType.Host);
        candidate.RelatedAddress.Should().BeNull();
        candidate.RelatedPort.Should().BeNull();
        candidate.Extensions.Should().Equal(new[] { new KeyValuePair<string, string>("generation", "0") });
    }

    [Fact]
    public void Parse_ReadsRaddrAndRportAndKeepsUnknownExtensionsInOrder()
    {
        var candidate = IceCandidate.Parse(
            "candidate:842163049 1 udp 1677729535 203.0.113.5 51772 typ srflx raddr 192.168.1.7 rport 61042 generation 0 ufrag Jhc7 network-id 1 network-cost 10");

        candidate.Type.Should().Be(IceCandidateType.ServerReflexive);
        candidate.RelatedAddress.Should().Be(IPAddress.Parse("192.168.1.7"));
        candidate.RelatedPort.Should().Be(61042);
        candidate.Extensions.Select(e => e.Key).Should().Equal("generation", "ufrag", "network-id", "network-cost");
        candidate.Extensions.Select(e => e.Value).Should().Equal("0", "Jhc7", "1", "10");
    }

    [Theory]
    [InlineData("a=candidate:1 1 udp 2130706431 127.0.0.1 7900 typ host")]
    [InlineData("1 1 udp 2130706431 127.0.0.1 7900 typ host")]
    [InlineData("  candidate:1 1 UDP 2130706431 127.0.0.1 7900 TYP HOST  ")]
    public void Parse_ToleratesTheOptionalPrefixesAndCasing(string attribute)
    {
        var candidate = IceCandidate.Parse(attribute);

        candidate.Type.Should().Be(IceCandidateType.Host);
        candidate.IsUdp.Should().BeTrue();
        candidate.EndPoint.Should().Be(new IPEndPoint(IPAddress.Loopback, 7900));
    }

    [Fact]
    public void Parse_KeepsTheTransportTokenVerbatimSoUppercaseRoundTrips()
    {
        var candidate = IceCandidate.Parse("candidate:1 1 UDP 2130706431 127.0.0.1 7900 typ host");

        candidate.Transport.Should().Be("UDP");
        candidate.IsUdp.Should().BeTrue();
        candidate.ToAttributeString().Should().Be("candidate:1 1 UDP 2130706431 127.0.0.1 7900 typ host");
    }

    [Fact]
    public void Parse_IgnoresATrailingExtensionNameWithNoValue()
    {
        var candidate = IceCandidate.Parse("candidate:1 1 udp 2130706431 127.0.0.1 7900 typ host generation");

        candidate.Extensions.Should().BeEmpty();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("candidate:1 1 udp 2130706431 127.0.0.1 7900")]
    [InlineData("candidate:1 1 udp 2130706431 127.0.0.1 7900 nottyp host")]
    [InlineData("candidate:1 1 udp 2130706431 not-an-address 7900 typ host")]
    [InlineData("candidate:1 1 udp 2130706431 127.0.0.1 99999 typ host")]
    [InlineData("candidate:1 1 udp 2130706431 127.0.0.1 7900 typ bogus")]
    [InlineData("candidate:1 0 udp 2130706431 127.0.0.1 7900 typ host")]
    [InlineData("candidate:1 1 udp -5 127.0.0.1 7900 typ host")]
    public void TryParse_RejectsMalformedAttributes(string? attribute)
    {
        IceCandidate.TryParse(attribute, out var candidate).Should().BeFalse();
        candidate.Should().BeNull();
    }

    [Fact]
    public void Parse_ThrowsFormatExceptionOnGarbage()
    {
        var act = () => IceCandidate.Parse("not a candidate");

        act.Should().Throw<FormatException>();
    }

    [Fact]
    public void Equality_IgnoresFoundationPriorityAndExtensions()
    {
        var a = IceCandidate.Parse("candidate:1 1 udp 2130706431 127.0.0.1 7900 typ host generation 0");
        var b = IceCandidate.Parse("candidate:999 1 UDP 12345 127.0.0.1 7900 typ host");
        var different = IceCandidate.Parse("candidate:1 1 udp 2130706431 127.0.0.1 7901 typ host");

        a.Should().Be(b);
        a.GetHashCode().Should().Be(b.GetHashCode());
        a.Should().NotBe(different);
    }

    [Fact]
    public void TryParse_RejectsAnMdnsHostCandidateBecauseTheAddressIsNotAnIP()
    {
        // The whole reason .local candidates need separate handling: the address token is a host
        // name, so the normal parser cannot accept it.
        IceCandidate.TryParse(
            "candidate:1 1 udp 2130706431 3f4a1c9e-2b6d-4e11-9a7c-1d2e3f4a5b6c.local 50000 typ host",
            out var candidate).Should().BeFalse();
        candidate.Should().BeNull();
    }

    [Fact]
    public void TryParseMdnsCandidate_RecognisesALocalHostCandidateAndRebuildsItOnResolution()
    {
        IceCandidate.TryParseMdnsCandidate(
            "a=candidate:1 1 udp 2130706431 3f4a1c9e-2b6d-4e11-9a7c-1d2e3f4a5b6c.local 50000 typ host generation 0",
            out var hostName,
            out var resolve).Should().BeTrue();

        hostName.Should().Be("3f4a1c9e-2b6d-4e11-9a7c-1d2e3f4a5b6c.local");

        var resolved = resolve!(IPAddress.Parse("192.168.1.42"));
        resolved.Type.Should().Be(IceCandidateType.Host);
        resolved.Foundation.Should().Be("1");
        resolved.Priority.Should().Be(2130706431u);
        resolved.Address.Should().Be(IPAddress.Parse("192.168.1.42"));
        resolved.EndPoint.Should().Be(new IPEndPoint(IPAddress.Parse("192.168.1.42"), 50000));
        resolved.Extensions.Should().Equal(new[] { new KeyValuePair<string, string>("generation", "0") });
    }

    [Theory]
    [InlineData("candidate:1 1 udp 2130706431 192.168.1.7 50000 typ host")]
    [InlineData("candidate:1 1 udp 2130706431 ::1 50000 typ host")]
    [InlineData(".local 1 udp 2130706431 192.168.1.7 50000 typ host")]
    [InlineData("candidate:1 1 udp 2130706431 192.168.1.7 99999 typ host")]
    [InlineData("not a candidate")]
    [InlineData(null)]
    public void TryParseMdnsCandidate_RejectsNonMdnsOrMalformedAttributes(string? attribute)
    {
        IceCandidate.TryParseMdnsCandidate(attribute, out var hostName, out var resolve).Should().BeFalse();
        hostName.Should().BeNull();
        resolve.Should().BeNull();
    }

    [Fact]
    public void TypeToken_MatchesTheSdpSpelling()
    {
        IceCandidate.TypeToken(IceCandidateType.Host).Should().Be("host");
        IceCandidate.TypeToken(IceCandidateType.ServerReflexive).Should().Be("srflx");
        IceCandidate.TypeToken(IceCandidateType.PeerReflexive).Should().Be("prflx");
        IceCandidate.TypeToken(IceCandidateType.Relayed).Should().Be("relay");
    }
}
