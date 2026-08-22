using System.Net;
using FluentAssertions;
using Xunit;

namespace Keryx.Ice.Tests;

/// <summary>The RFC 8445 candidate (section 5.1.2.1) and pair (section 6.1.2.3) priority formulas.</summary>
public sealed class IcePriorityTests
{
    [Fact]
    public void Compute_UsesTheRecommendedTypePreferences()
    {
        IcePriority.TypePreference(IceCandidateType.Host).Should().Be(126);
        IcePriority.TypePreference(IceCandidateType.PeerReflexive).Should().Be(110);
        IcePriority.TypePreference(IceCandidateType.ServerReflexive).Should().Be(100);
        IcePriority.TypePreference(IceCandidateType.Relayed).Should().Be(0);
    }

    [Fact]
    public void Compute_MatchesTheFormulaAtTheTopOfTheLocalPreferenceRange()
    {
        // 2^24 * 126 + 2^8 * 65535 + (256 - 1)
        IcePriority.Compute(IceCandidateType.Host).Should().Be(2130706431u);
        IcePriority.Compute(IceCandidateType.PeerReflexive).Should().Be(1862270975u);
    }

    [Fact]
    public void Compute_ReproducesRealChromeCandidatePriorities()
    {
        // From "candidate:2905311565 1 udp 2122260223 192.168.1.7 61042 typ host generation 0".
        IcePriority.Compute(IceCandidateType.Host, 32542).Should().Be(2122260223u);

        // From "candidate:842163049 1 udp 1677729535 203.0.113.5 51772 typ srflx ...".
        IcePriority.Compute(IceCandidateType.ServerReflexive, 30).Should().Be(1677729535u);
    }

    [Fact]
    public void Compute_LowersPriorityForHigherComponentIds()
    {
        IcePriority.Compute(IceCandidateType.Host, 65535, 1)
            .Should().Be(IcePriority.Compute(IceCandidateType.Host, 65535, 2) + 1);
    }

    [Fact]
    public void Compute_RejectsOutOfRangeInputs()
    {
        var localPreference = () => IcePriority.Compute(IceCandidateType.Host, 65536);
        var component = () => IcePriority.Compute(IceCandidateType.Host, 0, 0);

        localPreference.Should().Throw<ArgumentOutOfRangeException>();
        component.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void ComputePair_MatchesTheRfc8445Formula()
    {
        const uint host = 2122260223u;
        const uint srflx = 1677729535u;

        // 2^32 * MIN(G,D) + 2 * MAX(G,D) + (G > D ? 1 : 0)
        IcePriority.ComputePair(host, srflx).Should().Be(7205793488602807807ul);
        IcePriority.ComputePair(srflx, host).Should().Be(7205793488602807806ul);
        IcePriority.ComputePair(2130706431u, 2130706431u).Should().Be(9151314442783293438ul);
    }

    [Fact]
    public void ComputePair_TieBreaksTowardsTheControllingAgent()
    {
        IcePriority.ComputePair(100, 50).Should().Be(IcePriority.ComputePair(50, 100) + 1);
    }

    [Fact]
    public void CandidatePair_ComputesPriorityFromTheAgentRole()
    {
        var local = IceCandidate.Parse("candidate:1 1 udp 2122260223 192.168.1.7 61042 typ host");
        var remote = IceCandidate.Parse("candidate:2 1 udp 1677729535 203.0.113.5 51772 typ srflx");

        var controlling = new IceCandidatePair(local, remote, IceRole.Controlling);
        var controlled = new IceCandidatePair(local, remote, IceRole.Controlled);

        controlling.Priority.Should().Be(IcePriority.ComputePair(local.Priority, remote.Priority));
        controlled.Priority.Should().Be(IcePriority.ComputePair(remote.Priority, local.Priority));
        controlling.Priority.Should().Be(controlled.Priority + 1);

        controlling.State.Should().Be(IceCandidatePairState.Waiting);
        controlling.Nominated.Should().BeFalse();
        controlling.RemoteEndPoint.Should().Be(new IPEndPoint(IPAddress.Parse("203.0.113.5"), 51772));
    }

    [Fact]
    public void Credentials_AreIceCharsOfTheRequiredLength()
    {
        var ufrag = IceCredentials.NewUfrag();
        var password = IceCredentials.NewPassword();

        ufrag.Length.Should().BeGreaterThanOrEqualTo(4);
        password.Length.Should().BeGreaterThanOrEqualTo(22);
        ufrag.Should().MatchRegex("^[A-Za-z0-9+/]+$");
        password.Should().MatchRegex("^[A-Za-z0-9+/]+$");
        IceCredentials.NewUfrag().Should().NotBe(ufrag);

        var tooShort = () => IceCredentials.NewPassword(4);
        tooShort.Should().Throw<ArgumentOutOfRangeException>();
    }
}
