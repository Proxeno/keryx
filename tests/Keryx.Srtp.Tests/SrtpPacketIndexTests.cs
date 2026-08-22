using FluentAssertions;
using Xunit;

namespace Keryx.Srtp.Tests;

/// <summary>The index estimation pseudocode of RFC 3711 Appendix A and the update rules of Section 3.3.1.</summary>
public class SrtpPacketIndexTests
{
    [Fact]
    public void Compose_BuildsThe48BitIndex()
    {
        SrtpPacketIndex.Compose(0, 0).Should().Be(0UL);
        SrtpPacketIndex.Compose(0, 65535).Should().Be(65535UL);
        SrtpPacketIndex.Compose(1, 0).Should().Be(65536UL);
        SrtpPacketIndex.Compose(0xFFFF_FFFF, 0xFFFF).Should().Be(0xFFFF_FFFF_FFFFUL);
    }

    /// <summary>
    /// RFC 3711 Appendix A:
    /// <code>
    /// if (s_l &lt; 32,768)
    ///    if (SEQ - s_l &gt; 32,768) set v to (ROC-1) mod 2^32 else set v to ROC
    /// else
    ///    if (s_l - 32,768 &gt; SEQ)  set v to (ROC+1) mod 2^32 else set v to ROC
    /// </code>
    /// </summary>
    [Theory]
    // s_l < 32768, in-order packet: stay on the current ROC.
    [InlineData(5u, (ushort)100, (ushort)101, 5u)]
    [InlineData(5u, (ushort)100, (ushort)99, 5u)]
    [InlineData(5u, (ushort)0, (ushort)32768, 5u)]
    // s_l < 32768, packet far ahead: it is really a straggler from the previous period.
    [InlineData(5u, (ushort)0, (ushort)32769, 4u)]
    [InlineData(5u, (ushort)1, (ushort)65535, 4u)]
    // s_l >= 32768, in-order packet.
    [InlineData(5u, (ushort)40000, (ushort)40001, 5u)]
    [InlineData(5u, (ushort)65535, (ushort)32768, 5u)]
    // s_l >= 32768, packet far behind: the sequence number has wrapped.
    [InlineData(5u, (ushort)65535, (ushort)0, 6u)]
    [InlineData(5u, (ushort)65535, (ushort)32766, 6u)]
    [InlineData(5u, (ushort)32769, (ushort)0, 6u)]
    public void EstimateRolloverCounter_FollowsAppendixA(
        uint rolloverCounter,
        ushort highestSequence,
        ushort sequenceNumber,
        uint expected)
    {
        SrtpPacketIndex.EstimateRolloverCounter(rolloverCounter, highestSequence, sequenceNumber)
            .Should().Be(expected);
    }

    /// <summary>
    /// The one deliberate deviation from the literal pseudocode: an SRTP stream has no packets
    /// before ROC 0, so "ROC - 1" is clamped instead of wrapping to 2^32-1 and producing an index
    /// near 2^48.
    /// </summary>
    [Fact]
    public void EstimateRolloverCounter_ClampsBelowZero()
    {
        SrtpPacketIndex.EstimateRolloverCounter(0, highestSequence: 1, sequenceNumber: 65535).Should().Be(0u);
    }

    [Fact]
    public void EstimateRolloverCounter_WrapsPastMaxRoc()
    {
        SrtpPacketIndex.EstimateRolloverCounter(0xFFFF_FFFF, highestSequence: 65535, sequenceNumber: 0)
            .Should().Be(0u);
    }

    /// <summary>
    /// RFC 3711 Section 3.3.1: "the receiver SHALL initialize s_l to the RTP sequence number (SEQ)
    /// of the first observed SRTP packet".
    /// </summary>
    [Fact]
    public void FirstPacket_InitialisesHighestSequenceWithoutChangingTheRoc()
    {
        var state = new SrtpStreamState(0x1234);
        state.RolloverCounter.Should().Be(0u);

        const ushort first = 60000;
        var candidate = state.EstimateRolloverCounter(first);
        candidate.Should().Be(0u);

        state.Commit(candidate, first);
        state.RolloverCounter.Should().Be(0u);
        state.HighestSequence.Should().Be(first);
    }

    /// <summary>
    /// RFC 3711 Section 3.3.1: "If v=(ROC-1) mod 2^32, then there is no update to s_l or ROC. If
    /// v=ROC, then s_l is set to SEQ if and only if SEQ is larger than the current s_l. If
    /// v=(ROC+1) mod 2^32, then s_l is set to SEQ and ROC is set to v."
    /// </summary>
    [Fact]
    public void Commit_AppliesTheSection331UpdateRules()
    {
        var state = new SrtpStreamState(1);
        state.Commit(state.EstimateRolloverCounter(65534), 65534);
        state.RolloverCounter.Should().Be(0u);
        state.HighestSequence.Should().Be((ushort)65534);

        // v = ROC and SEQ > s_l: s_l advances.
        state.Commit(state.EstimateRolloverCounter(65535), 65535);
        state.RolloverCounter.Should().Be(0u);
        state.HighestSequence.Should().Be((ushort)65535);

        // v = ROC + 1: the counter rolls over and s_l follows the packet.
        var wrapCandidate = state.EstimateRolloverCounter(0);
        wrapCandidate.Should().Be(1u);
        state.Commit(wrapCandidate, 0);
        state.RolloverCounter.Should().Be(1u);
        state.HighestSequence.Should().Be((ushort)0);

        // v = ROC - 1: a straggler from before the wrap leaves both values alone.
        var stragglerCandidate = state.EstimateRolloverCounter(65535);
        stragglerCandidate.Should().Be(0u);
        state.Commit(stragglerCandidate, 65535);
        state.RolloverCounter.Should().Be(1u);
        state.HighestSequence.Should().Be((ushort)0);

        // v = ROC but SEQ < s_l: no change.
        state.Commit(state.EstimateRolloverCounter(5), 5);
        state.HighestSequence.Should().Be((ushort)5);
        state.Commit(state.EstimateRolloverCounter(3), 3);
        state.HighestSequence.Should().Be((ushort)5);
        state.RolloverCounter.Should().Be(1u);
    }
}

/// <summary>The sliding-window Replay List of RFC 3711 Section 3.3.2.</summary>
public class SrtpReplayWindowTests
{
    [Fact]
    public void WindowIsAtLeastTheRequiredSixtyFourEntries()
    {
        SrtpReplayWindow.WindowSize.Should().BeGreaterThanOrEqualTo(64);
    }

    [Fact]
    public void FirstPacketIsAlwaysAccepted()
    {
        var window = default(SrtpReplayWindow);
        window.IsAcceptable(0).Should().BeTrue();
        window.IsAcceptable(1_000_000).Should().BeTrue();
    }

    [Fact]
    public void CheckDoesNotMutateState()
    {
        var window = default(SrtpReplayWindow);
        window.IsAcceptable(10).Should().BeTrue();
        window.IsAcceptable(10).Should().BeTrue();

        window.Commit(10);
        window.IsAcceptable(10).Should().BeFalse();
    }

    [Fact]
    public void PacketsAheadOfTheWindowAreAccepted()
    {
        var window = default(SrtpReplayWindow);
        window.Commit(100);
        window.Highest.Should().Be(100UL);

        window.IsAcceptable(101).Should().BeTrue();
        window.Commit(101);
        window.IsAcceptable(1000).Should().BeTrue();
        window.Commit(1000);
        window.Highest.Should().Be(1000UL);

        // A jump larger than the window clears the history. Indices in the gap were genuinely never
        // received, so they are still acceptable while they remain inside the window.
        window.IsAcceptable(999).Should().BeTrue();
        window.IsAcceptable(1000).Should().BeFalse();
        window.IsAcceptable(1000 - SrtpReplayWindow.WindowSize).Should().BeFalse();
    }

    [Fact]
    public void PacketsInsideTheWindowAreAcceptedOnceEach()
    {
        var window = default(SrtpReplayWindow);
        window.Commit(200);

        for (ulong index = 199; index > 200 - SrtpReplayWindow.WindowSize; index--)
        {
            window.IsAcceptable(index).Should().BeTrue();
            window.Commit(index);
            window.IsAcceptable(index).Should().BeFalse();
        }
    }

    [Fact]
    public void PacketsOlderThanTheWindowAreRejected()
    {
        var window = default(SrtpReplayWindow);
        window.Commit(500);

        window.IsAcceptable(500 - SrtpReplayWindow.WindowSize + 1).Should().BeTrue();
        window.IsAcceptable(500 - SrtpReplayWindow.WindowSize).Should().BeFalse();
        window.IsAcceptable(0).Should().BeFalse();
    }

    [Fact]
    public void SlidingForwardForgetsIndicesThatFallOutOfTheWindow()
    {
        var window = default(SrtpReplayWindow);
        window.Commit(0);
        window.Commit(1);

        window.Commit(SrtpReplayWindow.WindowSize + 1);
        window.IsAcceptable(1).Should().BeFalse("index 1 is now outside the window and assumed received");
        window.IsAcceptable(SrtpReplayWindow.WindowSize).Should().BeTrue();
    }
}
