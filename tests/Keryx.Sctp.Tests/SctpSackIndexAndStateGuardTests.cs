using System.Diagnostics;
using FluentAssertions;
using Keryx.Sctp;
using Xunit;

namespace Keryx.Sctp.Tests;

/// <summary>
/// Adversarial tests for two SCTP hardening measures beyond PR #46:
/// <list type="bullet">
/// <item>
/// A TSN-&gt;outstanding-chunk index so cumulative-ack, gap-ack and fast-retransmit processing resolve
/// a chunk in O(1) instead of scanning the whole retransmission queue. A peer that grows a large
/// outbound backlog and then floods overlapping in-window gap-ack blocks must not be able to force
/// O(blocks x window x _out) work; the SACK must be processed in bounded time and acknowledge exactly
/// the outstanding chunks it names.
/// </item>
/// <item>
/// State guards so FORWARD TSN and SHUTDOWN are honoured only once the association is up. A peer that
/// learned our verification tag from our INIT must not be able to drive receive-side or shutdown
/// state churn while we are still in CookieWait/CookieEchoed.
/// </item>
/// </list>
/// </summary>
public class SctpSackIndexAndStateGuardTests
{
    // ---------------------------------------------------------------- Finding 1

    [Fact]
    public void GapAckFloodAgainstLargeBacklogIsProcessedInBoundedTimeAndAcksTheRightChunks()
    {
        // A large outbound backlog: many single-chunk messages queued before the handshake completes,
        // so a single flush at Establish transmits them all. The peer is a silent injector that never
        // acknowledges anything, so the whole backlog stays transmitted-but-outstanding and the peer
        // cumulative ack stays pinned at its initial value — exactly the state an attacker needs.
        const int backlog = 64_000;

        // A large MTU makes the initial congestion window big enough to put the whole backlog in flight
        // in one flush; a large advertised peer window keeps flow control from throttling it.
        var (injectorTransport, victimTransport) = LoopbackTransport.CreatePair();
        victimTransport.MaxDatagramSize = 1 << 20;
        var victim = new SctpAssociation(victimTransport, Config(isInitiator: true, usesEvenStreamIds: true, receiveWindow: 16u * 1024 * 1024));

        try
        {
            // Queue the backlog before the association exists. While the state is Closed a send only
            // enqueues (Flush is a no-op), so building the backlog is O(backlog), not O(n^2).
            victim.Start();
            var channel = victim.CreateChannel("bulk");
            var payload = new byte[] { 0x5a };
            for (var i = 0; i < backlog; i++)
            {
                channel.Send(payload);
            }

            // Drive the initiator to Established with crafted INIT ACK + COOKIE ACK (the initiator does
            // not validate the cookie it echoed). On Establish the victim flushes the whole backlog to
            // the injector, which has no association listening, so nothing is ever acknowledged.
            _ = victim.ConnectAsync().ContinueWith(t => _ = t.Exception, TaskScheduler.Default);
            WaitFor(() => victim.State == SctpAssociationState.CookieWait).Should().BeTrue();
            InjectInitAck(injectorTransport, victim.LocalVerificationTag, peerTag: 0x2222_2222u, peerInitialTsn: 1000u, advertisedWindow: 16u * 1024 * 1024);
            WaitFor(() => victim.State == SctpAssociationState.CookieEchoed).Should().BeTrue();
            InjectCookieAck(injectorTransport, victim.LocalVerificationTag);

            WaitFor(() => victim.State == SctpAssociationState.Established).Should().BeTrue();
            WaitFor(() => victim.GetStatistics().BytesInFlight > 0
                          && victim.GetStatistics().QueuedChunks >= backlog).Should().BeTrue();

            var before = victim.GetStatistics();
            before.BytesInFlight.Should().BeGreaterThan(0);
            var window = before.QueuedChunks; // every queued chunk was transmitted, so offsets 1..window are in range.

            // A SACK that advances nothing cumulatively (its cumulative ack equals the peer ack point we
            // already hold) but gap-acks the entire in-window range as many overlapping blocks — the
            // whole tiling repeated several times, the "many overlapping in-window gap-ack blocks" of the
            // finding. Before the index each offset drove an O(_out) FindChunk scan of the backlog under
            // the association lock, so the whole SACK cost O(passes x window x _out) and stalled the
            // endpoint; with the TSN index each offset is an O(1) lookup.
            var blocks = TileGapBlocks(window, stepOffsets: 2000, passes: 12);
            blocks.Count.Should().BeGreaterThan(100, "the flood is deliberately many overlapping gap-ack blocks");

            var stopwatch = Stopwatch.StartNew();
            InjectSack(injectorTransport, victim.LocalVerificationTag, before.PeerCumulativeTsnAck, window: 16u * 1024 * 1024, blocks);

            // Every outstanding chunk the gap blocks name is acknowledged, so flight drains to zero.
            WaitFor(() => victim.GetStatistics().BytesInFlight == 0, timeoutMs: 30_000).Should().BeTrue();
            stopwatch.Stop();

            // Bounded time: an O(_out)-per-offset scan of this backlog could not finish this quickly.
            stopwatch.ElapsedMilliseconds.Should().BeLessThan(2000);

            // Right chunks: every in-flight chunk the gap blocks named is acknowledged, so flight is
            // fully cleared. The queue itself is unchanged — a non-cumulative gap ack marks chunks
            // acknowledged but does not remove them (only a cumulative ack / FORWARD TSN does), and this
            // crafted peer advertised neither, so the chunks correctly remain queued.
            var after = victim.GetStatistics();
            after.BytesInFlight.Should().Be(0);
            after.QueuedChunks.Should().Be(before.QueuedChunks);
            victim.State.Should().Be(SctpAssociationState.Established);
        }
        finally
        {
            victim.Dispose();
            injectorTransport.Dispose();
            victimTransport.Dispose();
        }
    }

    // ---------------------------------------------------------------- Finding 2

    [Fact]
    public void ForwardTsnInCookieEchoedIsIgnored()
    {
        var (victim, injectorTransport, victimTransport) = DriveInitiatorToCookieEchoed();
        try
        {
            var before = victim.GetStatistics();
            before.State.Should().Be(SctpAssociationState.CookieEchoed);

            // A FORWARD TSN naming a cumulative TSN well beyond ours. In an established association this
            // would advance the receive cumulative TSN; in CookieEchoed it must be dropped so a peer that
            // knows our verification tag cannot churn receive-side state before the handshake completes.
            InjectForwardTsn(injectorTransport, victim.LocalVerificationTag, unchecked(before.CumulativeTsnReceived + 1000u));
            Quiesce();

            var after = victim.GetStatistics();
            after.State.Should().Be(SctpAssociationState.CookieEchoed);
            after.CumulativeTsnReceived.Should().Be(before.CumulativeTsnReceived);
        }
        finally
        {
            victim.Dispose();
            injectorTransport.Dispose();
            victimTransport.Dispose();
        }
    }

    [Fact]
    public void ShutdownInCookieEchoedIsIgnored()
    {
        var (victim, injectorTransport, victimTransport) = DriveInitiatorToCookieEchoed();
        try
        {
            victim.State.Should().Be(SctpAssociationState.CookieEchoed);

            // A SHUTDOWN is only meaningful once the association is up. In CookieEchoed it must be ignored
            // rather than moving us to SHUTDOWN ACK SENT.
            InjectShutdown(injectorTransport, victim.LocalVerificationTag, cumulativeTsnAck: 0);
            Quiesce();

            victim.State.Should().Be(SctpAssociationState.CookieEchoed);
        }
        finally
        {
            victim.Dispose();
            injectorTransport.Dispose();
            victimTransport.Dispose();
        }
    }

    // ---------------------------------------------------------------- helpers

    private static (SctpAssociation Victim, LoopbackTransport Injector, LoopbackTransport VictimTransport) DriveInitiatorToCookieEchoed()
    {
        // The injector transport carries our crafted chunks to the victim; the victim's own outbound
        // (INIT, COOKIE ECHO) is delivered to the injector, which has no association listening, so no
        // COOKIE ACK ever comes back and the victim stalls in CookieEchoed.
        var (injectorTransport, victimTransport) = LoopbackTransport.CreatePair();
        var victim = new SctpAssociation(victimTransport, Config(isInitiator: true, usesEvenStreamIds: false, receiveWindow: 64u * 1024));

        // Fire-and-forget: the association never establishes, so observe (and discard) the connect fault.
        _ = victim.ConnectAsync().ContinueWith(t => _ = t.Exception, TaskScheduler.Default);

        WaitFor(() => victim.State == SctpAssociationState.CookieWait).Should().BeTrue();

        // A crafted INIT ACK carrying a (never-validated-by-us) state cookie drives CookieWait ->
        // CookieEchoed: the victim adopts the peer parameters and echoes the cookie.
        InjectInitAck(injectorTransport, victim.LocalVerificationTag, peerTag: 0x2222_2222u, peerInitialTsn: 1000u, advertisedWindow: 64 * 1024);
        WaitFor(() => victim.State == SctpAssociationState.CookieEchoed).Should().BeTrue();

        return (victim, injectorTransport, victimTransport);
    }

    private static SctpAssociationConfig Config(bool isInitiator, bool usesEvenStreamIds, uint receiveWindow) => new()
    {
        IsInitiator = isInitiator,
        UsesEvenStreamIds = usesEvenStreamIds,
        ReceiveWindow = receiveWindow,
        MaxMessageSize = receiveWindow,
        EnableInterleaving = false,
        TickInterval = TimeSpan.FromMilliseconds(5),
        // A long RTO keeps T3 retransmission from firing during the measured window.
        InitialRto = TimeSpan.FromSeconds(60),
        MinRto = TimeSpan.FromMilliseconds(50),
        MaxRto = TimeSpan.FromSeconds(60),
        HeartbeatInterval = TimeSpan.Zero,
    };

    private static List<SctpGapAckBlock> TileGapBlocks(int window, int stepOffsets, int passes)
    {
        var blocks = new List<SctpGapAckBlock>();
        for (var pass = 0; pass < passes; pass++)
        {
            for (var start = 1; start <= window; start += stepOffsets)
            {
                var end = Math.Min(start + stepOffsets - 1, window);
                blocks.Add(new SctpGapAckBlock((ushort)start, (ushort)end));
            }
        }

        return blocks;
    }

    private static void InjectSack(LoopbackTransport transport, uint victimTag, uint cumulativeTsnAck, uint window, IEnumerable<SctpGapAckBlock> blocks)
    {
        var sack = new SctpSackChunk
        {
            CumulativeTsnAck = cumulativeTsnAck,
            AdvertisedReceiverWindow = window,
        };
        sack.GapAckBlocks.AddRange(blocks);

        var packet = new SctpPacket(5000, 5000, victimTag);
        packet.Chunks.Add(sack);
        transport.Send(packet.ToArray());
    }

    private static void InjectInitAck(LoopbackTransport transport, uint victimTag, uint peerTag, uint peerInitialTsn, uint advertisedWindow)
    {
        var initAck = new SctpInitChunk(SctpChunkType.InitAck)
        {
            InitiateTag = peerTag,
            AdvertisedReceiverWindow = advertisedWindow,
            NumberOfOutboundStreams = 16,
            NumberOfInboundStreams = 16,
            InitialTsn = peerInitialTsn,
        };
        initAck.Parameters.Add(new SctpParameter(SctpParameterType.StateCookie, new byte[16]));

        var packet = new SctpPacket(5000, 5000, victimTag);
        packet.Chunks.Add(initAck);
        transport.Send(packet.ToArray());
    }

    private static void InjectCookieAck(LoopbackTransport transport, uint victimTag)
    {
        var packet = new SctpPacket(5000, 5000, victimTag);
        packet.Chunks.Add(new SctpCookieAckChunk());
        transport.Send(packet.ToArray());
    }

    private static void InjectForwardTsn(LoopbackTransport transport, uint victimTag, uint newCumulativeTsn)
    {
        var packet = new SctpPacket(5000, 5000, victimTag);
        packet.Chunks.Add(new SctpForwardTsnChunk { NewCumulativeTsn = newCumulativeTsn });
        transport.Send(packet.ToArray());
    }

    private static void InjectShutdown(LoopbackTransport transport, uint victimTag, uint cumulativeTsnAck)
    {
        var packet = new SctpPacket(5000, 5000, victimTag);
        packet.Chunks.Add(new SctpShutdownChunk(cumulativeTsnAck));
        transport.Send(packet.ToArray());
    }

    private static void Quiesce() => Thread.Sleep(120);

    private static bool WaitFor(Func<bool> condition, int timeoutMs = 5000)
    {
        var stopwatch = Stopwatch.StartNew();
        while (stopwatch.ElapsedMilliseconds < timeoutMs)
        {
            if (condition())
            {
                return true;
            }

            Thread.Sleep(5);
        }

        return condition();
    }
}
