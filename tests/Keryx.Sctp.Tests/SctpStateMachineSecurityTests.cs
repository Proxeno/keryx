using System.Buffers.Binary;
using System.Diagnostics;
using FluentAssertions;
using Keryx.Sctp;
using Xunit;

namespace Keryx.Sctp.Tests;

/// <summary>
/// Adversarial tests for the SCTP association state machine beyond the receive-buffer reassembly
/// path. A peer past the DTLS handshake drives an established association with crafted control
/// chunks; each test injects them straight onto the victim's transport and asserts the state machine
/// stays bounded in time and memory and never advances state on values it never authorised.
/// </summary>
/// <remarks>
/// The scenarios cover: a FORWARD TSN naming a cumulative TSN almost 2^31 beyond ours (a dense
/// per-TSN eviction loop would stall the association thread for billions of iterations under the
/// lock); a flood of distinct RFC 6525 incoming reset requests whose Sender's Last Assigned TSN is
/// never reached (an unbounded deferred-request list); and a SACK acknowledging TSNs we never sent
/// (advancing the peer's ack point past our send queue).
/// </remarks>
public class SctpStateMachineSecurityTests : IDisposable
{
    private const uint Window = 64 * 1024;

    private readonly LoopbackTransport _attackerTransport;
    private readonly LoopbackTransport _victimTransport;
    private readonly SctpAssociation _attacker;
    private readonly SctpAssociation _victim;

    private uint _victimTag;

    public SctpStateMachineSecurityTests()
    {
        (_attackerTransport, _victimTransport) = LoopbackTransport.CreatePair();

        _victimTransport.OnReceived += datagram =>
        {
            if (datagram.Length >= 8 && Volatile.Read(ref _victimTag) == 0)
            {
                var tag = BinaryPrimitives.ReadUInt32BigEndian(datagram.Slice(4, 4));
                if (tag != 0)
                {
                    Volatile.Write(ref _victimTag, tag);
                }
            }
        };

        _attacker = new SctpAssociation(_attackerTransport, Config(isInitiator: true, usesEvenStreamIds: true));
        _victim = new SctpAssociation(_victimTransport, Config(isInitiator: false, usesEvenStreamIds: false));
    }

    public void Dispose()
    {
        _attacker.Dispose();
        _victim.Dispose();
        _attackerTransport.Dispose();
        _victimTransport.Dispose();
    }

    [Fact]
    public async Task ForwardTsnWithHugeGapIsHandledInBoundedTime()
    {
        var cumulative = await EstablishAsync();

        // Pin one incomplete fragment in the receive buffer: a Beginning-only chunk at a TSN above
        // the cumulative leaves a gap, so it is buffered rather than reassembled.
        InjectDataFragment(unchecked(cumulative + 5u), new byte[512], beginning: true, ending: false);
        WaitFor(() => _victim.ReceiveBufferBytes >= 512).Should().BeTrue();

        // FORWARD TSN naming a cumulative TSN ~2^30 beyond ours. A dense loop over every skipped TSN
        // would run for over a billion iterations under the association lock; the eviction must walk
        // only the buffered entries instead, completing effectively instantly.
        var target = unchecked(cumulative + 0x40000000u);
        var stopwatch = Stopwatch.StartNew();
        InjectForwardTsn(target);

        WaitFor(() => _victim.GetStatistics().CumulativeTsnReceived == target).Should().BeTrue();
        stopwatch.Stop();

        // Bounded time: the whole receive path processes the chunk far inside the WaitFor budget. A
        // per-TSN walk of the 2^30-wide gap could not finish this quickly.
        stopwatch.ElapsedMilliseconds.Should().BeLessThan(2000);

        // The buffered fragment the FORWARD TSN skipped past was evicted, and the association survives.
        _victim.ReceiveBufferBytes.Should().Be(0);
        _victim.State.Should().Be(SctpAssociationState.Established);
    }

    [Fact]
    public async Task DeferredIncomingResetFloodIsBounded()
    {
        var cumulative = await EstablishAsync();

        // Every request names a distinct request sequence and a Sender's Last Assigned TSN far beyond
        // anything we will receive, so each is eligible to be deferred forever. A well-behaved peer
        // keeps at most one outstanding; this flood would otherwise pin an unbounded deferred list.
        var neverReached = unchecked(cumulative + 0x10000000u);
        for (uint seq = 1; seq <= 400; seq++)
        {
            InjectOutgoingReset(seq, neverReached, streamId: 0);
        }

        // Give the victim time to process the whole flood, then assert the parked set stayed capped.
        WaitFor(() => _victim.DeferredIncomingResetCount >= 1).Should().BeTrue();
        Quiesce();

        _victim.DeferredIncomingResetCount.Should().BeLessThanOrEqualTo(16);
        _victim.State.Should().Be(SctpAssociationState.Established);
    }

    [Fact]
    public async Task SackAcknowledgingUnsentTsnIsIgnored()
    {
        await EstablishAsync();

        // The victim (a non-initiator that has sent no DATA) has acknowledged nothing, so its peer
        // ack point sits at its initial TSN minus one. A forged SACK claiming a cumulative ack ~2^30
        // beyond any TSN it ever transmitted must be discarded, not accepted: accepting it would let
        // a peer advance the ack point past the send queue and silently flush un-transmitted DATA.
        Quiesce();
        var before = _victim.GetStatistics().PeerCumulativeTsnAck;

        InjectSack(unchecked(before + 0x40000000u), gapStart: 1, gapEnd: ushort.MaxValue);
        Quiesce();

        _victim.GetStatistics().PeerCumulativeTsnAck.Should().Be(before);
        _victim.State.Should().Be(SctpAssociationState.Established);
    }

    private static SctpAssociationConfig Config(bool isInitiator, bool usesEvenStreamIds) => new()
    {
        IsInitiator = isInitiator,
        UsesEvenStreamIds = usesEvenStreamIds,
        ReceiveWindow = Window,
        MaxMessageSize = Window,
        TickInterval = TimeSpan.FromMilliseconds(5),
        InitialRto = TimeSpan.FromMilliseconds(100),
        MinRto = TimeSpan.FromMilliseconds(50),
        HeartbeatInterval = TimeSpan.Zero,
    };

    private async Task<uint> EstablishAsync()
    {
        _victim.Start();
        await _attacker.ConnectAsync(new CancellationTokenSource(TimeSpan.FromSeconds(10)).Token);

        WaitFor(() => _victim.State == SctpAssociationState.Established).Should().BeTrue();
        WaitFor(() => Volatile.Read(ref _victimTag) != 0).Should().BeTrue();
        Quiesce();

        return _victim.GetStatistics().CumulativeTsnReceived;
    }

    private void InjectDataFragment(uint tsn, byte[] payload, bool beginning, bool ending)
    {
        var packet = new SctpPacket(5000, 5000, Volatile.Read(ref _victimTag));
        packet.Chunks.Add(new SctpDataChunk(
            tsn,
            streamId: 0,
            streamSequence: 0,
            SctpPpid.Binary,
            payload,
            beginning,
            ending,
            unordered: false));
        _attackerTransport.Send(packet.ToArray());
    }

    private void InjectForwardTsn(uint newCumulativeTsn)
    {
        var packet = new SctpPacket(5000, 5000, Volatile.Read(ref _victimTag));
        packet.Chunks.Add(new SctpForwardTsnChunk { NewCumulativeTsn = newCumulativeTsn });
        _attackerTransport.Send(packet.ToArray());
    }

    private void InjectOutgoingReset(uint requestSequence, uint sendersLastAssignedTsn, ushort streamId)
    {
        var packet = new SctpPacket(5000, 5000, Volatile.Read(ref _victimTag));
        packet.Chunks.Add(new SctpReConfigChunk(new SctpOutgoingSsnResetRequest(
            requestSequence,
            responseSequence: 0,
            sendersLastAssignedTsn,
            new ushort[] { streamId })));
        _attackerTransport.Send(packet.ToArray());
    }

    private void InjectSack(uint cumulativeTsnAck, ushort gapStart, ushort gapEnd)
    {
        var sack = new SctpSackChunk
        {
            CumulativeTsnAck = cumulativeTsnAck,
            AdvertisedReceiverWindow = Window,
        };
        sack.GapAckBlocks.Add(new SctpGapAckBlock(gapStart, gapEnd));

        var packet = new SctpPacket(5000, 5000, Volatile.Read(ref _victimTag));
        packet.Chunks.Add(sack);
        _attackerTransport.Send(packet.ToArray());
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
