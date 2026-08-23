using System.Buffers.Binary;
using System.Diagnostics;
using FluentAssertions;
using Keryx.Sctp;
using Xunit;

namespace Keryx.Sctp.Tests;

/// <summary>
/// Adversarial tests for receive-side flow control: a hostile peer must not be able to grow the
/// out-of-order receive buffer (<c>_received</c>/<c>_fragments</c>) without bound and OOM the host.
/// Crafted DATA chunks are injected straight onto the victim's transport, bypassing a well-behaved
/// sender, so the victim's own buffering limits are exercised in isolation.
/// </summary>
public class SctpReceiveWindowTests : IDisposable
{
    // Small, equal window and message cap so the hard cap is exactly the receive window and every
    // assertion is tight. The tick/RTO values keep the handshake fast.
    private const uint Window = 16 * 1024;

    private readonly LoopbackTransport _attackerTransport;
    private readonly LoopbackTransport _victimTransport;
    private readonly SctpAssociation _attacker;
    private readonly SctpAssociation _victim;

    private uint _victimTag;

    public SctpReceiveWindowTests()
    {
        (_attackerTransport, _victimTransport) = LoopbackTransport.CreatePair();

        // Sniff the verification tag the peer expects on packets addressed to the victim. Its first
        // COOKIE ECHO (and every later packet) carries the victim's local tag; INIT carries zero.
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
    public async Task OutOfOrderTsnFloodStaysBoundedAndAssociationSurvives()
    {
        var cumulative = await EstablishAsync();

        // A never-filling gap of distinct, self-contained messages: every TSN sits above
        // cumulative + 1, so the cumulative TSN never advances and each TSN lingers in the
        // _received set forever. Left unchecked this set grows without bound; the count cap must
        // stop it well before the 400 TSNs we throw at it.
        var payload = new byte[1000];
        for (var i = 0; i < 400; i++)
        {
            InjectData(unchecked(cumulative + 2u + (uint)i), payload);
        }

        WaitFor(() => _victim.BufferedChunkCount > 0).Should().BeTrue();
        Quiesce();

        _victim.BufferedChunkCount.Should().BeLessThanOrEqualTo(_victim.MaxBufferedChunks);
        _victim.ReceiveBufferBytes.Should().BeLessThanOrEqualTo((long)_victim.ReceiveBufferHardCap);
        _victim.State.Should().Be(SctpAssociationState.Established);
    }

    [Fact]
    public async Task TinyChunkFloodIsBoundedByChunkCount()
    {
        var cumulative = await EstablishAsync();

        // One-byte incomplete fragments (no beginning, so they can never reassemble) sit in the gap
        // and barely move the byte total, so only the companion chunk-count cap can stop
        // _received/_fragments from growing without limit.
        var payload = new byte[1];
        for (var i = 0; i < 5000; i++)
        {
            InjectData(unchecked(cumulative + 2u + (uint)i), payload, beginning: false, ending: false);
        }

        WaitFor(() => _victim.BufferedChunkCount > 0).Should().BeTrue();
        Quiesce();

        _victim.BufferedChunkCount.Should().BeLessThanOrEqualTo(_victim.MaxBufferedChunks);
        _victim.ReceiveBufferBytes.Should().BeLessThanOrEqualTo((long)_victim.ReceiveBufferHardCap);
        _victim.State.Should().Be(SctpAssociationState.Established);
    }

    [Fact]
    public async Task NeverCompletingFragmentFloodAbortsInsteadOfExhaustingMemory()
    {
        var cumulative = await EstablishAsync();

        // A message that never ends: a contiguous run of B/continuation fragments with no E fragment.
        // The cumulative TSN advances but reassembly can never complete, so the fragments would pin
        // memory forever. The receiver has no legitimate way to recover and must abort.
        var payload = new byte[1000];
        for (var i = 0; i < 200; i++)
        {
            var tsn = unchecked(cumulative + 1u + (uint)i);
            InjectData(tsn, payload, beginning: i == 0, ending: false);
        }

        WaitFor(() => _victim.State == SctpAssociationState.Closed).Should().BeTrue();

        // Aborting released the pinned memory rather than leaving it buffered.
        _victim.ReceiveBufferBytes.Should().Be(0);
        _victim.BufferedChunkCount.Should().Be(0);
    }

    [Fact]
    public async Task ReceiveWindowOverflowStopsBufferingAndAdvertisesZero()
    {
        var cumulative = await EstablishAsync();

        // Push more out-of-order bytes than the whole receive window in one burst, as incomplete
        // fragments in the gap so the bytes stay pinned. 1 KiB divides the window evenly, so a
        // compliant fill lands exactly on the window edge and the advertised a_rwnd reaches zero.
        var payload = new byte[1024];
        var chunks = (int)(Window / 1024) + 20;
        for (var i = 0; i < chunks; i++)
        {
            InjectData(unchecked(cumulative + 2u + (uint)i), payload, beginning: false, ending: false);
        }

        WaitFor(() => _victim.GetStatistics().LocalReceiveWindow == 0).Should().BeTrue();
        Quiesce();

        // Buffered bytes never exceed the configured window even though we sent well past it.
        _victim.ReceiveBufferBytes.Should().BeLessThanOrEqualTo((long)Window);
        _victim.State.Should().Be(SctpAssociationState.Established);
    }

    [Fact]
    public async Task InWindowReorderingStillReassembles()
    {
        var cumulative = await EstablishAsync();

        // A legitimate three-fragment message that arrives out of order, entirely within the window.
        var b = new byte[500];
        var mid = new byte[500];
        var e = new byte[500];
        Array.Fill(b, (byte)1);
        Array.Fill(mid, (byte)2);
        Array.Fill(e, (byte)3);

        // Deliver last, then middle, then first: the buffer holds the gap until the opener arrives.
        InjectData(unchecked(cumulative + 3u), e, beginning: false, ending: true);
        InjectData(unchecked(cumulative + 2u), mid, beginning: false, ending: false);
        WaitFor(() => _victim.BufferedChunkCount == 2).Should().BeTrue();

        InjectData(unchecked(cumulative + 1u), b, beginning: true, ending: false);

        // Once the opener fills the gap the whole message reassembles: the buffer drains and the
        // cumulative TSN advances past all three fragments. The association stays healthy.
        WaitFor(() => _victim.BufferedChunkCount == 0).Should().BeTrue();
        _victim.ReceiveBufferBytes.Should().Be(0);
        _victim.GetStatistics().CumulativeTsnReceived.Should().Be(unchecked(cumulative + 3u));
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

    /// <summary>Completes the handshake and returns the victim's cumulative received TSN.</summary>
    private async Task<uint> EstablishAsync()
    {
        _victim.Start();
        await _attacker.ConnectAsync(new CancellationTokenSource(TimeSpan.FromSeconds(10)).Token);

        WaitFor(() => _victim.State == SctpAssociationState.Established).Should().BeTrue();
        WaitFor(() => Volatile.Read(ref _victimTag) != 0).Should().BeTrue();
        Quiesce();

        return _victim.GetStatistics().CumulativeTsnReceived;
    }

    /// <summary>Crafts a DATA chunk with the victim's verification tag and injects it onto the wire.</summary>
    private void InjectData(uint tsn, byte[] payload, bool beginning = true, bool ending = true)
    {
        var packet = new SctpPacket(5000, 5000, Volatile.Read(ref _victimTag));
        packet.Chunks.Add(new SctpDataChunk(
            tsn,
            streamId: 0,
            streamSequence: 0,
            payloadProtocolId: SctpPpid.Binary,
            payload: payload,
            beginning: beginning,
            ending: ending,
            unordered: false));

        // Delivered through the attacker's transport, which ships raw bytes to the victim's inbox.
        _attackerTransport.Send(packet.ToArray());
    }

    /// <summary>Lets both endpoints settle so no SACK traffic is still in flight.</summary>
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
