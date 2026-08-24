using System.Buffers.Binary;
using System.Diagnostics;
using FluentAssertions;
using Keryx.Sctp;
using Xunit;

namespace Keryx.Sctp.Tests;

/// <summary>
/// Adversarial tests for the receive-side reassembly / ordered-delivery path. A fully reassembled
/// message whose stream sequence number (classic DATA) or message identifier (RFC 8260 I-DATA) is
/// ahead of the next expected one is held for in-order delivery. Those held messages leave the
/// fragment buffer, so a peer that withholds the next expected SSN/MID while flooding later,
/// self-contained messages could once grow that ordered-hold buffer without bound even though the
/// fragment buffer stayed near empty. These tests inject crafted chunks straight onto the victim's
/// transport and assert the whole receive path — fragments plus held messages — stays bounded and
/// that a legitimate gap-fill still drains the hold buffer.
/// </summary>
public class SctpReassemblyBoundsTests : IDisposable
{
    // Equal window and message cap so the hard cap on the whole receive path is exactly the window.
    private const uint Window = 16 * 1024;

    private readonly LoopbackTransport _attackerTransport;
    private readonly LoopbackTransport _victimTransport;
    private readonly SctpAssociation _attacker;
    private readonly SctpAssociation _victim;

    private uint _victimTag;

    public SctpReassemblyBoundsTests()
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
    public async Task WithheldSsnFloodOfCompleteOrderedMessagesStaysBoundedAndAborts()
    {
        var cumulative = await EstablishAsync();

        // Every message is a self-contained ordered DATA chunk (B+E) with a stream sequence number
        // above the next expected one (0), which is never sent. Each reassembles immediately and is
        // parked in the ordered-hold buffer forever. The TSNs are contiguous so the cumulative TSN
        // advances and the fragment buffer stays empty: only a bound on the hold buffer can stop
        // this. 32 KiB of held payload is twice the hard cap, so the victim must abort.
        var payload = new byte[1024];
        for (var i = 0; i < 32; i++)
        {
            InjectData(unchecked(cumulative + 1u + (uint)i), streamSequence: (ushort)(i + 1), payload);
        }

        WaitFor(() => _victim.State == SctpAssociationState.Closed).Should().BeTrue();

        // Aborting released the pinned memory rather than leaving it held.
        _victim.TotalReceiveBufferBytes.Should().Be(0);
        _victim.ReceiveBufferBytes.Should().Be(0);
    }

    [Fact]
    public async Task WithheldMidFloodOfCompleteIDataMessagesStaysBoundedAndAborts()
    {
        var cumulative = await EstablishAsync();

        // The I-DATA analogue: self-contained ordered I-DATA messages (B+E, implicit FSN 0) whose
        // 32-bit MID is always above the next expected one (0). Each reassembles at once and is
        // parked in the per-stream ordered-hold buffer. Contiguous TSNs keep the fragment buffer
        // empty, so again only a bound on the hold buffer stops the growth.
        var payload = new byte[1024];
        for (var i = 0; i < 32; i++)
        {
            InjectIData(unchecked(cumulative + 1u + (uint)i), messageId: (uint)(i + 1), payload);
        }

        WaitFor(() => _victim.State == SctpAssociationState.Closed).Should().BeTrue();

        _victim.TotalReceiveBufferBytes.Should().Be(0);
        _victim.ReceiveBufferBytes.Should().Be(0);
    }

    [Fact]
    public async Task ManyStreamsOfHeldOrderedMessagesAreBoundedInAggregate()
    {
        var cumulative = await EstablishAsync();

        // Spread the held messages across many stream ids so no single stream's hold buffer is large,
        // but the aggregate is. The shared hard cap must bound the total across every stream.
        var payload = new byte[1024];
        var tsn = unchecked(cumulative + 1u);
        for (var round = 0; round < 40; round++)
        {
            for (ushort stream = 0; stream < 8; stream++)
            {
                InjectData(tsn, streamSequence: (ushort)(round + 1), payload, streamId: stream);
                tsn = unchecked(tsn + 1u);
            }
        }

        WaitFor(() => _victim.State == SctpAssociationState.Closed).Should().BeTrue();
        _victim.TotalReceiveBufferBytes.Should().Be(0);
    }

    [Fact]
    public async Task HeldOrderedMessageIsReleasedWhenTheGapFills()
    {
        var cumulative = await EstablishAsync();

        // A future-SSN message is held (the hold buffer charges the receive path), then the missing
        // opener arrives and both messages drain in order. Using the DCEP protocol id with an unknown
        // message type means delivery consumes and discards them, so the hold accounting must return
        // exactly to zero — proving the new charge is released on the happy path, not leaked.
        var held = new byte[1024];
        held[0] = 0xFF; // unknown DCEP message type: delivered, logged, and dropped.

        // SSN 1 first, out of order (its TSN leaves a one-slot gap), so it is parked in the hold buffer.
        InjectData(unchecked(cumulative + 2u), streamSequence: 1, held, payloadProtocolId: SctpPpid.Dcep);
        WaitFor(() => _victim.TotalReceiveBufferBytes >= 1024).Should().BeTrue();

        var opener = new byte[8];
        opener[0] = 0xFF;
        // SSN 0 fills the gap: it delivers immediately and drains SSN 1 behind it.
        InjectData(unchecked(cumulative + 1u), streamSequence: 0, opener, payloadProtocolId: SctpPpid.Dcep);

        WaitFor(() => _victim.TotalReceiveBufferBytes == 0).Should().BeTrue();
        _victim.State.Should().Be(SctpAssociationState.Established);
        _victim.GetStatistics().CumulativeTsnReceived.Should().Be(unchecked(cumulative + 2u));
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

    private void InjectData(
        uint tsn,
        ushort streamSequence,
        byte[] payload,
        ushort streamId = 0,
        uint payloadProtocolId = SctpPpid.Binary)
    {
        var packet = new SctpPacket(5000, 5000, Volatile.Read(ref _victimTag));
        packet.Chunks.Add(new SctpDataChunk(
            tsn,
            streamId,
            streamSequence,
            payloadProtocolId,
            payload,
            beginning: true,
            ending: true,
            unordered: false));

        _attackerTransport.Send(packet.ToArray());
    }

    private void InjectIData(
        uint tsn,
        uint messageId,
        byte[] payload,
        ushort streamId = 0,
        uint payloadProtocolId = SctpPpid.Binary)
    {
        var packet = new SctpPacket(5000, 5000, Volatile.Read(ref _victimTag));
        packet.Chunks.Add(new SctpIDataChunk(
            tsn,
            streamId,
            messageId,
            payloadProtocolId,
            fragmentSequenceNumber: 0,
            payload,
            beginning: true,
            ending: true,
            unordered: false));

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
