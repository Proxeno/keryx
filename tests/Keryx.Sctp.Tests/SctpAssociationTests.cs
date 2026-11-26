using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using FluentAssertions;
using Keryx.Sctp;
using Xunit;

namespace Keryx.Sctp.Tests;

/// <summary>
/// End-to-end tests over a pair of in-memory transports: handshake, DCEP negotiation,
/// fragmentation, unordered delivery, partial reliability and retransmission.
/// </summary>
public class SctpAssociationTests : IDisposable
{
    private readonly Harness _harness = new();

    public void Dispose() => _harness.Dispose();

    [Fact]
    public async Task AssociatesOverLoopback()
    {
        await _harness.ConnectAsync();

        _harness.A.Association.State.Should().Be(SctpAssociationState.Established);
        WaitFor(() => _harness.B.Association.State == SctpAssociationState.Established).Should().BeTrue();
        _harness.A.Associated.Should().BeTrue();
        _harness.B.Associated.Should().BeTrue();
    }

    [Fact]
    public async Task ChannelsCreatedBeforeConnectAreOpenedOnThePeer()
    {
        var controller = _harness.A.CreateChannel("controller", ordered: false, maxRetransmits: 0);
        var telemetry = _harness.A.CreateChannel("telemetry");

        // Stream identifier parity follows the DTLS role: side A is configured as the even side.
        controller.StreamId.Should().Be(0);
        telemetry.StreamId.Should().Be(2);

        await _harness.ConnectAsync();

        WaitFor(() => _harness.B.Channels.Count == 2).Should().BeTrue();

        var remoteController = _harness.B.Channels["controller"];
        remoteController.StreamId.Should().Be(0);
        remoteController.Ordered.Should().BeFalse();
        remoteController.MaxRetransmits.Should().Be(0);
        remoteController.NegotiatedByPeer.Should().BeTrue();
        remoteController.State.Should().Be(DataChannelState.Open);

        var remoteTelemetry = _harness.B.Channels["telemetry"];
        remoteTelemetry.StreamId.Should().Be(2);
        remoteTelemetry.Ordered.Should().BeTrue();
        remoteTelemetry.MaxRetransmits.Should().BeNull();

        // The DATA_CHANNEL_ACK travels back, so the opener's channels also reach Open.
        WaitFor(() => controller.State == DataChannelState.Open && telemetry.State == DataChannelState.Open)
            .Should().BeTrue();
    }

    [Fact]
    public async Task RemoteInitiatedChannelIsReportedToTheOtherSide()
    {
        await _harness.ConnectAsync();

        var fromB = _harness.B.CreateChannel("browser-opened", protocol: "prox");

        // Side B is the odd side.
        fromB.StreamId.Should().Be(1);
        WaitFor(() => _harness.A.Channels.ContainsKey("browser-opened")).Should().BeTrue();

        var seen = _harness.A.Channels["browser-opened"];
        seen.StreamId.Should().Be(1);
        seen.Protocol.Should().Be("prox");
        seen.NegotiatedByPeer.Should().BeTrue();
        WaitFor(() => fromB.State == DataChannelState.Open).Should().BeTrue();
    }

    [Fact]
    public async Task TextAndBinaryMessagesFlowInBothDirections()
    {
        var telemetry = _harness.A.CreateChannel("telemetry");
        await _harness.ConnectAsync();
        WaitFor(() => _harness.B.Channels.ContainsKey("telemetry")).Should().BeTrue();
        var remote = _harness.B.Channels["telemetry"];

        telemetry.SendText("hello from A");
        telemetry.Send(new byte[] { 1, 2, 3, 250 });
        telemetry.SendText(string.Empty);
        telemetry.Send(ReadOnlySpan<byte>.Empty);

        WaitFor(() => _harness.B.Messages.Count == 4).Should().BeTrue();
        var toB = _harness.B.Messages.ToArray();
        toB[0].Should().BeEquivalentTo(new Message("telemetry", false, Encoding.UTF8.GetBytes("hello from A")));
        toB[1].Should().BeEquivalentTo(new Message("telemetry", true, new byte[] { 1, 2, 3, 250 }));
        toB[2].Binary.Should().BeFalse();
        toB[2].Payload.Should().BeEmpty();
        toB[3].Binary.Should().BeTrue();
        toB[3].Payload.Should().BeEmpty();

        remote.SendText("hello from B");
        remote.Send(new byte[] { 9, 9 });

        WaitFor(() => _harness.A.Messages.Count == 2).Should().BeTrue();
        var toA = _harness.A.Messages.ToArray();
        toA[0].Should().BeEquivalentTo(new Message("telemetry", false, Encoding.UTF8.GetBytes("hello from B")));
        toA[1].Should().BeEquivalentTo(new Message("telemetry", true, new byte[] { 9, 9 }));
    }

    [Fact]
    public async Task LargeMessageIsFragmentedAndReassembled()
    {
        var telemetry = _harness.A.CreateChannel("telemetry");
        await _harness.ConnectAsync();
        WaitFor(() => _harness.B.Channels.ContainsKey("telemetry")).Should().BeTrue();

        var payload = new byte[100 * 1024];
        new Random(20260821).NextBytes(payload);

        // The message is far larger than one datagram, so it must be split across DATA chunks.
        payload.Length.Should().BeGreaterThan(_harness.A.Association.MaxPayloadPerChunk * 50);

        telemetry.Send(payload);

        WaitFor(() => _harness.B.Messages.Count == 1, 20_000).Should().BeTrue();
        var received = _harness.B.Messages.Single();
        received.Binary.Should().BeTrue();
        received.Payload.Should().Equal(payload);

        WaitFor(() => telemetry.BufferedAmount == 0).Should().BeTrue();
    }

    [Fact]
    public async Task UnorderedMessagesAreDeliveredWithoutHeadOfLineBlocking()
    {
        var channel = _harness.A.CreateChannel("reorder", ordered: false);
        await _harness.ConnectAsync();
        WaitFor(() => _harness.B.Channels.ContainsKey("reorder")).Should().BeTrue();

        // Only reorder once the DCEP handshake has settled.
        WaitFor(() => channel.State == DataChannelState.Open).Should().BeTrue();
        Quiesce();

        _harness.A.Transport.SetDataReordering(true);
        for (var i = 0; i < 4; i++)
        {
            channel.SendText($"msg{i}");
        }

        WaitFor(() => _harness.B.Messages.Count == 4).Should().BeTrue();
        _harness.A.Transport.SetDataReordering(false);

        var order = _harness.B.Messages.Select(m => Encoding.UTF8.GetString(m.Payload)).ToArray();
        order.Should().BeEquivalentTo(new[] { "msg0", "msg1", "msg2", "msg3" });

        // The transport swapped adjacent datagrams, and unordered delivery passed them straight up.
        order.Should().NotEqual(new[] { "msg0", "msg1", "msg2", "msg3" });
    }

    [Fact]
    public async Task UnreliableMessageIsAbandonedAndLaterMessagesStillFlow()
    {
        var controller = _harness.A.CreateChannel("controller", ordered: false, maxRetransmits: 0);
        await _harness.ConnectAsync();
        WaitFor(() => _harness.B.Channels.ContainsKey("controller")).Should().BeTrue();
        WaitFor(() => controller.State == DataChannelState.Open).Should().BeTrue();
        Quiesce();

        _harness.A.Transport.DropNextDataDatagrams(1);
        controller.SendText("lost");
        controller.SendText("kept");

        WaitFor(() => _harness.B.Messages.Count >= 1).Should().BeTrue();
        _harness.A.Transport.DroppedDatagrams.Should().Be(1);

        // Give the T3 timer time to fire, abandon the message and send FORWARD TSN.
        Thread.Sleep(400);

        _harness.B.Messages.Should().ContainSingle();
        Encoding.UTF8.GetString(_harness.B.Messages.Single().Payload).Should().Be("kept");

        // The association is healthy and the receiver's cumulative TSN has moved past the hole.
        _harness.A.Association.State.Should().Be(SctpAssociationState.Established);
        _harness.B.Association.State.Should().Be(SctpAssociationState.Established);

        controller.SendText("after");
        WaitFor(() => _harness.B.Messages.Count == 2).Should().BeTrue();
        Encoding.UTF8.GetString(_harness.B.Messages.Last().Payload).Should().Be("after");
        WaitFor(() => controller.BufferedAmount == 0).Should().BeTrue();
    }

    [Fact]
    public async Task TimedUnreliableMessageIsAbandonedAfterItsLifetimeElapses()
    {
        // Unordered timed-unreliable (maxPacketLifetime) is the common WebRTC data-channel case.
        var time = new TestTimeProvider();
        using var harness = new Harness(time);
        var lossy = harness.A.CreateChannel("lossy", ordered: false, maxPacketLifetime: 200);
        await harness.ConnectAsync();
        WaitFor(() => harness.B.Channels.ContainsKey("lossy")).Should().BeTrue();
        WaitFor(() => lossy.State == DataChannelState.Open).Should().BeTrue();
        Quiesce();

        // Drop the one and only transmission attempt. The fake clock is frozen, so the T3
        // retransmission timer (which fires when NowMs reaches an already-computed expiry) never
        // trips and no further attempt is made — the message can only be freed by its lifetime.
        harness.A.Transport.DropNextDataDatagrams(1);
        lossy.SendText("lost-to-time");
        WaitFor(() => harness.A.Transport.DroppedDatagrams == 1).Should().BeTrue();

        // Give the periodic Tick a moment to observe the still-frozen clock and confirm it does
        // NOT abandon the message early.
        Thread.Sleep(60);
        lossy.BufferedAmount.Should().BeGreaterThan(0);
        harness.B.Messages.Should().BeEmpty();

        // Advance past the message's lifetime; the next Tick abandons it via FORWARD-TSN.
        time.Advance(TimeSpan.FromMilliseconds(250));

        lossy.SendText("kept");
        WaitFor(() => harness.B.Messages.Count == 1).Should().BeTrue();
        Encoding.UTF8.GetString(harness.B.Messages.Single().Payload).Should().Be("kept");

        // The abandoned message's buffered bytes were released and the association kept flowing.
        WaitFor(() => lossy.BufferedAmount == 0).Should().BeTrue();
        harness.A.Association.State.Should().Be(SctpAssociationState.Established);
        harness.B.Association.State.Should().Be(SctpAssociationState.Established);
    }

    [Fact]
    public async Task TimedMessageDeliveredWithinItsLifetimeIsNotAbandoned()
    {
        var time = new TestTimeProvider();
        using var harness = new Harness(time);
        var channel = harness.A.CreateChannel("prompt", ordered: false, maxPacketLifetime: 5000);
        await harness.ConnectAsync();
        WaitFor(() => harness.B.Channels.ContainsKey("prompt")).Should().BeTrue();
        WaitFor(() => channel.State == DataChannelState.Open).Should().BeTrue();
        Quiesce();

        channel.SendText("on-time");
        WaitFor(() => harness.B.Messages.Count == 1).Should().BeTrue();
        WaitFor(() => channel.BufferedAmount == 0).Should().BeTrue();

        // Advance well past the lifetime after delivery already completed: nothing left to abandon.
        time.Advance(TimeSpan.FromSeconds(10));
        Thread.Sleep(60);

        Encoding.UTF8.GetString(harness.B.Messages.Single().Payload).Should().Be("on-time");
        harness.A.Association.State.Should().Be(SctpAssociationState.Established);
        harness.B.Association.State.Should().Be(SctpAssociationState.Established);
    }

    [Fact]
    public void CreateChannelRejectsBothReliabilityLimitsAtOnce()
    {
        using var harness = new Harness();
        var act = () => harness.A.CreateChannel("bad", maxRetransmits: 0, maxPacketLifetime: 100);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public async Task ReliableMessageSurvivesADroppedFirstAttempt()
    {
        var telemetry = _harness.A.CreateChannel("telemetry");
        await _harness.ConnectAsync();
        WaitFor(() => _harness.B.Channels.ContainsKey("telemetry")).Should().BeTrue();
        WaitFor(() => telemetry.State == DataChannelState.Open).Should().BeTrue();
        Quiesce();

        _harness.A.Transport.DropNextDataDatagrams(1);
        telemetry.SendText("must arrive");

        WaitFor(() => _harness.B.Messages.Count == 1).Should().BeTrue();
        _harness.A.Transport.DroppedDatagrams.Should().Be(1);
        Encoding.UTF8.GetString(_harness.B.Messages.Single().Payload).Should().Be("must arrive");
        _harness.A.Association.State.Should().Be(SctpAssociationState.Established);
    }

    [Fact]
    public async Task OrderedDeliveryIsPreservedUnderReordering()
    {
        var telemetry = _harness.A.CreateChannel("telemetry");
        await _harness.ConnectAsync();
        WaitFor(() => _harness.B.Channels.ContainsKey("telemetry")).Should().BeTrue();
        WaitFor(() => telemetry.State == DataChannelState.Open).Should().BeTrue();
        Quiesce();

        _harness.A.Transport.SetDataReordering(true);
        for (var i = 0; i < 6; i++)
        {
            telemetry.SendText($"ordered{i}");
        }

        WaitFor(() => _harness.B.Messages.Count == 6).Should().BeTrue();
        _harness.A.Transport.SetDataReordering(false);

        _harness.B.Messages.Select(m => Encoding.UTF8.GetString(m.Payload))
            .Should().Equal("ordered0", "ordered1", "ordered2", "ordered3", "ordered4", "ordered5");
    }

    [Fact]
    public async Task ShutdownClosesBothEndpoints()
    {
        _harness.A.CreateChannel("telemetry");
        await _harness.ConnectAsync();
        WaitFor(() => _harness.B.Channels.ContainsKey("telemetry")).Should().BeTrue();

        _harness.A.Association.Shutdown();

        WaitFor(() => _harness.A.Association.State == SctpAssociationState.Closed).Should().BeTrue();
        WaitFor(() => _harness.B.Association.State == SctpAssociationState.Closed).Should().BeTrue();
        WaitFor(() => _harness.B.Channels["telemetry"].State == DataChannelState.Closed).Should().BeTrue();
        WaitFor(() => _harness.A.Closed && _harness.B.Closed).Should().BeTrue();
    }

    [Fact]
    public async Task AbortTearsDownThePeer()
    {
        await _harness.ConnectAsync();

        _harness.A.Association.Abort("test over");

        WaitFor(() => _harness.A.Association.State == SctpAssociationState.Closed).Should().BeTrue();
        WaitFor(() => _harness.B.Association.State == SctpAssociationState.Closed).Should().BeTrue();
        WaitFor(() => _harness.B.Errors.Count == 1).Should().BeTrue();
    }

    /// <summary>
    /// Simultaneous open, where both endpoints send INIT — the shape a browser drives when it both
    /// offers and creates the data channel. Establishing through the peer's COOKIE ECHO must also
    /// disarm this side's own INIT handshake timer. Without that, the timer keeps re-sending a stale
    /// COOKIE ECHO and after <see cref="SctpAssociationConfig.MaxRetransmitAttempts"/> fails an
    /// otherwise healthy association with "SCTP handshake timed out".
    /// </summary>
    [Fact]
    public async Task SimultaneousOpen_StaysEstablishedPastInitRetransmitLimit()
    {
        var time = new TestTimeProvider();
        using var harness = new Harness(time, simultaneousOpen: true);
        var channelA = harness.A.CreateChannel("control");

        // Both directions call ConnectAsync up front, so both send INIT before either can finish.
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await Task.WhenAll(
            harness.A.Association.ConnectAsync(timeout.Token),
            harness.B.Association.ConnectAsync(timeout.Token));

        harness.A.Association.State.Should().Be(SctpAssociationState.Established);
        harness.B.Association.State.Should().Be(SctpAssociationState.Established);
        WaitFor(() => harness.B.Channels.ContainsKey("control")).Should().BeTrue();
        WaitFor(() => channelA.State == DataChannelState.Open).Should().BeTrue();
        Quiesce();

        // Drive the periodic Tick well past every INIT retransmission the test config allows. The RTO
        // doubles from 100 ms up to the 60 s ceiling and MaxRetransmitAttempts is 8, so eleven 61 s
        // jumps (~11 min of fake time) clear the 8 x 60 s bound with room to spare. Each jump lets one
        // Tick observe the expired deadline; with the bug, the stale COOKIE ECHO is re-sent and
        // attempt 9 fails the association.
        for (var i = 0; i < 11; i++)
        {
            time.Advance(TimeSpan.FromSeconds(61));
            Thread.Sleep(20);
        }

        harness.A.Association.State.Should().Be(
            SctpAssociationState.Established,
            "the INIT handshake timer must be disarmed once simultaneous open establishes");
        harness.B.Association.State.Should().Be(SctpAssociationState.Established);
        harness.A.Errors.Should().BeEmpty("a healthy simultaneous open must never raise a failure");
        harness.B.Errors.Should().BeEmpty();
        harness.A.Closed.Should().BeFalse();
        harness.B.Closed.Should().BeFalse();

        // The association still carries data in both directions after the old timer deadline passed.
        channelA.SendText("still here");
        WaitFor(() => harness.B.Messages.Count == 1).Should().BeTrue();
        Encoding.UTF8.GetString(harness.B.Messages.Single().Payload).Should().Be("still here");

        var channelB = harness.B.Channels["control"];
        channelB.SendText("and back");
        WaitFor(() => harness.A.Messages.Count == 1).Should().BeTrue();
        Encoding.UTF8.GetString(harness.A.Messages.Single().Payload).Should().Be("and back");
    }

    [Fact]
    public async Task OversizedMessageIsRejected()
    {
        var telemetry = _harness.A.CreateChannel("telemetry");
        await _harness.ConnectAsync();

        var act = () => telemetry.Send(new byte[262145]);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    /// <summary>Lets both endpoints settle so no SACK or DCEP traffic is still in flight.</summary>
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

    internal sealed record Message(string Label, bool Binary, byte[] Payload);

    internal sealed class Endpoint : IDisposable
    {
        private readonly ConcurrentQueue<Message> _messages = new();
        private readonly ConcurrentQueue<Exception> _errors = new();

        public Endpoint(LoopbackTransport transport, bool isInitiator, bool usesEvenStreamIds, TimeProvider? timeProvider = null)
        {
            Transport = transport;
            Association = new SctpAssociation(transport, new SctpAssociationConfig
            {
                IsInitiator = isInitiator,
                UsesEvenStreamIds = usesEvenStreamIds,
                TickInterval = TimeSpan.FromMilliseconds(5),
                InitialRto = TimeSpan.FromMilliseconds(100),
                MinRto = TimeSpan.FromMilliseconds(50),
                HeartbeatInterval = TimeSpan.Zero,
                TimeProvider = timeProvider ?? TimeProvider.System,
            });

            Association.OnAssociated += () => Associated = true;
            Association.OnClosed += () => Closed = true;
            Association.OnError += error => _errors.Enqueue(error);
            Association.OnChannelOpened += channel =>
            {
                Observe(channel);
                Channels[channel.Label] = channel;
            };
        }

        public LoopbackTransport Transport { get; }

        public SctpAssociation Association { get; }

        public ConcurrentDictionary<string, DataChannel> Channels { get; } = new();

        public IReadOnlyList<Message> Messages => _messages.ToArray();

        public IReadOnlyList<Exception> Errors => _errors.ToArray();

        public bool Associated { get; private set; }

        public bool Closed { get; private set; }

        public DataChannel CreateChannel(
            string label,
            bool ordered = true,
            ushort? maxRetransmits = null,
            string protocol = "",
            ushort? maxPacketLifetime = null)
        {
            var channel = Association.CreateChannel(label, ordered, maxRetransmits, protocol, maxPacketLifetime);
            Observe(channel);
            return channel;
        }

        public void Dispose() => Association.Dispose();

        private void Observe(DataChannel channel)
        {
            channel.OnMessage += (binary, payload) => _messages.Enqueue(new Message(channel.Label, binary, payload.ToArray()));
        }
    }

    internal sealed class Harness : IDisposable
    {
        private readonly LoopbackTransport _transportA;
        private readonly LoopbackTransport _transportB;

        public Harness(TimeProvider? timeProviderA = null, bool simultaneousOpen = false)
        {
            (_transportA, _transportB) = LoopbackTransport.CreatePair();
            A = new Endpoint(_transportA, isInitiator: true, usesEvenStreamIds: true, timeProviderA);
            B = new Endpoint(
                _transportB,
                isInitiator: simultaneousOpen,
                usesEvenStreamIds: false,
                timeProvider: simultaneousOpen ? timeProviderA : null);
        }

        public Endpoint A { get; }

        public Endpoint B { get; }

        public Task ConnectAsync()
        {
            B.Association.Start();
            return A.Association.ConnectAsync(new CancellationTokenSource(TimeSpan.FromSeconds(10)).Token);
        }

        public void Dispose()
        {
            A.Dispose();
            B.Dispose();
            _transportA.Dispose();
            _transportB.Dispose();
        }
    }
}
