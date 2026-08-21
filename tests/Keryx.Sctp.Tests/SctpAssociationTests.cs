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

        public Endpoint(LoopbackTransport transport, bool isInitiator, bool usesEvenStreamIds)
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

        public DataChannel CreateChannel(string label, bool ordered = true, ushort? maxRetransmits = null, string protocol = "")
        {
            var channel = Association.CreateChannel(label, ordered, maxRetransmits, protocol);
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

        public Harness()
        {
            (_transportA, _transportB) = LoopbackTransport.CreatePair();
            A = new Endpoint(_transportA, isInitiator: true, usesEvenStreamIds: true);
            B = new Endpoint(_transportB, isInitiator: false, usesEvenStreamIds: false);
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
