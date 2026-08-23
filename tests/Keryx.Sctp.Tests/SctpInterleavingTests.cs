using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using FluentAssertions;
using Keryx.Sctp;
using Xunit;

namespace Keryx.Sctp.Tests;

/// <summary>
/// End-to-end tests for RFC 8260 user-message interleaving (I-DATA): that it is negotiated through
/// the Supported Extensions parameter, that it falls back to classic DATA when a peer does not
/// advertise it, and that a large message no longer head-of-line-blocks small messages on other
/// streams.
/// </summary>
public class SctpInterleavingTests : IDisposable
{
    private Harness? _harness;

    public void Dispose() => _harness?.Dispose();

    [Fact]
    public async Task UserDataTravelsAsIDataWhenBothPeersAdvertiseInterleaving()
    {
        _harness = new Harness(interleavingOnA: true, interleavingOnB: true);
        var channel = _harness.A.CreateChannel("telemetry");
        await _harness.ConnectAsync();
        WaitFor(() => _harness.B.Channels.ContainsKey("telemetry")).Should().BeTrue();
        WaitFor(() => channel.State == DataChannelState.Open).Should().BeTrue();

        channel.SendText("interleaved hello");
        WaitFor(() => _harness.B.Messages.Count == 1).Should().BeTrue();
        Encoding.UTF8.GetString(_harness.B.Messages[0].Payload).Should().Be("interleaved hello");

        // Every user message (DCEP and payload) is carried in I-DATA chunks, never classic DATA.
        _harness.B.ChunkTypesSeen.Should().Contain(SctpChunkType.IData);
        _harness.B.ChunkTypesSeen.Should().NotContain(SctpChunkType.Data);
    }

    [Fact]
    public async Task FallsBackToClassicDataWhenPeerDoesNotAdvertiseInterleaving()
    {
        _harness = new Harness(interleavingOnA: true, interleavingOnB: false);
        var channel = _harness.A.CreateChannel("telemetry");
        await _harness.ConnectAsync();
        WaitFor(() => _harness.B.Channels.ContainsKey("telemetry")).Should().BeTrue();
        WaitFor(() => channel.State == DataChannelState.Open).Should().BeTrue();

        channel.SendText("classic hello");
        WaitFor(() => _harness.B.Messages.Count == 1).Should().BeTrue();
        Encoding.UTF8.GetString(_harness.B.Messages[0].Payload).Should().Be("classic hello");

        // The initiator advertised I-DATA but the responder did not, so both fall back to DATA.
        _harness.B.ChunkTypesSeen.Should().Contain(SctpChunkType.Data);
        _harness.B.ChunkTypesSeen.Should().NotContain(SctpChunkType.IData);
        _harness.A.ChunkTypesSeen.Should().NotContain(SctpChunkType.IData);
    }

    [Fact]
    public async Task LargeMessageDoesNotBlockSmallMessagesOnAnotherStream()
    {
        _harness = new Harness(interleavingOnA: true, interleavingOnB: true);
        var bulk = _harness.A.CreateChannel("bulk");
        var control = _harness.A.CreateChannel("control");
        await _harness.ConnectAsync();
        WaitFor(() => _harness.B.Channels.ContainsKey("bulk") && _harness.B.Channels.ContainsKey("control"))
            .Should().BeTrue();
        WaitFor(() => bulk.State == DataChannelState.Open && control.State == DataChannelState.Open).Should().BeTrue();
        Quiesce();

        // A large message that fragments into many chunks, followed by several small messages on a
        // different stream. Interleaving must let the small messages reach the peer before the large
        // one finishes reassembling.
        var large = new byte[80 * 1024];
        new Random(20260823).NextBytes(large);
        large.Length.Should().BeGreaterThan(_harness.A.Association.MaxPayloadPerChunk * 20);

        bulk.Send(large);
        for (var i = 0; i < 5; i++)
        {
            control.SendText($"c{i}");
        }

        WaitFor(() => _harness.B.Messages.Count == 6).Should().BeTrue();

        var order = _harness.B.Messages.ToArray();
        var bulkIndex = Array.FindIndex(order, m => m.Label == "bulk");
        var firstControlIndex = Array.FindIndex(order, m => m.Label == "control");

        bulkIndex.Should().BeGreaterThanOrEqualTo(0);
        firstControlIndex.Should().BeGreaterThanOrEqualTo(0);

        // At least one small message was delivered before the large one completed: no head-of-line
        // blocking. Without interleaving the large message (enqueued first) would occupy the wire in
        // one contiguous run and be delivered ahead of every small message.
        firstControlIndex.Should().BeLessThan(bulkIndex);

        // And the large message still arrives intact.
        order.Single(m => m.Label == "bulk").Payload.Should().Equal(large);
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

    internal sealed record Message(string Label, bool Binary, byte[] Payload);

    internal sealed class Endpoint : IDisposable
    {
        private readonly ConcurrentQueue<Message> _messages = new();
        private readonly ConcurrentDictionary<SctpChunkType, byte> _chunkTypes = new();

        public Endpoint(LoopbackTransport transport, bool isInitiator, bool usesEvenStreamIds, bool enableInterleaving)
        {
            Transport = transport;

            // Record every chunk type delivered to this endpoint, so a test can assert whether user
            // data arrived as classic DATA or as RFC 8260 I-DATA.
            transport.OnReceived += datagram =>
            {
                try
                {
                    foreach (var chunk in SctpPacket.Parse(datagram, verifyChecksum: false).Chunks)
                    {
                        _chunkTypes[chunk.Type] = 0;
                    }
                }
                catch (Keryx.Core.ByteBufferException)
                {
                }
            };

            Association = new SctpAssociation(transport, new SctpAssociationConfig
            {
                IsInitiator = isInitiator,
                UsesEvenStreamIds = usesEvenStreamIds,
                EnableInterleaving = enableInterleaving,
                TickInterval = TimeSpan.FromMilliseconds(5),
                InitialRto = TimeSpan.FromMilliseconds(100),
                MinRto = TimeSpan.FromMilliseconds(50),
                HeartbeatInterval = TimeSpan.Zero,
            });

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

        public IReadOnlyCollection<SctpChunkType> ChunkTypesSeen => _chunkTypes.Keys.ToArray();

        public DataChannel CreateChannel(string label, bool ordered = true, ushort? maxRetransmits = null)
        {
            var channel = Association.CreateChannel(label, ordered, maxRetransmits);
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

        public Harness(bool interleavingOnA, bool interleavingOnB)
        {
            (_transportA, _transportB) = LoopbackTransport.CreatePair();
            A = new Endpoint(_transportA, isInitiator: true, usesEvenStreamIds: true, enableInterleaving: interleavingOnA);
            B = new Endpoint(_transportB, isInitiator: false, usesEvenStreamIds: false, enableInterleaving: interleavingOnB);
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
