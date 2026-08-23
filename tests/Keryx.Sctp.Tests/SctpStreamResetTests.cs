using System.Collections.Concurrent;
using System.Diagnostics;
using FluentAssertions;
using Keryx.Sctp;
using Xunit;

namespace Keryx.Sctp.Tests;

/// <summary>
/// End-to-end tests for RFC 6525 stream reconfiguration (RE-CONFIG): the extension is advertised
/// in INIT, closing a channel resets its SCTP stream on the wire, freed stream identifiers are
/// reused by later channels, and a peer-initiated reset is handled and answered.
/// </summary>
public class SctpStreamResetTests : IDisposable
{
    private readonly List<IDisposable> _disposables = new();

    public void Dispose()
    {
        foreach (var disposable in _disposables)
        {
            disposable.Dispose();
        }
    }

    [Fact]
    public void ReConfigIsAdvertisedInInit()
    {
        var (a, b) = LoopbackTransport.CreatePair();
        _disposables.Add(a);
        _disposables.Add(b);

        SctpInitChunk? capturedInit = null;
        b.OnReceived += datagram =>
        {
            foreach (var chunk in SctpPacket.Parse(datagram).Chunks)
            {
                if (chunk is SctpInitChunk init && init.Type == SctpChunkType.Init)
                {
                    capturedInit = init;
                }
            }
        };

        var association = new SctpAssociation(a, new SctpAssociationConfig
        {
            IsInitiator = true,
            TickInterval = TimeSpan.FromMilliseconds(5),
            HeartbeatInterval = TimeSpan.Zero,
        });
        _disposables.Add(association);

        // Kick off the handshake so INIT is put on the wire; the peer never answers, which is fine.
        _ = association.ConnectAsync(new CancellationTokenSource(TimeSpan.FromMilliseconds(300)).Token);

        WaitFor(() => capturedInit is not null).Should().BeTrue();
        capturedInit!.ReconfigSupported.Should().BeTrue();
        capturedInit.SupportsExtension(SctpChunkType.ReConfig).Should().BeTrue();
    }

    [Fact]
    public async Task ReConfigIsAdvertisedInInitAck()
    {
        using var harness = new Harness();

        SctpInitChunk? capturedInitAck = null;
        harness.TransportA.OnReceived += datagram =>
        {
            foreach (var chunk in SctpPacket.Parse(datagram).Chunks)
            {
                if (chunk is SctpInitChunk initAck && initAck.Type == SctpChunkType.InitAck)
                {
                    capturedInitAck = initAck;
                }
            }
        };

        await harness.ConnectAsync();

        WaitFor(() => capturedInitAck is not null).Should().BeTrue();
        capturedInitAck!.ReconfigSupported.Should().BeTrue();
    }

    [Fact]
    public async Task ClosingChannelsResetsStreamsAndFreesIdsForReuse()
    {
        using var harness = new Harness();

        // A owns even stream ids: these three channels take 0, 2 and 4.
        var first = harness.A.CreateChannel("first");
        var second = harness.A.CreateChannel("second");
        var third = harness.A.CreateChannel("third");
        first.StreamId.Should().Be(0);
        second.StreamId.Should().Be(2);
        third.StreamId.Should().Be(4);

        var resetStreams = new ConcurrentBag<ushort>();
        harness.TransportB.OnReceived += datagram =>
        {
            foreach (var chunk in SctpPacket.Parse(datagram).Chunks)
            {
                if (chunk is SctpReConfigChunk reconfig)
                {
                    foreach (var parameter in reconfig.Parameters)
                    {
                        if (parameter is SctpOutgoingSsnResetRequest request)
                        {
                            foreach (var stream in request.Streams)
                            {
                                resetStreams.Add(stream);
                            }
                        }
                    }
                }
            }
        };

        await harness.ConnectAsync();
        WaitFor(() => harness.B.Channels.Count == 3).Should().BeTrue();
        WaitFor(() => first.State == DataChannelState.Open && second.State == DataChannelState.Open && third.State == DataChannelState.Open)
            .Should().BeTrue();
        Quiesce();

        first.Close();
        second.Close();
        third.Close();

        // Every channel reaches Closed once its outgoing RE-CONFIG has been answered.
        WaitFor(() => first.State == DataChannelState.Closed
            && second.State == DataChannelState.Closed
            && third.State == DataChannelState.Closed).Should().BeTrue();

        // An outgoing RE-CONFIG carrying an Outgoing SSN Reset Request went out for every stream.
        WaitFor(() => resetStreams.Distinct().Count() == 3).Should().BeTrue();
        resetStreams.Should().Contain(new ushort[] { 0, 2, 4 });

        // The peer closed its mirror channels in response to the reset.
        WaitFor(() => harness.B.ClosedLabels.Count == 3).Should().BeTrue();

        // A later channel reuses the smallest freed identifier instead of allocating a fresh one.
        var reused = harness.A.CreateChannel("reused");
        reused.StreamId.Should().Be(0);

        WaitFor(() => harness.B.Channels.ContainsKey("reused")).Should().BeTrue();
        WaitFor(() => reused.State == DataChannelState.Open).Should().BeTrue();

        // The reused stream carries traffic cleanly with its sequence numbers reset.
        reused.SendText("after reuse");
        WaitFor(() => harness.B.Messages.Any(m => System.Text.Encoding.UTF8.GetString(m) == "after reuse")).Should().BeTrue();
    }

    [Fact]
    public async Task PeerInitiatedResetIsHandledAndAnswered()
    {
        using var harness = new Harness();
        await harness.ConnectAsync();

        // B owns odd stream ids: this channel takes id 1.
        var bChannel = harness.B.CreateChannel("from-b");
        bChannel.StreamId.Should().Be(1);
        WaitFor(() => harness.A.Channels.ContainsKey("from-b")).Should().BeTrue();
        WaitFor(() => bChannel.State == DataChannelState.Open).Should().BeTrue();
        Quiesce();

        // Capture the Re-configuration Response A sends back to B.
        var responses = new ConcurrentBag<SctpReconfigResult>();
        ushort? resetStream = null;
        harness.TransportB.OnReceived += datagram =>
        {
            foreach (var chunk in SctpPacket.Parse(datagram).Chunks)
            {
                if (chunk is SctpReConfigChunk reconfig)
                {
                    foreach (var parameter in reconfig.Parameters)
                    {
                        switch (parameter)
                        {
                            case SctpReconfigResponse response:
                                responses.Add(response.Result);
                                break;
                            case SctpIncomingSsnResetRequest incoming when incoming.Streams.Count > 0:
                                resetStream = incoming.Streams[0];
                                break;
                        }
                    }
                }
            }
        };

        var aChannel = harness.A.Channels["from-b"];
        bChannel.Close();

        // A resets its incoming stream and answers with a successful Re-configuration Response.
        WaitFor(() => responses.Contains(SctpReconfigResult.SuccessPerformed)).Should().BeTrue();

        // Both endpoints observe the channel closing.
        WaitFor(() => aChannel.State == DataChannelState.Closed).Should().BeTrue();
        WaitFor(() => bChannel.State == DataChannelState.Closed).Should().BeTrue();
        WaitFor(() => harness.A.ClosedLabels.Contains("from-b")).Should().BeTrue();
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

    private sealed class Endpoint
    {
        private readonly ConcurrentQueue<byte[]> _messages = new();

        public Endpoint(LoopbackTransport transport, bool isInitiator, bool usesEvenStreamIds)
        {
            Association = new SctpAssociation(transport, new SctpAssociationConfig
            {
                IsInitiator = isInitiator,
                UsesEvenStreamIds = usesEvenStreamIds,
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

        public SctpAssociation Association { get; }

        public ConcurrentDictionary<string, DataChannel> Channels { get; } = new();

        public ConcurrentBag<string> ClosedLabels { get; } = new();

        public IReadOnlyList<byte[]> Messages => _messages.ToArray();

        public DataChannel CreateChannel(string label)
        {
            var channel = Association.CreateChannel(label);
            Observe(channel);
            return channel;
        }

        private void Observe(DataChannel channel)
        {
            channel.OnMessage += (_, payload) => _messages.Enqueue(payload.ToArray());
            channel.OnClosed += () => ClosedLabels.Add(channel.Label);
        }
    }

    private sealed class Harness : IDisposable
    {
        public Harness()
        {
            (TransportA, TransportB) = LoopbackTransport.CreatePair();
            A = new Endpoint(TransportA, isInitiator: true, usesEvenStreamIds: true);
            B = new Endpoint(TransportB, isInitiator: false, usesEvenStreamIds: false);
        }

        public LoopbackTransport TransportA { get; }

        public LoopbackTransport TransportB { get; }

        public Endpoint A { get; }

        public Endpoint B { get; }

        public Task ConnectAsync()
        {
            B.Association.Start();
            return A.Association.ConnectAsync(new CancellationTokenSource(TimeSpan.FromSeconds(10)).Token);
        }

        public void Dispose()
        {
            A.Association.Dispose();
            B.Association.Dispose();
            TransportA.Dispose();
            TransportB.Dispose();
        }
    }
}
