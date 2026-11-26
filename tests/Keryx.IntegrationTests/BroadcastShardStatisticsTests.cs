using System.Net;
using System.Net.Sockets;
using FluentAssertions;
using Keryx;
using Keryx.Broadcast;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// The gate for the broadcast socket pool's observability and pinning
/// (<c>broadcast-scale.md</c> §2/§4): the mixed shard hash spreads sequential destinations instead of
/// clustering them, and <see cref="BroadcastEndpoint.GetShardStatistics"/> reports per-shard send, drop,
/// flush, control and receive counters that agree with the endpoint-wide totals. Where
/// <c>SO_REUSEPORT</c> is unavailable (macOS/Windows) the pool correctly falls back to one socket, so the
/// multi-shard assertions are gated on Linux and the single-socket invariants hold everywhere.
/// </summary>
public sealed class BroadcastShardStatisticsTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    // -------------------------------------------------------------------------------------------------
    // Shard-hash mixing.
    // -------------------------------------------------------------------------------------------------

    [Fact]
    public void ShardIndexFor_IsStableAndInRange()
    {
        int[] shardCounts = [1, 2, 3, 4, 8];
        foreach (var shardCount in shardCounts)
        {
            for (var port = 20000; port < 21000; port++)
            {
                var destination = new IPEndPoint(IPAddress.Loopback, port);
                var shard = BroadcastEndpoint.ShardIndexFor(destination, shardCount);

                shard.Should().BeInRange(0, shardCount - 1);

                // A new, equal IPEndPoint instance must pin to the same shard.
                var equal = new IPEndPoint(IPAddress.Parse("127.0.0.1"), port);
                BroadcastEndpoint.ShardIndexFor(equal, shardCount).Should().Be(shard);

                if (shardCount == 1)
                {
                    shard.Should().Be(0, "a single-shard pool has only shard 0");
                }
            }
        }
    }

    [Fact]
    public void ShardIndexFor_SpreadsSequentialPortsAndSequentialAddresses()
    {
        const int count = 4096;
        int[] shardCounts = [4, 8];

        // (a) One address, 4096 sequential ports.
        var byPort = new List<IPEndPoint>(count);
        for (var i = 0; i < count; i++)
        {
            byPort.Add(new IPEndPoint(IPAddress.Loopback, 20000 + i));
        }

        // (b) 4096 distinct addresses 10.0.x.y, one fixed port.
        var byAddress = new List<IPEndPoint>(count);
        for (var i = 0; i < count; i++)
        {
            byAddress.Add(new IPEndPoint(new IPAddress([10, 0, (byte)(i / 256), (byte)(i % 256)]), 50000));
        }

        foreach (var shardCount in shardCounts)
        {
            var floor = (int)(0.5 * count / shardCount);
            foreach (var destinations in new[] { byPort, byAddress })
            {
                var perShard = new int[shardCount];
                foreach (var destination in destinations)
                {
                    perShard[BroadcastEndpoint.ShardIndexFor(destination, shardCount)]++;
                }

                // The mean is count/shardCount; the 50% floor is many standard deviations below it for a
                // mixed hash, so this cannot flake — it only fails when a shard is genuinely starved.
                perShard.Should().OnlyContain(n => n >= floor);
            }
        }
    }

    // -------------------------------------------------------------------------------------------------
    // Per-shard statistics.
    // -------------------------------------------------------------------------------------------------

    [Fact]
    public async Task GetShardStatistics_SingleSocket_CountsSentAndFlushes()
    {
        await using var endpoint = new BroadcastEndpoint(new BroadcastEndpointOptions
        {
            MaxViewers = 1,
            SocketPoolSize = 1,
        });

        using var sink = BindSink();
        var batch = MakeDatagrams(5, (IPEndPoint)sink.LocalEndPoint!);

        for (var i = 0; i < 3; i++)
        {
            endpoint.SendBatch(batch).Should().Be(5);
        }

        var statistics = endpoint.GetShardStatistics();
        statistics.Should().ContainSingle();
        statistics[0].ShardIndex.Should().Be(0);
        statistics[0].SentDatagrams.Should().Be(15, "three batches of five datagrams went out");
        statistics[0].BatchFlushes.Should().Be(3, "one non-empty flush per SendBatch call");
        statistics[0].DroppedDatagrams.Should().Be(0);
        endpoint.DroppedDatagrams.Should().Be(0);
    }

    [Fact]
    public async Task GetShardStatistics_PerShardDrops_SumToEndpointDroppedDatagrams()
    {
        await using var endpoint = new BroadcastEndpoint(new BroadcastEndpointOptions
        {
            MaxViewers = 64,
            SocketPoolSize = 4,
        });

        var sinks = new List<Socket>(64);
        try
        {
            var destinations = new List<IPEndPoint>(64);
            for (var i = 0; i < 64; i++)
            {
                var sink = BindSink();
                sinks.Add(sink);
                destinations.Add((IPEndPoint)sink.LocalEndPoint!);
            }

            var batch = MakeDatagrams(64, destinations);

            // Script the socket as permanently backpressured: nothing is accepted, so every datagram of the
            // batch is a per-shard tail drop. Set before the first SendBatch; only changed between calls.
            endpoint._sendWindowOverrideForTest = (_, _) => 0;

            endpoint.SendBatch(batch).Should().Be(0, "a permanently-full send buffer accepts nothing");
            endpoint.DroppedDatagrams.Should().Be(64, "all 64 datagrams were dropped pool-wide");

            var statistics = endpoint.GetShardStatistics();
            statistics.Should().HaveCount(endpoint.SocketPoolSize);
            statistics.Select(s => s.ShardIndex).Should().Equal(Enumerable.Range(0, endpoint.SocketPoolSize));
            statistics.Sum(s => s.DroppedDatagrams).Should().Be(64, "the pool-wide drop total is the sum of the shards");
            statistics.Sum(s => s.SentDatagrams).Should().Be(0, "nothing was accepted");

            if (OperatingSystem.IsLinux())
            {
                endpoint.SocketPoolSize.Should().Be(4, "SO_REUSEPORT lets the pool bind one port on Linux");
                statistics.Count(s => s.DroppedDatagrams > 0).Should().BeGreaterThanOrEqualTo(
                    2, "64 distinct destinations spread over a 4-shard pool touch more than one shard");
            }

            // Clear the backpressure and flush the same batch again: it all goes out, and each shard's
            // counters must agree with the shard the destination hash pins it to — stats shard == pinning
            // shard, over two batches.
            endpoint._sendWindowOverrideForTest = null;
            var sent = endpoint.SendBatch(batch);
            sent.Should().Be(64);

            statistics = endpoint.GetShardStatistics();
            sent.Should().Be((int)statistics.Sum(s => s.SentDatagrams));

            foreach (var shard in statistics)
            {
                var expected = destinations.Count(
                    d => BroadcastEndpoint.ShardIndexFor(d, endpoint.SocketPoolSize) == shard.ShardIndex) * 2;
                (shard.SentDatagrams + shard.DroppedDatagrams).Should().Be(
                    expected,
                    $"shard {shard.ShardIndex} owns exactly the destinations the hash pins to it, over both batches");
            }
        }
        finally
        {
            foreach (var sink in sinks)
            {
                sink.Dispose();
            }
        }
    }

    /// <summary>
    /// ICE and DTLS run both ways through the pool, so a connected viewer leaves receive and control-send
    /// traffic on the shard sockets.
    /// </summary>
    [Fact]
    public async Task GetShardStatistics_CountsReceivedAndControl()
    {
        var cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(90)).Token;
        await using var endpoint = new BroadcastEndpoint(new BroadcastEndpointOptions
        {
            MaxViewers = 1,
            SocketPoolSize = 2,
        });

        var (viewer, _) = await ConnectViewerAsync(endpoint, cancellationToken);
        try
        {
            var statistics = endpoint.GetShardStatistics();
            statistics.Sum(s => s.ReceivedDatagrams).Should().BeGreaterThan(
                0, "viewer checks and DTLS handshake datagrams arrive on the pool's sockets");
            statistics.Sum(s => s.ControlDatagramsSent).Should().BeGreaterThan(
                0, "ICE and DTLS responses left through the shards' per-datagram send seam");
        }
        finally
        {
            await viewer.DisposeAsync();
        }
    }

    // -------------------------------------------------------------------------------------------------
    // Helpers.
    // -------------------------------------------------------------------------------------------------

    private static Socket BindSink()
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return socket;
    }

    private static IReadOnlyList<BroadcastDatagram> MakeDatagrams(int count, IPEndPoint destination)
    {
        var list = new List<BroadcastDatagram>(count);
        for (var i = 0; i < count; i++)
        {
            var payload = new byte[32];
            payload[0] = (byte)i;
            list.Add(new BroadcastDatagram(payload, destination));
        }

        return list;
    }

    private static IReadOnlyList<BroadcastDatagram> MakeDatagrams(int count, IReadOnlyList<IPEndPoint> destinations)
    {
        var list = new List<BroadcastDatagram>(count);
        for (var i = 0; i < count; i++)
        {
            var payload = new byte[32];
            payload[0] = (byte)i;
            list.Add(new BroadcastDatagram(payload, destinations[i]));
        }

        return list;
    }

    // Mirrors BroadcastSocketPoolTests.ConnectViewerAsync: a real viewer completes ICE + DTLS over the
    // endpoint's pool. Copied privately so this file owns its own harness.
    private static async Task<(PeerConnection Viewer, ViewerSession Session)> ConnectViewerAsync(
        BroadcastEndpoint endpoint,
        CancellationToken cancellationToken)
    {
        var viewer = new PeerConnection(TestSupport.NewConfig());
        var session = endpoint.AddViewer(TestSupport.NewConfig());
        var egress = session.Connection;

        viewer.OnLocalIceCandidate += (_, e) => egress.AddIceCandidate(e.Candidate, e.SdpMid);
        egress.OnLocalIceCandidate += (_, e) => viewer.AddIceCandidate(e.Candidate, e.SdpMid);

        var offer = await viewer.CreateOfferAsync(cancellationToken);
        var recvonlyOffer = offer.Replace("a=sendonly", "a=recvonly", StringComparison.Ordinal);
        await egress.SetRemoteDescriptionAsync(recvonlyOffer, SdpType.Offer, cancellationToken);
        var answer = await egress.CreateAnswerAsync(cancellationToken);
        await viewer.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        (await egress.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue(
            "the viewer's egress must connect over the socket pool");
        (await viewer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue(
            "the viewer must connect over the socket pool");

        return (viewer, session);
    }
}
