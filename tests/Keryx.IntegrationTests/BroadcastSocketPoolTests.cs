using System.Buffers.Binary;
using System.Collections.Concurrent;
using FluentAssertions;
using Keryx.Broadcast;
using Keryx.Rtp;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// The gate for the sharded broadcast socket pool (<c>broadcast-scale.md</c> §2/§4): many viewers served
/// across a <b>pool</b> of UDP sockets bound to one advertised port (Linux <c>SO_REUSEPORT</c>), each
/// viewer's egress pinned to one shard so the fan-out sends spread across cores — while inbound demux stays
/// correct however the kernel load-balances the receive, and pool size 1 stays byte-for-byte the original
/// single-socket path. Where <c>SO_REUSEPORT</c> is unavailable (macOS/Windows) the endpoint falls back to a
/// single socket, so these tests assert media correctness on every platform and the effective pool size only
/// where the kernel supports it.
/// </summary>
public sealed class BroadcastSocketPoolTests
{
    private const int RequestedPool = 4;
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    private static CancellationToken TestTimeout(int seconds = 90) =>
        new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    [Fact]
    public async Task ManyViewersAcrossASocketPool_EachReceivesItsOwnMediaDemuxedByFiveTuple()
    {
        var cancellationToken = TestTimeout();
        const int viewerCount = 6;
        const int packetsPerViewer = 25;

        await using var endpoint = new BroadcastEndpoint(new BroadcastEndpointOptions
        {
            MaxViewers = viewerCount,
            SocketPoolSize = RequestedPool,
        });

        // The pool shards across RequestedPool sockets on Linux (SO_REUSEPORT); elsewhere it correctly falls
        // back to one socket. Either way one advertised host:port serves every viewer.
        if (OperatingSystem.IsLinux())
        {
            endpoint.SocketPoolSize.Should().Be(RequestedPool, "SO_REUSEPORT lets the pool bind one port on Linux");
        }
        else
        {
            endpoint.SocketPoolSize.Should().Be(1, "the endpoint falls back to a single socket without SO_REUSEPORT");
        }

        var viewers = new List<ViewerHarness>();
        try
        {
            for (var i = 0; i < viewerCount; i++)
            {
                viewers.Add(await ConnectViewerAsync(endpoint, i, cancellationToken));
            }

            endpoint.ViewerCount.Should().Be(viewerCount);
            viewers.Should().OnlyContain(v => v.Session.BoundEndPoints.Count == 1);

            await Task.WhenAll(viewers.Select(v => ForwardTaggedStreamAsync(v, packetsPerViewer, cancellationToken)));

            foreach (var viewer in viewers)
            {
                (await TestSupport.WaitForAsync(() => viewer.DistinctIndices.Count >= packetsPerViewer)).Should().BeTrue(
                    $"viewer {viewer.Index} must receive its whole stream across the socket pool");
                viewer.ReceivedViewerTags.Should().OnlyContain(tag => tag == viewer.Index,
                    "a viewer must only ever see media addressed to its own session, whichever shard delivered it");
            }
        }
        finally
        {
            foreach (var viewer in viewers)
            {
                await viewer.Viewer.DisposeAsync();
            }
        }
    }

    [Fact]
    public async Task ViewerJoiningAndLeaving_AcrossASocketPool_LandsOnAShardAndIsDemuxedRight()
    {
        var cancellationToken = TestTimeout();

        await using var endpoint = new BroadcastEndpoint(new BroadcastEndpointOptions
        {
            MaxViewers = 8,
            SocketPoolSize = RequestedPool,
        });

        var initial = new List<ViewerHarness>();
        for (var i = 0; i < 3; i++)
        {
            initial.Add(await ConnectViewerAsync(endpoint, i, cancellationToken));
        }

        try
        {
            var latecomer = await ConnectViewerAsync(endpoint, 3, cancellationToken);
            endpoint.ViewerCount.Should().Be(4);

            var leaving = initial[1];
            (await endpoint.RemoveViewerAsync(leaving.Session)).Should().BeTrue();
            await leaving.Viewer.DisposeAsync();
            endpoint.ViewerCount.Should().Be(3);

            var survivors = new[] { initial[0], initial[2], latecomer };
            await Task.WhenAll(survivors.Select(v => ForwardTaggedStreamAsync(v, 20, cancellationToken)));

            foreach (var viewer in survivors)
            {
                (await TestSupport.WaitForAsync(() => viewer.DistinctIndices.Count >= 20)).Should().BeTrue(
                    $"survivor viewer {viewer.Index} keeps receiving after a peer left the pool");
                viewer.ReceivedViewerTags.Should().OnlyContain(tag => tag == viewer.Index);
            }

            foreach (var viewer in survivors)
            {
                await viewer.Viewer.DisposeAsync();
            }
        }
        finally
        {
            await initial[1].Viewer.DisposeAsync();
        }
    }

    /// <summary>Pool size 1 is exactly the original single-socket endpoint: one socket, media still flows.</summary>
    [Fact]
    public async Task PoolSizeOne_IsTheSingleSocketPath()
    {
        var cancellationToken = TestTimeout();
        await using var endpoint = new BroadcastEndpoint(new BroadcastEndpointOptions
        {
            MaxViewers = 2,
            SocketPoolSize = 1,
        });

        endpoint.SocketPoolSize.Should().Be(1);

        var viewer = await ConnectViewerAsync(endpoint, 0, cancellationToken);
        try
        {
            await ForwardTaggedStreamAsync(viewer, 15, cancellationToken);
            (await TestSupport.WaitForAsync(() => viewer.DistinctIndices.Count >= 15)).Should().BeTrue();
            viewer.ReceivedViewerTags.Should().OnlyContain(tag => tag == viewer.Index);
        }
        finally
        {
            await viewer.Viewer.DisposeAsync();
        }
    }

    private static async Task<ViewerHarness> ConnectViewerAsync(
        BroadcastEndpoint endpoint,
        int index,
        CancellationToken cancellationToken)
    {
        var viewer = new PeerConnection(TestSupport.NewConfig());
        var session = endpoint.AddViewer(TestSupport.NewConfig());
        var egress = session.Connection;

        var received = new ConcurrentQueue<int>();
        var distinct = new ConcurrentDictionary<int, byte>();
        viewer.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            if (info.Kind != MediaKind.Video || payload.Length < 8)
            {
                return;
            }

            received.Enqueue(BinaryPrimitives.ReadInt32BigEndian(payload));
            distinct.TryAdd(BinaryPrimitives.ReadInt32BigEndian(payload[4..]), 0);
        };

        viewer.OnLocalIceCandidate += (_, e) => egress.AddIceCandidate(e.Candidate, e.SdpMid);
        egress.OnLocalIceCandidate += (_, e) => viewer.AddIceCandidate(e.Candidate, e.SdpMid);

        var offer = await viewer.CreateOfferAsync(cancellationToken);
        var recvonlyOffer = offer.Replace("a=sendonly", "a=recvonly", StringComparison.Ordinal);
        await egress.SetRemoteDescriptionAsync(recvonlyOffer, SdpType.Offer, cancellationToken);
        var answer = await egress.CreateAnswerAsync(cancellationToken);
        await viewer.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        (await egress.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue(
            $"viewer {index} egress must connect over the socket pool");
        (await viewer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue(
            $"viewer {index} must connect over the socket pool");

        return new ViewerHarness(index, viewer, session, received, distinct);
    }

    private static async Task ForwardTaggedStreamAsync(ViewerHarness viewer, int packets, CancellationToken cancellationToken)
    {
        var egress = viewer.Session.Connection;
        var payloadType = egress.GetNegotiatedPayloadType(MediaKind.Video);
        payloadType.Should().NotBeNull();

        for (var packetIndex = 0; packetIndex < packets; packetIndex++)
        {
            var payload = new byte[64];
            BinaryPrimitives.WriteInt32BigEndian(payload, viewer.Index);
            BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(4), packetIndex);

            var marker = packetIndex == packets - 1;
            egress.TryForwardRtp(MediaKind.Video, payload, 1_000_000u + ((uint)packetIndex * 3000u), marker, payloadType!.Value)
                .Should().BeTrue();
            await Task.Delay(3, cancellationToken);
        }
    }

    private sealed record ViewerHarness(
        int Index,
        PeerConnection Viewer,
        ViewerSession Session,
        ConcurrentQueue<int> ReceivedViewerTags,
        ConcurrentDictionary<int, byte> DistinctIndices);
}
