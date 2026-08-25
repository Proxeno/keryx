using System.Buffers.Binary;
using System.Collections.Concurrent;
using FluentAssertions;
using Keryx.Broadcast;
using Keryx.Rtp;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// The gate for the shared-socket broadcast fan-out transport (<c>broadcast-scale.md</c> §2): many
/// viewers, each with its own ICE session, DTLS handshake and per-viewer SRTP keys, served over ONE
/// UDP socket. Every viewer completes ICE + DTLS over the shared socket, its inbound datagrams are
/// demultiplexed to the right session by 5-tuple (first learned from its STUN Binding request), and it
/// receives its own media stream — proving isolation across viewers sharing a file descriptor.
/// </summary>
public sealed class BroadcastSharedSocketTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    private static CancellationToken TestTimeout(int seconds = 90) =>
        new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    [Fact]
    public async Task ManyViewersShareOneSocketEachReceivesItsOwnMediaDemuxedByFiveTuple()
    {
        var cancellationToken = TestTimeout();
        const int viewerCount = 5;
        const int packetsPerViewer = 30;

        await using var endpoint = new BroadcastEndpoint(new BroadcastEndpointOptions
        {
            MaxViewers = viewerCount,
        });

        var viewers = new List<ViewerHarness>();
        try
        {
            for (var i = 0; i < viewerCount; i++)
            {
                viewers.Add(await ConnectViewerAsync(endpoint, i, cancellationToken));
            }

            // Every viewer bound its own 5-tuple through first-contact demux, and one socket carries all.
            endpoint.ViewerCount.Should().Be(viewerCount);
            viewers.Should().OnlyContain(v => v.Session.BoundEndPoints.Count == 1);
            viewers.Select(v => v.Session.BoundEndPoints[0]).Distinct().Should().HaveCount(
                viewerCount, "each viewer reaches the shared socket from a distinct remote 5-tuple");

            // Fan out a per-viewer-tagged stream from each session's egress simultaneously.
            await Task.WhenAll(viewers.Select(v => ForwardTaggedStreamAsync(v, packetsPerViewer, cancellationToken)));

            foreach (var viewer in viewers)
            {
                (await TestSupport.WaitForAsync(() => viewer.DistinctIndices.Count >= packetsPerViewer)).Should().BeTrue(
                    $"viewer {viewer.Index} must receive its whole stream over the shared socket");

                // Isolation: every packet this viewer received was tagged for THIS viewer — inbound was
                // demuxed to the right session and no other viewer's media leaked in.
                viewer.ReceivedViewerTags.Should().OnlyContain(tag => tag == viewer.Index,
                    "a viewer must only ever see media addressed to its own session");
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
    public async Task ViewerJoiningAndLeavingMidFlightLeavesOthersUndisturbed()
    {
        var cancellationToken = TestTimeout();

        await using var endpoint = new BroadcastEndpoint(new BroadcastEndpointOptions
        {
            MaxViewers = 8,
        });

        var initial = new List<ViewerHarness>();
        for (var i = 0; i < 3; i++)
        {
            initial.Add(await ConnectViewerAsync(endpoint, i, cancellationToken));
        }

        try
        {
            // A fourth viewer joins while the first three are live.
            var latecomer = await ConnectViewerAsync(endpoint, 3, cancellationToken);
            endpoint.ViewerCount.Should().Be(4);

            // One of the originals leaves mid-flight; its session and 5-tuple binding are freed.
            var leaving = initial[1];
            var leavingEndpoint = leaving.Session.BoundEndPoints[0];
            (await endpoint.RemoveViewerAsync(leaving.Session)).Should().BeTrue();
            await leaving.Viewer.DisposeAsync();
            endpoint.ViewerCount.Should().Be(3);

            // The survivors — two originals plus the latecomer — keep receiving their own media.
            var survivors = new[] { initial[0], initial[2], latecomer };
            await Task.WhenAll(survivors.Select(v => ForwardTaggedStreamAsync(v, 25, cancellationToken)));

            foreach (var viewer in survivors)
            {
                (await TestSupport.WaitForAsync(() => viewer.DistinctIndices.Count >= 25)).Should().BeTrue(
                    $"survivor viewer {viewer.Index} keeps receiving after a peer left");
                viewer.ReceivedViewerTags.Should().OnlyContain(tag => tag == viewer.Index);
            }

            // Re-adding a viewer works: the endpoint frees and reuses capacity cleanly.
            var rejoiner = await ConnectViewerAsync(endpoint, 4, cancellationToken);
            endpoint.ViewerCount.Should().Be(4);
            await ForwardTaggedStreamAsync(rejoiner, 25, cancellationToken);
            (await TestSupport.WaitForAsync(() => rejoiner.DistinctIndices.Count >= 25)).Should().BeTrue();
            rejoiner.ReceivedViewerTags.Should().OnlyContain(tag => tag == rejoiner.Index);

            foreach (var viewer in new[] { initial[0], initial[2], latecomer, rejoiner })
            {
                await viewer.Viewer.DisposeAsync();
            }
        }
        finally
        {
            await initial[1].Viewer.DisposeAsync();
        }
    }

    [Fact]
    public async Task ViewerCapIsEnforced()
    {
        await using var endpoint = new BroadcastEndpoint(new BroadcastEndpointOptions { MaxViewers = 1 });

        _ = endpoint.AddViewer(TestSupport.NewConfig());
        endpoint.ViewerCount.Should().Be(1);

        var addOverCap = () => endpoint.AddViewer(TestSupport.NewConfig());
        addOverCap.Should().Throw<InvalidOperationException>("the broadcast-level viewer cap must bound fan-out state");
    }

    /// <summary>
    /// Stands up one viewer over the shared socket: the viewer offers <c>recvonly</c> from its own
    /// socket, the endpoint's <see cref="ViewerSession"/> answers <c>sendonly</c> in endpoint-session
    /// mode, and both complete ICE + DTLS with the viewer's checks demuxed to its session by ufrag.
    /// </summary>
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

            // Each payload is tagged {viewerIndex, packetIndex} so a misrouted packet is detectable.
            received.Enqueue(BinaryPrimitives.ReadInt32BigEndian(payload));
            distinct.TryAdd(BinaryPrimitives.ReadInt32BigEndian(payload[4..]), 0);
        };

        // Signalling is in-process string exchange, exactly as the peer-to-peer loopback tests do.
        viewer.OnLocalIceCandidate += (_, e) => egress.AddIceCandidate(e.Candidate, e.SdpMid);
        egress.OnLocalIceCandidate += (_, e) => viewer.AddIceCandidate(e.Candidate, e.SdpMid);

        var offer = await viewer.CreateOfferAsync(cancellationToken);
        var recvonlyOffer = offer.Replace("a=sendonly", "a=recvonly", StringComparison.Ordinal);

        await egress.SetRemoteDescriptionAsync(recvonlyOffer, SdpType.Offer, cancellationToken);
        var answer = await egress.CreateAnswerAsync(cancellationToken);
        answer.Should().Contain("a=sendonly", "a recvonly offer must be answered sendonly");

        await viewer.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        (await egress.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue(
            $"viewer {index} egress must connect over the shared socket");
        (await viewer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue(
            $"viewer {index} must connect over the shared socket");

        return new ViewerHarness(index, viewer, session, received, distinct);
    }

    private static async Task ForwardTaggedStreamAsync(ViewerHarness viewer, int packets, CancellationToken cancellationToken)
    {
        var egress = viewer.Session.Connection;
        var payloadType = egress.GetNegotiatedPayloadType(MediaKind.Video);
        payloadType.Should().NotBeNull("the sendonly egress negotiated a video payload type");

        for (var packetIndex = 0; packetIndex < packets; packetIndex++)
        {
            var payload = new byte[64];
            BinaryPrimitives.WriteInt32BigEndian(payload, viewer.Index); // who this stream belongs to
            BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(4), packetIndex); // position within it

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
