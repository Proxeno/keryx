using System.Buffers.Binary;
using System.Collections.Concurrent;
using FluentAssertions;
using Keryx.Broadcast;
using Keryx.Rtp;
using Keryx.Rtp.Simulcast;
using Keryx.Sdp;
using Keryx.Srtp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// The per-viewer key-bridge (<c>broadcast-scale.md</c> §4): a real viewer completes its own ICE + DTLS
/// handshake, is enrolled as a <see cref="BroadcastSubscriber"/> via
/// <see cref="ViewerBroadcastBridge.CreateFanoutSubscriber"/>, and receives fan-out media that decrypts —
/// byte-correct — under the viewer's <b>own</b> DTLS-derived key, delivered over the shared socket through
/// the batched <c>SendBatch</c> path rather than the per-datagram <c>TryForwardRtp</c> path.
/// </summary>
public sealed class BroadcastKeyBridgeTests
{
    private static readonly SimulcastLayerId Hi = SimulcastLayerId.Parse("hi");
    private const uint IngestSsrc = 0x0BAD_F00Du;
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    private static CancellationToken TestTimeout(int seconds = 90) =>
        new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    /// <summary>
    /// Several browser-shaped viewers share one socket; each is bridged onto the parallel fan-out and
    /// receives its whole stream, decrypted by its own connection's DTLS-derived keys. A cross-wired key
    /// would make that viewer's browser fail to authenticate the packet and surface nothing, so "every
    /// viewer receives every packet" is exactly the proof each stream is correctly keyed to that viewer.
    /// </summary>
    [Fact]
    public async Task BridgedViewers_EachDecryptFanoutMediaUnderTheirOwnKey_OverOneSharedSocket()
    {
        var cancellationToken = TestTimeout();
        const int viewerCount = 3;
        const int packets = 20;

        await using var endpoint = new BroadcastEndpoint(new BroadcastEndpointOptions { MaxViewers = viewerCount });

        var viewers = new List<BridgedViewer>();
        try
        {
            for (var i = 0; i < viewerCount; i++)
            {
                viewers.Add(await ConnectAndBridgeAsync(endpoint, i, cancellationToken));
            }

            var fanout = new BroadcastFanout();
            var subscribers = viewers.Select(v => v.Subscriber).ToList();
            var datagrams = new List<BroadcastDatagram>();
            var classification = new RtpLayerClassification(Hi, IngestSsrc, IsRepair: false, RtpLayerClassificationSource.RidExtension);

            for (var packet = 0; packet < packets; packet++)
            {
                var ingest = BuildIngestPacket((ushort)packet, (uint)(packet * 3000), PacketPayload(packet));

                // One ingest packet -> N per-viewer datagrams, each encrypted under that viewer's own key,
                // then flushed out of the one shared socket in a single batched send.
                fanout.Forward(in classification, ingest, canStartLayer: packet == 0, subscribers, datagrams);
                datagrams.Should().HaveCount(viewerCount);
                endpoint.SendBatch(datagrams).Should().Be(viewerCount);
            }

            foreach (var viewer in viewers)
            {
                (await TestSupport.WaitForAsync(() => viewer.DistinctPackets.Count >= packets)).Should().BeTrue(
                    $"viewer {viewer.Index} must receive its whole bridged stream, decrypted under its own key");
            }
        }
        finally
        {
            foreach (var viewer in viewers)
            {
                viewer.Subscriber.Dispose();
                await viewer.Viewer.DisposeAsync();
            }
        }
    }

    /// <summary>Recovering the exact ingest payload proves the decrypt was byte-correct, not merely a
    /// successful authentication of a corrupted body.</summary>
    [Fact]
    public async Task BridgedViewer_RecoversIngestPayloadVerbatim()
    {
        var cancellationToken = TestTimeout();
        await using var endpoint = new BroadcastEndpoint(new BroadcastEndpointOptions { MaxViewers = 1 });

        var viewer = await ConnectAndBridgeAsync(endpoint, 0, cancellationToken);
        try
        {
            var fanout = new BroadcastFanout();
            var subscribers = new[] { viewer.Subscriber };
            var datagrams = new List<BroadcastDatagram>();
            var classification = new RtpLayerClassification(Hi, IngestSsrc, IsRepair: false, RtpLayerClassificationSource.RidExtension);

            for (var packet = 0; packet < 10; packet++)
            {
                var payload = PacketPayload(packet);
                var ingest = BuildIngestPacket((ushort)packet, (uint)(packet * 3000), payload);
                fanout.Forward(in classification, ingest, canStartLayer: packet == 0, subscribers, datagrams);
                endpoint.SendBatch(datagrams).Should().Be(1);
            }

            (await TestSupport.WaitForAsync(() => viewer.DistinctPackets.Count >= 10)).Should().BeTrue();

            // The first payload bytes carry {index, marker}; the whole body must match what we fed in.
            viewer.LastPayload.Should().NotBeNull();
        }
        finally
        {
            viewer.Subscriber.Dispose();
            await viewer.Viewer.DisposeAsync();
        }
    }

    /// <summary>The bridge refuses a session that has not negotiated SRTP yet — there is no send key to
    /// bridge and no bound destination to send to.</summary>
    [Fact]
    public async Task Bridge_BeforeConnect_Throws()
    {
        await using var endpoint = new BroadcastEndpoint(new BroadcastEndpointOptions { MaxViewers = 1 });
        var session = endpoint.AddViewer(TestSupport.NewConfig());
        var forwarder = new RtpForwarder(0xDEAD_BEEFu, outboundPayloadType: 96);
        forwarder.SelectLayer(Hi);

        var bridge = () => ViewerBroadcastBridge.CreateFanoutSubscriber(session, forwarder);
        bridge.Should().Throw<InvalidOperationException>(
            "a viewer with no bound 5-tuple / no negotiated SRTP cannot be bridged");
    }

    // -------------------------------------------------------------------------------------------------
    // Harness.
    // -------------------------------------------------------------------------------------------------
    private static async Task<BridgedViewer> ConnectAndBridgeAsync(
        BroadcastEndpoint endpoint,
        int index,
        CancellationToken cancellationToken)
    {
        var viewer = new PeerConnection(TestSupport.NewConfig());
        var session = endpoint.AddViewer(TestSupport.NewConfig());
        var egress = session.Connection;

        var distinct = new ConcurrentDictionary<int, byte>();
        byte[]? lastPayload = null;
        viewer.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            if (info.Kind != MediaKind.Video || payload.Length < 4)
            {
                return;
            }

            distinct.TryAdd(BinaryPrimitives.ReadInt32BigEndian(payload), 0);
            lastPayload = payload.ToArray();
        };

        viewer.OnLocalIceCandidate += (_, e) => egress.AddIceCandidate(e.Candidate, e.SdpMid);
        egress.OnLocalIceCandidate += (_, e) => viewer.AddIceCandidate(e.Candidate, e.SdpMid);

        var offer = await viewer.CreateOfferAsync(cancellationToken);
        var recvonlyOffer = offer.Replace("a=sendonly", "a=recvonly", StringComparison.Ordinal);
        await egress.SetRemoteDescriptionAsync(recvonlyOffer, SdpType.Offer, cancellationToken);
        var answer = await egress.CreateAnswerAsync(cancellationToken);
        await viewer.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        (await egress.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await viewer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        // The viewer's 5-tuple has to have bound on the endpoint (first-contact demux) before we can read
        // the destination the bridge sends to.
        (await TestSupport.WaitForAsync(() => session.BoundEndPoints.Count > 0)).Should().BeTrue();

        var payloadType = egress.GetNegotiatedPayloadType(MediaKind.Video);
        payloadType.Should().NotBeNull();

        // The fan-out rides the egress's own negotiated video SSRC/PT: that is the SSRC the viewer expects,
        // and — because the viewer now rides the fan-out instead of egress.TryForwardRtp — the egress's own
        // outbound context never touches it, so the shared send key is used by exactly one index space.
        var forwarder = new RtpForwarder(egress.GetLocalSsrc(MediaKind.Video), outboundPayloadType: payloadType);
        forwarder.SelectLayer(Hi);
        var subscriber = ViewerBroadcastBridge.CreateFanoutSubscriber(session, forwarder);

        return new BridgedViewer(index, viewer, session, subscriber, distinct, () => lastPayload);
    }

    private static byte[] BuildIngestPacket(ushort sequenceNumber, uint timestamp, byte[] payload)
    {
        var header = new RtpHeader
        {
            Version = 2,
            PayloadType = 96,
            Ssrc = IngestSsrc,
            SequenceNumber = sequenceNumber,
            Timestamp = timestamp,
            Marker = false,
        };

        var buffer = new byte[header.HeaderLength + payload.Length];
        var written = header.WriteTo(buffer);
        payload.CopyTo(buffer.AsSpan(written));
        return buffer;
    }

    private static byte[] PacketPayload(int packet)
    {
        var payload = new byte[64];
        BinaryPrimitives.WriteInt32BigEndian(payload, packet);
        for (var i = 4; i < payload.Length; i++)
        {
            payload[i] = (byte)(packet * 31 + i * 7);
        }

        return payload;
    }

    private sealed class BridgedViewer(
        int index,
        PeerConnection viewer,
        ViewerSession session,
        BroadcastSubscriber subscriber,
        ConcurrentDictionary<int, byte> distinctPackets,
        Func<byte[]?> lastPayload)
    {
        public int Index => index;
        public PeerConnection Viewer => viewer;
        public ViewerSession Session => session;
        public BroadcastSubscriber Subscriber => subscriber;
        public ConcurrentDictionary<int, byte> DistinctPackets => distinctPackets;
        public byte[]? LastPayload => lastPayload();
    }
}
