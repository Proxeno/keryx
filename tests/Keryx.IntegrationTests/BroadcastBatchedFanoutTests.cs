using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using FluentAssertions;
using Keryx.Broadcast;
using Keryx.Rtp;
using Keryx.Rtp.Simulcast;
using Keryx.Sdp;
using Keryx.Srtp;
using Xunit;
using Xunit.Abstractions;

namespace Keryx.IntegrationTests;

/// <summary>
/// The gate for PR4 of <c>broadcast-scale.md</c>: the parallel per-subscriber fan-out
/// (<see cref="BroadcastFanout"/>) composed end-to-end with the batched shared-socket egress
/// (<see cref="BroadcastEndpoint.SendBatch"/> over a <c>BatchedDatagramSender</c>). Per ingest packet
/// the SFU produces the N per-viewer SRTP-encrypted datagrams and flushes them in one
/// <c>sendmmsg(2)</c> (Linux) / <c>SendTo</c> loop (elsewhere) out of the one shared socket. These
/// tests pin: every viewer receives and decrypts its own media over the real socket; a viewer's DTLS
/// handshake (control via the per-datagram <c>SendToViewer</c> seam) completes concurrently with the
/// media flood without racing the socket; and a stress loop of interleaved control and media sends
/// never corrupts a datagram.
/// </summary>
public sealed class BroadcastBatchedFanoutTests
{
    private static readonly SimulcastLayerId Hi = SimulcastLayerId.Parse("hi");
    private static readonly SrtpProtectionProfile Profile = SrtpProtectionProfile.AeadAes128Gcm;
    private const uint IngestSsrc = 0x1234_5678u;
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    private readonly ITestOutputHelper _output;

    public BroadcastBatchedFanoutTests(ITestOutputHelper output) => _output = output;

    private static CancellationToken TestTimeout(int seconds = 90) =>
        new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    /// <summary>
    /// N loopback viewers, each with its own SRTP key, are served over ONE shared socket: each ingest
    /// packet is fanned out through <see cref="BroadcastFanout"/> and flushed in one
    /// <see cref="BroadcastEndpoint.SendBatch"/>. Every viewer receives every packet, decrypts it under
    /// its own key, and recovers its own SSRC and the ingest payload verbatim — proving the batched
    /// egress delivers correctly-encrypted, correctly-addressed media per viewer (native sendmmsg on
    /// Linux, managed fallback elsewhere; both must be correct).
    /// </summary>
    [Fact]
    public async Task FannedOutBatch_EachViewerReceivesAndDecryptsItsOwnMedia_OverSharedSocket()
    {
        var cancellationToken = TestTimeout();
        const int viewerCount = 10;
        const int packets = 40;

        await using var endpoint = new BroadcastEndpoint(new BroadcastEndpointOptions());
        _output.WriteLine($"shared-socket batched send: {(endpoint.UsesNativeBatchSend ? "native sendmmsg(2)" : "managed fallback loop")}");

        using var viewers = new MediaViewerSet(viewerCount);
        using var receiving = viewers.StartReceiving(cancellationToken);

        var fanout = new BroadcastFanout();
        var datagrams = new List<BroadcastDatagram>();

        for (var packet = 0; packet < packets; packet++)
        {
            var ingest = BuildIngestPacket((ushort)packet, (uint)(packet * 3000), PacketPayload(packet));
            var classification = new RtpLayerClassification(Hi, IngestSsrc, IsRepair: false, RtpLayerClassificationSource.RidExtension);

            var forwarded = fanout.Forward(in classification, ingest, packet == 0, viewers.Subscribers, datagrams);
            forwarded.Should().Be(viewerCount);
            datagrams.Should().HaveCount(viewerCount);

            endpoint.SendBatch(datagrams).Should().Be(viewerCount, "the whole fan-out batch leaves the shared socket");
            await Task.Delay(2, cancellationToken);
        }

        for (var i = 0; i < viewerCount; i++)
        {
            var viewer = viewers[i];
            (await TestSupport.WaitForAsync(() => viewer.DistinctPackets.Count >= packets)).Should().BeTrue(
                $"viewer {i} must receive its whole fanned-out stream over the shared socket");
            viewer.DecryptFailures.Should().Be(0, $"every datagram viewer {i} received must authenticate under its own key");
            viewer.ForeignSsrc.Should().Be(0, $"viewer {i} must only ever decrypt media carrying its own SSRC");
        }
    }

    /// <summary>
    /// A real viewer <see cref="PeerConnection"/> completes ICE + DTLS over the shared socket — control
    /// traffic on the per-datagram <see cref="BroadcastEndpoint"/> send seam — WHILE a background loop
    /// floods the same socket with batched media fan-out. Because both producers serialise through the
    /// endpoint's one send lock, the handshake still connects and the media still arrives: control and
    /// media do not race the socket. This is the "viewer joining mid-broadcast is unaffected" bar.
    /// </summary>
    [Fact]
    public async Task RealViewerHandshakeMidBroadcast_IsUnaffectedByConcurrentBatchedFanout()
    {
        var cancellationToken = TestTimeout();

        await using var endpoint = new BroadcastEndpoint(new BroadcastEndpointOptions { MaxViewers = 4 });

        using var sinks = new MediaViewerSet(8);
        using var sinkReceiving = sinks.StartReceiving(cancellationToken);

        using var floodStop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var flood = Task.Run(() => FloodBatchedMediaAsync(endpoint, sinks, floodStop.Token), CancellationToken.None);

        try
        {
            // A viewer joins and handshakes while the media flood hammers the shared socket.
            var viewer = await ConnectViewerAsync(endpoint, cancellationToken);
            try
            {
                viewer.Session.BoundEndPoints.Should().HaveCount(1, "the joining viewer's 5-tuple bound through first-contact demux");

                // The concurrent flood kept delivering to the sinks throughout the handshake.
                (await TestSupport.WaitForAsync(() => sinks[0].DistinctPackets.Count >= 20)).Should().BeTrue(
                    "batched media fan-out keeps flowing while a viewer handshakes");
                sinks.Viewers.Should().OnlyContain(v => v.DecryptFailures == 0 && v.ForeignSsrc == 0);
            }
            finally
            {
                await viewer.Viewer.DisposeAsync();
                await viewer.Session.Connection.DisposeAsync();
            }
        }
        finally
        {
            floodStop.Cancel();
            await flood;
        }
    }

    /// <summary>
    /// A long stress loop interleaves control-plane sends (the <see cref="BroadcastEndpoint"/> control
    /// seam) with batched media fan-out on the SAME shared socket, from different threads. A data race
    /// on the socket or the batch sender's reused native buffers would surface as a corrupted or
    /// unauthenticated datagram; here every media datagram must still decrypt under its viewer's own
    /// key and recover the ingest payload, and every control datagram must arrive byte-intact.
    /// </summary>
    [Fact]
    public async Task ConcurrentControlAndMediaSends_NoRaceUnderStress()
    {
        var cancellationToken = TestTimeout();
        const int viewerCount = 16;
        const int packets = 300;

        await using var endpoint = new BroadcastEndpoint(new BroadcastEndpointOptions());

        using var viewers = new MediaViewerSet(viewerCount);
        using var receiving = viewers.StartReceiving(cancellationToken);

        // A dedicated control sink and a distinctive control payload; a torn write under the send lock
        // would corrupt it.
        using var controlSink = new UdpSink();
        var controlEndPoint = controlSink.LocalEndPoint;
        var controlPayload = new byte[200];
        RandomNumberGenerator.Fill(controlPayload);
        var controlSent = 0L;
        var controlIntact = 0L;
        var controlTorn = 0L;
        var controlDone = new CancellationTokenSource();
        var controlReceiver = Task.Run(async () =>
        {
            var buffer = new byte[512];
            while (!controlDone.IsCancellationRequested)
            {
                int n;
                try
                {
                    n = await controlSink.Socket.ReceiveAsync(buffer, controlDone.Token);
                }
                catch (OperationCanceledException)
                {
                    return;
                }

                if (buffer.AsSpan(0, n).SequenceEqual(controlPayload))
                {
                    Interlocked.Increment(ref controlIntact);
                }
                else
                {
                    Interlocked.Increment(ref controlTorn);
                }
            }
        }, CancellationToken.None);

        // Control thread: pound the coordinated control-send path concurrently with the media fan-out.
        using var controlStop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var controlThread = Task.Run(() =>
        {
            while (!controlStop.IsCancellationRequested)
            {
                endpoint.SendControlForTest(controlPayload, controlEndPoint);
                Interlocked.Increment(ref controlSent);
            }
        }, CancellationToken.None);

        var fanout = new BroadcastFanout(maxDegreeOfParallelism: Math.Max(2, Environment.ProcessorCount));
        var datagrams = new List<BroadcastDatagram>();
        try
        {
            for (var packet = 0; packet < packets; packet++)
            {
                var ingest = BuildIngestPacket((ushort)packet, (uint)(packet * 3000), PacketPayload(packet));
                var classification = new RtpLayerClassification(Hi, IngestSsrc, IsRepair: false, RtpLayerClassificationSource.RidExtension);

                fanout.Forward(in classification, ingest, packet == 0, viewers.Subscribers, datagrams);
                endpoint.SendBatch(datagrams);
                if ((packet & 7) == 0)
                {
                    await Task.Delay(1, cancellationToken);
                }
            }
        }
        finally
        {
            controlStop.Cancel();
            await controlThread;
        }

        // Give the receivers a moment to drain, then stop them.
        foreach (var viewer in viewers.Viewers)
        {
            await TestSupport.WaitForAsync(() => viewer.DistinctPackets.Count >= packets, 5_000);
        }

        await TestSupport.WaitForAsync(() => Interlocked.Read(ref controlIntact) > 0, 2_000);
        controlDone.Cancel();
        await controlReceiver;

        _output.WriteLine($"control datagrams sent {Interlocked.Read(ref controlSent):N0}, received intact {Interlocked.Read(ref controlIntact):N0}");

        // No media datagram was corrupted or cross-wired: every one that arrived authenticated under its
        // viewer's own key and carried that viewer's SSRC.
        viewers.Viewers.Should().OnlyContain(v => v.DecryptFailures == 0 && v.ForeignSsrc == 0,
            "interleaved control and media sends must never corrupt a media datagram");

        // Control traffic rode the same socket unharmed: not one torn control datagram.
        Interlocked.Read(ref controlTorn).Should().Be(0, "a control datagram must never be torn by a concurrent media flush");
        Interlocked.Read(ref controlIntact).Should().BeGreaterThan(0, "control traffic kept flowing during the media flood");
    }

    // -------------------------------------------------------------------------------------------------
    // Media flood + a real viewer handshake, reused by the concurrency tests.
    // -------------------------------------------------------------------------------------------------
    private static async Task FloodBatchedMediaAsync(BroadcastEndpoint endpoint, MediaViewerSet sinks, CancellationToken cancellationToken)
    {
        var fanout = new BroadcastFanout();
        var datagrams = new List<BroadcastDatagram>();
        var packet = 0;
        while (!cancellationToken.IsCancellationRequested)
        {
            var ingest = BuildIngestPacket((ushort)packet, (uint)(packet * 3000), PacketPayload(packet));
            var classification = new RtpLayerClassification(Hi, IngestSsrc, IsRepair: false, RtpLayerClassificationSource.RidExtension);
            fanout.Forward(in classification, ingest, packet == 0, sinks.Subscribers, datagrams);
            endpoint.SendBatch(datagrams);
            packet++;
            try
            {
                await Task.Delay(2, cancellationToken); // ~ingest cadence; keeps the socket busy without starving control.
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    private static async Task<ConnectedViewer> ConnectViewerAsync(BroadcastEndpoint endpoint, CancellationToken cancellationToken)
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
            "the egress must complete DTLS over the shared socket while media floods it");
        (await viewer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue(
            "the viewer must connect over the shared socket while media floods it");

        return new ConnectedViewer(session, viewer);
    }

    private sealed record ConnectedViewer(ViewerSession Session, PeerConnection Viewer);

    // -------------------------------------------------------------------------------------------------
    // Ingest packet + payload helpers (shared with BroadcastFanoutTests' shape).
    // -------------------------------------------------------------------------------------------------
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
        var payload = new byte[1000];
        for (var i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)((packet * 31) + (i * 7));
        }

        return payload;
    }

    // -------------------------------------------------------------------------------------------------
    // A set of loopback media viewers: each a real UDP socket, a fan-out subscriber keyed to it, and a
    // matching SRTP decrypt context. The set is the SendBatch destination and the delivery assertion.
    // -------------------------------------------------------------------------------------------------
    private sealed class MediaViewerSet : IDisposable
    {
        private readonly List<BroadcastSubscriber> _subscribers;

        public MediaViewerSet(int count)
        {
            Viewers = new MediaViewer[count];
            _subscribers = new List<BroadcastSubscriber>(count);
            for (var i = 0; i < count; i++)
            {
                var key = new byte[Profile.MasterKeyLength];
                var salt = new byte[Profile.MasterSaltLength];
                RandomNumberGenerator.Fill(key);
                RandomNumberGenerator.Fill(salt);

                var ssrc = 0xA000_0000u + (uint)i;
                var sink = new UdpSink();
                var decrypt = new SrtpDecryptContext(Profile, new SrtpSessionKeys(key, salt));
                Viewers[i] = new MediaViewer(i, ssrc, sink, decrypt);

                var forwarder = new RtpForwarder(ssrc);
                forwarder.SelectLayer(Hi);
                var encrypt = new SrtpEncryptContext(Profile, new SrtpSessionKeys(key, salt));
                _subscribers.Add(new BroadcastSubscriber(forwarder, encrypt, sink.LocalEndPoint));
            }
        }

        public MediaViewer[] Viewers { get; }

        public IReadOnlyList<BroadcastSubscriber> Subscribers => _subscribers;

        public MediaViewer this[int index] => Viewers[index];

        public IDisposable StartReceiving(CancellationToken cancellationToken)
        {
            var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var tasks = Viewers.Select(v => v.ReceiveLoopAsync(stop.Token)).ToArray();
            return new Receiving(stop, tasks);
        }

        public void Dispose()
        {
            foreach (var subscriber in _subscribers)
            {
                subscriber.Dispose();
            }

            foreach (var viewer in Viewers)
            {
                viewer.Dispose();
            }
        }

        private sealed class Receiving(CancellationTokenSource stop, Task[] tasks) : IDisposable
        {
            public void Dispose()
            {
                stop.Cancel();
                try
                {
                    Task.WaitAll(tasks, TimeSpan.FromSeconds(5));
                }
                catch (Exception)
                {
                    // Receive loops only ever fault on cancellation / socket close.
                }

                stop.Dispose();
            }
        }
    }

    private sealed class MediaViewer(int index, uint ssrc, UdpSink sink, SrtpDecryptContext decrypt) : IDisposable
    {
        private readonly byte[] _recovered = new byte[2048];

        public ConcurrentDictionary<int, byte> DistinctPackets { get; } = new();

        public int DecryptFailures;

        public int ForeignSsrc;

        public async Task ReceiveLoopAsync(CancellationToken cancellationToken)
        {
            var buffer = new byte[2048];
            while (!cancellationToken.IsCancellationRequested)
            {
                int n;
                try
                {
                    n = await sink.Socket.ReceiveAsync(buffer, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (SocketException)
                {
                    return;
                }
                catch (ObjectDisposedException)
                {
                    return;
                }

                if (!decrypt.TryUnprotectRtp(buffer.AsSpan(0, n), _recovered, out var length))
                {
                    Interlocked.Increment(ref DecryptFailures);
                    continue;
                }

                if (!RtpHeader.TryParse(_recovered.AsSpan(0, length), out var header) || header.Ssrc != ssrc)
                {
                    Interlocked.Increment(ref ForeignSsrc);
                    continue;
                }

                DistinctPackets.TryAdd(header.SequenceNumber, 0);
            }
        }

        public int Index => index;

        public void Dispose() => decrypt.Dispose();
    }

    // A plain loopback UDP receiver: the stand-in for a viewer's transport address the shared socket
    // sends to. A large receive buffer so a burst of the media flood is not dropped before it is read.
    private sealed class UdpSink : IDisposable
    {
        public UdpSink()
        {
            Socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)
            {
                ReceiveBufferSize = 1 << 20,
            };
            Socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            LocalEndPoint = (IPEndPoint)Socket.LocalEndPoint!;
        }

        public Socket Socket { get; }

        public IPEndPoint LocalEndPoint { get; }

        public void Dispose() => Socket.Dispose();
    }
}
