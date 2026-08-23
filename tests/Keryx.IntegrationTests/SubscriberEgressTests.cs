using System.Buffers.Binary;
using System.Collections.Concurrent;
using FluentAssertions;
using Keryx.Rtp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// The SFU subscriber-egress path: a viewer (<c>subscriber</c>) offers <c>recvonly</c>, Keryx (the
/// gateway's subscriber PeerConnection, <c>egress</c>) answers <c>sendonly</c>, and forwards
/// already-packetized RTP verbatim with <see cref="PeerConnection.TryForwardRtp"/> on the SSRC and
/// sequence space it owns — RFC 4588 repair intact per subscriber.
/// </summary>
public sealed class SubscriberEgressTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    private static CancellationToken TestTimeout(int seconds = 60) =>
        new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    [Fact]
    public async Task AnswererForwardsRtpVerbatimOnItsOwnedSsrcSeqTimestampMarkerAndPayloadType()
    {
        var cancellationToken = TestTimeout();

        await using var egress = new PeerConnection(TestSupport.NewConfig());
        await using var subscriber = new PeerConnection(TestSupport.NewConfig());

        var received = new ConcurrentQueue<ForwardedPacket>();
        subscriber.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            if (info.Kind == MediaKind.Video)
            {
                received.Enqueue(new ForwardedPacket(
                    info.Ssrc,
                    info.SequenceNumber,
                    info.Timestamp,
                    info.Marker,
                    info.PayloadType,
                    payload.ToArray()));
            }
        };

        await ConnectEgressAsync(egress, subscriber, cancellationToken);

        // Introspection on the answerer lights up once the answer settles: the negotiated send PT and
        // the local send SSRC, the shape an SFU consumer polls.
        var payloadType = egress.GetNegotiatedPayloadType(MediaKind.Video);
        payloadType.Should().NotBeNull("the answerer negotiated a video send track against the recvonly offer");
        egress.GetLocalSsrc(MediaKind.Video).Should().Be(egress.VideoSsrc).And.NotBe(0u);

        // ---------------------------------------------------------------- forward verbatim payloads
        const int count = 40;
        var payloads = new byte[count][];
        var timestamps = new uint[count];
        for (var i = 0; i < count; i++)
        {
            var payload = new byte[120];
            Random.Shared.NextBytes(payload);
            BinaryPrimitives.WriteInt32BigEndian(payload, i); // tag each packet with its index
            payloads[i] = payload;
            timestamps[i] = 1_000_000u + ((uint)i * 3000u); // an arbitrary broadcaster timeline
        }

        for (var i = 0; i < count; i++)
        {
            var marker = i == count - 1; // marker on the last, as a video frame boundary would carry
            egress.TryForwardRtp(MediaKind.Video, payloads[i], timestamps[i], marker, payloadType!.Value)
                .Should().BeTrue("a connected, negotiated egress track must accept the forward");
            await Task.Delay(3, cancellationToken);
        }

        (await TestSupport.WaitForAsync(() => received.Count >= count)).Should().BeTrue(
            "every forwarded packet must reach the subscriber");

        // ---------------------------------------------------------------- verify verbatim + ownership
        var byIndex = received
            .ToArray()
            .DistinctBy(p => p.SequenceNumber)
            .ToDictionary(p => BinaryPrimitives.ReadInt32BigEndian(p.Payload));

        byIndex.Should().HaveCount(count);

        var firstSeq = byIndex[0].SequenceNumber;
        for (var i = 0; i < count; i++)
        {
            var packet = byIndex[i];

            // Verbatim: the payload is byte-for-byte what was forwarded, never re-packetized.
            packet.Payload.Should().Equal(payloads[i], "packet {0} must survive forwarding unchanged", i);

            // Keryx owns the SSRC (its local send SSRC) and the sequence space (monotonic, +1 each).
            packet.Ssrc.Should().Be(egress.VideoSsrc);
            packet.SequenceNumber.Should().Be(unchecked((ushort)(firstSeq + i)), "sequence numbers are monotonic");

            // The broadcaster timestamp is forwarded as-is on this subscriber's SSRC.
            packet.Timestamp.Should().Be(timestamps[i]);

            // The marker bit and the subscriber's negotiated payload type are stamped as supplied.
            packet.Marker.Should().Be(i == count - 1);
            packet.PayloadType.Should().Be(payloadType.Value);
        }
    }

    [Fact]
    public async Task ForwardedStreamRecoversLostPacketsThroughPerSubscriberRtx()
    {
        var cancellationToken = TestTimeout(90);

        var offered = new SequenceSet();
        var dropped = new SequenceSet();

        var egressConfig = TestSupport.NewConfig();
        uint mediaSsrc = 0;

        // A seeded lossy link spliced under the egress SRTP, dropping only its forwarded media stream
        // (never the repair stream), exactly as a network would.
        var faultProfile = new FaultProfile
        {
            DropProbability = 0.08,
            Selector = datagram =>
                DatagramClassifier.IsSrtpMedia(datagram)
                && DatagramClassifier.ReadSsrc(datagram) == Volatile.Read(ref mediaSsrc),
            Observer = (fault, datagram) =>
            {
                if (DatagramClassifier.ReadSsrc(datagram) != Volatile.Read(ref mediaSsrc))
                {
                    return;
                }

                var sequenceNumber = DatagramClassifier.ReadSequenceNumber(datagram);
                offered.Add(sequenceNumber);
                if (fault is DatagramFault.Dropped or DatagramFault.BurstDropped)
                {
                    dropped.Add(sequenceNumber);
                }
            },
        };

        FaultInjectingDatagramTransport? injector = null;
        egressConfig.TransportInterceptor = inner =>
            injector = new FaultInjectingDatagramTransport(inner, faultProfile, seed: 0x5FB5);

        await using var egress = new PeerConnection(egressConfig);
        await using var subscriber = new PeerConnection(TestSupport.NewConfig());

        Volatile.Write(ref mediaSsrc, egress.VideoSsrc);

        var arrived = new SequenceSet();
        var recovered = new SequenceSet();
        var haveWindow = 0;
        ushort first = 0;
        var highest = 0;
        byte mediaPayloadType = 0;
        byte? rtxPayloadType = null;

        subscriber.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            if (info.Kind != MediaKind.Video)
            {
                return;
            }

            if (rtxPayloadType is { } rtxPt && info.PayloadType == rtxPt)
            {
                // RFC 4588 §4: reconstruct the original packet from the repair, as any receiver must.
                Span<byte> rtxPacket = stackalloc byte[2048];
                Span<byte> original = stackalloc byte[2048];
                var header = new RtpHeader
                {
                    Version = RtpHeader.SupportedVersion,
                    Marker = info.Marker,
                    PayloadType = info.PayloadType,
                    SequenceNumber = info.SequenceNumber,
                    Timestamp = info.Timestamp,
                    Ssrc = info.Ssrc,
                };

                if (payload.Length + RtpHeader.FixedLength > rtxPacket.Length
                    || !header.TryWriteTo(rtxPacket, out var headerLength))
                {
                    return;
                }

                payload.CopyTo(rtxPacket[headerLength..]);
                if (RtxPacket.TryDecapsulate(
                        rtxPacket[..(headerLength + payload.Length)],
                        Volatile.Read(ref mediaSsrc),
                        mediaPayloadType,
                        original,
                        out var length,
                        out var originalSequenceNumber)
                    && RtpPacket.TryParse(original[..length], out var reconstructed)
                    && reconstructed.Header.SequenceNumber == originalSequenceNumber)
                {
                    recovered.Add(originalSequenceNumber);
                }

                return;
            }

            arrived.Add(info.SequenceNumber);
            if (Interlocked.CompareExchange(ref haveWindow, 1, 0) == 0)
            {
                first = info.SequenceNumber;
            }

            var distance = unchecked((ushort)(info.SequenceNumber - Volatile.Read(ref first)));
            if (distance < 32768 && distance > Volatile.Read(ref highest))
            {
                Volatile.Write(ref highest, distance);
            }
        };

        await ConnectEgressAsync(egress, subscriber, cancellationToken);

        mediaPayloadType = egress.GetNegotiatedPayloadType(MediaKind.Video)!.Value;
        rtxPayloadType = egress.NegotiatedVideoRtxPayloadType;
        rtxPayloadType.Should().NotBeNull("the recvonly offer kept the RFC 4588 rtx codec, so egress wires a repair stream");

        // ---------------------------------------------------------------- the subscriber's loss detector
        using var nackLoop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var nackTask = Task.Run(
            async () =>
            {
                var missing = new List<ushort>(256);
                while (!nackLoop.IsCancellationRequested)
                {
                    try
                    {
                        await Task.Delay(40, nackLoop.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        return;
                    }

                    if (Volatile.Read(ref haveWindow) == 0)
                    {
                        continue;
                    }

                    missing.Clear();
                    var start = Volatile.Read(ref first);
                    var top = Volatile.Read(ref highest);
                    for (var i = 0; i < top; i++)
                    {
                        var sequenceNumber = unchecked((ushort)(start + i));
                        if (!arrived.Contains(sequenceNumber) && !recovered.Contains(sequenceNumber))
                        {
                            missing.Add(sequenceNumber);
                        }
                    }

                    if (missing.Count > 0)
                    {
                        subscriber.SendNack(Volatile.Read(ref mediaSsrc), missing);
                    }
                }
            },
            CancellationToken.None);

        // ---------------------------------------------------------------- forward a run with loss
        const int count = 300;
        uint timestamp = 500_000;
        for (var i = 0; i < count; i++)
        {
            var payload = new byte[100];
            BinaryPrimitives.WriteInt32BigEndian(payload, i);
            egress.TryForwardRtp(MediaKind.Video, payload, timestamp, marker: true, mediaPayloadType)
                .Should().BeTrue();
            timestamp += 3000;
            await Task.Delay(4, cancellationToken);
        }

        // Settle: keep re-NACKing until the detectable window is whole or the deadline passes.
        await TestSupport.WaitForAsync(
            () =>
            {
                var start = Volatile.Read(ref first);
                var top = Volatile.Read(ref highest);
                for (var i = 0; i < top; i++)
                {
                    var sequenceNumber = unchecked((ushort)(start + i));
                    if (!arrived.Contains(sequenceNumber) && !recovered.Contains(sequenceNumber))
                    {
                        return false;
                    }
                }

                return top > 0;
            },
            5000);

        await nackLoop.CancelAsync();
        await nackTask;
        injector?.Flush();

        // ---------------------------------------------------------------- assertions
        dropped.Count.Should().BeGreaterThan(0, "the injector must actually have dropped forwarded packets");

        // Everything the subscriber could detect as missing came back through RTX.
        var start = Volatile.Read(ref first);
        var window = Volatile.Read(ref highest);
        var holes = 0;
        for (var i = 0; i < window; i++)
        {
            var sequenceNumber = unchecked((ushort)(start + i));
            if (!arrived.Contains(sequenceNumber) && !recovered.Contains(sequenceNumber))
            {
                holes++;
            }
        }

        holes.Should().Be(0, "every detectable gap in the forwarded stream must be repaired via per-subscriber RTX");
        recovered.Count.Should().BeGreaterThan(0, "at least some packets must have been recovered through RTX");

        var stats = egress.GetStats();
        var rtx = stats.Video!.Value.Retransmission;
        rtx.Should().NotBeNull();
        rtx!.Value.PacketsRetransmitted.Should().BeGreaterThan(0);
        rtx.Value.NacksReceived.Should().BeGreaterThan(0);

        await egress.CloseAsync();
        await subscriber.CloseAsync();
        injector?.Dispose();
    }

    [Fact]
    public async Task TryForwardRtpAndForwarderHandleReturnFalseBeforeNegotiationAndAfterClose()
    {
        var cancellationToken = TestTimeout();

        await using var egress = new PeerConnection(TestSupport.NewConfig());
        await using var subscriber = new PeerConnection(TestSupport.NewConfig());

        var payload = new byte[64];

        // Before any negotiation the connection has no send track: the forward is refused, never thrown.
        egress.TryForwardRtp(MediaKind.Video, payload, 0, false, 96).Should().BeFalse();
        egress.TryForwardRtp(MediaKind.Audio, payload, 0, false, 111).Should().BeFalse();
        egress.TryForwardRtp(MediaKind.Application, payload, 0, false, 96).Should().BeFalse();

        // The forwarder handle is total and stable, and refuses just as gracefully before negotiation.
        var forwarder = egress.GetForwarder(MediaKind.Video);
        forwarder.Kind.Should().Be(MediaKind.Video);
        forwarder.Ssrc.Should().Be(egress.VideoSsrc);
        forwarder.TryForwardRtp(payload, 0, false, 96).Should().BeFalse();

        await ConnectEgressAsync(egress, subscriber, cancellationToken);

        var payloadType = egress.GetNegotiatedPayloadType(MediaKind.Video)!.Value;
        forwarder.TryForwardRtp(payload, 90000, true, payloadType).Should().BeTrue(
            "once negotiated, the same handle reaches the wire");

        await egress.CloseAsync();

        // After close the transport is gone: the forward is refused, never thrown.
        egress.TryForwardRtp(MediaKind.Video, payload, 90000, true, payloadType).Should().BeFalse();
        forwarder.TryForwardRtp(payload, 90000, true, payloadType).Should().BeFalse();

        await subscriber.CloseAsync();
    }

    /// <summary>
    /// Stands up the SFU subscriber shape: <paramref name="subscriber"/> offers <c>recvonly</c> and
    /// <paramref name="egress"/> answers <c>sendonly</c>, then both connect over real UDP loopback.
    /// </summary>
    private static async Task ConnectEgressAsync(
        PeerConnection egress,
        PeerConnection subscriber,
        CancellationToken cancellationToken)
    {
        subscriber.OnLocalIceCandidate += (_, e) => egress.AddIceCandidate(e.Candidate, e.SdpMid);
        egress.OnLocalIceCandidate += (_, e) => subscriber.AddIceCandidate(e.Candidate, e.SdpMid);

        // Keryx always offers sendonly; a real viewer offers recvonly. Retarget the offer the egress
        // sees to recvonly so it answers sendonly — the direction the subscriber shape depends on.
        var offer = await subscriber.CreateOfferAsync(cancellationToken);
        var recvonlyOffer = offer.Replace("a=sendonly", "a=recvonly", StringComparison.Ordinal);

        await egress.SetRemoteDescriptionAsync(recvonlyOffer, SdpType.Offer, cancellationToken);
        var answer = await egress.CreateAnswerAsync(cancellationToken);
        answer.Should().Contain("a=sendonly", "a recvonly offer must be answered sendonly");

        await subscriber.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        (await egress.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await subscriber.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
    }

    private readonly record struct ForwardedPacket(
        uint Ssrc,
        ushort SequenceNumber,
        uint Timestamp,
        bool Marker,
        byte PayloadType,
        byte[] Payload);

    /// <summary>A tiny thread-safe set over the 16-bit RTP sequence space for the loss accounting.</summary>
    private sealed class SequenceSet
    {
        private readonly ConcurrentDictionary<ushort, bool> _seen = new();

        internal int Count => _seen.Count;

        internal void Add(ushort sequenceNumber) => _seen[sequenceNumber] = true;

        internal bool Contains(ushort sequenceNumber) => _seen.ContainsKey(sequenceNumber);
    }
}
