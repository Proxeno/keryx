using System.Collections.Concurrent;
using FluentAssertions;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// End-to-end coverage for inbound RFC 4588 RTX decapsulation: a keryx-to-keryx loopback where the
/// sender serves retransmission, one media packet is dropped outright so the receiver NACKs it, and the
/// receiver must turn the RTX repair back into the original media packet — delivering it on its original
/// SSRC, sequence number and payload type — and then stop NACKing it.
/// </summary>
public sealed class RtxIngestTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    private static CancellationToken TestTimeout() =>
        new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    [Fact]
    public async Task A_dropped_packet_is_recovered_from_its_rtx_repair_and_delivered_as_media_without_being_renacked()
    {
        var cancellationToken = TestTimeout();

        // A fault injector under the sender's SRTP drops exactly one media packet — the twentieth — so the
        // receiver has a single, deterministic gap: it is never delivered directly and can only reach the
        // handler through its RTX repair.
        uint mediaSsrc = 0;
        var mediaSeen = 0;
        var dropped = new ConcurrentQueue<ushort>();
        var senderConfig = TestSupport.NewConfig();
        senderConfig.TransportInterceptor = inner => new FaultInjectingDatagramTransport(
            inner,
            new FaultProfile
            {
                DropProbability = 1.0,
                Selector = datagram =>
                {
                    if (!DatagramClassifier.IsSrtpMedia(datagram)
                        || DatagramClassifier.ReadSsrc(datagram) != Volatile.Read(ref mediaSsrc))
                    {
                        return false;
                    }

                    // The selector runs serialised under the pipe lock, so a plain counter is safe.
                    mediaSeen++;
                    return mediaSeen == 20 && dropped.IsEmpty;
                },
                Observer = (fault, datagram) =>
                {
                    if (fault is DatagramFault.Dropped)
                    {
                        dropped.Enqueue(DatagramClassifier.ReadSequenceNumber(datagram));
                    }
                },
            },
            seed: 20260823);

        var receiverConfig = TestSupport.NewConfig();
        receiverConfig.EnableReceiverNack = true;
        receiverConfig.ReceiverNack.RetryInterval = TimeSpan.FromMilliseconds(15);

        await using var sender = new PeerConnection(senderConfig);
        await using var receiver = new PeerConnection(receiverConfig);

        Volatile.Write(ref mediaSsrc, sender.VideoSsrc);

        byte? rtxPayloadType = null;
        var delivered = new ConcurrentDictionary<ushort, int>();

        sender.OnLocalIceCandidate += (_, e) => receiver.AddIceCandidate(e.Candidate, e.SdpMid);

        receiver.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            if (info.Kind != MediaKind.Video)
            {
                return;
            }

            // A decapsulated repair must surface as ordinary media, never as a raw rtx-payload-type packet.
            if (rtxPayloadType is { } rtxPt)
            {
                info.PayloadType.Should().NotBe(rtxPt);
            }

            delivered.AddOrUpdate(info.SequenceNumber, 1, (_, count) => count + 1);
        };

        var offer = await sender.CreateOfferAsync(cancellationToken);
        await receiver.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await receiver.CreateAnswerAsync(cancellationToken);
        await sender.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        rtxPayloadType = sender.NegotiatedVideoRtxPayloadType;
        rtxPayloadType.Should().NotBeNull("Keryx answering Keryx keeps the RFC 4588 rtx codec");

        (await sender.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await receiver.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        // Pump enough video for the twentieth media packet to be dropped and for later packets to reveal
        // the gap, then keep a clean tail flowing so the repair has arrivals to ride.
        var accessUnits = H264TestStream.ReadAccessUnits(90);
        uint timestamp = 0;
        for (var i = 0; i < 90 && !cancellationToken.IsCancellationRequested; i++)
        {
            sender.SendVideoFrame(accessUnits[i % accessUnits.Count], timestamp);
            timestamp += 3000;
            await Task.Delay(4, cancellationToken);
        }

        // The receiver detected the gap, NACKed it, the sender served the RTX repair, and the recovered
        // original packet — one that was dropped outright and so never arrived directly — was decapsulated
        // and delivered as media on its original sequence number.
        (await TestSupport.WaitForAsync(
                () => dropped.TryPeek(out var seq)
                    && delivered.ContainsKey(seq)
                    && receiver.GetStats().Feedback.NacksSent > 0
                    && sender.GetStats().Video!.Value.Retransmission!.Value.PacketsRetransmitted > 0,
                15_000))
            .Should().BeTrue();

        dropped.TryPeek(out var recoveredSequenceNumber).Should().BeTrue();

        // Let any NACK that was already in flight when the repair landed settle, then take a baseline.
        await Task.Delay(200, cancellationToken);
        var nacksAfterRecovery = receiver.GetStats().Feedback.NacksSent;

        // Keep a wholly clean stream flowing. With the single gap already filled and no new loss, the
        // recovered packet must not be NACKed again: the receiver's NACK count must not move.
        for (var i = 90; i < 160 && !cancellationToken.IsCancellationRequested; i++)
        {
            sender.SendVideoFrame(accessUnits[i % accessUnits.Count], timestamp);
            timestamp += 3000;
            await Task.Delay(4, cancellationToken);
        }

        await Task.Delay(200, cancellationToken);
        receiver.GetStats().Feedback.NacksSent
            .Should().Be(nacksAfterRecovery, "a recovered packet is not re-NACKed once its repair fills the gap");
        delivered.Should().ContainKey(recoveredSequenceNumber);

        await sender.CloseAsync();
        await receiver.CloseAsync();
    }
}
