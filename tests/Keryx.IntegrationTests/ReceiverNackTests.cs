using System.Collections.Concurrent;
using FluentAssertions;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// End-to-end coverage for the receiver's automatic NACK generation
/// (<see cref="PeerConnectionConfig.EnableReceiverNack"/>): induced inbound loss is detected off the raw
/// arrival stream, NACKed, and repaired by the sender's RFC 4588 retransmission, while a clean stream
/// produces no NACKs at all.
/// </summary>
public sealed class ReceiverNackTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    private static CancellationToken TestTimeout() =>
        new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    [Fact]
    public async Task A_receiver_detecting_inbound_loss_nacks_it_and_the_sender_repairs_it()
    {
        var cancellationToken = TestTimeout();

        // The sender serves RFC 4588 retransmission; a fault injector under its SRTP drops a fraction of
        // the video media stream so the receiver has real gaps to detect.
        uint mediaSsrc = 0;
        var dropped = new ConcurrentDictionary<ushort, byte>();
        var senderConfig = TestSupport.NewConfig();
        senderConfig.TransportInterceptor = inner => new FaultInjectingDatagramTransport(
            inner,
            new FaultProfile
            {
                DropProbability = 0.06,
                Selector = datagram => DatagramClassifier.IsSrtpMedia(datagram)
                    && DatagramClassifier.ReadSsrc(datagram) == Volatile.Read(ref mediaSsrc),

                // Record which media sequence numbers were dropped outright, so the test can prove a
                // genuinely lost packet — never delivered directly — still reached the handler as normal
                // media once its RTX repair was decapsulated on the receiver.
                Observer = (fault, datagram) =>
                {
                    if (fault is DatagramFault.Dropped or DatagramFault.BurstDropped)
                    {
                        dropped[DatagramClassifier.ReadSequenceNumber(datagram)] = 1;
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

        var arrived = new ConcurrentDictionary<ushort, byte>();
        byte? rtxPayloadType = null;

        sender.OnLocalIceCandidate += (_, e) => receiver.AddIceCandidate(e.Candidate, e.SdpMid);

        // The receiver now decapsulates RTX repairs itself: a recovered packet is delivered as ordinary
        // media on its original SSRC/sequence/payload type, not as a raw rtx-payload-type packet.
        receiver.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            if (info.Kind != MediaKind.Video)
            {
                return;
            }

            if (rtxPayloadType is { } rtxPt)
            {
                info.PayloadType.Should().NotBe(rtxPt, "decapsulated packets carry the media payload type");
            }

            arrived[info.SequenceNumber] = 1;
        };

        var offer = await sender.CreateOfferAsync(cancellationToken);
        await receiver.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await receiver.CreateAnswerAsync(cancellationToken);
        await sender.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        rtxPayloadType = sender.NegotiatedVideoRtxPayloadType;
        rtxPayloadType.Should().NotBeNull("Keryx answering Keryx keeps the RFC 4588 rtx codec");

        (await sender.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await receiver.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        // Pump video, then a clean tail so late repairs have arrivals to ride and complete.
        var accessUnits = H264TestStream.ReadAccessUnits(90);
        uint timestamp = 0;
        for (var i = 0; i < 240 && !cancellationToken.IsCancellationRequested; i++)
        {
            sender.SendVideoFrame(accessUnits[i % accessUnits.Count], timestamp);
            timestamp += 3000;
            await Task.Delay(4, cancellationToken);
        }

        // The receiver detected gaps and emitted NACKs of its own accord, the sender served RTX repairs,
        // and at least one genuinely lost packet — dropped outright, so never delivered directly — was
        // recovered from its RTX repair and delivered as ordinary media.
        (await TestSupport.WaitForAsync(
                () => receiver.GetStats().Feedback.NacksSent > 0
                    && sender.GetStats().Video!.Value.Retransmission!.Value.PacketsRetransmitted > 0
                    && dropped.Keys.Any(arrived.ContainsKey),
                15_000))
            .Should().BeTrue();

        var senderRetransmission = sender.GetStats().Video!.Value.Retransmission!.Value;
        senderRetransmission.NacksReceived.Should().BeGreaterThan(0);
        senderRetransmission.NackRequestedPackets.Should().BeGreaterThan(0);

        await sender.CloseAsync();
        await receiver.CloseAsync();
    }

    [Fact]
    public async Task A_clean_stream_produces_no_receiver_nacks()
    {
        var cancellationToken = TestTimeout();

        var receiverConfig = TestSupport.NewConfig();
        receiverConfig.EnableReceiverNack = true;

        await using var sender = new PeerConnection(TestSupport.NewConfig());
        await using var receiver = new PeerConnection(receiverConfig);

        var videoSequenceNumbers = new ConcurrentQueue<ushort>();
        sender.OnLocalIceCandidate += (_, e) => receiver.AddIceCandidate(e.Candidate, e.SdpMid);
        receiver.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            if (info.Kind == MediaKind.Video)
            {
                videoSequenceNumbers.Enqueue(info.SequenceNumber);
            }
        };

        var offer = await sender.CreateOfferAsync(cancellationToken);
        await receiver.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await receiver.CreateAnswerAsync(cancellationToken);
        await sender.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        (await sender.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await receiver.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        var accessUnits = H264TestStream.ReadAccessUnits(90);
        for (var i = 0; i < 60 && !cancellationToken.IsCancellationRequested; i++)
        {
            sender.SendVideoFrame(accessUnits[i % accessUnits.Count], (uint)(i * 3000));
            await Task.Delay(4, cancellationToken);
        }

        (await TestSupport.WaitForAsync(() => videoSequenceNumbers.Count >= 30)).Should().BeTrue();

        // A lossless, in-order loopback leaves no gaps, so the detector never fires: duplicates and the
        // ordinary arrival stream must not be mistaken for loss.
        receiver.GetStats().Feedback.NacksSent.Should().Be(0);

        await sender.CloseAsync();
        await receiver.CloseAsync();
    }
}
