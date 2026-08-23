using System.Collections.Concurrent;
using FluentAssertions;
using Keryx.Rtp.Rtcp;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// End-to-end coverage for the receiver's transport-cc feedback generation
/// (<see cref="PeerConnectionConfig.EnableReceiverTransportCcFeedback"/>): a peer sending media into
/// Keryx receives transport-cc feedback on a cadence, its decoded statuses track the arrivals, induced
/// loss shows up as not-received, and the feedback can be suppressed by configuration.
/// </summary>
public sealed class ReceiverTransportCcFeedbackTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    private static CancellationToken TestTimeout() =>
        new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    [Fact]
    public async Task A_sender_receives_transport_cc_feedback_whose_statuses_track_its_packets()
    {
        var cancellationToken = TestTimeout();

        // Drop a fraction of the sender's video media so the transport-wide sequence stream has real gaps
        // the receiver must report as not-received.
        uint mediaSsrc = 0;
        var senderConfig = TestSupport.NewConfig();
        senderConfig.TransportInterceptor = inner => new FaultInjectingDatagramTransport(
            inner,
            new FaultProfile
            {
                DropProbability = 0.05,
                Selector = datagram => DatagramClassifier.IsSrtpMedia(datagram)
                    && DatagramClassifier.ReadSsrc(datagram) == Volatile.Read(ref mediaSsrc),
            },
            seed: 20260824);

        await using var sender = new PeerConnection(senderConfig);
        await using var receiver = new PeerConnection(TestSupport.NewConfig());

        Volatile.Write(ref mediaSsrc, sender.VideoSsrc);

        var feedbacks = new ConcurrentQueue<RtcpTransportCcFeedback>();
        sender.OnTransportCcFeedback += (_, e) => feedbacks.Enqueue(e.Feedback);
        sender.OnLocalIceCandidate += (_, e) => receiver.AddIceCandidate(e.Candidate, e.SdpMid);

        var offer = await sender.CreateOfferAsync(cancellationToken);
        await receiver.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await receiver.CreateAnswerAsync(cancellationToken);
        await sender.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        (await sender.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await receiver.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        var accessUnits = H264TestStream.ReadAccessUnits(90);
        uint timestamp = 0;
        for (var i = 0; i < 240 && !cancellationToken.IsCancellationRequested; i++)
        {
            sender.SendVideoFrame(accessUnits[i % accessUnits.Count], timestamp);
            timestamp += 3000;
            await Task.Delay(4, cancellationToken);
        }

        // The receiver emitted feedback of its own accord, and the sender received several — proof the
        // cadence fired more than once, and the feedback packet count advances across them.
        (await TestSupport.WaitForAsync(
                () => receiver.GetStats().Feedback.TransportCcFeedbacksSent > 1
                    && feedbacks.Count > 1,
                15_000))
            .Should().BeTrue();

        sender.GetStats().Feedback.TransportCcFeedbacks.Should().BeGreaterThan(1);

        var received = feedbacks.ToArray();

        // Every feedback decodes, reports on at least one packet, and its arrival deltas reconstruct in
        // order — the transport-cc contract the sender's estimator relies on.
        received.Should().OnlyContain(f => f.PacketStatusCount > 0);
        received.Should().Contain(f => f.PacketStatuses.Any(s => s.Received));

        // The feedback packet count is monotonic (modulo its byte wrap) across the run.
        received.Select(f => f.FeedbackPacketCount).Distinct().Count().Should().BeGreaterThan(1);

        // Induced loss surfaces as not-received statuses in at least one feedback packet.
        (await TestSupport.WaitForAsync(
                () => feedbacks.Any(f => f.PacketStatuses.Any(s => !s.Received)),
                5_000))
            .Should().BeTrue("dropped media leaves gaps the receiver reports as not-received");

        await sender.CloseAsync();
        await receiver.CloseAsync();
    }

    [Fact]
    public async Task Disabling_receiver_feedback_returns_none_while_the_extension_stays_negotiated()
    {
        var cancellationToken = TestTimeout();

        var receiverConfig = TestSupport.NewConfig();
        receiverConfig.EnableReceiverTransportCcFeedback = false; // still offers/honours the extension for the send path

        await using var sender = new PeerConnection(TestSupport.NewConfig());
        await using var receiver = new PeerConnection(receiverConfig);

        var received = 0;
        sender.OnTransportCcFeedback += (_, _) => Interlocked.Increment(ref received);
        sender.OnLocalIceCandidate += (_, e) => receiver.AddIceCandidate(e.Candidate, e.SdpMid);

        var offer = await sender.CreateOfferAsync(cancellationToken);
        await receiver.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await receiver.CreateAnswerAsync(cancellationToken);
        await sender.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        (await sender.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await receiver.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        var accessUnits = H264TestStream.ReadAccessUnits(90);
        var arrived = new ConcurrentQueue<ushort>();
        receiver.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            if (info.Kind == MediaKind.Video)
            {
                arrived.Enqueue(info.SequenceNumber);
            }
        };

        for (var i = 0; i < 60 && !cancellationToken.IsCancellationRequested; i++)
        {
            sender.SendVideoFrame(accessUnits[i % accessUnits.Count], (uint)(i * 3000));
            await Task.Delay(4, cancellationToken);
        }

        (await TestSupport.WaitForAsync(() => arrived.Count >= 30)).Should().BeTrue();

        // Media flowed and the extension is negotiated, but the receiver was told not to return feedback.
        receiver.GetStats().Feedback.TransportCcFeedbacksSent.Should().Be(0);
        Volatile.Read(ref received).Should().Be(0);

        await sender.CloseAsync();
        await receiver.CloseAsync();
    }
}
