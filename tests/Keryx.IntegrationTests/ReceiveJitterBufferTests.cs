using FluentAssertions;
using Keryx;
using Keryx.Core;
using Keryx.Rtp;
using Keryx.Sdp;
using Xunit;
using Xunit.Abstractions;

namespace Keryx.IntegrationTests;

/// <summary>
/// The receive jitter buffer end to end: a Keryx sender pushes H.264 over a
/// <see cref="FaultInjectingDatagramTransport"/> that reorders the media stream, and a Keryx receiver
/// with <see cref="PeerConnectionConfig.EnableReceiveJitterBuffer"/> set reassembles the order before
/// firing <see cref="PeerConnection.OnRtpPacketReceived"/>, so a depacketizer downstream of the event
/// sees a sequence-ordered stream.
/// </summary>
public sealed class ReceiveJitterBufferTests
{
    private readonly ITestOutputHelper _output;

    /// <summary>Captures the xunit output sink.</summary>
    /// <param name="output">Where the run's measurements are written.</param>
    public ReceiveJitterBufferTests(ITestOutputHelper output) => _output = output;

    private static CancellationToken TestTimeout(int seconds = 60) =>
        new CancellationTokenSource(TimeSpan.FromSeconds(seconds)).Token;

    /// <summary>True when <paramref name="current"/> is a forward step from <paramref name="previous"/> (RFC 3550 §A.1).</summary>
    private static bool IsForward(ushort previous, ushort current) =>
        current != previous && (ushort)(current - previous) < 0x8000;

    [Fact]
    public async Task ReordersTheInboundStreamBackIntoSequenceOrder()
    {
        var cancellationToken = TestTimeout();

        uint mediaSsrc = 0;
        FaultInjectingDatagramTransport? injector = null;

        var profile = new FaultProfile
        {
            ReorderProbability = 0.12,
            ReorderDistance = 3,
            Selector = datagram =>
                DatagramClassifier.IsSrtpMedia(datagram)
                && DatagramClassifier.ReadSsrc(datagram) == Volatile.Read(ref mediaSsrc),
        };

        var senderConfig = TestSupport.NewConfig();
        senderConfig.TransportInterceptor = inner =>
            injector = new FaultInjectingDatagramTransport(inner, profile, seed: 0x30D30);

        // The receiver reorders inbound RTP through a per-SSRC jitter buffer with a wait long enough to
        // outlast the injector's reorder distance, so every held packet's gap fills before it expires.
        var receiverConfig = TestSupport.NewConfig();
        receiverConfig.EnableReceiveJitterBuffer = true;
        receiverConfig.ReceiveJitterBuffer.MaxWait = TimeSpan.FromMilliseconds(500);
        receiverConfig.ReceiveJitterBuffer.Capacity = 256;

        await using var sender = new PeerConnection(senderConfig);
        await using var receiver = new PeerConnection(receiverConfig);

        Volatile.Write(ref mediaSsrc, sender.VideoSsrc);

        var gate = new object();
        var delivered = new List<ushort>();
        var outOfOrder = 0;
        ushort last = 0;
        var haveLast = false;

        receiver.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            if (info.Kind != MediaKind.Video)
            {
                return;
            }

            lock (gate)
            {
                delivered.Add(info.SequenceNumber);
                if (haveLast && !IsForward(last, info.SequenceNumber))
                {
                    outOfOrder++;
                }

                last = info.SequenceNumber;
                haveLast = true;
            }
        };

        sender.OnLocalIceCandidate += (_, e) => receiver.AddIceCandidate(e.Candidate, e.SdpMid);
        receiver.OnLocalIceCandidate += (_, e) => sender.AddIceCandidate(e.Candidate, e.SdpMid);

        var offer = await sender.CreateOfferAsync(cancellationToken);
        await receiver.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await receiver.CreateAnswerAsync(cancellationToken);
        await sender.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        (await sender.WaitForConnectedAsync(TimeSpan.FromSeconds(20), cancellationToken)).Should().BeTrue();
        (await receiver.WaitForConnectedAsync(TimeSpan.FromSeconds(20), cancellationToken)).Should().BeTrue();

        var accessUnits = H264TestStream.ReadAccessUnits(90);
        uint timestamp = 0;
        const int frames = 250;
        for (var i = 0; i < frames && !cancellationToken.IsCancellationRequested; i++)
        {
            sender.SendVideoFrame(accessUnits[i % accessUnits.Count], timestamp);
            timestamp += 3000;
            await Task.Delay(3, cancellationToken);
        }

        // Let the last reordered packets settle out of both the link's delay queue and the buffer.
        await Task.Delay(700, cancellationToken);

        injector.Should().NotBeNull();
        var reordered = injector!.SendCounters.Reordered;

        int deliveredCount;
        lock (gate)
        {
            deliveredCount = delivered.Count;
        }

        _output.WriteLine(
            $"injector reordered {reordered} packet(s); receiver delivered {deliveredCount} video packet(s) "
            + $"with {outOfOrder} order inversion(s).");

        reordered.Should().BeGreaterThan(0, "the scenario must actually reorder the media stream");
        deliveredCount.Should().BeGreaterThan(100, "a meaningful amount of media must have been delivered");
        outOfOrder.Should().Be(0, "the jitter buffer must hand the depacketizer a sequence-ordered stream");

        await sender.CloseAsync();
        await receiver.CloseAsync();
        injector.Dispose();
    }

    [Fact]
    public async Task DeliversInArrivalOrderWhenTheBufferIsOff()
    {
        var cancellationToken = TestTimeout();

        uint mediaSsrc = 0;
        FaultInjectingDatagramTransport? injector = null;

        var profile = new FaultProfile
        {
            ReorderProbability = 0.15,
            ReorderDistance = 4,
            Selector = datagram =>
                DatagramClassifier.IsSrtpMedia(datagram)
                && DatagramClassifier.ReadSsrc(datagram) == Volatile.Read(ref mediaSsrc),
        };

        var senderConfig = TestSupport.NewConfig();
        senderConfig.TransportInterceptor = inner =>
            injector = new FaultInjectingDatagramTransport(inner, profile, seed: 0x0FF12);

        // The default receiver leaves the buffer off, so the arrival stream reaches the handler as-is —
        // this pins the opt-in contract: without the flag, reordering is visible to the handler.
        await using var sender = new PeerConnection(senderConfig);
        await using var receiver = new PeerConnection(TestSupport.NewConfig());

        Volatile.Write(ref mediaSsrc, sender.VideoSsrc);

        var inversions = 0;
        ushort last = 0;
        var haveLast = false;
        var gate = new object();

        receiver.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            if (info.Kind != MediaKind.Video)
            {
                return;
            }

            lock (gate)
            {
                if (haveLast && !IsForward(last, info.SequenceNumber))
                {
                    inversions++;
                }

                last = info.SequenceNumber;
                haveLast = true;
            }
        };

        sender.OnLocalIceCandidate += (_, e) => receiver.AddIceCandidate(e.Candidate, e.SdpMid);
        receiver.OnLocalIceCandidate += (_, e) => sender.AddIceCandidate(e.Candidate, e.SdpMid);

        var offer = await sender.CreateOfferAsync(cancellationToken);
        await receiver.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await receiver.CreateAnswerAsync(cancellationToken);
        await sender.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        (await sender.WaitForConnectedAsync(TimeSpan.FromSeconds(20), cancellationToken)).Should().BeTrue();
        (await receiver.WaitForConnectedAsync(TimeSpan.FromSeconds(20), cancellationToken)).Should().BeTrue();

        var accessUnits = H264TestStream.ReadAccessUnits(90);
        uint timestamp = 0;
        for (var i = 0; i < 250 && !cancellationToken.IsCancellationRequested; i++)
        {
            sender.SendVideoFrame(accessUnits[i % accessUnits.Count], timestamp);
            timestamp += 3000;
            await Task.Delay(3, cancellationToken);
        }

        await Task.Delay(500, cancellationToken);

        injector.Should().NotBeNull();
        injector!.SendCounters.Reordered.Should().BeGreaterThan(0, "the scenario must reorder the media stream");
        _output.WriteLine($"buffer off: {inversions} order inversion(s) reached the handler.");

        // With the buffer off, the reordering the link injected is visible at the handler; the buffer is
        // what removes it (asserted by the companion test).
        inversions.Should().BeGreaterThan(0, "with the jitter buffer off, reordering reaches the handler unchanged");

        await sender.CloseAsync();
        await receiver.CloseAsync();
        injector.Dispose();
    }
}
