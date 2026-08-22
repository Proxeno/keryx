using System.Collections.Concurrent;
using FluentAssertions;
using Keryx.Rtp.CongestionControl;
using Keryx.Rtp.Packetization;
using Keryx.Rtp.Rtcp;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// Coverage for wiring the send-side GCC controller into <see cref="PeerConnection"/>: the RTCP
/// feedback dispatch (transport-cc, REMB, reception-report loss), the exposed controller and its
/// <c>TargetBitrateChanged</c> forwarding, and a live loopback session that proves the pacer and the
/// send-time recording do not break the media path.
/// </summary>
public class CongestionControlWiringTests
{
    private const int PacketSize = 1200;
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    private static PeerConnectionConfig CongestionConfig(TimeProvider time) => new()
    {
        BindAddress = System.Net.IPAddress.Loopback,
        MinPort = TestSupport.MinPort,
        MaxPort = TestSupport.MaxPort,
        EnableCongestionControl = true,
        TimeProvider = time,
        CongestionControl = new CongestionControllerOptions
        {
            StartBitrateBitsPerSecond = 300_000,
            MinBitrateBitsPerSecond = 30_000,
            MaxBitrateBitsPerSecond = 2_000_000,
        },
    };

    [Fact]
    public async Task TheControllerIsNotExposedUnlessEnabled()
    {
        await using var peer = new PeerConnection(TestSupport.NewConfig());
        peer.CongestionController.Should().BeNull();
    }

    [Fact]
    public async Task TheControllerIsExposedWhenEnabled()
    {
        await using var peer = new PeerConnection(CongestionConfig(new ManualTimeProvider()));
        peer.CongestionController.Should().NotBeNull();
        peer.CongestionController!.TargetBitrateBitsPerSecond.Should().Be(300_000);
    }

    [Fact]
    public async Task RembFeedbackFedThroughDispatchDrivesTheTargetAndRaisesTheEvent()
    {
        await using var peer = new PeerConnection(CongestionConfig(new ManualTimeProvider()));
        long observed = 0;
        peer.TargetBitrateChanged += (_, e) => observed = e.TargetBitrateBitsPerSecond;

        // No transport-cc feedback has arrived, so a fresh REMB is the sole driver (the fallback path).
        peer.DispatchRtcp(
            new RtcpReceiverEstimatedMaxBitrate(0x1234, 120_000, peer.VideoSsrc),
            DateTimeOffset.UtcNow);

        peer.CongestionController!.TargetBitrateBitsPerSecond.Should().Be(120_000);
        observed.Should().Be(120_000);
    }

    [Fact]
    public async Task ReceptionReportLossFedThroughDispatchLowersTheTarget()
    {
        await using var peer = new PeerConnection(CongestionConfig(new ManualTimeProvider()));
        long observed = 0;
        peer.TargetBitrateChanged += (_, e) => observed = e.TargetBitrateBitsPerSecond;

        // fractionLost 128/256 = 0.5: heavy loss, which the loss-based rule cuts the estimate for
        // (300000 * (1 - 0.5 * 0.5) = 225000).
        var report = new RtcpReceiverReport { SenderSsrc = 0x1234 };
        report.ReportBlocks.Add(new RtcpReportBlock(
            peer.VideoSsrc,
            fractionLost: 128,
            cumulativePacketsLost: 10,
            extendedHighestSequenceNumber: 500,
            jitter: 0,
            lastSenderReport: 0,
            delaySinceLastSenderReport: 0));

        peer.DispatchRtcp(report, DateTimeOffset.UtcNow);

        peer.CongestionController!.TargetBitrateBitsPerSecond.Should().Be(225_000);
        observed.Should().Be(225_000);
    }

    [Fact]
    public async Task TransportCcFeedbackFedThroughDispatchRampsTheTargetOnLowDelay()
    {
        var time = new ManualTimeProvider();
        await using var peer = new PeerConnection(CongestionConfig(time));
        var controller = peer.CongestionController!;

        long send = 0;
        long arrival = 5_000_000;
        ushort seq = 0;
        for (var round = 0; round < 12; round++)
        {
            var feedback = LowDelayBurst(controller, seq, count: 30, ref send, ref arrival);
            time.Advance(TimeSpan.FromMilliseconds(200));

            // Route the feedback through the real RTCP dispatch, the path this wiring adds.
            peer.DispatchRtcp(feedback, DateTimeOffset.UtcNow);
            seq += 30;
        }

        controller.TargetBitrateBitsPerSecond.Should().BeGreaterThan(300_000);
    }

    [Fact]
    public async Task ASessionWithCongestionControlEnabledStillDeliversMedia()
    {
        var cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(50)).Token;

        await using var offerer = new PeerConnection(CongestionConfig(TimeProvider.System));
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        offerer.OnLocalIceCandidate += (_, e) => answerer.AddIceCandidate(e.Candidate, e.SdpMid);
        answerer.OnLocalIceCandidate += (_, e) => offerer.AddIceCandidate(e.Candidate, e.SdpMid);

        var receivedAccessUnits = new ConcurrentQueue<byte[]>();
        var depacketizer = new H264Depacketizer();
        answerer.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            if (info.Kind == MediaKind.Video
                && depacketizer.TryAddPayload(payload, info.Marker, out var accessUnit))
            {
                receivedAccessUnits.Enqueue(accessUnit.ToArray());
                depacketizer.BeginNextAccessUnit();
            }
        };

        var offer = await offerer.CreateOfferAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await answerer.CreateAnswerAsync(cancellationToken);
        await offerer.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        (await offerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        // The offerer's controller is live and its outbound RTP is paced; media must still arrive.
        offerer.CongestionController.Should().NotBeNull();

        var accessUnits = H264TestStream.ReadAccessUnits(30);
        var timestamp = 0u;
        foreach (var accessUnit in accessUnits)
        {
            offerer.SendVideoFrame(accessUnit, timestamp).Should().BeGreaterThan(0);
            timestamp += 90000 / 30;
            await Task.Delay(5, cancellationToken);
        }

        (await TestSupport.WaitForAsync(() => receivedAccessUnits.Count >= 25)).Should().BeTrue(
            "the paced send path must still reassemble the access units the offerer sent");
    }

    /// <summary>
    /// Builds one low-delay transport-cc feedback burst, recording each packet's send time on the
    /// controller first (as the send path would) and reconstructing matched arrival times.
    /// </summary>
    private static RtcpTransportCcFeedback LowDelayBurst(
        ICongestionController controller,
        ushort baseSequence,
        int count,
        ref long sendMicroseconds,
        ref long arrivalMicroseconds)
    {
        var feedback = new RtcpTransportCcFeedback();
        for (var i = 0; i < count; i++)
        {
            var seq = (ushort)(baseSequence + i);
            controller.OnPacketSent(seq, sendMicroseconds, PacketSize);
            feedback.AddPacket(seq, arrivalMicroseconds);
            sendMicroseconds += 5_000;
            arrivalMicroseconds += 5_000;
        }

        return feedback;
    }
}

/// <summary>A manually advanced clock, so the controller's ramp and TTL windows can be driven exactly.</summary>
internal sealed class ManualTimeProvider : TimeProvider
{
    private long _timestamp;

    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    public override long GetTimestamp() => _timestamp;

    public override DateTimeOffset GetUtcNow() => DateTimeOffset.UnixEpoch.AddTicks(_timestamp);

    internal void Advance(TimeSpan delta) => _timestamp += delta.Ticks;
}
