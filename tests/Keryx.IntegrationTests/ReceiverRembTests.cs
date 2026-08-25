using FluentAssertions;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// End-to-end coverage for the receiver's REMB generation
/// (<see cref="PeerConnectionConfig.EnableReceiverRemb"/>): a peer that stamps abs-send-time on its
/// outbound media receives <c>RtcpReceiverEstimatedMaxBitrate</c> back from Keryx, whose send-side
/// congestion controller consumes it; and with the flag off no abs-send-time is negotiated and no REMB
/// is emitted.
/// </summary>
public sealed class ReceiverRembTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    private static CancellationToken TestTimeout() =>
        new CancellationTokenSource(TimeSpan.FromSeconds(90)).Token;

    private static PeerConnectionConfig RembConfig()
    {
        var config = TestSupport.NewConfig();
        config.EnableReceiverRemb = true;
        return config;
    }

    [Fact]
    public async Task A_sender_stamping_abs_send_time_receives_remb_the_congestion_controller_consumes()
    {
        var cancellationToken = TestTimeout();

        await using var sender = new PeerConnection(RembConfig());
        await using var receiver = new PeerConnection(RembConfig());

        sender.OnLocalIceCandidate += (_, e) => receiver.AddIceCandidate(e.Candidate, e.SdpMid);

        var offer = await sender.CreateOfferAsync(cancellationToken);
        await receiver.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await receiver.CreateAnswerAsync(cancellationToken);
        await sender.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        // Both sides kept the abs-send-time extmap.
        answer.Should().Contain(SdpExtMap.AbsoluteSendTimeUri);

        (await sender.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await receiver.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        var accessUnits = H264TestStream.ReadAccessUnits(90);
        uint timestamp = 0;

        // Keep sending until the receiver has emitted REMB and the sender has received it, or we give up.
        // The default REMB cadence is ~1 s, so this spans several seconds of steady media.
        var deadline = Environment.TickCount64 + 30_000;
        for (var i = 0; Environment.TickCount64 < deadline && !cancellationToken.IsCancellationRequested; i++)
        {
            sender.SendVideoFrame(accessUnits[i % accessUnits.Count], timestamp);
            timestamp += 3000;
            await Task.Delay(4, cancellationToken);

            if (receiver.GetStats().Feedback.RembsSent > 0 && sender.GetStats().Feedback.RembsReceived > 0)
            {
                break;
            }
        }

        receiver.GetStats().Feedback.RembsSent.Should().BeGreaterThan(0,
            "the receiver estimates the forward path from abs-send-time and returns REMB");
        sender.GetStats().Feedback.RembsReceived.Should().BeGreaterThan(0,
            "the sender's congestion controller consumes the REMB it receives");

        await sender.CloseAsync();
        await receiver.CloseAsync();
    }

    [Fact]
    public async Task With_remb_disabled_no_abs_send_time_is_negotiated_and_no_remb_is_sent()
    {
        var cancellationToken = TestTimeout();

        // Default config: EnableReceiverRemb is off on both peers.
        await using var sender = new PeerConnection(TestSupport.NewConfig());
        await using var receiver = new PeerConnection(TestSupport.NewConfig());

        sender.OnLocalIceCandidate += (_, e) => receiver.AddIceCandidate(e.Candidate, e.SdpMid);

        var offer = await sender.CreateOfferAsync(cancellationToken);
        offer.Should().NotContain(SdpExtMap.AbsoluteSendTimeUri);

        await receiver.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await receiver.CreateAnswerAsync(cancellationToken);
        answer.Should().NotContain(SdpExtMap.AbsoluteSendTimeUri);
        await sender.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        (await sender.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await receiver.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        var accessUnits = H264TestStream.ReadAccessUnits(30);
        for (var i = 0; i < 60 && !cancellationToken.IsCancellationRequested; i++)
        {
            sender.SendVideoFrame(accessUnits[i % accessUnits.Count], (uint)(i * 3000));
            await Task.Delay(4, cancellationToken);
        }

        (await TestSupport.WaitForAsync(() => receiver.GetStats().RtpPacketsReceived >= 30)).Should().BeTrue();

        receiver.GetStats().Feedback.RembsSent.Should().Be(0);
        sender.GetStats().Feedback.RembsReceived.Should().Be(0);

        await sender.CloseAsync();
        await receiver.CloseAsync();
    }
}
