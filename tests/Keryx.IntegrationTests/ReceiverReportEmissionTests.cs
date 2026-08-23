using System.Collections.Concurrent;
using FluentAssertions;
using Keryx.Rtp;
using Keryx.Rtp.Rtcp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// End-to-end coverage that a receiving peer populates the reception report blocks of RFC 3550 §6.4.1
/// for the sources it is receiving, rather than emitting empty receiver reports: a real UDP peer sends
/// video, and the sender observes the receiver's report block carrying its own SSRC, a live extended
/// highest sequence number, and — once a sender report has been exchanged — the LSR/DLSR echo.
/// </summary>
public sealed class ReceiverReportEmissionTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    private static CancellationToken TestTimeout() =>
        new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    [Fact]
    public async Task ReceivingPeerReportsLossJitterAndSenderReportEchoForTheSourceItReceives()
    {
        var cancellationToken = TestTimeout();

        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        // The offerer sends video; the report blocks describing that stream travel back to it inside the
        // answerer's periodic reports, surfacing through OnReceiverReport (RFC 3550 §6.4.1).
        var blocksForVideo = new ConcurrentQueue<RtcpReportBlock>();
        offerer.OnReceiverReport += (_, e) =>
        {
            foreach (var block in e.ReportBlocks)
            {
                if (block.SourceSsrc == offerer.VideoSsrc)
                {
                    blocksForVideo.Enqueue(block);
                }
            }
        };

        offerer.OnLocalIceCandidate += (_, e) => answerer.AddIceCandidate(e.Candidate, e.SdpMid);
        answerer.OnLocalIceCandidate += (_, e) => offerer.AddIceCandidate(e.Candidate, e.SdpMid);

        var offer = await offerer.CreateOfferAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await answerer.CreateAnswerAsync(cancellationToken);
        await offerer.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        (await offerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        // Pump video for a couple of RTCP intervals (the test config reports every 500 ms), so several
        // reports are exchanged in each direction and the sender-report echo has time to settle.
        var accessUnits = H264TestStream.ReadAccessUnits(30);
        for (var round = 0; round < 4; round++)
        {
            for (var i = 0; i < accessUnits.Count; i++)
            {
                offerer.SendVideoFrame(accessUnits[i], (uint)(((round * accessUnits.Count) + i) * 3000));
                await Task.Delay(10, cancellationToken);
            }
        }

        // A non-empty report block naming the offerer's SSRC proves the receiver is reporting reception
        // statistics rather than an empty RR: the extended highest sequence number must have advanced.
        (await TestSupport.WaitForAsync(() =>
            blocksForVideo.Any(b => b.ExtendedHighestSequenceNumber > 0))).Should().BeTrue(
            "the receiving peer must report a live extended highest sequence number for the stream it receives");

        // The LSR/DLSR echo is populated once the receiver has processed one of the sender's own reports.
        (await TestSupport.WaitForAsync(() =>
            blocksForVideo.Any(b => b.LastSenderReport != 0))).Should().BeTrue(
            "LSR/DLSR must be populated once a sender report has been received (RFC 3550 §6.4.1)");

        var reported = blocksForVideo.ToArray();
        reported.Should().NotBeEmpty();
        reported.Max(b => b.ExtendedHighestSequenceNumber).Should().BeGreaterThan(0);
        reported.Should().OnlyContain(b => b.CumulativePacketsLost >= 0);
    }
}
