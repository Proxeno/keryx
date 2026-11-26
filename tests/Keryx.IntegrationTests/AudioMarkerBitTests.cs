using System.Collections.Concurrent;
using FluentAssertions;
using Keryx.Core;
using Keryx.Rtp;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// The RTP marker bit on outbound audio, per negotiated codec (EWI-2824): Opus keeps reading its TOC
/// byte's duration, while PCMU, PCMA and G.722 (whose payload is sample data) mark only the first packet,
/// the first packet after a media-clock gap, and the first packet after a barge-in cut.
/// </summary>
public sealed class AudioMarkerBitTests
{
    [Theory]
    [InlineData("opus", 111, 48_000, 960)]
    [InlineData("PCMU", 0, 8_000, 160)]
    [InlineData("PCMA", 8, 8_000, 160)]
    [InlineData("G722", 9, 8_000, 160)]
    public async Task MarkerIsSetOnFirstPacketAfterGapAndAfterCutOnly(
        string encodingName, int payloadType, int clockRate, int step)
    {
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var codec = encodingName == "opus"
            ? SdpCodec.Opus()
            : new SdpCodec(payloadType, encodingName, clockRate);

        var offererConfig = TestSupport.NewConfig();
        offererConfig.AudioCodecs.Clear();
        offererConfig.AudioCodecs.Add(codec);
        var answererConfig = TestSupport.NewConfig();
        answererConfig.AudioCodecs.Clear();
        answererConfig.AudioCodecs.Add(codec);

        await using var offerer = new PeerConnection(offererConfig);
        await using var answerer = new PeerConnection(answererConfig);
        offerer.OnLocalIceCandidate += (_, e) => answerer.AddIceCandidate(e.Candidate, e.SdpMid);
        answerer.OnLocalIceCandidate += (_, e) => offerer.AddIceCandidate(e.Candidate, e.SdpMid);
        var offer = await offerer.CreateOfferAsync(shutdown.Token);
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, shutdown.Token);
        var answer = await answerer.CreateAnswerAsync(shutdown.Token);
        await offerer.SetRemoteDescriptionAsync(answer, SdpType.Answer, shutdown.Token);
        (await offerer.WaitForConnectedAsync(TimeSpan.FromSeconds(30), shutdown.Token)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(TimeSpan.FromSeconds(30), shutdown.Token)).Should().BeTrue();

        var audioSsrc = offerer.GetLocalSsrc(MediaKind.Audio);
        var wire = new ConcurrentQueue<(uint Ssrc, bool Marker)>();
        offerer.RtpWireObserverForTest = (rtp, _) =>
        {
            if (RtpPacket.TryParse(rtp.ToArray(), out var p))
            {
                wire.Enqueue((p.Header.Ssrc, p.Header.Marker));
            }
        };

        var payload = encodingName == "opus" ? OpusFrame() : new byte[160];
        var timestamp = 0u;

        void Send(int frames, int gapFrames = 0)
        {
            for (var i = 0; i < frames; i++)
            {
                if (i == 0)
                {
                    timestamp += (uint)(gapFrames * step);
                }

                offerer.SendAudioFrame(payload, timestamp).Should().Be(1);
                timestamp += (uint)step;
            }
        }

        Send(5);                  // first packet, then a steady stream
        Send(3, gapFrames: 1);    // one skipped frame of silence: timestamp gap greater than one frame
        offerer.CutOutboundAudio();
        Send(3);                  // first packet of the new generation, then steady

        (await TestSupport.WaitForAsync(() => wire.Count(p => p.Ssrc == audioSsrc) >= 11)).Should().BeTrue();

        wire.Where(p => p.Ssrc == audioSsrc).Select(p => p.Marker).Should().Equal(
            true, false, false, false, false,
            true, false, false,
            true, false, false);
    }

    private static byte[] OpusFrame()
    {
        var packet = new byte[80];
        packet[0] = 0xFC; // CELT, one 20 ms frame
        packet[1] = 0x11;
        return packet;
    }
}
