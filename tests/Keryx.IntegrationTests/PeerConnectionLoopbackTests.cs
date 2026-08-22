using System.Collections.Concurrent;
using System.Text;
using FluentAssertions;
using Keryx.Dtls;
using Keryx.Rtp.Packetization;
using Keryx.Sctp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// The gate for the whole stack: two <see cref="PeerConnection"/> instances on real UDP sockets on
/// 127.0.0.1, exchanging nothing but SDP strings, then carrying real H.264, Opus, data channel and
/// RTCP feedback traffic end to end.
/// </summary>
public sealed class PeerConnectionLoopbackTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(20);

    [Fact]
    public async Task FullSessionOverRealUdpLoopback()
    {
        var cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(50)).Token;

        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        // ---------------------------------------------------------------- receive surfaces
        var remoteChannels = new ConcurrentDictionary<string, DataChannel>();
        var atAnswerer = new ConcurrentQueue<ChannelMessage>();
        var atOfferer = new ConcurrentQueue<ChannelMessage>();
        var pictureLossIndications = new ConcurrentQueue<PliEventArgs>();
        var fullIntraRequests = new ConcurrentQueue<FirEventArgs>();
        var receivedAccessUnits = new ConcurrentQueue<byte[]>();
        var depacketizer = new H264Depacketizer();
        var trickledOut = 0;
        var audioPacketsReceived = 0;
        uint videoSsrcSeen = 0;

        var gatheringComplete = false;

        // Trickle every gathered candidate straight into the answerer, before it has even seen the
        // offer: they are buffered until its ICE agent exists. The same candidates also travel inside
        // the offer, so this doubles as a duplicate-candidate test.
        offerer.OnLocalIceCandidate += (_, e) =>
        {
            Interlocked.Increment(ref trickledOut);
            answerer.AddIceCandidate(e.Candidate, e.SdpMid);
        };
        offerer.OnIceGatheringComplete += (_, _) => Volatile.Write(ref gatheringComplete, true);
        offerer.OnPictureLossIndication += (_, e) => pictureLossIndications.Enqueue(e);
        offerer.OnFullIntraRequest += (_, e) => fullIntraRequests.Enqueue(e);

        answerer.OnDataChannel += (_, channel) =>
        {
            remoteChannels[channel.Label] = channel;
            channel.OnMessage += (binary, payload) =>
                atAnswerer.Enqueue(new ChannelMessage(channel.Label, binary, payload.ToArray()));
        };

        answerer.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            switch (info.Kind)
            {
                case MediaKind.Video:
                    Volatile.Write(ref videoSsrcSeen, info.Ssrc);
                    if (depacketizer.TryAddPayload(payload, info.Marker, out var accessUnit))
                    {
                        receivedAccessUnits.Enqueue(accessUnit.ToArray());
                        depacketizer.BeginNextAccessUnit();
                    }

                    break;

                case MediaKind.Audio:
                    Interlocked.Increment(ref audioPacketsReceived);
                    break;

                default:
                    break;
            }
        };

        // ---------------------------------------------------------------- data channels up front
        var controllerTask = offerer.CreateDataChannel("controller", ordered: false, maxRetransmits: 0);
        var telemetryTask = offerer.CreateDataChannel("telemetry");

        // ---------------------------------------------------------------- signalling: strings only
        var offer = await offerer.CreateOfferAsync(cancellationToken);
        offer.Should().Contain("a=setup:actpass").And.Contain("a=end-of-candidates");
        Volatile.Read(ref gatheringComplete).Should().BeTrue();

        // Trickle-in must tolerate everything a signalling layer might forward verbatim.
        answerer.AddIceCandidate(string.Empty);
        answerer.AddIceCandidate("   ");
        answerer.AddIceCandidate("a=end-of-candidates", "0");
        answerer.AddIceCandidate("end-of-candidates");
        answerer.AddIceCandidate("this is not a candidate", "0");

        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await answerer.CreateAnswerAsync(cancellationToken);
        answer.Should().Contain("a=setup:active").And.Contain("a=recvonly").And.Contain("a=end-of-candidates");

        await offerer.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        // ---------------------------------------------------------------- ICE + DTLS + SRTP
        (await offerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        trickledOut.Should().BeGreaterThan(0, "candidates must also be surfaced for trickle signalling");
        offerer.LocalDtlsRole.Should().Be(DtlsRole.Server, "the answerer chose setup:active");
        answerer.LocalDtlsRole.Should().Be(DtlsRole.Client);
        offerer.NegotiatedSrtpProfile!.Name.Should().Be("SRTP_AES128_CM_HMAC_SHA1_80");
        answerer.NegotiatedSrtpProfile!.Name.Should().Be("SRTP_AES128_CM_HMAC_SHA1_80");
        offerer.RemoteFingerprint.Should().Be(answerer.LocalFingerprint);
        answerer.RemoteFingerprint.Should().Be(offerer.LocalFingerprint);

        // ---------------------------------------------------------------- (1) real H.264
        var accessUnits = H264TestStream.ReadAccessUnits(30);
        accessUnits.Should().HaveCount(30);
        accessUnits[0].Should().StartWith(new byte[] { 0, 0, 0, 1 });

        var timestamp = 0u;
        foreach (var accessUnit in accessUnits)
        {
            offerer.SendVideoFrame(accessUnit, timestamp).Should().BeGreaterThan(0);
            timestamp += 90000 / 30;
            await Task.Delay(5, cancellationToken);
        }

        (await TestSupport.WaitForAsync(() => receivedAccessUnits.Count >= 25)).Should().BeTrue(
            "the loopback path must reassemble the access units the offerer sent");

        var reassembled = receivedAccessUnits.ToArray();
        reassembled.Length.Should().BeGreaterThanOrEqualTo(25);
        for (var i = 0; i < reassembled.Length; i++)
        {
            reassembled[i].Should().Equal(accessUnits[i], "access unit {0} must survive packetization intact", i);
        }

        Volatile.Read(ref videoSsrcSeen).Should().Be(offerer.VideoSsrc);

        // ---------------------------------------------------------------- (2) Opus-sized audio
        var opusPacket = new byte[80];
        Random.Shared.NextBytes(opusPacket);
        opusPacket[0] = 0xFC;

        for (var i = 0; i < 50; i++)
        {
            offerer.SendAudioFrame(opusPacket, (uint)(i * 960)).Should().Be(1);
            await Task.Delay(2, cancellationToken);
        }

        (await TestSupport.WaitForAsync(() => Volatile.Read(ref audioPacketsReceived) >= 45)).Should().BeTrue();

        // ---------------------------------------------------------------- (3) data channels
        var controller = await controllerTask.WaitAsync(ConnectTimeout, cancellationToken);
        var telemetry = await telemetryTask.WaitAsync(ConnectTimeout, cancellationToken);

        controller.Label.Should().Be("controller");
        controller.Ordered.Should().BeFalse();
        controller.MaxRetransmits.Should().Be(0);
        telemetry.Label.Should().Be("telemetry");
        telemetry.Ordered.Should().BeTrue();
        telemetry.MaxRetransmits.Should().BeNull();

        // The offerer is the DTLS server, so RFC 8832 gives it the odd stream identifiers.
        controller.StreamId.Should().Be(1);
        telemetry.StreamId.Should().Be(3);

        (await TestSupport.WaitForAsync(() => remoteChannels.Count == 2)).Should().BeTrue();
        remoteChannels["controller"].Ordered.Should().BeFalse();
        remoteChannels["controller"].MaxRetransmits.Should().Be(0);
        remoteChannels["controller"].NegotiatedByPeer.Should().BeTrue();
        remoteChannels["telemetry"].Ordered.Should().BeTrue();
        remoteChannels["telemetry"].MaxRetransmits.Should().BeNull();

        (await TestSupport.WaitForAsync(() =>
            controller.State == DataChannelState.Open && telemetry.State == DataChannelState.Open)).Should().BeTrue();

        controller.OnMessage += (binary, payload) =>
            atOfferer.Enqueue(new ChannelMessage("controller", binary, payload.ToArray()));
        telemetry.OnMessage += (binary, payload) =>
            atOfferer.Enqueue(new ChannelMessage("telemetry", binary, payload.ToArray()));

        var bigPayload = new byte[64 * 1024];
        Random.Shared.NextBytes(bigPayload);

        controller.SendText("controller: offerer to answerer");
        controller.Send(new byte[] { 1, 2, 3, 4 });
        telemetry.SendText("telemetry: offerer to answerer");
        telemetry.Send(bigPayload);

        (await TestSupport.WaitForAsync(() => atAnswerer.Count >= 4, 30_000)).Should().BeTrue();
        var inbound = atAnswerer.ToArray();
        inbound.Should().Contain(m =>
            m.Label == "controller" && !m.Binary && Encoding.UTF8.GetString(m.Payload) == "controller: offerer to answerer");
        inbound.Should().Contain(m => m.Label == "controller" && m.Binary && m.Payload.Length == 4);
        inbound.Should().Contain(m =>
            m.Label == "telemetry" && !m.Binary && Encoding.UTF8.GetString(m.Payload) == "telemetry: offerer to answerer");

        var large = inbound.Single(m => m.Label == "telemetry" && m.Binary);
        large.Payload.Should().Equal(bigPayload);

        remoteChannels["controller"].SendText("controller: answerer to offerer");
        remoteChannels["telemetry"].Send(new byte[] { 9, 8, 7, 6, 5 });

        (await TestSupport.WaitForAsync(() => atOfferer.Count >= 2)).Should().BeTrue();
        var returned = atOfferer.ToArray();
        returned.Should().Contain(m =>
            m.Label == "controller" && !m.Binary && Encoding.UTF8.GetString(m.Payload) == "controller: answerer to offerer");
        returned.Should().Contain(m => m.Label == "telemetry" && m.Binary && m.Payload.Length == 5);

        // ---------------------------------------------------------------- (4) typed RTCP feedback
        var videoSsrc = offerer.VideoSsrc;

        answerer.SendPictureLossIndication(videoSsrc).Should().BeTrue();
        (await TestSupport.WaitForAsync(() => !pictureLossIndications.IsEmpty)).Should().BeTrue(
            "a PLI composed by the answerer must surface as a typed event on the offerer");
        pictureLossIndications.TryDequeue(out var pli).Should().BeTrue();
        pli!.MediaSsrc.Should().Be(videoSsrc);
        pli.SenderSsrc.Should().NotBe(0u);

        var firSequenceNumber = answerer.SendFullIntraRequest(videoSsrc);
        firSequenceNumber.Should().NotBeNull();
        (await TestSupport.WaitForAsync(() => !fullIntraRequests.IsEmpty)).Should().BeTrue();
        fullIntraRequests.TryDequeue(out var fir).Should().BeTrue();
        fir!.TargetSsrc.Should().Be(videoSsrc);
        fir.SequenceNumber.Should().Be(firSequenceNumber!.Value);

        // The offerer's periodic SR/SDES compounds reach the answerer over SRTCP.
        (await TestSupport.WaitForAsync(() => answerer.GetStats().RtcpPacketsReceived > 0)).Should().BeTrue();

        // ---------------------------------------------------------------- stats
        var offererStats = offerer.GetStats();
        offererStats.State.Should().Be(PeerConnectionState.Connected);
        offererStats.Video!.Value.FramesSent.Should().Be(30);
        offererStats.Video!.Value.PacketsSent.Should().BeGreaterThan(30);
        offererStats.Audio!.Value.FramesSent.Should().Be(50);
        offererStats.Audio!.Value.PacketsSent.Should().Be(50);
        offererStats.Feedback.PictureLossIndications.Should().Be(1);
        offererStats.Feedback.FullIntraRequests.Should().Be(1);
        offererStats.SrtpAuthenticationFailures.Should().Be(0);

        var answererStats = answerer.GetStats();
        answererStats.RtpPacketsReceived.Should().BeGreaterThan(offererStats.Audio!.Value.PacketsSent);
        answererStats.SrtpAuthenticationFailures.Should().Be(0);

        // ---------------------------------------------------------------- (5) clean close
        await offerer.CloseAsync();
        await answerer.CloseAsync();

        offerer.State.Should().Be(PeerConnectionState.Closed);
        answerer.State.Should().Be(PeerConnectionState.Closed);
        offerer.IceState.Should().Be(Ice.IceAgentState.Closed);
        answerer.IceState.Should().Be(Ice.IceAgentState.Closed);
        offerer.DtlsState.Should().Be(DtlsTransportState.Closed);
    }

    [Fact]
    public async Task ClosingIsIdempotentAndTerminal()
    {
        var cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;

        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        var states = new ConcurrentQueue<PeerConnectionState>();
        offerer.OnConnectionStateChanged += (_, state) => states.Enqueue(state);

        var offer = await offerer.CreateOfferAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await answerer.CreateAnswerAsync(cancellationToken);
        await offerer.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        (await offerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        await offerer.CloseAsync();
        await offerer.CloseAsync();
        await offerer.DisposeAsync();
        await answerer.CloseAsync();

        offerer.State.Should().Be(PeerConnectionState.Closed);
        answerer.State.Should().Be(PeerConnectionState.Closed);
        states.Should().ContainInOrder(
            PeerConnectionState.Connecting,
            PeerConnectionState.Connected,
            PeerConnectionState.Closed);
        states.Count(s => s == PeerConnectionState.Closed).Should().Be(1, "close is idempotent");
    }
}
