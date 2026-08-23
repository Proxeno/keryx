using FluentAssertions;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// Covers <see cref="PeerConnection"/>'s track-introspection surface — the negotiated payload type and
/// the local/remote SSRC per media kind — the shape an SFU consumer polls in place of SIPSorcery's
/// <c>GetSendingFormat().ID</c> / <c>LocalTrack.Ssrc</c> / <c>RemoteTrack.Ssrc</c>.
/// </summary>
public sealed class TrackIntrospectionTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    [Fact]
    public async Task BeforeNegotiation_PayloadTypeIsNullAndSsrcAccessorsDoNotThrow()
    {
        await using var connection = new PeerConnection(TestSupport.NewConfig());

        // No offer/answer has happened yet: the negotiated payload type must be a soft null, never a
        // throw, so a consumer can poll this from the moment the connection is constructed.
        connection.GetNegotiatedPayloadType(MediaKind.Video).Should().BeNull();
        connection.GetNegotiatedPayloadType(MediaKind.Audio).Should().BeNull();
        connection.GetNegotiatedPayloadType(MediaKind.Unknown).Should().BeNull();
        connection.GetNegotiatedPayloadType(MediaKind.Application).Should().BeNull();

        // No RTP has arrived, so no remote SSRC has been observed.
        connection.GetRemoteSsrc(MediaKind.Video).Should().BeNull();
        connection.GetRemoteSsrc(MediaKind.Audio).Should().BeNull();
        connection.GetRemoteSsrc(MediaKind.Unknown).Should().BeNull();

        // The local sending SSRC is assigned at construction and does not depend on negotiation.
        connection.GetLocalSsrc(MediaKind.Video).Should().Be(connection.VideoSsrc);
        connection.GetLocalSsrc(MediaKind.Video).Should().NotBe(0u);
        connection.GetLocalSsrc(MediaKind.Audio).Should().Be(connection.AudioSsrc);
        connection.GetLocalSsrc(MediaKind.Audio).Should().NotBe(0u);
        connection.GetLocalSsrc(MediaKind.Unknown).Should().Be(0u);
    }

    [Fact]
    public async Task AfterOfferAnswer_PayloadTypeAndLocalSsrcResolve_AndRemoteSsrcResolvesOnceMediaFlows()
    {
        var cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(50)).Token;

        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        byte? observedVideoPayloadType = null;
        byte? observedAudioPayloadType = null;

        offerer.OnLocalIceCandidate += (_, e) => answerer.AddIceCandidate(e.Candidate, e.SdpMid);

        answerer.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            switch (info.Kind)
            {
                case MediaKind.Video:
                    observedVideoPayloadType = info.PayloadType;
                    break;

                case MediaKind.Audio:
                    observedAudioPayloadType = info.PayloadType;
                    break;

                default:
                    break;
            }
        };

        var offer = await offerer.CreateOfferAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await answerer.CreateAnswerAsync(cancellationToken);
        await offerer.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        (await offerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        // ---------------------------------------------------------------- negotiated PT + local SSRC
        // The offerer offers sendonly here, so it is the side that sends media and resolves a
        // negotiated codec/payload type; the answerer answers recvonly for a sendonly offer, so it
        // sets up no send track (an answerer only sends against a recvonly offer).
        var negotiatedVideoPt = offerer.GetNegotiatedPayloadType(MediaKind.Video);
        var negotiatedAudioPt = offerer.GetNegotiatedPayloadType(MediaKind.Audio);
        negotiatedVideoPt.Should().NotBeNull("the answer settled on a video codec");
        negotiatedAudioPt.Should().NotBeNull("the answer settled on an audio codec");

        offerer.GetLocalSsrc(MediaKind.Video).Should().Be(offerer.VideoSsrc);
        offerer.GetLocalSsrc(MediaKind.Audio).Should().Be(offerer.AudioSsrc);

        // Negotiation alone carries no RTP: the remote SSRC is still unresolved on both sides.
        answerer.GetRemoteSsrc(MediaKind.Video).Should().BeNull();
        answerer.GetRemoteSsrc(MediaKind.Audio).Should().BeNull();

        // ---------------------------------------------------------------- media flow
        var accessUnits = H264TestStream.ReadAccessUnits(10);
        accessUnits.Should().NotBeEmpty();

        var timestamp = 0u;
        foreach (var accessUnit in accessUnits)
        {
            offerer.SendVideoFrame(accessUnit, timestamp).Should().BeGreaterThan(0);
            timestamp += 90000 / 30;
            await Task.Delay(5, cancellationToken);
        }

        var opusPacket = new byte[80];
        Random.Shared.NextBytes(opusPacket);
        opusPacket[0] = 0xFC;
        for (var i = 0; i < 10; i++)
        {
            offerer.SendAudioFrame(opusPacket, (uint)(i * 960)).Should().Be(1);
            await Task.Delay(2, cancellationToken);
        }

        (await TestSupport.WaitForAsync(() => observedVideoPayloadType is not null)).Should().BeTrue();
        (await TestSupport.WaitForAsync(() => observedAudioPayloadType is not null)).Should().BeTrue();

        // What actually travelled on the wire must match what the introspection API reports.
        observedVideoPayloadType.Should().Be(negotiatedVideoPt);
        observedAudioPayloadType.Should().Be(negotiatedAudioPt);

        // ---------------------------------------------------------------- remote SSRC resolves
        (await TestSupport.WaitForAsync(() => answerer.GetRemoteSsrc(MediaKind.Video) is not null)).Should().BeTrue(
            "the video SSRC must resolve once the offerer's RTP has been demultiplexed");
        (await TestSupport.WaitForAsync(() => answerer.GetRemoteSsrc(MediaKind.Audio) is not null)).Should().BeTrue(
            "the audio SSRC must resolve once the offerer's RTP has been demultiplexed");

        answerer.GetRemoteSsrc(MediaKind.Video).Should().Be(offerer.VideoSsrc);
        answerer.GetRemoteSsrc(MediaKind.Audio).Should().Be(offerer.AudioSsrc);

        await offerer.CloseAsync();
        await answerer.CloseAsync();
    }
}
