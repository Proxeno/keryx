using System.Collections.Concurrent;
using FluentAssertions;
using Keryx.Rtp.Packetization;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// The send path must packetize by the negotiated codec, not a hardcoded type: a transceiver that
/// offers a codec list and is answered with one member has to send that member — correct payload type
/// and matching packetizer — end to end over the loopback stack.
/// </summary>
public sealed class SendSideCodecSelectionTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    [Fact]
    public async Task OfferH264AndVp8AnsweredWithVp8SendsVp8EndToEnd()
    {
        // The offerer prefers H.264 but also offers VP8; the answerer only accepts VP8, so the session
        // settles on VP8 and the offerer must actually SEND VP8 (VP8's payload type + Vp8Packetizer).
        await using var offerer = new PeerConnection(VideoConfig(SdpCodec.H264(96), SdpCodec.Vp8(98)));
        await using var answerer = new PeerConnection(VideoConfig(SdpCodec.Vp8(98)));

        var received = new ConcurrentQueue<(byte PayloadType, byte[] Frame)>();
        var depacketizer = new Vp8Depacketizer();
        byte lastPayloadType = 0;
        answerer.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            if (info.Kind != MediaKind.Video)
            {
                return;
            }

            lastPayloadType = info.PayloadType;
            if (depacketizer.TryAddPayload(payload, info.Marker, out var frame))
            {
                received.Enqueue((lastPayloadType, frame.ToArray()));
                depacketizer.BeginNextFrame();
            }
        };

        await ConnectAsync(offerer, answerer);

        // The offerer's send codec settled on VP8 at its offered payload type (98).
        offerer.GetNegotiatedPayloadType(MediaKind.Video).Should().Be(98);
        var video = offerer.Transceivers.Single(t => t.Kind == MediaKind.Video);
        video.NegotiatedCodec!.EncodingName.Should().Be("VP8");
        video.NegotiatedCodecs.Should().ContainSingle().Which.EncodingName.Should().Be("VP8");

        var frames = SyntheticVp8Frames(20);
        var timestamp = 0u;
        foreach (var frame in frames)
        {
            offerer.SendVideoFrame(frame, timestamp).Should().BeGreaterThan(0);
            timestamp += 90000 / 30;
            await Task.Delay(5);
        }

        (await TestSupport.WaitForAsync(() => received.Count >= 15)).Should().BeTrue(
            "VP8 frames the offerer sent must reassemble as VP8 on the answerer");

        var got = received.ToArray();
        got.Should().OnlyContain(x => x.PayloadType == 98, "every inbound video packet must carry VP8's payload type");
        for (var i = 0; i < got.Length; i++)
        {
            got[i].Frame.Should().Equal(frames[i], "VP8 frame {0} must survive packetization intact", i);
        }
    }

    [Fact]
    public async Task OfferVp8AndH264AnsweredWithH264SendsH264EndToEnd()
    {
        // Mirror image: the offerer lists VP8 first but the answerer only accepts H.264, so the session
        // settles on H.264 and the offerer must send H.264 (H.264's payload type + H264Packetizer).
        await using var offerer = new PeerConnection(VideoConfig(SdpCodec.Vp8(96), SdpCodec.H264(98)));
        await using var answerer = new PeerConnection(VideoConfig(SdpCodec.H264(98)));

        var received = new ConcurrentQueue<(byte PayloadType, byte[] Frame)>();
        var depacketizer = new H264Depacketizer();
        answerer.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            if (info.Kind != MediaKind.Video)
            {
                return;
            }

            if (depacketizer.TryAddPayload(payload, info.Marker, out var accessUnit))
            {
                received.Enqueue((info.PayloadType, accessUnit.ToArray()));
                depacketizer.BeginNextAccessUnit();
            }
        };

        await ConnectAsync(offerer, answerer);

        offerer.GetNegotiatedPayloadType(MediaKind.Video).Should().Be(98);
        var video = offerer.Transceivers.Single(t => t.Kind == MediaKind.Video);
        video.NegotiatedCodec!.EncodingName.Should().Be("H264");

        var accessUnits = H264TestStream.ReadAccessUnits(20);
        var timestamp = 0u;
        foreach (var accessUnit in accessUnits)
        {
            offerer.SendVideoFrame(accessUnit, timestamp).Should().BeGreaterThan(0);
            timestamp += 90000 / 30;
            await Task.Delay(5);
        }

        (await TestSupport.WaitForAsync(() => received.Count >= 15)).Should().BeTrue(
            "H.264 access units the offerer sent must reassemble as H.264 on the answerer");

        received.ToArray().Should().OnlyContain(
            x => x.PayloadType == 98, "every inbound video packet must carry H.264's payload type");
    }

    /// <summary>A config whose video codecs are exactly <paramref name="codecs"/>, in order.</summary>
    private static PeerConnectionConfig VideoConfig(params SdpCodec[] codecs)
    {
        var config = TestSupport.NewConfig();
        config.VideoCodecs.Clear();
        foreach (var codec in codecs)
        {
            config.VideoCodecs.Add(codec);
        }

        return config;
    }

    /// <summary>Builds <paramref name="count"/> deterministic, VP8-shaped opaque frames.</summary>
    private static byte[][] SyntheticVp8Frames(int count)
    {
        var frames = new byte[count][];
        for (var f = 0; f < count; f++)
        {
            var length = 200 + (f * 37);
            var frame = new byte[length];

            // RFC 6386 §9.1 uncompressed data chunk: bit 0 of byte 0 is the (inverted) key-frame flag.
            frame[0] = (byte)((f == 0 ? 0x00 : 0x01) | 0x02);
            for (var i = 1; i < length; i++)
            {
                frame[i] = (byte)(((i * 11) + f) % 253);
            }

            frames[f] = frame;
        }

        return frames;
    }

    private static async Task ConnectAsync(PeerConnection offerer, PeerConnection answerer)
    {
        var cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(50)).Token;

        offerer.OnLocalIceCandidate += (_, e) => answerer.AddIceCandidate(e.Candidate, e.SdpMid);
        answerer.OnLocalIceCandidate += (_, e) => offerer.AddIceCandidate(e.Candidate, e.SdpMid);

        var offer = await offerer.CreateOfferAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await answerer.CreateAnswerAsync(cancellationToken);
        await offerer.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        (await offerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
    }
}
