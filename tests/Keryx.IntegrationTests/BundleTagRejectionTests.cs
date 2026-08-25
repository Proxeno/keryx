using System.Collections.Concurrent;
using FluentAssertions;
using Keryx.Sctp;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// Survival of a peer rejecting the m-line Keryx offered as the BUNDLE tag (RFC 8843 §8.3). Keryx
/// offers video as the tag (mid 0, first in <c>a=group:BUNDLE</c>); a peer that cannot negotiate the
/// video codec rejects that m-line with port 0. The shared transport must re-anchor onto a surviving
/// section so ICE/DTLS/SRTP and the data channel keep working — video alone is lost, not the whole
/// connection.
/// </summary>
public sealed class BundleTagRejectionTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Rewrites an answer into the strict RFC 8843 / Firefox shape: a rejected section carries no
    /// transport and is absent from the BUNDLE group, so the offerer can only connect by re-anchoring
    /// the transport onto a surviving section rather than reading it off the rejected tag.
    /// </summary>
    private static string StrictReject(string answerSdp)
    {
        var answer = SessionDescription.Parse(answerSdp);
        foreach (var m in answer.MediaDescriptions.Where(static m => m.IsRejected))
        {
            m.RemoveAttributes(SdpAttributeNames.IceUfrag);
            m.RemoveAttributes(SdpAttributeNames.IcePwd);
            m.RemoveAttributes(SdpAttributeNames.IceOptions);
            m.RemoveAttributes(SdpAttributeNames.Fingerprint);
            m.RemoveAttributes(SdpAttributeNames.Setup);
            m.RemoveAttributes(SdpAttributeNames.Candidate);
            m.RemoveAttributes(SdpAttributeNames.EndOfCandidates);
        }

        return answer.ToSdpString();
    }

    [Fact]
    public async Task VideoTagRejected_AudioAndDataStillConnect()
    {
        var ct = new CancellationTokenSource(TimeSpan.FromSeconds(50)).Token;

        var answererConfig = TestSupport.NewConfig();
        answererConfig.VideoCodecs.Clear(); // the peer cannot do video, so it rejects Keryx's tag m-line

        await using var offerer = new PeerConnection(TestSupport.NewConfig());
        await using var answerer = new PeerConnection(answererConfig);

        offerer.OnLocalIceCandidate += (_, e) => answerer.AddIceCandidate(e.Candidate, e.SdpMid);
        answerer.OnLocalIceCandidate += (_, e) => offerer.AddIceCandidate(e.Candidate, e.SdpMid);

        var audioReceived = 0;
        answerer.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            if (info.Kind == MediaKind.Audio)
            {
                Interlocked.Increment(ref audioReceived);
            }
        };

        var remoteChannels = new ConcurrentDictionary<string, DataChannel>();
        answerer.OnDataChannel += (_, channel) => remoteChannels[channel.Label] = channel;
        var channelTask = offerer.CreateDataChannel("control");

        var offer = await offerer.CreateOfferAsync(ct);
        offer.Should().Contain("a=group:BUNDLE 0 1 2", "Keryx offers video (mid 0) as the BUNDLE tag");

        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, ct);
        var answer = await answerer.CreateAnswerAsync(ct);

        // The video (tag) m-line is rejected, and Keryx's own answer is RFC 8843-conformant: the rejected
        // mid is dropped from the group, re-anchoring the tag onto audio (mid 1).
        var parsedAnswer = SessionDescription.Parse(answer);
        parsedAnswer.GetMediaByMid("0")!.IsRejected.Should().BeTrue("the peer cannot negotiate video");
        parsedAnswer.GetBundleGroup().Should().Equal(["1", "2"]); // rejected tag dropped, BUNDLE re-anchors

        // Feed the offerer the strict (Firefox-shaped) form: the rejected section carries no transport at
        // all, so the offerer must re-anchor purely from the surviving audio/data sections.
        await offerer.SetRemoteDescriptionAsync(StrictReject(answer), SdpType.Answer, ct);

        (await offerer.WaitForConnectedAsync(ConnectTimeout, ct)).Should().BeTrue(
            "the connection survives rejection of the BUNDLE-tag m-line");
        (await answerer.WaitForConnectedAsync(ConnectTimeout, ct)).Should().BeTrue();

        offerer.NegotiatedSrtpProfile.Should().NotBeNull("SRTP is keyed over the re-anchored transport");

        var channel = await channelTask.WaitAsync(ConnectTimeout, ct);
        (await TestSupport.WaitForAsync(() => channel.State == DataChannelState.Open)).Should().BeTrue(
            "the data channel opens even though the video tag was rejected");

        for (var i = 0; i < 40; i++)
        {
            offerer.SendAudioFrame(new byte[80], (uint)(i * 960));
            await Task.Delay(2, ct);
        }

        (await TestSupport.WaitForAsync(() => Volatile.Read(ref audioReceived) >= 25)).Should().BeTrue(
            "audio flows over the re-anchored SRTP transport");

        await offerer.CloseAsync();
        await answerer.CloseAsync();
    }

    [Fact]
    public async Task VideoOnlyPlusData_VideoTagRejected_DataStillConnects()
    {
        // No audio: rejecting the video tag leaves the application (data) section as the sole survivor,
        // so the transport must re-anchor onto the data m-line.
        var ct = new CancellationTokenSource(TimeSpan.FromSeconds(50)).Token;

        var offererConfig = TestSupport.NewConfig();
        offererConfig.AudioCodecs.Clear();
        var answererConfig = TestSupport.NewConfig();
        answererConfig.AudioCodecs.Clear();
        answererConfig.VideoCodecs.Clear();

        await using var offerer = new PeerConnection(offererConfig);
        await using var answerer = new PeerConnection(answererConfig);

        offerer.OnLocalIceCandidate += (_, e) => answerer.AddIceCandidate(e.Candidate, e.SdpMid);
        answerer.OnLocalIceCandidate += (_, e) => offerer.AddIceCandidate(e.Candidate, e.SdpMid);

        var remoteChannels = new ConcurrentDictionary<string, DataChannel>();
        answerer.OnDataChannel += (_, channel) => remoteChannels[channel.Label] = channel;
        var channelTask = offerer.CreateDataChannel("control");

        var offer = await offerer.CreateOfferAsync(ct);
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, ct);
        var answer = await answerer.CreateAnswerAsync(ct);

        await offerer.SetRemoteDescriptionAsync(StrictReject(answer), SdpType.Answer, ct);

        (await offerer.WaitForConnectedAsync(ConnectTimeout, ct)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(ConnectTimeout, ct)).Should().BeTrue();

        var channel = await channelTask.WaitAsync(ConnectTimeout, ct);
        (await TestSupport.WaitForAsync(() => channel.State == DataChannelState.Open)).Should().BeTrue();

        await offerer.CloseAsync();
        await answerer.CloseAsync();
    }
}
