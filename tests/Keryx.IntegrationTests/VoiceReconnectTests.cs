using System.Collections.Concurrent;
using FluentAssertions;
using Keryx.Sctp;
using Keryx.Sdp;
using Xunit;
using Xunit.Abstractions;

namespace Keryx.IntegrationTests;

/// <summary>
/// Reconnection for the voice-agent session shape. A voice call survives the two events an app has to
/// handle: a brand-new <see cref="PeerConnection"/> after the old one closed, and an ICE restart on the
/// live one. In every case audio must flow both ways again and the control data channel must keep
/// carrying messages.
/// <para>
/// The application hooks are the same in each test: <see cref="PeerConnection.OnConnectionStateChanged"/>
/// or <see cref="PeerConnection.WaitForConnectedAsync"/> tells it the transport is confirmed again; a
/// fresh peer connection has a new audio SSRC (a new call), while an ICE restart keeps the SSRC (the
/// same call, new path); and a control-channel message (<c>epoch:2</c>) is the application-level marker
/// that audio received after it belongs to the new epoch.
/// </para>
/// </summary>
public sealed class VoiceReconnectTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    private readonly ITestOutputHelper _output;

    /// <summary>Captures the xunit output sink.</summary>
    /// <param name="output">Where the run's measurements are written.</param>
    public VoiceReconnectTests(ITestOutputHelper output) => _output = output;

    private static CancellationToken TestTimeout() =>
        new CancellationTokenSource(TimeSpan.FromSeconds(120)).Token;

    /// <summary>
    /// A fresh peer connection after the previous call closed: the new call has new audio SSRCs, carries
    /// audio and control messages in both directions, and accepts the application's <c>epoch:2</c> marker.
    /// </summary>
    /// <remarks>
    /// App hooks: <see cref="PeerConnection.CloseAsync"/> on the old pair, then
    /// <see cref="PeerConnection.WaitForConnectedAsync"/> (or
    /// <see cref="PeerConnection.OnConnectionStateChanged"/>) on the new pair; the new pair's
    /// <see cref="PeerConnection.AudioSsrc"/> differs from the old one's; the control channel carries
    /// <c>epoch:2</c>.
    /// </remarks>
    [Fact]
    public async Task FreshPeerConnection_AfterClose_AudioAndChannelResume()
    {
        var cancellationToken = TestTimeout();

        // ---------------------------------------------------------------- first call
        await using var firstOfferer = new PeerConnection(VoiceTestSupport.NewVoiceConfig());
        await using var firstAnswerer = new PeerConnection(VoiceTestSupport.NewVoiceConfig());
        var firstAudio = new AudioFlow(firstOfferer, firstAnswerer);
        var (_, _, firstOffererChannel, firstAnswererChannel) = await EstablishAsync(
            firstOfferer, firstAnswerer, cancellationToken);

        var firstMessagesAtAnswerer = new ConcurrentQueue<string>();
        var firstMessagesAtOfferer = new ConcurrentQueue<string>();
        firstOffererChannel.OnMessage += (binary, payload) =>
        {
            _ = binary;
            firstMessagesAtOfferer.Enqueue(System.Text.Encoding.UTF8.GetString(payload));
        };
        firstAnswererChannel.OnMessage += (binary, payload) =>
        {
            _ = binary;
            firstMessagesAtAnswerer.Enqueue(System.Text.Encoding.UTF8.GetString(payload));
        };

        await AssertAudioBothWaysAsync(firstAudio, firstOfferer, firstAnswerer, 25, cancellationToken);
        await AssertMessageAsync(firstOffererChannel, "before:offerer", firstMessagesAtAnswerer);
        await AssertMessageAsync(firstAnswererChannel, "before:answerer", firstMessagesAtOfferer);

        var firstOffererSsrc = firstOfferer.AudioSsrc;
        var firstAnswererSsrc = firstAnswerer.AudioSsrc;

        // ---------------------------------------------------------------- close the first call
        var offererClosed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var answererClosed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        firstOffererChannel.OnClosed += () => offererClosed.TrySetResult();
        firstAnswererChannel.OnClosed += () => answererClosed.TrySetResult();

        await firstOfferer.CloseAsync();
        await firstAnswerer.CloseAsync();

        (await TestSupport.WaitForAsync(
            () => firstOffererChannel.State == DataChannelState.Closed || offererClosed.Task.IsCompleted,
            timeoutMilliseconds: 10_000))
            .Should().BeTrue("the offerer's control channel must reach Closed or raise OnClosed");
        (await TestSupport.WaitForAsync(
            () => firstAnswererChannel.State == DataChannelState.Closed || answererClosed.Task.IsCompleted,
            timeoutMilliseconds: 10_000))
            .Should().BeTrue("the answerer's control channel must reach Closed or raise OnClosed");

        // ---------------------------------------------------------------- second call, new peers
        await using var secondOfferer = new PeerConnection(VoiceTestSupport.NewVoiceConfig());
        await using var secondAnswerer = new PeerConnection(VoiceTestSupport.NewVoiceConfig());
        var secondAudio = new AudioFlow(secondOfferer, secondAnswerer);
        var (_, _, secondOffererChannel, secondAnswererChannel) = await EstablishAsync(
            secondOfferer, secondAnswerer, cancellationToken);

        // A fresh peer connection draws fresh SSRCs: the far end can tell it is a new call.
        secondOfferer.AudioSsrc.Should().NotBe(firstOffererSsrc);
        secondAnswerer.AudioSsrc.Should().NotBe(firstAnswererSsrc);

        var messagesAtSecondAnswerer = new ConcurrentQueue<string>();
        secondAnswererChannel.OnMessage += (binary, payload) =>
        {
            _ = binary;
            messagesAtSecondAnswerer.Enqueue(System.Text.Encoding.UTF8.GetString(payload));
        };

        // The server side marks the new epoch; audio counted from here is new-call audio.
        secondOffererChannel.SendText("epoch:2");
        (await TestSupport.WaitForAsync(() => messagesAtSecondAnswerer.Contains("epoch:2")))
            .Should().BeTrue("the control channel must carry the epoch:2 marker after reconnecting");

        secondAudio.Reset();
        await AssertAudioBothWaysAsync(secondAudio, secondOfferer, secondAnswerer, 25, cancellationToken);

        var messagesAtSecondOfferer = new ConcurrentQueue<string>();
        secondOffererChannel.OnMessage += (binary, payload) =>
        {
            _ = binary;
            messagesAtSecondOfferer.Enqueue(System.Text.Encoding.UTF8.GetString(payload));
        };
        await AssertMessageAsync(secondOffererChannel, "after:offerer", messagesAtSecondAnswerer);
        await AssertMessageAsync(secondAnswererChannel, "after:answerer", messagesAtSecondOfferer);

        _output.WriteLine(
            $"fresh call: ssrc {firstOffererSsrc}->{secondOfferer.AudioSsrc}, "
            + $"{firstAnswererSsrc}->{secondAnswerer.AudioSsrc}; audio offerer {secondAudio.AToB}, "
            + $"answerer {secondAudio.BToA} after epoch:2.");
    }

    /// <summary>
    /// An ICE restart armed by the original offerer: fresh ICE credentials and a new selected pair, the
    /// same audio SSRCs (same call) and the same open control channel, with audio and messages resuming.
    /// </summary>
    /// <remarks>
    /// App hooks: <see cref="PeerConnection.RestartIce"/> by the offerer, then
    /// <see cref="PeerConnection.WaitForConnectedAsync"/> /
    /// <see cref="PeerConnection.OnConnectionStateChanged"/> or the new
    /// <see cref="PeerConnection.SelectedIceCandidatePairForTest"/>; <see cref="PeerConnection.AudioSsrc"/>
    /// is unchanged; the control channel carries <c>epoch:2</c>.
    /// </remarks>
    [Fact]
    public async Task IceRestart_InitiatedByOriginalOfferer_AudioAndChannelResume()
    {
        var cancellationToken = TestTimeout();

        await using var offerer = new PeerConnection(VoiceTestSupport.NewVoiceConfig());
        await using var answerer = new PeerConnection(VoiceTestSupport.NewVoiceConfig());
        var audio = new AudioFlow(offerer, answerer);
        var (offer1Sdp, _, offererChannel, answererChannel) = await EstablishAsync(
            offerer, answerer, cancellationToken);

        var messagesAtAnswerer = new ConcurrentQueue<string>();
        answererChannel.OnMessage += (binary, payload) =>
        {
            _ = binary;
            messagesAtAnswerer.Enqueue(System.Text.Encoding.UTF8.GetString(payload));
        };

        await AssertAudioBothWaysAsync(audio, offerer, answerer, 25, cancellationToken);
        await AssertMessageAsync(offererChannel, "before:offerer", messagesAtAnswerer);

        var offererSsrcBefore = offerer.AudioSsrc;
        var answererSsrcBefore = answerer.AudioSsrc;
        var offererPairBefore = offerer.SelectedIceCandidatePairForTest;
        var answererPairBefore = answerer.SelectedIceCandidatePairForTest;
        var offererChannelBefore = offererChannel;
        var answererChannelBefore = answererChannel;
        var offer1 = SessionDescription.Parse(offer1Sdp);

        offerer.RestartIce();
        var offer2Sdp = await offerer.CreateOfferAsync(cancellationToken);
        var offer2 = SessionDescription.Parse(offer2Sdp);
        offer2.MediaDescriptions[0].IceUfrag.Should().NotBe(
            offer1.MediaDescriptions[0].IceUfrag, "an ICE restart carries fresh credentials");

        await answerer.SetRemoteDescriptionAsync(offer2Sdp, SdpType.Offer, cancellationToken);
        VoiceTestSupport.MakeAudioSendRecv(answerer);
        var answer2 = await answerer.CreateAnswerAsync(cancellationToken);
        await offerer.SetRemoteDescriptionAsync(answer2, SdpType.Answer, cancellationToken);

        (await TestSupport.WaitForAsync(() =>
            offerer.SelectedIceCandidatePairForTest is { } op && !ReferenceEquals(op, offererPairBefore)))
            .Should().BeTrue("the offerer must nominate a new pair after the restart");
        (await TestSupport.WaitForAsync(() =>
            answerer.SelectedIceCandidatePairForTest is { } ap && !ReferenceEquals(ap, answererPairBefore)))
            .Should().BeTrue("the answerer must nominate a new pair after the restart");

        // Same call: the sender SSRCs are unchanged across the restart.
        offerer.AudioSsrc.Should().Be(offererSsrcBefore);
        answerer.AudioSsrc.Should().Be(answererSsrcBefore);

        // Same channel object, still open.
        ReferenceEquals(offererChannel, offererChannelBefore).Should().BeTrue();
        ReferenceEquals(answererChannel, answererChannelBefore).Should().BeTrue();
        offererChannel.State.Should().Be(DataChannelState.Open);
        answererChannel.State.Should().Be(DataChannelState.Open);

        offererChannel.SendText("epoch:2");
        (await TestSupport.WaitForAsync(() => messagesAtAnswerer.Contains("epoch:2")))
            .Should().BeTrue("the control channel must carry epoch:2 after the ICE restart");

        audio.Reset();
        await AssertAudioBothWaysAsync(audio, offerer, answerer, 25, cancellationToken);

        var messagesAtOfferer = new ConcurrentQueue<string>();
        offererChannel.OnMessage += (binary, payload) =>
        {
            _ = binary;
            messagesAtOfferer.Enqueue(System.Text.Encoding.UTF8.GetString(payload));
        };
        await AssertMessageAsync(offererChannel, "after:offerer", messagesAtAnswerer);
        await AssertMessageAsync(answererChannel, "after:answerer", messagesAtOfferer);

        _output.WriteLine(
            $"ICE restart by offerer: ssrc unchanged ({offerer.AudioSsrc}); audio offerer {audio.AToB}, "
            + $"answerer {audio.BToA} after epoch:2.");
    }

    /// <summary>
    /// An ICE restart armed by the original answerer, which then offers and is answered by the original
    /// offerer — what a browser does when its network changes. The same assertions apply.
    /// </summary>
    /// <remarks>
    /// App hooks: <see cref="PeerConnection.RestartIce"/> by the answerer followed by
    /// <see cref="PeerConnection.CreateOfferAsync"/>; the offerer applies it and answers;
    /// <see cref="PeerConnection.WaitForConnectedAsync"/> / a new selected ICE pair; unchanged
    /// <see cref="PeerConnection.AudioSsrc"/>; the control channel carries <c>epoch:2</c>.
    /// </remarks>
    [Fact]
    public async Task IceRestart_InitiatedByOriginalAnswerer_AudioAndChannelResume()
    {
        var cancellationToken = TestTimeout();

        await using var offerer = new PeerConnection(VoiceTestSupport.NewVoiceConfig());
        await using var answerer = new PeerConnection(VoiceTestSupport.NewVoiceConfig());
        var audio = new AudioFlow(offerer, answerer);
        var (_, answer1Sdp, offererChannel, answererChannel) = await EstablishAsync(
            offerer, answerer, cancellationToken);

        var messagesAtAnswerer = new ConcurrentQueue<string>();
        answererChannel.OnMessage += (binary, payload) =>
        {
            _ = binary;
            messagesAtAnswerer.Enqueue(System.Text.Encoding.UTF8.GetString(payload));
        };

        await AssertAudioBothWaysAsync(audio, offerer, answerer, 25, cancellationToken);
        await AssertMessageAsync(offererChannel, "before:offerer", messagesAtAnswerer);

        var offererSsrcBefore = offerer.AudioSsrc;
        var answererSsrcBefore = answerer.AudioSsrc;
        var offererPairBefore = offerer.SelectedIceCandidatePairForTest;
        var answererPairBefore = answerer.SelectedIceCandidatePairForTest;
        var offererChannelBefore = offererChannel;
        var answererChannelBefore = answererChannel;
        var answer1 = SessionDescription.Parse(answer1Sdp);

        // The original answerer restarts ICE and offers; the original offerer answers.
        answerer.RestartIce();
        var offer2Sdp = await answerer.CreateOfferAsync(cancellationToken);
        var offer2 = SessionDescription.Parse(offer2Sdp);
        offer2.MediaDescriptions[0].IceUfrag.Should().NotBe(
            answer1.MediaDescriptions[0].IceUfrag, "the restarting side offers fresh credentials");

        await offerer.SetRemoteDescriptionAsync(offer2Sdp, SdpType.Offer, cancellationToken);

        // This side is now the answerer; keep its audio m-line bidirectional.
        VoiceTestSupport.MakeAudioSendRecv(offerer);
        var answer2 = await offerer.CreateAnswerAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(answer2, SdpType.Answer, cancellationToken);

        (await TestSupport.WaitForAsync(() =>
            offerer.SelectedIceCandidatePairForTest is { } op && !ReferenceEquals(op, offererPairBefore)))
            .Should().BeTrue("the original offerer must nominate a new pair after the restart");
        (await TestSupport.WaitForAsync(() =>
            answerer.SelectedIceCandidatePairForTest is { } ap && !ReferenceEquals(ap, answererPairBefore)))
            .Should().BeTrue("the original answerer must nominate a new pair after the restart");

        offerer.AudioSsrc.Should().Be(offererSsrcBefore);
        answerer.AudioSsrc.Should().Be(answererSsrcBefore);

        ReferenceEquals(offererChannel, offererChannelBefore).Should().BeTrue();
        ReferenceEquals(answererChannel, answererChannelBefore).Should().BeTrue();
        offererChannel.State.Should().Be(DataChannelState.Open);
        answererChannel.State.Should().Be(DataChannelState.Open);

        offererChannel.SendText("epoch:2");
        (await TestSupport.WaitForAsync(() => messagesAtAnswerer.Contains("epoch:2")))
            .Should().BeTrue("the control channel must carry epoch:2 after the reversing restart");

        audio.Reset();
        await AssertAudioBothWaysAsync(audio, offerer, answerer, 25, cancellationToken);

        var messagesAtOfferer = new ConcurrentQueue<string>();
        offererChannel.OnMessage += (binary, payload) =>
        {
            _ = binary;
            messagesAtOfferer.Enqueue(System.Text.Encoding.UTF8.GetString(payload));
        };
        await AssertMessageAsync(offererChannel, "after:offerer", messagesAtAnswerer);
        await AssertMessageAsync(answererChannel, "after:answerer", messagesAtOfferer);

        _output.WriteLine(
            $"ICE restart by answerer: ssrc unchanged ({answerer.AudioSsrc}); audio offerer {audio.AToB}, "
            + $"answerer {audio.BToA} after epoch:2.");
    }

    // -------------------------------------------------------------------------------- helpers

    /// <summary>Negotiates the voice shape with a control channel and returns both channel handles.</summary>
    private static async Task<(string Offer, string Answer, DataChannel OffererChannel, DataChannel AnswererChannel)>
        EstablishAsync(PeerConnection offerer, PeerConnection answerer, CancellationToken cancellationToken)
    {
        VoiceTestSupport.WireCandidates(offerer, answerer);

        var offererChannelTask = offerer.CreateDataChannel("control");
        var answererChannelTcs = new TaskCompletionSource<DataChannel>(TaskCreationOptions.RunContinuationsAsynchronously);
        answerer.OnDataChannel += (_, channel) =>
        {
            if (channel.Label == "control")
            {
                answererChannelTcs.TrySetResult(channel);
            }
        };

        var (offer, answer) = await VoiceTestSupport.NegotiateVoiceAsync(
            offerer, answerer, cancellationToken);

        (await offerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        var offererChannel = await offererChannelTask.WaitAsync(ConnectTimeout, cancellationToken);
        var answererChannel = await answererChannelTcs.Task.WaitAsync(ConnectTimeout, cancellationToken);

        (await TestSupport.WaitForAsync(
            () => offererChannel.State == DataChannelState.Open && answererChannel.State == DataChannelState.Open))
            .Should().BeTrue("the control channel must open on both ends");

        return (offer, answer, offererChannel, answererChannel);
    }

    /// <summary>Sends a control message from one channel and waits until it arrives at the other side's queue.</summary>
    private static async Task AssertMessageAsync(
        DataChannel from,
        string text,
        ConcurrentQueue<string> received)
    {
        from.SendText(text);
        (await TestSupport.WaitForAsync(() => received.Contains(text)))
            .Should().BeTrue($"the control channel must deliver '{text}'");
    }

    /// <summary>Sends <paramref name="frames"/> Opus frames each way and asserts at least 20 arrive each way.</summary>
    private static async Task AssertAudioBothWaysAsync(
        AudioFlow audio,
        PeerConnection first,
        PeerConnection second,
        int frames,
        CancellationToken cancellationToken)
    {
        static async Task PumpAsync(PeerConnection peer, int frames, CancellationToken cancellationToken)
        {
            for (var i = 0; i < frames; i++)
            {
                peer.SendAudioFrame(VoiceTestSupport.OpusSilence, (uint)(i * 960)).Should().Be(1);
                await Task.Delay(20, cancellationToken);
            }
        }

        await Task.WhenAll(
            PumpAsync(first, frames, cancellationToken),
            PumpAsync(second, frames, cancellationToken));

        (await TestSupport.WaitForAsync(() => audio.AToB >= 20 && audio.BToA >= 20))
            .Should().BeTrue(
                $"audio must flow both ways after the reconnect; first got {audio.BToA}, "
                + $"second got {audio.AToB}");
    }

    /// <summary>Counts inbound audio packets between two peers, per direction.</summary>
    private sealed class AudioFlow
    {
        private readonly uint _firstSsrc;
        private readonly uint _secondSsrc;
        private int _firstToSecond;
        private int _secondToFirst;

        internal AudioFlow(PeerConnection first, PeerConnection second)
        {
            _firstSsrc = first.AudioSsrc;
            _secondSsrc = second.AudioSsrc;
            second.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
            {
                _ = payload;
                if (info.Kind == MediaKind.Audio && info.Ssrc == _firstSsrc)
                {
                    Interlocked.Increment(ref _firstToSecond);
                }
            };
            first.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
            {
                _ = payload;
                if (info.Kind == MediaKind.Audio && info.Ssrc == _secondSsrc)
                {
                    Interlocked.Increment(ref _secondToFirst);
                }
            };
        }

        /// <summary>Packets the second peer received from the first.</summary>
        internal int AToB => Volatile.Read(ref _firstToSecond);

        /// <summary>Packets the first peer received from the second.</summary>
        internal int BToA => Volatile.Read(ref _secondToFirst);

        /// <summary>Zeroes both counters, so "new packets after the reconnect" can be counted.</summary>
        internal void Reset()
        {
            Interlocked.Exchange(ref _firstToSecond, 0);
            Interlocked.Exchange(ref _secondToFirst, 0);
        }
    }
}
