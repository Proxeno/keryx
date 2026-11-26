using System.Collections.Concurrent;
using FluentAssertions;
using Keryx.Sctp;
using Keryx.Sdp;
using Xunit;
using Xunit.Abstractions;

namespace Keryx.IntegrationTests;

/// <summary>
/// The voice-agent session shape: audio-only and bidirectional. Exactly one <c>sendrecv</c> Opus audio
/// m-line and one SCTP (<c>m=application</c>) m-line carry the call — no video — and one reliable,
/// ordered "control" data channel carries control events and playout receipts.
/// <para>
/// The tests cover the Keryx-offers (media-server) and browser-offers (voice-client) roles, and pin the
/// recvonly-offer guard so an audio-only session can never grow a video section.
/// </para>
/// </summary>
public sealed class VoiceSessionShapeTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    private readonly ITestOutputHelper _output;

    /// <summary>Captures the xunit output sink.</summary>
    /// <param name="output">Where the run's measurements are written.</param>
    public VoiceSessionShapeTests(ITestOutputHelper output) => _output = output;

    private static CancellationToken TestTimeout() =>
        new CancellationTokenSource(TimeSpan.FromSeconds(90)).Token;

    [Fact]
    public async Task KeryxOffers_AudioOnlySendRecvPlusSctp_NoVideo()
    {
        var cancellationToken = TestTimeout();

        await using var offerer = new PeerConnection(VoiceTestSupport.NewVoiceConfig());
        await using var answerer = new PeerConnection(VoiceTestSupport.NewVoiceConfig());
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

        var receivedByAnswerer = 0;
        var receivedByOfferer = 0;
        answerer.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            _ = payload;
            if (info.Kind == MediaKind.Audio && info.Ssrc == offerer.AudioSsrc)
            {
                Interlocked.Increment(ref receivedByAnswerer);
            }
        };
        offerer.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            _ = payload;
            if (info.Kind == MediaKind.Audio && info.Ssrc == answerer.AudioSsrc)
            {
                Interlocked.Increment(ref receivedByOfferer);
            }
        };

        var (offerSdp, answerSdp) = await VoiceTestSupport.NegotiateVoiceAsync(
            offerer, answerer, cancellationToken);

        AssertVoiceShape(SessionDescription.Parse(offerSdp), MediaDirection.SendRecv, "offer");
        AssertVoiceShape(SessionDescription.Parse(answerSdp), MediaDirection.SendRecv, "answer");

        (await offerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        VoiceTestSupport.Audio(offerer).CurrentDirection.Should().Be(MediaDirection.SendRecv);
        VoiceTestSupport.Audio(answerer).CurrentDirection.Should().Be(MediaDirection.SendRecv);

        var offererChannel = await offererChannelTask.WaitAsync(ConnectTimeout, cancellationToken);
        var answererChannel = await answererChannelTcs.Task.WaitAsync(ConnectTimeout, cancellationToken);
        await WaitForOpenAsync(offererChannel, answererChannel);

        AssertReliableOrdered(offererChannel, "the offerer's 'control' channel");
        AssertReliableOrdered(answererChannel, "the answerer's 'control' channel");

        await SendAudioBothWaysAsync(offerer, answerer, cancellationToken);
        (await TestSupport.WaitForAsync(
            () => Volatile.Read(ref receivedByAnswerer) >= 45 && Volatile.Read(ref receivedByOfferer) >= 45))
            .Should().BeTrue(
                $"each side must receive the other's audio; offerer saw {Volatile.Read(ref receivedByOfferer)}, "
                + $"answerer saw {Volatile.Read(ref receivedByAnswerer)}");

        await ExchangeMessagesAsync(
            offererChannel,
            answererChannel,
            "offerer-to-answerer",
            "answerer-to-offerer",
            cancellationToken);

        _output.WriteLine(
            $"audio received: offerer {Volatile.Read(ref receivedByOfferer)}, "
            + $"answerer {Volatile.Read(ref receivedByAnswerer)}; 200 messages each way in order.");
    }

    [Fact]
    public async Task BrowserShapedOffer_KeryxAnswers_AudioOnlySendRecvPlusSctp()
    {
        var cancellationToken = TestTimeout();

        // The browser-shaped client offers, creates the channel, and is answered.
        await using var browser = new PeerConnection(VoiceTestSupport.NewVoiceConfig());
        await using var server = new PeerConnection(VoiceTestSupport.NewVoiceConfig());
        VoiceTestSupport.WireCandidates(browser, server);

        var browserChannelTask = browser.CreateDataChannel("control");
        var serverChannelTcs = new TaskCompletionSource<DataChannel>(TaskCreationOptions.RunContinuationsAsynchronously);
        server.OnDataChannel += (_, channel) =>
        {
            if (channel.Label == "control")
            {
                serverChannelTcs.TrySetResult(channel);
            }
        };

        var receivedByServer = 0;
        var receivedByBrowser = 0;
        server.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            _ = payload;
            if (info.Kind == MediaKind.Audio && info.Ssrc == browser.AudioSsrc)
            {
                Interlocked.Increment(ref receivedByServer);
            }
        };
        browser.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            _ = payload;
            if (info.Kind == MediaKind.Audio && info.Ssrc == server.AudioSsrc)
            {
                Interlocked.Increment(ref receivedByBrowser);
            }
        };

        var (offerSdp, answerSdp) = await VoiceTestSupport.NegotiateVoiceAsync(
            browser, server, cancellationToken);

        AssertVoiceShape(SessionDescription.Parse(offerSdp), MediaDirection.SendRecv, "browser offer");
        AssertVoiceShape(SessionDescription.Parse(answerSdp), MediaDirection.SendRecv, "server answer");

        (await browser.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await server.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        VoiceTestSupport.Audio(browser).CurrentDirection.Should().Be(MediaDirection.SendRecv);
        VoiceTestSupport.Audio(server).CurrentDirection.Should().Be(MediaDirection.SendRecv);

        var browserChannel = await browserChannelTask.WaitAsync(ConnectTimeout, cancellationToken);
        var serverChannel = await serverChannelTcs.Task.WaitAsync(ConnectTimeout, cancellationToken);
        await WaitForOpenAsync(browserChannel, serverChannel);

        AssertReliableOrdered(browserChannel, "the browser's 'control' channel");
        AssertReliableOrdered(serverChannel, "the server's 'control' channel");

        await SendAudioBothWaysAsync(browser, server, cancellationToken);
        (await TestSupport.WaitForAsync(
            () => Volatile.Read(ref receivedByServer) >= 45 && Volatile.Read(ref receivedByBrowser) >= 45))
            .Should().BeTrue(
                $"audio must flow both ways; browser saw {Volatile.Read(ref receivedByBrowser)}, "
                + $"server saw {Volatile.Read(ref receivedByServer)}");

        await ExchangeMessagesAsync(
            browserChannel,
            serverChannel,
            "browser-to-server",
            "server-to-browser",
            cancellationToken);

        _output.WriteLine(
            $"audio received: browser {Volatile.Read(ref receivedByBrowser)}, server {Volatile.Read(ref receivedByServer)}; "
            + "200 messages each way in order.");
    }

    [Fact]
    public async Task RecvOnlyOffer_IsAnsweredSendOnly_StillNoVideo()
    {
        var cancellationToken = TestTimeout();

        await using var offerer = new PeerConnection(VoiceTestSupport.NewVoiceConfig());
        await using var answerer = new PeerConnection(VoiceTestSupport.NewVoiceConfig());
        VoiceTestSupport.WireCandidates(offerer, answerer);

        // The offerer only wants to receive; it still offers the single audio m-line.
        VoiceTestSupport.Audio(offerer).Direction = MediaDirection.RecvOnly;
        var offerSdp = await offerer.CreateOfferAsync(cancellationToken);
        var offer = SessionDescription.Parse(offerSdp);
        offer.MediaDescriptions.Should().ContainSingle(m => m.Media == "audio");
        offer.MediaDescriptions.Should().NotContain(m => m.Media == "video");
        offer.MediaDescriptions.Single(m => m.Media == "audio").DirectionOrDefault
            .Should().Be(MediaDirection.RecvOnly);

        await answerer.SetRemoteDescriptionAsync(offerSdp, SdpType.Offer, cancellationToken);
        var answerSdp = await answerer.CreateAnswerAsync(cancellationToken);
        var answer = SessionDescription.Parse(answerSdp);

        AssertVoiceShape(answer, MediaDirection.SendOnly, "answer to a recvonly offer");
        answer.MediaDescriptions.Count(m => m.Media == "audio").Should().Be(1);
    }

    // -------------------------------------------------------------------------------- helpers

    /// <summary>
    /// Asserts the voice m-line shape: exactly two m-lines (one audio, one application), no video, the
    /// requested audio direction, the BUNDLE group naming exactly those two mids, and Opus 48 kHz stereo.
    /// </summary>
    private static void AssertVoiceShape(SessionDescription sdp, MediaDirection audioDirection, string what)
    {
        sdp.MediaDescriptions.Should().HaveCount(2, $"{what} carries exactly the audio and application m-lines");

        var audio = sdp.MediaDescriptions.Single(m => m.Media == "audio");
        var application = sdp.MediaDescriptions.Single(m => m.Media == "application");
        sdp.MediaDescriptions.Should().NotContain(
            m => m.Media == "video", $"{what} must carry no video m-line");

        audio.DirectionOrDefault.Should().Be(audioDirection, $"{what} audio direction");
        audio.GetRtpMaps().Should().ContainSingle(
            m => m.EncodingName.Equals("opus", StringComparison.OrdinalIgnoreCase)
                && m.ClockRate == 48000
                && m.Channels == 2,
            $"{what} offers opus/48000/2");

        audio.Mid.Should().NotBeNullOrEmpty();
        application.Mid.Should().NotBeNullOrEmpty();
        sdp.GetBundleGroup().Should().Equal(
            new[] { audio.Mid!, application.Mid! },
            $"{what} bundles exactly the audio and application mids");
    }

    private static async Task WaitForOpenAsync(DataChannel first, DataChannel second)
    {
        (await TestSupport.WaitForAsync(
            () => first.State == DataChannelState.Open && second.State == DataChannelState.Open))
            .Should().BeTrue("both ends of the control channel must open");
    }

    private static void AssertReliableOrdered(DataChannel channel, string what)
    {
        channel.Ordered.Should().BeTrue($"{what} is ordered");
        channel.MaxRetransmits.Should().BeNull($"{what} is fully reliable (no retransmit cap)");
        channel.MaxPacketLifetime.Should().BeNull($"{what} is fully reliable (no lifetime cap)");
    }

    /// <summary>Sends 50 Opus frames from each side at a 20 ms cadence, concurrently.</summary>
    private static Task SendAudioBothWaysAsync(
        PeerConnection first,
        PeerConnection second,
        CancellationToken cancellationToken)
    {
        static async Task PumpAsync(PeerConnection peer, CancellationToken cancellationToken)
        {
            for (var i = 0; i < 50; i++)
            {
                peer.SendAudioFrame(VoiceTestSupport.OpusSilence, (uint)(i * 960)).Should().Be(1);
                await Task.Delay(20, cancellationToken);
            }
        }

        return Task.WhenAll(
            PumpAsync(first, cancellationToken),
            PumpAsync(second, cancellationToken));
    }

    /// <summary>
    /// Sends 200 numbered text messages each way as fast as the API allows and asserts each side receives
    /// every one, in order. The directions are run one after the other so the ordering assertion is about
    /// a single ordered stream rather than two interleaved ones.
    /// </summary>
    private static async Task ExchangeMessagesAsync(
        DataChannel firstChannel,
        DataChannel secondChannel,
        string firstToSecond,
        string secondToFirst,
        CancellationToken cancellationToken)
    {
        const int count = 200;
        var atSecond = new ConcurrentQueue<string>();
        var atFirst = new ConcurrentQueue<string>();
        firstChannel.OnMessage += (binary, payload) =>
        {
            _ = binary;
            atFirst.Enqueue(System.Text.Encoding.UTF8.GetString(payload));
        };
        secondChannel.OnMessage += (binary, payload) =>
        {
            _ = binary;
            atSecond.Enqueue(System.Text.Encoding.UTF8.GetString(payload));
        };

        for (var i = 0; i < count; i++)
        {
            firstChannel.SendText($"{firstToSecond}:{i}");
        }

        (await TestSupport.WaitForAsync(() => atSecond.Count >= count, timeoutMilliseconds: 30_000))
            .Should().BeTrue($"{firstToSecond} must deliver all {count} messages");
        atSecond.Should().Equal(Enumerable.Range(0, count).Select(i => $"{firstToSecond}:{i}"));

        for (var i = 0; i < count; i++)
        {
            secondChannel.SendText($"{secondToFirst}:{i}");
        }

        (await TestSupport.WaitForAsync(() => atFirst.Count >= count, timeoutMilliseconds: 30_000))
            .Should().BeTrue($"{secondToFirst} must deliver all {count} messages");
        atFirst.Should().Equal(Enumerable.Range(0, count).Select(i => $"{secondToFirst}:{i}"));
    }
}
