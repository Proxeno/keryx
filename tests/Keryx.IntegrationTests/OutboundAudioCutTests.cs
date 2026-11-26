using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using FluentAssertions;
using Keryx.Core;
using Keryx.Rtp;
using Keryx.Rtp.CongestionControl;
using Keryx.Rtp.Packetization;
using Keryx.Sctp;
using Keryx.Sdp;
using Xunit;
using Xunit.Abstractions;

namespace Keryx.IntegrationTests;

/// <summary>
/// Barge-in outbound-audio cut coverage: the pacer's per-SSRC removal, the wire-level sequence/timestamp
/// guarantees across a cut, the retransmission-history purge, the transport-wide-cc gap's effect on the
/// congestion estimate, and a concurrent loopback soak proving cuts never deadlock or stall other tracks.
/// </summary>
public sealed class OutboundAudioCutTests
{
    private const int AudioSampleIncrement = 960; // 20 ms of Opus at 48 kHz

    // Keryx offers transport-wide congestion control at extmap 3; a Keryx-to-Keryx answer echoes it.
    private const byte TransportCcExtensionId = 3;

    private readonly ITestOutputHelper _output;

    /// <summary>Captures the xunit output sink for the congestion-measurement test.</summary>
    /// <param name="output">Where the before/min/after numbers land.</param>
    public OutboundAudioCutTests(ITestOutputHelper output) => _output = output;

    // ---------------------------------------------------------------- part 1: pacer unit tests

    [Fact]
    public void RemoveQueuedDropsOnlyTheTargetSsrcAndKeepsOrder()
    {
        var time = new FakeTimerTimeProvider();
        var pacer = new PacketPacer(100_000_000, time);
        var sent = new ConcurrentQueue<(uint Ssrc, ushort SequenceNumber)>();
        using var sender = new PeerConnection.PacedRtpSender(pacer, time, srtpOverhead: 0, Capture, NullLogger.Instance);

        void Capture(byte[] buffer, int length)
        {
            RtpPacket.TryParse(buffer.AsSpan(0, length), out var packet).Should().BeTrue();
            sent.Enqueue((packet.Header.Ssrc, packet.Header.SequenceNumber));
        }

        var aSsrc = 0xAAAA_AAA1u;
        var bSsrc = 0xBBBB_BBB2u;
        var a = new RtpStreamSender(aSsrc, 111, 48_000, initialSequenceNumber: 1, initialTimestamp: 0);
        var b = new RtpStreamSender(bSsrc, 111, 48_000, initialSequenceNumber: 100, initialTimestamp: 0);

        // Interleave A (seq 1..5) and B (seq 100..102) in one queue.
        sender.Enqueue(OpusPacket(a));
        sender.Enqueue(OpusPacket(b));
        sender.Enqueue(OpusPacket(a));
        sender.Enqueue(OpusPacket(b));
        sender.Enqueue(OpusPacket(a));
        sender.Enqueue(OpusPacket(b));
        sender.Enqueue(OpusPacket(a));
        sender.Enqueue(OpusPacket(a));

        var removed = new List<PeerConnection.PacedRtpSender.RemovedPacket>();
        var count = 0;
        sender.RunWithDrainsExcluded(
            () => count = sender.RemoveQueued(aSsrc, AudioPayloadTiming.FromCodec("opus", 48_000), removed));

        count.Should().Be(5);
        removed.Select(r => r.SequenceNumber).Should().Equal(new ushort[] { 1, 2, 3, 4, 5 });
        removed.Should().OnlyContain(r => r.PayloadSamples == AudioSampleIncrement);

        // Nothing drained yet: only B survives, in its original order.
        sent.Should().BeEmpty();

        time.Advance(TimeSpan.FromSeconds(1));
        time.FireDueTimers();

        sent.Should().Equal(
            (bSsrc, (ushort)100),
            (bSsrc, (ushort)101),
            (bSsrc, (ushort)102));
    }

    [Fact]
    public void RemoveQueuedOnAnEmptyQueueReturnsZero()
    {
        var time = new FakeTimerTimeProvider();
        var pacer = new PacketPacer(100_000_000, time);
        using var sender = new PeerConnection.PacedRtpSender(pacer, time, srtpOverhead: 0, (_, _) => { }, NullLogger.Instance);

        var removed = new List<PeerConnection.PacedRtpSender.RemovedPacket>();
        var count = sender.RemoveQueued(0x1234, AudioPayloadTiming.FromCodec("opus", 48_000), removed);

        count.Should().Be(0);
        removed.Should().BeEmpty();
    }

    [Theory]
    [InlineData("PCMU", 8000, 160, 160)]
    [InlineData("PCMA", 8000, 160, 160)]
    [InlineData("G722", 8000, 160, 320)]
    [InlineData("opus", 48000, 80, 960)]
    [InlineData("L16", 44100, 160, -1)]
    public void RemoveQueuedCountsSamplesByCodec(string encodingName, uint clockRate, int payloadLength, long expected)
    {
        var time = new FakeTimerTimeProvider();
        var pacer = new PacketPacer(100_000_000, time);
        using var sender = new PeerConnection.PacedRtpSender(pacer, time, srtpOverhead: 0, (_, _) => { }, NullLogger.Instance);

        var ssrc = 0xAAAA_AAA1u;
        var stream = new RtpStreamSender(ssrc, 111, clockRate, initialSequenceNumber: 1, initialTimestamp: 0);
        var payload = encodingName == "opus" ? Tone() : new byte[payloadLength];
        var buffer = new byte[256];

        for (var i = 0; i < 3; i++)
        {
            var length = stream.WritePacket(payload, marker: false, buffer);
            sender.Enqueue(buffer.AsSpan(0, length));
        }

        var removed = new List<PeerConnection.PacedRtpSender.RemovedPacket>();
        var count = 0;
        sender.RunWithDrainsExcluded(
            () => count = sender.RemoveQueued(
                ssrc,
                AudioPayloadTiming.FromCodec(encodingName, clockRate),
                removed));

        count.Should().Be(3);
        removed.Should().OnlyContain(r => r.PayloadSamples == expected);
    }

    // ---------------------------------------------------------------- part 2: loopback

    [Fact]
    public async Task CutDiscardsQueuedAudioAndReportsCountAndSamples()
    {
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var pair = await ConnectAsync(congestionControl: true, shutdown.Token);
        await using var offerer = pair.Offerer;
        await using var answerer = pair.Answerer;

        var audioSsrc = offerer.GetLocalSsrc(MediaKind.Audio);
        var wire = new ConcurrentQueue<WirePacket>();
        offerer.RtpWireObserverForTest = (rtp, ticks) => Record(rtp, ticks, wire);

        for (var i = 0; i < 5; i++)
        {
            offerer.SendAudioFrame(Tone(), (uint)(i * AudioSampleIncrement)).Should().Be(1);
        }

        (await TestSupport.WaitForAsync(() => AudioCount(wire, audioSsrc) >= 5)).Should().BeTrue();

        var paced = offerer.PacedSenderForTest;
        paced.Should().NotBeNull("congestion control builds the pacer");
        paced!.HoldDrainForTest = true;

        for (var i = 5; i < 15; i++)
        {
            offerer.SendAudioFrame(Tone(), (uint)(i * AudioSampleIncrement)).Should().Be(1);
        }

        var cut = offerer.CutOutboundAudio();
        cut.PacketsDiscarded.Should().Be(10);
        cut.SamplesDiscarded.Should().Be(10L * AudioSampleIncrement);
        cut.SampleRate.Should().Be(48_000);
        cut.DurationDiscarded.Should().Be(TimeSpan.FromMilliseconds(200));
        cut.Generation.Should().Be(1);

        paced.HoldDrainForTest = false;
        await Task.Delay(200, shutdown.Token);

        AudioCount(wire, audioSsrc).Should().Be(5, "the cut audio must never reach the wire");
    }

    [Fact]
    public async Task NextGenerationIsContiguousMarkedAndTimestampContinuous()
    {
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var pair = await ConnectAsync(congestionControl: true, shutdown.Token);
        await using var offerer = pair.Offerer;
        await using var answerer = pair.Answerer;

        var audioSsrc = offerer.GetLocalSsrc(MediaKind.Audio);
        var wire = new ConcurrentQueue<WirePacket>();
        offerer.RtpWireObserverForTest = (rtp, ticks) => Record(rtp, ticks, wire);

        for (var i = 0; i < 5; i++)
        {
            offerer.SendAudioFrame(Tone(), (uint)(i * AudioSampleIncrement)).Should().Be(1);
        }

        (await TestSupport.WaitForAsync(() => AudioCount(wire, audioSsrc) >= 5)).Should().BeTrue();
        var paced = offerer.PacedSenderForTest!;
        paced.HoldDrainForTest = true;

        for (var i = 5; i < 15; i++)
        {
            offerer.SendAudioFrame(Tone(), (uint)(i * AudioSampleIncrement)).Should().Be(1);
        }

        var cutStart = Stopwatch.GetTimestamp();
        var cut = offerer.CutOutboundAudio();
        var cutEnd = Stopwatch.GetTimestamp();
        cut.PacketsDiscarded.Should().Be(10);

        paced.HoldDrainForTest = false;
        await Task.Delay(100, shutdown.Token);

        // The application does not rebase: it keeps its own clock running from where it was.
        for (var i = 15; i < 20; i++)
        {
            offerer.SendAudioFrame(Tone(), (uint)(i * AudioSampleIncrement)).Should().Be(1);
        }

        (await TestSupport.WaitForAsync(() => AudioCount(wire, audioSsrc) >= 10)).Should().BeTrue();
        await Task.Delay(100, shutdown.Token);

        var packets = wire.Where(p => p.Ssrc == audioSsrc).ToArray();
        packets.Should().HaveCount(10);
        var before = packets[4];
        var firstNew = packets[5];

        firstNew.SequenceNumber.Should().Be(unchecked((ushort)(before.SequenceNumber + 1)),
            "the sequence space is rewound to the first discarded number");
        firstNew.Marker.Should().BeTrue("the first packet of the new generation marks a talkspurt");
        packets[6..].Should().OnlyContain(p => !p.Marker);

        for (var i = 6; i < packets.Length; i++)
        {
            unchecked((ushort)(packets[i].SequenceNumber - packets[i - 1].SequenceNumber)).Should().Be(1);
            unchecked((int)(packets[i].Timestamp - packets[i - 1].Timestamp)).Should().Be(AudioSampleIncrement);
            unchecked((int)(packets[i].Timestamp - before.Timestamp)).Should().BeGreaterThan(0);
        }

        var actualGap = unchecked((int)(firstNew.Timestamp - (before.Timestamp + AudioSampleIncrement)));
        var elapsedSeconds = (firstNew.Ticks - cutEnd) / (double)Stopwatch.Frequency;
        var expectedGap = (int)Math.Round(elapsedSeconds * 48_000);
        actualGap.Should().BeGreaterThanOrEqualTo(0);
        Math.Abs(actualGap - expectedGap).Should().BeLessThanOrEqualTo(40 * 48,
            "the new timestamp tracks the wall-clock time since the cut");
        cutEnd.Should().BeGreaterThanOrEqualTo(cutStart);
    }

    [Fact]
    public async Task CutWithoutPacingStillStartsANewGeneration()
    {
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var pair = await ConnectAsync(congestionControl: false, shutdown.Token);
        await using var offerer = pair.Offerer;
        await using var answerer = pair.Answerer;

        var audioSsrc = offerer.GetLocalSsrc(MediaKind.Audio);
        var wire = new ConcurrentQueue<WirePacket>();
        offerer.RtpWireObserverForTest = (rtp, ticks) => Record(rtp, ticks, wire);

        for (var i = 0; i < 3; i++)
        {
            offerer.SendAudioFrame(Tone(), (uint)(i * AudioSampleIncrement)).Should().Be(1);
        }

        (await TestSupport.WaitForAsync(() => AudioCount(wire, audioSsrc) >= 3)).Should().BeTrue();
        var cutStart = Stopwatch.GetTimestamp();
        var cut = offerer.CutOutboundAudio();
        var cutEnd = Stopwatch.GetTimestamp();
        cut.PacketsDiscarded.Should().Be(0);
        cut.SamplesDiscarded.Should().Be(0);

        await Task.Delay(60, shutdown.Token);

        for (var i = 3; i < 5; i++)
        {
            offerer.SendAudioFrame(Tone(), (uint)(i * AudioSampleIncrement)).Should().Be(1);
        }

        (await TestSupport.WaitForAsync(() => AudioCount(wire, audioSsrc) >= 5)).Should().BeTrue();

        var packets = wire.Where(p => p.Ssrc == audioSsrc).ToArray();
        packets.Should().HaveCount(5);
        packets[3].Marker.Should().BeTrue("the first post-cut packet marks the new talkspurt");
        packets[4].Marker.Should().BeFalse();

        var actualGap = unchecked((int)(packets[3].Timestamp - (packets[2].Timestamp + AudioSampleIncrement)));
        var elapsedSeconds = (packets[3].Ticks - cutEnd) / (double)Stopwatch.Frequency;
        var expectedGap = (int)Math.Round(elapsedSeconds * 48_000);
        actualGap.Should().BeGreaterThanOrEqualTo(0);
        Math.Abs(actualGap - expectedGap).Should().BeLessThanOrEqualTo(40 * 48);
        cutEnd.Should().BeGreaterThanOrEqualTo(cutStart);
    }

    [Fact]
    public async Task NackForCutSequenceNumbersNeverResurrectsCutAudio()
    {
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var pair = await ConnectAsync(congestionControl: true, shutdown.Token);
        await using var offerer = pair.Offerer;
        await using var answerer = pair.Answerer;

        var audioSsrc = offerer.GetLocalSsrc(MediaKind.Audio);
        var wire = new ConcurrentQueue<WirePacket>();
        offerer.RtpWireObserverForTest = (rtp, ticks) => Record(rtp, ticks, wire);

        for (var i = 0; i < 5; i++)
        {
            offerer.SendAudioFrame(Tone(second: 0x11), (uint)(i * AudioSampleIncrement)).Should().Be(1);
        }

        (await TestSupport.WaitForAsync(() => AudioCount(wire, audioSsrc) >= 5)).Should().BeTrue();
        var paced = offerer.PacedSenderForTest!;
        paced.HoldDrainForTest = true;

        for (var i = 5; i < 15; i++)
        {
            offerer.SendAudioFrame(Tone(second: 0x11), (uint)(i * AudioSampleIncrement)).Should().Be(1);
        }

        var cut = offerer.CutOutboundAudio();
        cut.PacketsDiscarded.Should().Be(10);
        paced.HoldDrainForTest = false;

        var sent = wire.Where(p => p.Ssrc == audioSsrc).ToArray();
        sent.Should().HaveCount(5);
        var lastSent = sent[^1].SequenceNumber;
        var discarded = new ushort[10];
        for (var i = 0; i < discarded.Length; i++)
        {
            discarded[i] = unchecked((ushort)(lastSent + 1 + i));
        }

        answerer.SendNack(audioSsrc, discarded).Should().BeTrue();
        await Task.Delay(300, shutdown.Token);

        wire.Where(p => discarded.Contains(p.SequenceNumber)).Should().BeEmpty(
            "a NACK for a cut sequence number must not put anything on the wire");

        // Now send genuinely new content that reuses those sequence numbers, and NACK them again.
        for (var i = 15; i < 20; i++)
        {
            offerer.SendAudioFrame(Tone(second: 0xAB), (uint)(i * AudioSampleIncrement)).Should().Be(1);
        }

        (await TestSupport.WaitForAsync(() => AudioCount(wire, audioSsrc) >= 10)).Should().BeTrue();
        answerer.SendNack(audioSsrc, discarded).Should().BeTrue();
        await Task.Delay(300, shutdown.Token);

        var reused = wire.Where(p => discarded.Contains(p.SequenceNumber)).ToArray();
        reused.Should().NotBeEmpty("the new generation reuses the discarded sequence numbers");
        reused.Should().OnlyContain(p => p.ContentByte == 0xAB,
            "every packet on a discarded sequence number must carry the new content, never the cut audio");
    }

    [Fact]
    public async Task TrackSenderCutPurgesRetransmissionHistory()
    {
        var peer = new PeerConnection(TestSupport.NewConfig());
        await using var peerLease = peer;

        var history = new RtpSendHistory(1200, new RtpSendHistoryOptions { Capacity = 64 });
        var rtx = new RtxRetransmitter(0x9999_0001, 97, 48_000, history);
        var stream = new RtpStreamSender(0x9999_0002, 111, 48_000, initialSequenceNumber: 500, initialTimestamp: 0);
        var track = new PeerConnection.TrackSender(
            peer, "0", MediaKind.Audio, stream, new OpusPacketizer(), maxPayload: 1000, srtpOverhead: 0,
            retransmitter: rtx, audioTiming: AudioPayloadTiming.FromCodec("opus", 48_000));

        track.SendFrame(Tone(), 0).Should().Be(1);
        track.SendFrame(Tone(), 960).Should().Be(1);
        track.SendFrame(Tone(), 1920).Should().Be(1);

        stream.NextSequenceNumber.Should().Be(503);
        history.TryCopy(500, TimeSpan.Zero, new byte[1200], out _).Should().Be(RtpSendHistoryResult.Found);
        history.TryCopy(501, TimeSpan.Zero, new byte[1200], out _).Should().Be(RtpSendHistoryResult.Found);
        history.TryCopy(502, TimeSpan.Zero, new byte[1200], out _).Should().Be(RtpSendHistoryResult.Found);

        var cut = track.Cut(
        [
            new PeerConnection.PacedRtpSender.RemovedPacket(501, 960, 80, 960),
            new PeerConnection.PacedRtpSender.RemovedPacket(502, 1920, 80, 960),
        ]);

        cut.PacketsDiscarded.Should().Be(2);
        cut.SamplesDiscarded.Should().Be(1920);
        history.TryCopy(501, TimeSpan.Zero, new byte[1200], out _).Should().Be(RtpSendHistoryResult.Missing);
        history.TryCopy(502, TimeSpan.Zero, new byte[1200], out _).Should().Be(RtpSendHistoryResult.Missing);
        history.TryCopy(500, TimeSpan.Zero, new byte[1200], out _).Should().Be(RtpSendHistoryResult.Found);
        stream.NextSequenceNumber.Should().Be(501);
    }

    [Fact]
    public async Task ConcurrentCutsDoNotDeadlockStallOtherTracksOrBreakContiguity()
    {
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(40));

        var offererConfig = TestSupport.NewConfig();
        offererConfig.EnableCongestionControl = true;

        // A generous fixed target so the pacer never becomes the bottleneck: this test is about lock
        // ordering and accounting, not about congestion response.
        offererConfig.CongestionControl = new CongestionControllerOptions
        {
            StartBitrateBitsPerSecond = 100_000_000,
            MinBitrateBitsPerSecond = 1_000_000,
            MaxBitrateBitsPerSecond = 200_000_000,
        };
        await using var offerer = new PeerConnection(offererConfig);
        await using var answerer = new PeerConnection(TestSupport.NewConfig());

        var audioSsrc = offerer.GetLocalSsrc(MediaKind.Audio);
        var videoSsrc = offerer.GetLocalSsrc(MediaKind.Video);

        var wire = new ConcurrentQueue<WirePacket>();
        offerer.RtpWireObserverForTest = (rtp, ticks) => Record(rtp, ticks, wire);

        var channelTask = offerer.CreateDataChannel("control");
        long receivedMessages = 0;
        answerer.OnDataChannel += (_, channel) =>
        {
            channel.OnMessage += (_, _) => Interlocked.Increment(ref receivedMessages);
        };

        offerer.OnLocalIceCandidate += (_, e) => answerer.AddIceCandidate(e.Candidate, e.SdpMid);
        answerer.OnLocalIceCandidate += (_, e) => offerer.AddIceCandidate(e.Candidate, e.SdpMid);
        var offer = await offerer.CreateOfferAsync(shutdown.Token);
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, shutdown.Token);
        var answer = await answerer.CreateAnswerAsync(shutdown.Token);
        await offerer.SetRemoteDescriptionAsync(answer, SdpType.Answer, shutdown.Token);
        (await offerer.WaitForConnectedAsync(TimeSpan.FromSeconds(30), shutdown.Token)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(TimeSpan.FromSeconds(30), shutdown.Token)).Should().BeTrue();

        var channel = await channelTask.WaitAsync(TimeSpan.FromSeconds(20), shutdown.Token);
        (await TestSupport.WaitForAsync(() => channel.State == DataChannelState.Open)).Should().BeTrue();

        var accessUnits = H264TestStream.ReadAccessUnits(90);
        var runFor = TimeSpan.FromSeconds(3);
        long audioFramesSent = 0;
        long discarded = 0;
        long messagesSent = 0;

        var audioTask = Task.Run(async () =>
        {
            var clock = Stopwatch.StartNew();
            uint index = 0;
            var next = TimeSpan.Zero;
            while (clock.Elapsed < runFor)
            {
                if (offerer.SendAudioFrame(Tone(), unchecked(index * (uint)AudioSampleIncrement)) == 1)
                {
                    Interlocked.Increment(ref audioFramesSent);
                }

                index++;
                next += TimeSpan.FromMilliseconds(2);
                var wait = next - clock.Elapsed;
                if (wait > TimeSpan.Zero)
                {
                    await Task.Delay(wait).ConfigureAwait(false);
                }
            }
        });

        var videoTask = Task.Run(async () =>
        {
            var clock = Stopwatch.StartNew();
            var index = 0;
            var videoTimestamp = 0u;
            var next = TimeSpan.Zero;
            var nextMessage = TimeSpan.Zero;
            while (clock.Elapsed < runFor)
            {
                offerer.SendVideoFrame(accessUnits[index % accessUnits.Count], videoTimestamp);
                index++;
                videoTimestamp += 3000;

                if (clock.Elapsed >= nextMessage)
                {
                    if (channel.State == DataChannelState.Open)
                    {
                        channel.SendText($"tick:{index}");
                        Interlocked.Increment(ref messagesSent);
                    }

                    nextMessage += TimeSpan.FromMilliseconds(50);
                }

                next += TimeSpan.FromMilliseconds(10);
                var wait = next - clock.Elapsed;
                if (wait > TimeSpan.Zero)
                {
                    await Task.Delay(wait).ConfigureAwait(false);
                }
            }
        });

        var cutTask = Task.Run(async () =>
        {
            var clock = Stopwatch.StartNew();
            while (clock.Elapsed < runFor)
            {
                var result = offerer.CutOutboundAudio();
                Interlocked.Add(ref discarded, result.PacketsDiscarded);
                await Task.Delay(7).ConfigureAwait(false);
            }
        });

        // A hang fails here rather than wedging the test run.
        await Task.WhenAll(audioTask, videoTask, cutTask).WaitAsync(TimeSpan.FromSeconds(20), shutdown.Token);

        var expectedOnWire = Interlocked.Read(ref audioFramesSent) - Interlocked.Read(ref discarded);
        (await TestSupport.WaitForAsync(
            () => AudioCount(wire, audioSsrc) >= expectedOnWire,
            timeoutMilliseconds: 15_000)).Should().BeTrue(
            $"everything not cut must eventually drain; sent={Interlocked.Read(ref audioFramesSent)} "
            + $"discarded={Interlocked.Read(ref discarded)} onWire={AudioCount(wire, audioSsrc)}");

        var audio = wire.Where(p => p.Ssrc == audioSsrc).ToArray();
        audio.Should().HaveCount((int)expectedOnWire);
        for (var i = 1; i < audio.Length; i++)
        {
            unchecked((ushort)(audio[i].SequenceNumber - audio[i - 1].SequenceNumber)).Should().Be(1,
                "audio sequence numbers stay contiguous across every cut");
            unchecked((int)(audio[i].Timestamp - audio[i - 1].Timestamp)).Should().BeGreaterThan(0,
                "audio timestamps never go backwards");
        }

        wire.Count(p => p.Ssrc == videoSsrc).Should().BeGreaterThan(200, "video kept flowing during the cuts");
        Interlocked.Read(ref receivedMessages).Should().BeGreaterThanOrEqualTo(
            (long)(Interlocked.Read(ref messagesSent) * 0.9), "the data channel kept flowing during the cuts");
    }

    [Fact]
    public async Task CutTransportCcGapDoesNotDropTheCongestionEstimate()
    {
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        // A start target well above what the pumps offer: the pacer then never builds a backlog, so the
        // delay estimate reflects the path rather than pacing, and the target stays stable at the clamp.
        var pair = await ConnectAsync(
            congestionControl: true,
            shutdown.Token,
            new CongestionControllerOptions
            {
                StartBitrateBitsPerSecond = 5_000_000,
                MinBitrateBitsPerSecond = 100_000,
                MaxBitrateBitsPerSecond = 20_000_000,
            });
        await using var offerer = pair.Offerer;
        await using var answerer = pair.Answerer;

        var audioSsrc = offerer.GetLocalSsrc(MediaKind.Audio);
        var wire = new ConcurrentQueue<WirePacket>();
        offerer.RtpWireObserverForTest = (rtp, ticks) => Record(rtp, ticks, wire);

        var accessUnits = H264TestStream.ReadAccessUnits(90);
        long audioFrames = 0;
        using var pumpStop = new CancellationTokenSource();

        var audioPump = Task.Run(async () =>
        {
            var clock = Stopwatch.StartNew();
            var next = TimeSpan.Zero;
            try
            {
                while (!pumpStop.IsCancellationRequested)
                {
                    var frame = Interlocked.Read(ref audioFrames);
                    offerer.SendAudioFrame(Tone(), unchecked((uint)(frame * AudioSampleIncrement)));
                    Interlocked.Increment(ref audioFrames);
                    next += TimeSpan.FromMilliseconds(20);
                    var wait = next - clock.Elapsed;
                    if (wait > TimeSpan.Zero)
                    {
                        await Task.Delay(wait, pumpStop.Token).ConfigureAwait(false);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // stopped at the end of the measurement
            }
        });

        var videoPump = Task.Run(async () =>
        {
            var clock = Stopwatch.StartNew();
            var index = 0;
            var timestamp = 0u;
            var next = TimeSpan.Zero;
            try
            {
                while (!pumpStop.IsCancellationRequested)
                {
                    offerer.SendVideoFrame(accessUnits[index % accessUnits.Count], timestamp);
                    index++;
                    timestamp += 3000;
                    next += TimeSpan.FromMilliseconds(33);
                    var wait = next - clock.Elapsed;
                    if (wait > TimeSpan.Zero)
                    {
                        await Task.Delay(wait, pumpStop.Token).ConfigureAwait(false);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // stopped at the end of the measurement
            }
        });

        try
        {
            (await TestSupport.WaitForAsync(() => wire.Any(p => p.Ssrc == audioSsrc), 10_000))
                .Should().BeTrue("audio should reach the wire through the pacer");

            await Task.Delay(2000, shutdown.Token);

            var controller = offerer.CongestionController;
            controller.Should().NotBeNull("congestion control was enabled");
            var before = controller!.TargetBitrateBitsPerSecond;

            const int KindNone = 0;
            const int KindControl = 1;
            const int KindCut = 2;
            var currentKind = new int[1];
            var minimum = new long[] { before };
            var decreaseCounts = new long[2]; // [control, cut]
            var gate = new object();

            // Read the prior target just before subscribing so the first event compares against reality.
            var previous = controller.TargetBitrateBitsPerSecond;
            offerer.TargetBitrateChanged += (_, e) =>
            {
                lock (gate)
                {
                    var target = e.TargetBitrateBitsPerSecond;
                    minimum[0] = Math.Min(minimum[0], target);
                    if (target < previous)
                    {
                        switch (Volatile.Read(ref currentKind[0]))
                        {
                            case KindControl:
                                decreaseCounts[0]++;
                                break;
                            case KindCut:
                                decreaseCounts[1]++;
                                break;
                            default:
                                break;
                        }
                    }

                    previous = target;
                }
            };

            var paced = offerer.PacedSenderForTest;
            paced.Should().NotBeNull();
            paced!.HoldDrainForTest = false;

            async Task RoundAsync(int kind)
            {
                Volatile.Write(ref currentKind[0], kind);
                paced.HoldDrainForTest = true;
                for (var i = 0; i < 10; i++)
                {
                    var frame = Interlocked.Read(ref audioFrames);
                    offerer.SendAudioFrame(Tone(), unchecked((uint)(frame * AudioSampleIncrement)));
                    Interlocked.Increment(ref audioFrames);
                }

                if (kind == KindCut)
                {
                    offerer.CutOutboundAudio();
                }

                paced.HoldDrainForTest = false;

                lock (gate)
                {
                    minimum[0] = Math.Min(minimum[0], controller.TargetBitrateBitsPerSecond);
                }

                await Task.Delay(300, shutdown.Token);
            }

            // Five interleaved control/cut pairs, so a spurious overuse is equally likely in either and the
            // decrease counts are comparable.
            for (var roundPair = 0; roundPair < 5; roundPair++)
            {
                await RoundAsync(KindControl);
                await RoundAsync(KindCut);
            }

            // Keep attributing feedback to the last round until its feedback window has passed.
            await Task.Delay(300, shutdown.Token);
            Volatile.Write(ref currentKind[0], KindNone);

            await Task.Delay(1500, shutdown.Token);

            var after = controller.TargetBitrateBitsPerSecond;
            long minDuringCuts;
            long controlDecreases;
            long cutDecreases;
            lock (gate)
            {
                minDuringCuts = minimum[0];
                controlDecreases = decreaseCounts[0];
                cutDecreases = decreaseCounts[1];
            }

            pumpStop.Cancel();
            await Task.WhenAll(audioPump, videoPump);

            _output.WriteLine(
                $"congestion target before={before} minDuringCuts={minDuringCuts} after={after} "
                + $"controlDecreases={controlDecreases} cutDecreases={cutDecreases}");

            // The extension must actually be negotiated, or the gap assertion below is vacuous.
            var numbers = wire.Where(p => p.TransportSequenceNumber >= 0)
                .Select(p => (ushort)p.TransportSequenceNumber)
                .ToArray();
            numbers.Should().NotBeEmpty("transport-wide congestion control must be negotiated for this test");

            // A cut discards packets that already drew transport-wide sequence numbers, leaving a real gap.
            var sawGap = false;
            for (var i = 1; i < numbers.Length; i++)
            {
                var delta = unchecked((int)(short)(numbers[i] - numbers[i - 1]));
                delta.Should().BeGreaterThan(0, "transport-wide sequence numbers stay monotonic on the wire");
                sawGap |= delta > 1;
            }

            sawGap.Should().BeTrue("the cut must leave a transport-wide-cc gap on the wire");

            // Tolerance arithmetic. Loopback has no real congestion, but a loaded CI box can produce a spurious
            // delay-based overuse; each one is a decrease event, and it is equally likely in a control round
            // (same hold/release burst, no cut) as in a cut round because the rounds are interleaved 300 ms apart.
            // We allow ONE more decrease in cut rounds than in control rounds for that noise.
            // Regression signature: if the cut's TWCC gap were read as loss or corrupted the delay estimate, every
            // cut round's feedback carries 10 not-received entries out of roughly 10 audio + 5 audio + ~15 video
            // = ~30 packets per 100 ms feedback window, i.e. ~33% apparent loss, far above the 10% high-loss
            // threshold, so each of the 5 cut rounds would produce at least one decrease: cutDecreases >= 5, while
            // the bound allows at most controlDecreases + 1. A clean run measures 0 and 0.
            // We do not assert "target never drops" or "recovers to 90%": Decrease() backs off to 0.85 x measured
            // throughput and Increase() is capped at 1.5 x throughput, so one spurious overuse keeps the target
            // well below the 5 Mbps start for the rest of the test.
            cutDecreases.Should().BeLessThanOrEqualTo(
                controlDecreases + 1,
                "a transport-wide-cc gap from a cut must not lower the congestion estimate more often "
                + "than the no-cut control rounds do");
        }
        finally
        {
            pumpStop.Cancel();
            await Task.WhenAny(Task.WhenAll(audioPump, videoPump), Task.Delay(2000));
        }
    }

    // ---------------------------------------------------------------- helpers

    private static async Task<(PeerConnection Offerer, PeerConnection Answerer)> ConnectAsync(
        bool congestionControl,
        CancellationToken cancellationToken,
        CongestionControllerOptions? congestionOptions = null)
    {
        var offererConfig = TestSupport.NewConfig();
        offererConfig.EnableCongestionControl = congestionControl;
        if (congestionOptions is not null)
        {
            offererConfig.CongestionControl = congestionOptions;
        }
        var offerer = new PeerConnection(offererConfig);
        var answerer = new PeerConnection(TestSupport.NewConfig());
        offerer.OnLocalIceCandidate += (_, e) => answerer.AddIceCandidate(e.Candidate, e.SdpMid);
        answerer.OnLocalIceCandidate += (_, e) => offerer.AddIceCandidate(e.Candidate, e.SdpMid);

        var offer = await offerer.CreateOfferAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await answerer.CreateAnswerAsync(cancellationToken);
        await offerer.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        (await offerer.WaitForConnectedAsync(TimeSpan.FromSeconds(30), cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(TimeSpan.FromSeconds(30), cancellationToken)).Should().BeTrue();
        return (offerer, answerer);
    }

    private static byte[] Tone(byte second = 0x11)
    {
        var packet = new byte[80];
        packet[0] = 0xFC; // Opus TOC: CELT, one 20 ms frame
        packet[1] = second;
        return packet;
    }

    private static byte[] OpusPacket(RtpStreamSender sender)
    {
        var buffer = new byte[256];
        var length = sender.WritePacket(Tone(), marker: false, buffer);
        return buffer[..length];
    }

    private static void Record(ReadOnlySpan<byte> rtp, long ticks, ConcurrentQueue<WirePacket> sink)
    {
        var copy = rtp.ToArray();
        if (!RtpPacket.TryParse(copy, out var packet))
        {
            return;
        }

        var transportSequenceNumber = -1;
        if (PeerConnection.TryLocateTransportCc(copy.AsSpan(), TransportCcExtensionId, out var offset))
        {
            transportSequenceNumber = BinaryPrimitives.ReadUInt16BigEndian(copy.AsSpan(offset, 2));
        }

        sink.Enqueue(new WirePacket(
            packet.Header.Ssrc,
            packet.Header.SequenceNumber,
            packet.Header.Timestamp,
            packet.Header.Marker,
            transportSequenceNumber,
            ticks,
            packet.Payload.Length > 1 ? packet.Payload[1] : (byte)0));
    }

    private static int AudioCount(ConcurrentQueue<WirePacket> wire, uint audioSsrc) =>
        wire.Count(p => p.Ssrc == audioSsrc);

    private readonly record struct WirePacket(
        uint Ssrc,
        ushort SequenceNumber,
        uint Timestamp,
        bool Marker,
        int TransportSequenceNumber,
        long Ticks,
        byte ContentByte);
}
