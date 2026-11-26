using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using FluentAssertions;
using Keryx.Rtp;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// Coverage for <see cref="RtpSender.OnRtpPacketSent"/>: the events must mirror exactly what the wire
/// observer sees, carry the rebased sequence/timestamp and the output generation after a cut, stay quiet
/// for other senders, survive a throwing handler, tolerate concurrent subscription churn, and add no
/// per-packet allocation.
/// </summary>
public sealed class RtpSenderPacketSentTests
{
    private const int AudioSampleIncrement = 960; // 20 ms of Opus at 48 kHz

    // Keryx offers transport-wide congestion control at extmap 3; a Keryx-to-Keryx answer echoes it.
    private const byte TransportCcExtensionId = 3;

    // A static counter so the allocation test's handler captures nothing per call.
    private static long _handlerCalls;

    [Fact]
    public async Task PacedSendsAreReportedExactlyAsTheyHitTheWire()
    {
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var pair = await ConnectAsync(congestionControl: true, shutdown.Token);
        await using var offerer = pair.Offerer;
        await using var answerer = pair.Answerer;

        var audioSsrc = offerer.GetLocalSsrc(MediaKind.Audio);
        var wire = new ConcurrentQueue<WirePacket>();
        offerer.RtpWireObserverForTest = (rtp, ticks) => Record(rtp, ticks, wire);

        var sender = AudioSender(offerer);
        var events = new ConcurrentQueue<SentEvent>();
        sender.OnRtpPacketSent += (RtpSender _, in RtpPacketSentInfo info) =>
            events.Enqueue(new SentEvent(info.SequenceNumber, info.RtpTimestamp, info.SentAtTimestamp, info.Generation));

        for (var i = 0; i < 20; i++)
        {
            offerer.SendAudioFrame(Tone(), (uint)(i * AudioSampleIncrement)).Should().Be(1);
        }

        (await TestSupport.WaitForAsync(() => AudioCount(wire, audioSsrc) >= 20 && events.Count >= 20))
            .Should().BeTrue();

        var ev = events.ToArray();
        ev.Select(e => (e.Seq, e.Ts)).Should().Equal(AudioSeqTs(wire, audioSsrc));
        ev.Should().OnlyContain(e => e.Gen == 0, "no cut happened");

        var wireTicks = wire.Where(p => p.Ssrc == audioSsrc).Select(p => p.Ticks).ToArray();
        var at = ev.Select(e => e.At).ToArray();
        at.Should().BeInAscendingOrder();
        for (var i = 0; i < at.Length; i++)
        {
            at[i].Should().BeGreaterThanOrEqualTo(wireTicks[i],
                "the observer runs just before the send, so the event's timestamp is at least as late");
        }
    }

    [Fact]
    public async Task DirectSendsAreReportedOnTheCallingThread()
    {
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var pair = await ConnectAsync(congestionControl: false, shutdown.Token);
        await using var offerer = pair.Offerer;
        await using var answerer = pair.Answerer;

        var audioSsrc = offerer.GetLocalSsrc(MediaKind.Audio);
        var wire = new ConcurrentQueue<WirePacket>();
        offerer.RtpWireObserverForTest = (rtp, ticks) => Record(rtp, ticks, wire);

        var sender = AudioSender(offerer);
        var events = new ConcurrentQueue<SentEvent>();
        var threadIds = new ConcurrentQueue<int>();
        sender.OnRtpPacketSent += (RtpSender _, in RtpPacketSentInfo info) =>
        {
            events.Enqueue(new SentEvent(info.SequenceNumber, info.RtpTimestamp, info.SentAtTimestamp, info.Generation));
            threadIds.Enqueue(Environment.CurrentManagedThreadId);
        };

        var sendingThread = Environment.CurrentManagedThreadId;
        for (var i = 0; i < 10; i++)
        {
            offerer.SendAudioFrame(Tone(), (uint)(i * AudioSampleIncrement)).Should().Be(1);
        }

        (await TestSupport.WaitForAsync(() => AudioCount(wire, audioSsrc) >= 10 && events.Count >= 10))
            .Should().BeTrue();

        events.Select(e => (e.Seq, e.Ts)).Should().Equal(AudioSeqTs(wire, audioSsrc));
        threadIds.Should().OnlyContain(id => id == sendingThread);
    }

    [Fact]
    public async Task AfterACutEventsCarryTheRebasedTimestampAndTheNewGeneration()
    {
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var pair = await ConnectAsync(congestionControl: true, shutdown.Token);
        await using var offerer = pair.Offerer;
        await using var answerer = pair.Answerer;

        var audioSsrc = offerer.GetLocalSsrc(MediaKind.Audio);
        var wire = new ConcurrentQueue<WirePacket>();
        offerer.RtpWireObserverForTest = (rtp, ticks) => Record(rtp, ticks, wire);

        var sender = AudioSender(offerer);
        var events = new ConcurrentQueue<SentEvent>();
        sender.OnRtpPacketSent += (RtpSender _, in RtpPacketSentInfo info) =>
            events.Enqueue(new SentEvent(info.SequenceNumber, info.RtpTimestamp, info.SentAtTimestamp, info.Generation));

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

        var cut = offerer.CutOutboundAudio();
        cut.Generation.Should().Be(1);
        cut.PacketsDiscarded.Should().Be(10);

        paced.HoldDrainForTest = false;
        await Task.Delay(100, shutdown.Token);

        // The application keeps its own clock running from where it was.
        for (var i = 15; i < 20; i++)
        {
            offerer.SendAudioFrame(Tone(), (uint)(i * AudioSampleIncrement)).Should().Be(1);
        }

        (await TestSupport.WaitForAsync(() => AudioCount(wire, audioSsrc) >= 10 && events.Count >= 10))
            .Should().BeTrue();
        await Task.Delay(100, shutdown.Token);

        var ev = events.ToArray();
        ev.Should().HaveCount(10, "the ten cut packets must never be reported");
        ev.Select(e => (e.Seq, e.Ts)).Should().Equal(AudioSeqTs(wire, audioSsrc));

        ev[..5].Should().OnlyContain(e => e.Gen == 0);
        ev[5..].Should().OnlyContain(e => e.Gen == 1);

        ev[5].Seq.Should().Be(unchecked((ushort)(ev[4].Seq + 1)), "the sequence space is rewound");
        unchecked((int)(ev[5].Ts - ev[4].Ts)).Should().BeGreaterThanOrEqualTo(AudioSampleIncrement);

        // The event carries the rebased wire value, not the app's 15 * 960 value plus the pre-cut offset.
        var appValueWithoutRebase = unchecked((uint)(15 * AudioSampleIncrement) + (ev[0].Ts - 0));
        ev[5].Ts.Should().NotBe(appValueWithoutRebase);

        // No cut packet's app timestamp may be reported under the old generation beyond the first five.
        var cutAppTimestamps = new HashSet<uint>();
        for (var i = 5; i < 15; i++)
        {
            cutAppTimestamps.Add((uint)(i * AudioSampleIncrement));
        }

        ev.Skip(5).Should().NotContain(e => e.Gen == 0 && cutAppTimestamps.Contains(e.Ts));
    }

    [Fact]
    public async Task ASecondCutAdvancesTheGenerationAgain()
    {
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var pair = await ConnectAsync(congestionControl: false, shutdown.Token);
        await using var offerer = pair.Offerer;
        await using var answerer = pair.Answerer;

        var audioSsrc = offerer.GetLocalSsrc(MediaKind.Audio);
        var wire = new ConcurrentQueue<WirePacket>();
        offerer.RtpWireObserverForTest = (rtp, ticks) => Record(rtp, ticks, wire);

        var sender = AudioSender(offerer);
        var events = new ConcurrentQueue<SentEvent>();
        sender.OnRtpPacketSent += (RtpSender _, in RtpPacketSentInfo info) =>
            events.Enqueue(new SentEvent(info.SequenceNumber, info.RtpTimestamp, info.SentAtTimestamp, info.Generation));

        var first = offerer.CutOutboundAudio();
        offerer.SendAudioFrame(Tone(), 0).Should().Be(1);
        offerer.SendAudioFrame(Tone(), AudioSampleIncrement).Should().Be(1);

        var second = offerer.CutOutboundAudio();
        offerer.SendAudioFrame(Tone(), (uint)(2 * AudioSampleIncrement)).Should().Be(1);
        offerer.SendAudioFrame(Tone(), (uint)(3 * AudioSampleIncrement)).Should().Be(1);

        (await TestSupport.WaitForAsync(() => AudioCount(wire, audioSsrc) >= 4 && events.Count >= 4))
            .Should().BeTrue();

        first.Generation.Should().Be(1);
        second.Generation.Should().Be(2);
        events.Select(e => e.Gen).Should().Equal(1, 1, 2, 2);
    }

    [Fact]
    public async Task UnsubscribedHandlerStopsReceivingAndOtherSendersAreNotReported()
    {
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var pair = await ConnectAsync(congestionControl: false, shutdown.Token);
        await using var offerer = pair.Offerer;
        await using var answerer = pair.Answerer;

        var audioSsrc = offerer.GetLocalSsrc(MediaKind.Audio);
        var videoSsrc = offerer.GetLocalSsrc(MediaKind.Video);
        var wire = new ConcurrentQueue<WirePacket>();
        offerer.RtpWireObserverForTest = (rtp, ticks) => Record(rtp, ticks, wire);

        var sender = AudioSender(offerer);
        var events = new ConcurrentQueue<SentEvent>();
        RtpPacketSentHandler handler = (RtpSender _, in RtpPacketSentInfo info) =>
            events.Enqueue(new SentEvent(info.SequenceNumber, info.RtpTimestamp, info.SentAtTimestamp, info.Generation));
        sender.OnRtpPacketSent += handler;

        for (var i = 0; i < 10; i++)
        {
            offerer.SendAudioFrame(Tone(), (uint)(i * AudioSampleIncrement)).Should().Be(1);
        }

        var accessUnits = H264TestStream.ReadAccessUnits(5);
        offerer.SendVideoFrame(accessUnits[0], 0).Should().BeGreaterThan(0);

        (await TestSupport.WaitForAsync(
            () => AudioCount(wire, audioSsrc) >= 10
                && events.Count >= 10
                && wire.Any(p => p.Ssrc == videoSsrc))).Should().BeTrue();

        var audioSeqTs = new HashSet<(ushort, uint)>(AudioSeqTs(wire, audioSsrc));
        var ev = events.ToArray();
        ev.Should().HaveCount(AudioCount(wire, audioSsrc));
        ev.Where(e => !audioSeqTs.Contains((e.Seq, e.Ts))).Should().BeEmpty(
            "video packets travel on their own SSRC and are not reported on the audio sender");

        sender.OnRtpPacketSent -= handler;

        for (var i = 10; i < 15; i++)
        {
            offerer.SendAudioFrame(Tone(), (uint)(i * AudioSampleIncrement)).Should().Be(1);
        }

        (await TestSupport.WaitForAsync(() => AudioCount(wire, audioSsrc) >= 15)).Should().BeTrue();
        await Task.Delay(100, shutdown.Token);
        events.Should().HaveCount(10, "the removed handler must stop receiving");
    }

    [Fact]
    public async Task AThrowingHandlerDoesNotBreakSending()
    {
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var pair = await ConnectAsync(congestionControl: false, shutdown.Token);
        await using var offerer = pair.Offerer;
        await using var answerer = pair.Answerer;

        var audioSsrc = offerer.GetLocalSsrc(MediaKind.Audio);
        var wire = new ConcurrentQueue<WirePacket>();
        offerer.RtpWireObserverForTest = (rtp, ticks) => Record(rtp, ticks, wire);

        AudioSender(offerer).OnRtpPacketSent += static (RtpSender _, in RtpPacketSentInfo _) =>
            throw new InvalidOperationException("simulated handler failure");

        for (var i = 0; i < 5; i++)
        {
            offerer.SendAudioFrame(Tone(), (uint)(i * AudioSampleIncrement)).Should().Be(1);
        }

        (await TestSupport.WaitForAsync(() => AudioCount(wire, audioSsrc) >= 5)).Should().BeTrue();
        AudioCount(wire, audioSsrc).Should().Be(5);
    }

    [Fact]
    public async Task ConcurrentSendsCutsAndSubscriptionChurnStayConsistent()
    {
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var pair = await ConnectAsync(congestionControl: true, shutdown.Token);
        await using var offerer = pair.Offerer;
        await using var answerer = pair.Answerer;

        var audioSsrc = offerer.GetLocalSsrc(MediaKind.Audio);
        var wire = new ConcurrentQueue<WirePacket>();
        offerer.RtpWireObserverForTest = (rtp, ticks) => Record(rtp, ticks, wire);

        var sender = AudioSender(offerer);
        var events = new ConcurrentQueue<SentEvent>();
        sender.OnRtpPacketSent += (RtpSender _, in RtpPacketSentInfo info) =>
            events.Enqueue(new SentEvent(info.SequenceNumber, info.RtpTimestamp, info.SentAtTimestamp, info.Generation));

        var cuts = new ConcurrentQueue<int>();
        var faults = new ConcurrentQueue<Exception>();
        var runFor = TimeSpan.FromSeconds(2);

        async Task Guarded(Func<Task> body)
        {
            try
            {
                await body().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                faults.Enqueue(ex);
            }
        }

        var sendTask = Guarded(async () =>
        {
            var clock = Stopwatch.StartNew();
            uint index = 0;
            var next = TimeSpan.Zero;
            while (clock.Elapsed < runFor)
            {
                offerer.SendAudioFrame(Tone(), unchecked(index * (uint)AudioSampleIncrement));
                index++;
                next += TimeSpan.FromMilliseconds(2);
                var wait = next - clock.Elapsed;
                if (wait > TimeSpan.Zero)
                {
                    await Task.Delay(wait).ConfigureAwait(false);
                }
            }
        });

        var cutTask = Guarded(async () =>
        {
            var clock = Stopwatch.StartNew();
            while (clock.Elapsed < runFor)
            {
                cuts.Enqueue(offerer.CutOutboundAudio().Generation);
                await Task.Delay(15).ConfigureAwait(false);
            }
        });

        RtpPacketSentHandler churn = static (RtpSender _, in RtpPacketSentInfo _) => { };
        var churnTask = Guarded(async () =>
        {
            var clock = Stopwatch.StartNew();
            while (clock.Elapsed < runFor)
            {
                sender.OnRtpPacketSent += churn;
                sender.OnRtpPacketSent -= churn;
                await Task.Delay(1).ConfigureAwait(false);
            }
        });

        await Task.WhenAll(sendTask, cutTask, churnTask).WaitAsync(TimeSpan.FromSeconds(20), shutdown.Token);

        // Let the pacer drain everything it still holds.
        await Task.Delay(300, shutdown.Token);
        (await TestSupport.WaitForAsync(
            () => AudioCount(wire, audioSsrc) == events.Count,
            timeoutMilliseconds: 10_000)).Should().BeTrue();
        await Task.Delay(50, shutdown.Token);

        faults.Should().BeEmpty("no send, cut or subscription task may fault");

        var ev = events.ToArray();
        var wireAudio = wire.Where(p => p.Ssrc == audioSsrc).ToArray();
        wireAudio.Should().HaveCount(ev.Length);
        ev.Select(e => (e.Seq, e.Ts)).Should().Equal(
            wireAudio.Select(p => (p.SequenceNumber, p.Timestamp)));

        for (var i = 1; i < ev.Length; i++)
        {
            ev[i].Gen.Should().BeGreaterThanOrEqualTo(ev[i - 1].Gen, "generations only move forward");
        }

        var cutGenerations = cuts.ToArray();
        cutGenerations.Should().Equal(Enumerable.Range(1, cutGenerations.Length));
        if (ev.Length > 0 && cutGenerations.Length > 0)
        {
            ev[^1].Gen.Should().BeLessThanOrEqualTo(cutGenerations[^1]);
        }

        for (var i = 1; i < wireAudio.Length; i++)
        {
            unchecked((ushort)(wireAudio[i].SequenceNumber - wireAudio[i - 1].SequenceNumber))
                .Should().Be(1, "audio sequence numbers stay contiguous across every cut");
        }
    }

    [Fact]
    public async Task PcmuCutReportsSamplesPerByteAndRebasesOnThe8kClock()
    {
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var pair = await ConnectAsync(congestionControl: true, shutdown.Token, ReplaceAudioCodecs(
            new SdpCodec(0, "PCMU", 8000, 1)));
        await using var offerer = pair.Offerer;
        await using var answerer = pair.Answerer;

        var audioSsrc = offerer.GetLocalSsrc(MediaKind.Audio);
        var wire = new ConcurrentQueue<WirePacket>();
        offerer.RtpWireObserverForTest = (rtp, ticks) => Record(rtp, ticks, wire);

        var frame = new byte[160];
        for (var i = 0; i < 5; i++)
        {
            offerer.SendAudioFrame(frame, (uint)(i * 160)).Should().Be(1);
        }

        (await TestSupport.WaitForAsync(() => AudioCount(wire, audioSsrc) >= 5)).Should().BeTrue();
        var paced = offerer.PacedSenderForTest!;
        paced.HoldDrainForTest = true;

        for (var i = 5; i < 15; i++)
        {
            offerer.SendAudioFrame(frame, (uint)(i * 160)).Should().Be(1);
        }

        var cutEnd = Stopwatch.GetTimestamp();
        var cut = offerer.CutOutboundAudio();
        cut.PacketsDiscarded.Should().Be(10);
        cut.SamplesDiscarded.Should().Be(1600, "one sample per payload byte at 8 kHz");
        cut.SampleRate.Should().Be(8_000);
        cut.DurationDiscarded.Should().Be(TimeSpan.FromMilliseconds(200));

        paced.HoldDrainForTest = false;
        await Task.Delay(100, shutdown.Token);

        for (var i = 15; i < 20; i++)
        {
            offerer.SendAudioFrame(frame, (uint)(i * 160)).Should().Be(1);
        }

        (await TestSupport.WaitForAsync(() => AudioCount(wire, audioSsrc) >= 10)).Should().BeTrue();
        await Task.Delay(100, shutdown.Token);

        var packets = wire.Where(p => p.Ssrc == audioSsrc).ToArray();
        packets.Should().HaveCount(10);
        var before = packets[4];
        var firstNew = packets[5];

        var actualGap = unchecked((int)(firstNew.Timestamp - (before.Timestamp + 160)));
        var elapsedSeconds = (firstNew.Ticks - cutEnd) / (double)Stopwatch.Frequency;
        var expectedGap = (int)Math.Round(elapsedSeconds * 8_000);
        actualGap.Should().BeGreaterThanOrEqualTo(0);
        Math.Abs(actualGap - expectedGap).Should().BeLessThanOrEqualTo(40 * 8,
            "the rebase tracks the wall clock on the 8 kHz RTP clock");
    }

    [Fact]
    public async Task G722CutReportsTwoSamplesPerByteAt16k()
    {
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var pair = await ConnectAsync(congestionControl: true, shutdown.Token, ReplaceAudioCodecs(
            new SdpCodec(9, "G722", 8000, 1)));
        await using var offerer = pair.Offerer;
        await using var answerer = pair.Answerer;

        var audioSsrc = offerer.GetLocalSsrc(MediaKind.Audio);
        var wire = new ConcurrentQueue<WirePacket>();
        offerer.RtpWireObserverForTest = (rtp, ticks) => Record(rtp, ticks, wire);

        var frame = new byte[160];
        for (var i = 0; i < 5; i++)
        {
            offerer.SendAudioFrame(frame, (uint)(i * 160)).Should().Be(1);
        }

        (await TestSupport.WaitForAsync(() => AudioCount(wire, audioSsrc) >= 5)).Should().BeTrue();
        var paced = offerer.PacedSenderForTest!;
        paced.HoldDrainForTest = true;

        for (var i = 5; i < 15; i++)
        {
            offerer.SendAudioFrame(frame, (uint)(i * 160)).Should().Be(1);
        }

        var cut = offerer.CutOutboundAudio();
        cut.PacketsDiscarded.Should().Be(10);
        cut.SamplesDiscarded.Should().Be(3200, "two audio samples per payload byte at 16 kHz");
        cut.SampleRate.Should().Be(16_000);
        cut.DurationDiscarded.Should().Be(TimeSpan.FromMilliseconds(200));

        paced.HoldDrainForTest = false;
        await Task.Delay(100, shutdown.Token);

        for (var i = 15; i < 20; i++)
        {
            offerer.SendAudioFrame(frame, (uint)(i * 160)).Should().Be(1);
        }

        (await TestSupport.WaitForAsync(() => AudioCount(wire, audioSsrc) >= 10)).Should().BeTrue();
        AudioCount(wire, audioSsrc).Should().Be(10, "the ten cut packets must never reach the wire");
    }

    [Fact]
    public async Task UnknownCodecCutReportsTheSentinelNotAGuess()
    {
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var pair = await ConnectAsync(congestionControl: true, shutdown.Token, ReplaceAudioCodecs(
            new SdpCodec(97, "L16", 16000, 1)));
        await using var offerer = pair.Offerer;
        await using var answerer = pair.Answerer;

        var audioSsrc = offerer.GetLocalSsrc(MediaKind.Audio);
        var wire = new ConcurrentQueue<WirePacket>();
        offerer.RtpWireObserverForTest = (rtp, ticks) => Record(rtp, ticks, wire);

        var frame = new byte[160];
        for (var i = 0; i < 5; i++)
        {
            offerer.SendAudioFrame(frame, (uint)(i * 160)).Should().Be(1);
        }

        (await TestSupport.WaitForAsync(() => AudioCount(wire, audioSsrc) >= 5)).Should().BeTrue();
        var paced = offerer.PacedSenderForTest!;
        paced.HoldDrainForTest = true;

        for (var i = 5; i < 15; i++)
        {
            offerer.SendAudioFrame(frame, (uint)(i * 160)).Should().Be(1);
        }

        var cut = offerer.CutOutboundAudio();
        cut.PacketsDiscarded.Should().Be(10);
        cut.SamplesDiscarded.Should().Be(OutboundCutResult.UnknownSamples);
        cut.SampleRate.Should().Be(0);
        cut.DurationDiscarded.Should().BeNull();

        paced.HoldDrainForTest = false;
        await Task.Delay(50, shutdown.Token);

        // Nothing is queued now: an empty cut reports zero samples, not the sentinel.
        var emptyCut = offerer.CutOutboundAudio();
        emptyCut.PacketsDiscarded.Should().Be(0);
        emptyCut.SamplesDiscarded.Should().Be(0);
        emptyCut.DurationDiscarded.Should().Be(TimeSpan.Zero);

        for (var i = 15; i < 17; i++)
        {
            offerer.SendAudioFrame(frame, (uint)(i * 160)).Should().Be(1);
        }

        (await TestSupport.WaitForAsync(() => AudioCount(wire, audioSsrc) >= 7)).Should().BeTrue();
        var packets = wire.Where(p => p.Ssrc == audioSsrc).ToArray();
        packets.Should().HaveCount(7);
        packets[5].Timestamp.Should().NotBe(packets[4].Timestamp,
            "the post-cut timestamp must not repeat the last one, even for an unmeasurable codec");
    }

    [Fact]
    public async Task SubscribingAddsNoPerPacketAllocation()
    {
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var pair = await ConnectAsync(congestionControl: false, shutdown.Token);
        await using var offerer = pair.Offerer;
        await using var answerer = pair.Answerer;

        var sender = AudioSender(offerer);
        var frame = Tone();
        uint timestamp = 0;

        for (var i = 0; i < 500; i++)
        {
            offerer.SendAudioFrame(frame, timestamp).Should().Be(1);
            timestamp += AudioSampleIncrement;
        }

        var start = GC.GetAllocatedBytesForCurrentThread();
        for (var i = 0; i < 2000; i++)
        {
            offerer.SendAudioFrame(frame, timestamp);
            timestamp += AudioSampleIncrement;
        }

        var withoutSubscriber = GC.GetAllocatedBytesForCurrentThread() - start;

        Interlocked.Exchange(ref _handlerCalls, 0);
        RtpPacketSentHandler handler = CountSentPacket;
        sender.OnRtpPacketSent += handler;

        start = GC.GetAllocatedBytesForCurrentThread();
        for (var i = 0; i < 2000; i++)
        {
            offerer.SendAudioFrame(frame, timestamp);
            timestamp += AudioSampleIncrement;
        }

        var withSubscriber = GC.GetAllocatedBytesForCurrentThread() - start;
        sender.OnRtpPacketSent -= handler;

        Interlocked.Read(ref _handlerCalls).Should().Be(2000);

        // Any per-packet allocation on the report path would be at least 24 bytes (object header plus at
        // least one field), so 2000 packets would add at least 48,000 bytes. The bound below is 16 bytes
        // per packet (32,000), which leaves room for runtime bookkeeping while still catching a real
        // allocation.
        (withSubscriber - withoutSubscriber).Should().BeLessThan(2000 * 16);
    }

    private static void CountSentPacket(RtpSender sender, in RtpPacketSentInfo info) =>
        Interlocked.Increment(ref _handlerCalls);

    // ---------------------------------------------------------------- helpers

    private static RtpSender AudioSender(PeerConnection connection) =>
        connection.Transceivers.Single(t => t.Kind == MediaKind.Audio).Sender;

    private static Action<PeerConnectionConfig> ReplaceAudioCodecs(params SdpCodec[] codecs) => config =>
    {
        config.AudioCodecs.Clear();
        foreach (var codec in codecs)
        {
            config.AudioCodecs.Add(new SdpCodec(codec.PayloadType, codec.EncodingName, codec.ClockRate, codec.Channels));
        }
    };

    private static async Task<(PeerConnection Offerer, PeerConnection Answerer)> ConnectAsync(
        bool congestionControl,
        CancellationToken cancellationToken,
        Action<PeerConnectionConfig>? configure = null)
    {
        var offererConfig = TestSupport.NewConfig();
        offererConfig.EnableCongestionControl = congestionControl;
        configure?.Invoke(offererConfig);

        var answererConfig = TestSupport.NewConfig();
        configure?.Invoke(answererConfig);

        var offerer = new PeerConnection(offererConfig);
        var answerer = new PeerConnection(answererConfig);
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

    private static (ushort Seq, uint Ts)[] AudioSeqTs(ConcurrentQueue<WirePacket> wire, uint ssrc) =>
        wire.Where(p => p.Ssrc == ssrc).Select(p => (p.SequenceNumber, p.Timestamp)).ToArray();

    private static int AudioCount(ConcurrentQueue<WirePacket> wire, uint ssrc) =>
        wire.Count(p => p.Ssrc == ssrc);

    private readonly record struct SentEvent(ushort Seq, uint Ts, long At, int Gen);

    private readonly record struct WirePacket(
        uint Ssrc,
        ushort SequenceNumber,
        uint Timestamp,
        bool Marker,
        int TransportSequenceNumber,
        long Ticks,
        byte ContentByte);
}
