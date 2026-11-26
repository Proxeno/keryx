using System.Buffers.Binary;
using FluentAssertions;
using Keryx.Core;
using Keryx.Sdp;
using Xunit;
using Xunit.Abstractions;

namespace Keryx.IntegrationTests;

/// <summary>
/// The inbound frame surface a voice agent consumes: each delivered audio packet carries its RTP
/// timestamp, the instant its datagram arrived (<see cref="RtpPacketInfo.ArrivalTimestamp"/>), and —
/// when the receive jitter buffer released it — the number of packets declared lost immediately before
/// it (<see cref="RtpPacketInfo.LostBefore"/>, with <see cref="RtpPacketInfo.LossTracked"/> true).
/// <para>
/// A Keryx sender pushes 100 Opus frames over loopback while a transport interceptor on the sender
/// drops one isolated audio packet and one run of three. The receiver runs with
/// <see cref="PeerConnectionConfig.EnableReceiveJitterBuffer"/> and must report exactly those two gaps
/// on the packets that follow them.
/// </para>
/// </summary>
public sealed class InboundAudioFrameSurfaceTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    private readonly ITestOutputHelper _output;

    /// <summary>Captures the xunit output sink.</summary>
    /// <param name="output">Where the run's measurements are written.</param>
    public InboundAudioFrameSurfaceTests(ITestOutputHelper output) => _output = output;

    private static CancellationToken TestTimeout() =>
        new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    /// <summary>One delivered audio packet, as the handler saw it.</summary>
    private readonly record struct Delivered(
        ushort SequenceNumber,
        uint Timestamp,
        long ArrivalTimestamp,
        int LostBefore,
        bool LossTracked);

    [Fact]
    public async Task JitterBuffer_reports_arrival_time_and_the_exact_gap_before_each_packet()
    {
        var cancellationToken = TestTimeout();

        SequenceDroppingTransport? injector = null;
        var audioSsrc = 0u;
        var senderConfig = VoiceTestSupport.NewVoiceConfig();
        senderConfig.TransportInterceptor = inner =>
            injector = new SequenceDroppingTransport(
                inner,
                dropOffsets: [10, 40, 41, 42],
                audioSsrc: () => Volatile.Read(ref audioSsrc));

        var receiverConfig = VoiceTestSupport.NewVoiceConfig();
        receiverConfig.EnableReceiveJitterBuffer = true;
        receiverConfig.ReceiveJitterBuffer.MaxWait = TimeSpan.FromMilliseconds(100);
        receiverConfig.ReceiveJitterBuffer.Capacity = 64;

        await using var sender = new PeerConnection(senderConfig);
        await using var receiver = new PeerConnection(receiverConfig);
        Volatile.Write(ref audioSsrc, sender.AudioSsrc);

        var delivered = new List<Delivered>();
        var gate = new object();
        receiver.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            _ = payload;
            if (info.Kind != MediaKind.Audio)
            {
                return;
            }

            lock (gate)
            {
                delivered.Add(new Delivered(
                    info.SequenceNumber,
                    info.Timestamp,
                    info.ArrivalTimestamp,
                    info.LostBefore,
                    info.LossTracked));
            }
        };

        await ConnectVoiceAsync(sender, receiver, cancellationToken);

        for (var i = 0; i < 100 && !cancellationToken.IsCancellationRequested; i++)
        {
            sender.SendAudioFrame(VoiceTestSupport.OpusSilence, (uint)(i * 960)).Should().Be(1);
            await Task.Delay(20, cancellationToken);
        }

        // Wait for every releasable packet to drain, including the two gaps' declared loss.
        (await TestSupport.WaitForAsync(
            () => { lock (gate) { return delivered.Count >= 96; } },
            timeoutMilliseconds: 10_000)).Should().BeTrue("all 96 surviving audio packets must be delivered");

        await Task.Delay(300, cancellationToken);

        Delivered[] packets;
        lock (gate)
        {
            packets = [.. delivered];
        }

        injector.Should().NotBeNull();
        injector!.BaseSequenceNumber.Should().NotBeNull("the interceptor saw the outbound audio stream");
        var baseSeq = injector.BaseSequenceNumber!.Value;
        var baseTimestamp = injector.BaseTimestamp!.Value;

        _output.WriteLine(
            $"delivered {packets.Length} audio packet(s); dropped offsets 10, 40, 41, 42 from seq {baseSeq}; "
            + $"losses declared={packets.Sum(static p => p.LostBefore)}");

        packets.Should().HaveCount(96);
        packets.Should().OnlyContain(static p => p.LossTracked, "the jitter buffer released every packet");

        // Every surviving packet arrived exactly once, with the timestamp the sender stamped and the
        // arrival time the receive path recorded.
        var expectedSequences = Enumerable.Range(0, 100)
            .Where(static offset => offset is not (10 or 40 or 41 or 42))
            .Select(offset => (ushort)(baseSeq + offset))
            .ToArray();
        packets.Select(static p => p.SequenceNumber).Should().Equal(expectedSequences);

        foreach (var packet in packets)
        {
            var offset = (ushort)(packet.SequenceNumber - baseSeq);
            packet.Timestamp.Should().Be(unchecked(baseTimestamp + (uint)(offset * 960)),
                "packet offset {0} must carry the sender's RTP timestamp", (int)offset);
        }

        packets.Should().OnlyContain(static p => p.ArrivalTimestamp != 0, "arrival time is always stamped");
        var arrivalTimes = packets.Select(static p => p.ArrivalTimestamp).ToArray();
        arrivalTimes.Should().BeInAscendingOrder("the jitter buffer releases in playout order");

        // Exactly the two gaps, each reported on the packet immediately after it.
        packets.Where(static p => p.LostBefore > 0).Select(static p => p.SequenceNumber)
            .Should().Equal((ushort)(baseSeq + 11), (ushort)(baseSeq + 43));
        packets.Where(p => p.SequenceNumber == (ushort)(baseSeq + 11))
            .Single().LostBefore.Should().Be(1, "the isolated drop was one packet");
        packets.Where(p => p.SequenceNumber == (ushort)(baseSeq + 43))
            .Single().LostBefore.Should().Be(3, "the run of three was three packets");
        packets.Should().OnlyContain(
            p => p.LostBefore == 0 || p.LostBefore == 1 || p.LostBefore == 3,
            "no other packet may report a gap");

        await sender.CloseAsync();
        await receiver.CloseAsync();
        injector!.Dispose();
    }

    [Fact]
    public async Task Buffer_off_reports_no_loss_tracking_and_a_non_zero_arrival_time()
    {
        var cancellationToken = TestTimeout();

        SequenceDroppingTransport? injector = null;
        var audioSsrc = 0u;
        var senderConfig = VoiceTestSupport.NewVoiceConfig();
        senderConfig.TransportInterceptor = inner =>
            injector = new SequenceDroppingTransport(
                inner,
                dropOffsets: [10, 40, 41, 42],
                audioSsrc: () => Volatile.Read(ref audioSsrc));

        // The default receiver leaves EnableReceiveJitterBuffer off: packets arrive in wire order and
        // the handler must not claim loss knowledge it does not have.
        await using var sender = new PeerConnection(senderConfig);
        await using var receiver = new PeerConnection(VoiceTestSupport.NewVoiceConfig());
        Volatile.Write(ref audioSsrc, sender.AudioSsrc);

        var delivered = new List<Delivered>();
        var gate = new object();
        receiver.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            _ = payload;
            if (info.Kind != MediaKind.Audio)
            {
                return;
            }

            lock (gate)
            {
                delivered.Add(new Delivered(
                    info.SequenceNumber,
                    info.Timestamp,
                    info.ArrivalTimestamp,
                    info.LostBefore,
                    info.LossTracked));
            }
        };

        await ConnectVoiceAsync(sender, receiver, cancellationToken);

        for (var i = 0; i < 100 && !cancellationToken.IsCancellationRequested; i++)
        {
            sender.SendAudioFrame(VoiceTestSupport.OpusSilence, (uint)(i * 960)).Should().Be(1);
            await Task.Delay(20, cancellationToken);
        }

        (await TestSupport.WaitForAsync(
            () => { lock (gate) { return delivered.Count >= 96; } },
            timeoutMilliseconds: 10_000)).Should().BeTrue("all 96 surviving audio packets must be delivered");

        Delivered[] packets;
        lock (gate)
        {
            packets = [.. delivered];
        }

        _output.WriteLine($"buffer off: delivered {packets.Length} audio packet(s).");
        packets.Should().HaveCount(96);
        packets.Should().OnlyContain(static p => !p.LossTracked, "arrival-order delivery tracks no loss");
        packets.Should().OnlyContain(static p => p.LostBefore == 0, "LostBefore means 'not tracked' here");
        packets.Should().OnlyContain(static p => p.ArrivalTimestamp != 0);

        await sender.CloseAsync();
        await receiver.CloseAsync();
        injector?.Dispose();
    }

    /// <summary>Negotiates the voice shape and waits for both peers to connect.</summary>
    private static async Task ConnectVoiceAsync(
        PeerConnection offerer,
        PeerConnection answerer,
        CancellationToken cancellationToken)
    {
        VoiceTestSupport.WireCandidates(offerer, answerer);
        VoiceTestSupport.MakeAudioSendRecv(offerer);

        var offer = await offerer.CreateOfferAsync(cancellationToken);
        await answerer.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);

        // Binding a legacy audio transceiver resets its direction to the complement of the offer, so
        // make it bidirectional again before the answer is built.
        VoiceTestSupport.MakeAudioSendRecv(answerer);

        var answer = await answerer.CreateAnswerAsync(cancellationToken);
        await offerer.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        (await offerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await answerer.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
    }

    /// <summary>
    /// An <see cref="IDatagramTransport"/> that drops outbound audio RTP datagrams by their offset from
    /// the first audio sequence number it observes. It matches only SRTP media on the audio SSRC, never
    /// STUN, DTLS, RTCP or SCTP, so the handshake and the data channels are untouched.
    /// </summary>
    private sealed class SequenceDroppingTransport : IDatagramTransport, IDisposable
    {
        private readonly IDatagramTransport _inner;
        private readonly HashSet<int> _dropOffsets;
        private readonly Func<uint> _audioSsrc;
        private int? _baseSequenceNumber;
        private uint? _baseTimestamp;

        internal SequenceDroppingTransport(
            IDatagramTransport inner,
            IEnumerable<int> dropOffsets,
            Func<uint> audioSsrc)
        {
            _inner = inner;
            _dropOffsets = [.. dropOffsets];
            _audioSsrc = audioSsrc;
            _inner.OnReceived += Forward;
        }

        /// <inheritdoc/>
        public event DatagramReceivedHandler? OnReceived;

        /// <inheritdoc/>
        public int MaxDatagramSize => _inner.MaxDatagramSize;

        /// <summary>The first outbound audio sequence number observed, or null before one was sent.</summary>
        internal ushort? BaseSequenceNumber => _baseSequenceNumber is { } seq ? (ushort)seq : null;

        /// <summary>The RTP timestamp of the first outbound audio packet observed.</summary>
        internal uint? BaseTimestamp => _baseTimestamp;

        /// <inheritdoc/>
        public void Send(ReadOnlySpan<byte> datagram)
        {
            if (DatagramClassifier.IsSrtpMedia(datagram) && DatagramClassifier.ReadSsrc(datagram) == _audioSsrc())
            {
                var sequenceNumber = DatagramClassifier.ReadSequenceNumber(datagram);
                if (_baseSequenceNumber is null)
                {
                    _baseSequenceNumber = sequenceNumber;
                    _baseTimestamp = BinaryPrimitives.ReadUInt32BigEndian(datagram[4..]);
                }

                var offset = (ushort)(sequenceNumber - (ushort)_baseSequenceNumber!.Value);
                if (_dropOffsets.Contains(offset))
                {
                    return;
                }
            }

            _inner.Send(datagram);
        }

        /// <summary>Unsubscribes from the wrapped transport.</summary>
        public void Dispose() => _inner.OnReceived -= Forward;

        private void Forward(ReadOnlySpan<byte> datagram) => OnReceived?.Invoke(datagram);
    }
}
