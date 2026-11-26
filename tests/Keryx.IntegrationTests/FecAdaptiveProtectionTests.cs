using System.Collections.Concurrent;
using FluentAssertions;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// End-to-end proof that a lossy path shrinks the FEC protection group through the live
/// <see cref="PeerConnection"/>: the receiver's reception reports feed the sender's protection
/// controller, the group size is published to the send path, and the overhead is exposed to an encoder.
/// </summary>
public sealed class FecAdaptiveProtectionTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    public enum FecScheme
    {
        Ulpfec,
        FlexFec,
    }

    [Theory]
    [InlineData(FecScheme.Ulpfec)]
    [InlineData(FecScheme.FlexFec)]
    public async Task Sustained_media_loss_shrinks_the_protection_group(FecScheme scheme)
    {
        var cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(90)).Token;

        var senderConfig = TestSupport.NewConfig();
        var receiverConfig = TestSupport.NewConfig();
        ApplyScheme(senderConfig, scheme);
        ApplyScheme(receiverConfig, scheme);

        // Adaptive group sizing is deliberately left at its default (on) here.

        uint mediaSsrc = 0;
        var mediaSeen = 0;

        // Drop one in four media datagrams, deterministically by arrival index: enough sustained loss to
        // move the group below its initial size from the very first reception report.
        var profile = new FaultProfile
        {
            DropProbability = 1.0,
            Selector = datagram =>
            {
                if (!DatagramClassifier.IsSrtpMedia(datagram)
                    || DatagramClassifier.ReadSsrc(datagram) != Volatile.Read(ref mediaSsrc))
                {
                    return false;
                }

                var index = Interlocked.Increment(ref mediaSeen) - 1;
                return index % 4 == 3;
            },
        };

        FaultInjectingDatagramTransport? injector = null;
        senderConfig.TransportInterceptor = inner =>
            injector = new FaultInjectingDatagramTransport(inner, profile, seed: 20260901);

        await using var sender = new PeerConnection(senderConfig);
        await using var receiver = new PeerConnection(receiverConfig);
        await ConnectAsync(sender, receiver, cancellationToken);

        Volatile.Write(ref mediaSsrc, sender.VideoSsrc);

        var events = new ConcurrentQueue<FecProtectionChangedEventArgs>();
        sender.FecProtectionChanged += (_, e) => events.Enqueue(e);

        sender.VideoFecGroupSize.Should().Be(10, "a fresh path starts at the initial group size");

        var accessUnits = H264TestStream.ReadAccessUnits(90);
        var deadline = Environment.TickCount64 + 30_000;
        var timestamp = 0u;
        var frame = 0;
        while (sender.VideoFecGroupSize >= 10 && Environment.TickCount64 < deadline)
        {
            sender.SendVideoFrame(accessUnits[frame % accessUnits.Count], timestamp);
            timestamp += 3000;
            frame++;
            await Task.Delay(5, cancellationToken);
        }

        (await TestSupport.WaitForAsync(() => sender.VideoFecGroupSize < 10, 30_000))
            .Should().BeTrue("sustained reported loss must shrink the protection group below its initial size");

        var changed = events.ToArray();
        changed.Should().NotBeEmpty("a group size change raises FecProtectionChanged");
        changed.Should().Contain(
            e => e.GroupSize < 10
                && e.OverheadFraction == 1.0 / (e.GroupSize + 1)
                && e.SmoothedLoss > 0,
            "the event carries the new size, its nominal overhead and the smoothed loss that drove it");
        changed.Should().Contain(
            e => e.GroupSize == sender.VideoFecGroupSize,
            "the last published size is what the sender reports");

        sender.VideoFecOverheadFraction.Should().BeGreaterThan(1.0 / 11, "a smaller group costs more overhead");

        injector!.Flush();
    }

    [Fact]
    public async Task A_connection_without_fec_reports_no_overhead()
    {
        await using var connection = new PeerConnection(TestSupport.NewConfig());

        connection.VideoFecGroupSize.Should().Be(0);
        connection.VideoFecOverheadFraction.Should().Be(0);
        connection.MediaTargetBitrateBitsPerSecond.Should().BeNull("congestion control is off");
    }

    [Theory]
    [InlineData(FecScheme.Ulpfec)]
    [InlineData(FecScheme.FlexFec)]
    public async Task Media_target_bitrate_subtracts_the_fec_overhead(FecScheme scheme)
    {
        var cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

        var senderConfig = TestSupport.NewConfig();
        senderConfig.EnableCongestionControl = true;
        ApplyScheme(senderConfig, scheme);

        var receiverConfig = TestSupport.NewConfig();
        ApplyScheme(receiverConfig, scheme);

        await using var sender = new PeerConnection(senderConfig);
        await using var receiver = new PeerConnection(receiverConfig);
        await ConnectAsync(sender, receiver, cancellationToken);

        sender.CongestionController.Should().NotBeNull();
        sender.VideoFecGroupSize.Should().Be(10);

        long? mediaTarget = null;
        for (var attempt = 0; attempt < 50 && mediaTarget is null; attempt++)
        {
            var before = sender.CongestionController!.TargetBitrateBitsPerSecond;
            var value = sender.MediaTargetBitrateBitsPerSecond;
            var after = sender.CongestionController.TargetBitrateBitsPerSecond;
            if (before == after)
            {
                // The target did not move across the read, so the comparison is meaningful.
                value.Should().Be((long)(before * (1 - sender.VideoFecOverheadFraction)));
                mediaTarget = value;
            }
            else
            {
                await Task.Delay(20, cancellationToken);
            }
        }

        mediaTarget.Should().NotBeNull("the controller reports a target once connected");
    }

    private static async Task ConnectAsync(
        PeerConnection sender,
        PeerConnection receiver,
        CancellationToken cancellationToken)
    {
        sender.OnLocalIceCandidate += (_, e) => receiver.AddIceCandidate(e.Candidate, e.SdpMid);

        var offer = await sender.CreateOfferAsync(cancellationToken);
        await receiver.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await receiver.CreateAnswerAsync(cancellationToken);
        await sender.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        (await sender.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await receiver.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
    }

    private static void ApplyScheme(PeerConnectionConfig config, FecScheme scheme)
    {
        if (scheme == FecScheme.FlexFec)
        {
            config.EnableFlexFec = true;
        }
        else
        {
            config.EnableUlpfec = true;
        }
    }
}
