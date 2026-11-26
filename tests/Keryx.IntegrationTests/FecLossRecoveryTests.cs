using System.Buffers.Binary;
using System.Collections.Concurrent;
using FluentAssertions;
using Keryx.Sdp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// End-to-end proof that forward error correction, wired into the live <see cref="PeerConnection"/>
/// media path, conceals loss: a sender protects its video with ULPFEC or FlexFEC, a fault injector
/// spliced under the sender's SRTP drops exactly one media packet in each protection group, and the
/// receiver must still deliver every media packet — the missing one rebuilt from the group's repair
/// packet and delivered through the ordinary inbound path, exactly as an RTX recovery would be.
/// </summary>
public sealed class FecLossRecoveryTests
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(20);

    // Keryx offers transport-wide congestion control at extmap 3; a Keryx-to-Keryx answer echoes it.
    private const byte TransportCcExtensionId = 3;

    // Impair the first several complete groups only, so every dropped packet belongs to a group whose
    // repair packet is emitted (the tail's partial group carries no repair), and a long undropped tail
    // closes the detectable window on packets that arrive directly.
    private const int GroupsToImpair = 8;

    public enum FecScheme
    {
        Ulpfec,
        FlexFec,
    }

    [Theory]
    [InlineData(FecScheme.Ulpfec, false)]
    [InlineData(FecScheme.Ulpfec, true)]
    [InlineData(FecScheme.FlexFec, false)]
    [InlineData(FecScheme.FlexFec, true)]
    public async Task Every_media_packet_is_delivered_despite_one_drop_per_group(FecScheme scheme, bool transportCc)
    {
        var cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(50)).Token;

        var senderConfig = TestSupport.NewConfig();
        var receiverConfig = TestSupport.NewConfig();
        ApplyScheme(senderConfig, scheme);
        ApplyScheme(receiverConfig, scheme);

        // PeerConnectionConfig defaults this to true, so pin the theory value explicitly: the
        // transportCc == false cases must run without the extension as well as with it.
        senderConfig.EnableTransportWideCc = transportCc;
        receiverConfig.EnableTransportWideCc = transportCc;

        uint mediaSsrc = 0;
        var mediaSeen = 0;
        var offered = new ConcurrentDictionary<ushort, byte>();
        var dropped = new ConcurrentDictionary<ushort, byte>();

        // Every outbound SRTP media datagram the sender emits, as it looks on the wire (the RTP header and
        // header extension are in the clear under SRTP), so the transport-cc stamping can be checked.
        var wireRecords = new ConcurrentQueue<WireRecord>();

        // The test's arithmetic assumes a fixed group ("drop the sixth packet of each group"), so the
        // adaptive group size is pinned off in ApplyScheme and this is the group the sender will use.
        var groupSize = senderConfig.FecProtection.InitialGroupSize;

        var profile = new FaultProfile
        {
            DropProbability = 1.0,
            Selector = datagram =>
            {
                if (!DatagramClassifier.IsSrtpMedia(datagram))
                {
                    return false;
                }

                if (transportCc)
                {
                    // Record every media/repair datagram before the drop decision, with its transport-wide
                    // sequence number read off the plaintext header extension.
                    var copy = datagram.ToArray();
                    var hasTransportCc = PeerConnection.TryLocateTransportCc(
                        copy.AsSpan(), TransportCcExtensionId, out var offset);
                    wireRecords.Enqueue(new WireRecord(
                        DatagramClassifier.ReadSsrc(datagram),
                        DatagramClassifier.ReadPayloadType(datagram),
                        hasTransportCc,
                        hasTransportCc ? BinaryPrimitives.ReadUInt16BigEndian(copy.AsSpan(offset, 2)) : (ushort)0));
                }

                if (DatagramClassifier.ReadSsrc(datagram) != Volatile.Read(ref mediaSsrc))
                {
                    // Only the media stream is faulted; FEC and RTX ride their own SSRCs and pass through.
                    return false;
                }

                var sequenceNumber = DatagramClassifier.ReadSequenceNumber(datagram);
                offered.TryAdd(sequenceNumber, 0);

                // Drop the sixth packet of each of the first GroupsToImpair groups: exactly one loss per
                // protection group, and always inside a group whose repair packet is sent.
                var index = Interlocked.Increment(ref mediaSeen) - 1;
                if (index / groupSize < GroupsToImpair && index % groupSize == groupSize / 2)
                {
                    dropped.TryAdd(sequenceNumber, 0);
                    return true;
                }

                return false;
            },
        };

        FaultInjectingDatagramTransport? injector = null;
        senderConfig.TransportInterceptor = inner => injector = new FaultInjectingDatagramTransport(inner, profile, seed: 20260824);

        await using var sender = new PeerConnection(senderConfig);
        await using var receiver = new PeerConnection(receiverConfig);

        Volatile.Write(ref mediaSsrc, sender.VideoSsrc);

        var delivered = new ConcurrentDictionary<ushort, byte>();
        receiver.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            if (info.Kind == MediaKind.Video)
            {
                delivered.TryAdd(info.SequenceNumber, 0);
            }
        };

        sender.OnLocalIceCandidate += (_, e) => receiver.AddIceCandidate(e.Candidate, e.SdpMid);

        var offer = await sender.CreateOfferAsync(cancellationToken);
        offer.Should().Contain(scheme == FecScheme.FlexFec ? "flexfec-03/90000" : "ulpfec/90000");

        await receiver.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await receiver.CreateAnswerAsync(cancellationToken);

        // The answer must keep the FEC codec so the offerer turns its send-side FEC on. FlexFEC's
        // answerer also echoes the FEC-FR group when it sends; here the answerer is recvonly, so it only
        // needs to keep the codec — the offerer's FlexFEC still binds through the offer's FEC-FR line.
        answer.Should().Contain(scheme == FecScheme.FlexFec ? "flexfec-03/90000" : "ulpfec/90000");

        await sender.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        (await sender.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await receiver.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        // Push enough H.264 to fill well past GroupsToImpair groups, with a long undropped tail.
        var accessUnits = H264TestStream.ReadAccessUnits(90);
        var timestamp = 0u;
        foreach (var accessUnit in accessUnits)
        {
            sender.SendVideoFrame(accessUnit, timestamp);
            timestamp += 3000;
            await Task.Delay(3, cancellationToken);
        }

        // Wait until every offered media packet has been delivered — the dropped ones only reach the
        // handler as an FEC recovery, so this waits out the repair path too.
        (await TestSupport.WaitForAsync(() => delivered.Count >= offered.Count && offered.Count > groupSize * GroupsToImpair))
            .Should().BeTrue("every media packet, recovered ones included, must reach the receiver");

        injector!.Flush();
        await TestSupport.WaitForAsync(() => delivered.Count >= offered.Count, 2_000);

        dropped.Count.Should().Be(GroupsToImpair, "exactly one packet is dropped in each impaired group");
        dropped.Keys.Should().OnlyContain(seq => delivered.ContainsKey(seq), "every dropped packet is recovered by FEC");
        delivered.Keys.Should().BeEquivalentTo(offered.Keys, "the delivered media stream is complete");
        receiver.FecPacketsRecoveredForTest.Should().BeGreaterThanOrEqualTo(
            GroupsToImpair,
            "each drop is rebuilt from its group's repair packet");

        if (transportCc)
        {
            var wire = wireRecords.ToArray();

            // Only the first GroupsToImpair media groups are impaired, but every full group after them
            // also emits a repair, so at least one repair datagram per impaired group must be visible.
            var repairs = wire
                .Where(record => record.Ssrc != Volatile.Read(ref mediaSsrc))
                .ToArray();
            repairs.Should().HaveCountGreaterThanOrEqualTo(
                GroupsToImpair,
                "each impaired group's repair rides its own SSRC");
            repairs.Should().OnlyContain(
                record => record.HasTransportCc,
                "every FEC repair packet carries transport-wide cc");

            wire.Should().OnlyContain(
                record => record.HasTransportCc,
                "media and repair packets share the stamped transport-wide space");

            var sequences = wire.Select(record => record.TransportSequence).OrderBy(value => value).ToArray();
            sequences.Should().OnlyHaveUniqueItems("the transport-wide sequence space has no duplicates");
            for (var i = 1; i < sequences.Length; i++)
            {
                sequences[i].Should().Be(
                    unchecked((ushort)(sequences[i - 1] + 1)),
                    "the transport-wide sequence space is contiguous across media, RTX and FEC repair");
            }
        }
    }

    [Fact]
    public async Task Default_configuration_neither_offers_nor_recovers_fec()
    {
        var cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(50)).Token;

        await using var sender = new PeerConnection(TestSupport.NewConfig());
        await using var receiver = new PeerConnection(TestSupport.NewConfig());

        var delivered = 0;
        receiver.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> _) =>
        {
            if (info.Kind == MediaKind.Video)
            {
                Interlocked.Increment(ref delivered);
            }
        };

        sender.OnLocalIceCandidate += (_, e) => receiver.AddIceCandidate(e.Candidate, e.SdpMid);

        var offer = await sender.CreateOfferAsync(cancellationToken);
        offer.Should().NotContain("ulpfec/90000");
        offer.Should().NotContain("flexfec-03/90000");

        await receiver.SetRemoteDescriptionAsync(offer, SdpType.Offer, cancellationToken);
        var answer = await receiver.CreateAnswerAsync(cancellationToken);
        await sender.SetRemoteDescriptionAsync(answer, SdpType.Answer, cancellationToken);

        (await sender.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();
        (await receiver.WaitForConnectedAsync(ConnectTimeout, cancellationToken)).Should().BeTrue();

        var accessUnits = H264TestStream.ReadAccessUnits(20);
        var timestamp = 0u;
        foreach (var accessUnit in accessUnits)
        {
            sender.SendVideoFrame(accessUnit, timestamp);
            timestamp += 3000;
            await Task.Delay(3, cancellationToken);
        }

        (await TestSupport.WaitForAsync(() => Volatile.Read(ref delivered) >= 15)).Should().BeTrue();
        receiver.FecPacketsRecoveredForTest.Should().Be(0, "no FEC is negotiated on the default path");
    }

    private static void ApplyScheme(PeerConnectionConfig config, FecScheme scheme)
    {
        // This test's arithmetic assumes a fixed group of InitialGroupSize. The receiver's reception
        // reports would otherwise shrink the group mid-test and break the one-drop-per-group
        // construction; adaptation is covered end-to-end by FecAdaptiveProtectionTests.
        config.FecProtection.AdaptiveGroupSize = false;

        if (scheme == FecScheme.FlexFec)
        {
            config.EnableFlexFec = true;
        }
        else
        {
            config.EnableUlpfec = true;
        }
    }

    private readonly record struct WireRecord(
        uint Ssrc,
        byte PayloadType,
        bool HasTransportCc,
        ushort TransportSequence);
}
