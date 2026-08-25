using System.Net;
using System.Security.Cryptography;
using FluentAssertions;
using Keryx.Rtp;
using Keryx.Rtp.Simulcast;
using Keryx.Srtp;
using Xunit;

namespace Keryx.IntegrationTests;

/// <summary>
/// Correctness of the parallel per-subscriber SRTP fan-out (<see cref="BroadcastFanout"/>): a parallel
/// pass must produce byte-identical per-subscriber datagrams to the serial reference, every datagram
/// must decrypt under that subscriber's own key, no data races may appear under a many-packet /
/// many-subscriber stress loop, and each subscriber's stream must stay ordered.
/// </summary>
public sealed class BroadcastFanoutTests
{
    private static readonly SimulcastLayerId Hi = SimulcastLayerId.Parse("hi");
    private const uint IngestSsrc = 0x1234_5678u;

    /// <summary>
    /// A parallel fan-out to N subscribers produces, for every subscriber and every packet, byte-for-byte
    /// the same datagram as the serial fan-out over an identically-keyed mirror set — the correctness
    /// contract that makes the parallel path a drop-in for the serial one.
    /// </summary>
    [Fact]
    public void ParallelFanout_IsByteIdenticalToSerial_ForEverySubscriberAndPacket()
    {
        const int subscribers = 64;
        var seeds = SubscriberSeeds(subscribers);

        using var parallelSet = new SubscriberSet(seeds);
        using var serialSet = new SubscriberSet(seeds);
        var fanout = new BroadcastFanout();

        for (var packet = 0; packet < 200; packet++)
        {
            var seq = (ushort)packet;
            var ts = (uint)(packet * 3000);
            var ingest = BuildIngestPacket(seq, ts, PacketPayload(packet));
            var canStart = packet == 0; // the first packet is the keyframe that promotes the layer.
            var classification = new RtpLayerClassification(Hi, IngestSsrc, IsRepair: false, RtpLayerClassificationSource.RidExtension);

            var parallelForwarded = fanout.Forward(in classification, ingest, canStart, parallelSet.Subscribers);
            var serialForwarded = fanout.ForwardSerial(in classification, ingest, canStart, serialSet.Subscribers);

            parallelForwarded.Should().Be(subscribers);
            serialForwarded.Should().Be(subscribers);

            for (var i = 0; i < subscribers; i++)
            {
                parallelSet.Subscribers[i].TryGetDatagram(out var fromParallel).Should().BeTrue();
                serialSet.Subscribers[i].TryGetDatagram(out var fromSerial).Should().BeTrue();

                fromParallel.Payload.ToArray().Should().Equal(
                    fromSerial.Payload.ToArray(),
                    "subscriber {0} packet {1} must encrypt identically in parallel and serial",
                    i,
                    packet);
                fromParallel.Destination.Should().BeSameAs(parallelSet.Subscribers[i].Destination);
            }
        }
    }

    /// <summary>
    /// Every datagram a parallel pass produces decrypts under exactly that subscriber's own SRTP key,
    /// recovering the subscriber's outbound SSRC and the original ingest payload — proving each
    /// subscriber's ciphertext is genuinely its own, not a cross-wired neighbour's.
    /// </summary>
    [Fact]
    public void EachParallelDatagram_DecryptsUnderItsOwnSubscriberKey()
    {
        const int subscribers = 48;
        var seeds = SubscriberSeeds(subscribers);
        using var set = new SubscriberSet(seeds);
        var fanout = new BroadcastFanout();
        var datagrams = new List<BroadcastDatagram>();
        var recovered = new byte[2048];

        for (var packet = 0; packet < 50; packet++)
        {
            var seq = (ushort)packet;
            var ts = (uint)(packet * 3000);
            var payload = PacketPayload(packet);
            var ingest = BuildIngestPacket(seq, ts, payload);
            var classification = new RtpLayerClassification(Hi, IngestSsrc, IsRepair: false, RtpLayerClassificationSource.RidExtension);

            fanout.Forward(in classification, ingest, packet == 0, set.Subscribers, datagrams);
            datagrams.Should().HaveCount(subscribers);

            for (var i = 0; i < subscribers; i++)
            {
                var subscriber = set.Subscribers[i];
                subscriber.TryGetDatagram(out var datagram).Should().BeTrue();

                // Decrypt with THIS subscriber's key; a cross-wired ciphertext would fail to authenticate.
                set.Decrypt[i].TryUnprotectRtp(datagram.Payload.Span, recovered, out var length)
                    .Should().BeTrue("subscriber {0} packet {1} must authenticate under its own key", i, packet);

                RtpHeader.TryParse(recovered.AsSpan(0, length), out var header).Should().BeTrue();
                header.Ssrc.Should().Be(subscriber.OutboundSsrc);
                recovered.AsSpan(header.HeaderLength, length - header.HeaderLength).ToArray()
                    .Should().Equal(payload, "the recovered payload must be the ingest payload verbatim");
            }
        }
    }

    /// <summary>
    /// A long stress loop of many packets across many subscribers, driven through the parallel path,
    /// must never corrupt a subscriber's stream: every datagram still decrypts, the recovered SSRC is
    /// always the right subscriber's, and each subscriber's forwarded sequence numbers stay strictly
    /// increasing. A data race on a shared buffer or shared SRTP state would surface as a decrypt
    /// failure or a sequence anomaly here.
    /// </summary>
    [Fact]
    public void ParallelStressLoop_NoRaces_StreamsStayIntactAndOrdered()
    {
        const int subscribers = 256;
        const int packets = 300;
        var seeds = SubscriberSeeds(subscribers);
        using var set = new SubscriberSet(seeds);

        // A small worker pool relative to the subscriber count keeps several subscribers per worker and
        // maximises the chance of exposing any shared-state contention.
        var fanout = new BroadcastFanout(maxDegreeOfParallelism: Math.Max(2, Environment.ProcessorCount));
        var recovered = new byte[2048];
        var lastSeq = new int[subscribers];
        Array.Fill(lastSeq, -1);

        for (var packet = 0; packet < packets; packet++)
        {
            var seq = (ushort)packet;
            var ts = (uint)(packet * 3000);
            var payload = PacketPayload(packet);
            var ingest = BuildIngestPacket(seq, ts, payload);
            var classification = new RtpLayerClassification(Hi, IngestSsrc, IsRepair: false, RtpLayerClassificationSource.RidExtension);

            var forwarded = fanout.Forward(in classification, ingest, packet == 0, set.Subscribers);
            forwarded.Should().Be(subscribers);

            for (var i = 0; i < subscribers; i++)
            {
                var subscriber = set.Subscribers[i];
                subscriber.TryGetDatagram(out var datagram).Should().BeTrue();

                set.Decrypt[i].TryUnprotectRtp(datagram.Payload.Span, recovered, out var length).Should().BeTrue();
                RtpHeader.TryParse(recovered.AsSpan(0, length), out var header).Should().BeTrue();
                header.Ssrc.Should().Be(subscriber.OutboundSsrc);
                recovered.AsSpan(header.HeaderLength, length - header.HeaderLength).ToArray().Should().Equal(payload);

                // Per-subscriber ordering: forwarded sequence numbers strictly increase, no reorder/dup.
                ((int)header.SequenceNumber).Should().BeGreaterThan(lastSeq[i]);
                lastSeq[i] = header.SequenceNumber;
            }
        }
    }

    /// <summary>A pass with no subscribers forwards nothing and does not throw.</summary>
    [Fact]
    public void Forward_WithNoSubscribers_IsANoOp()
    {
        var fanout = new BroadcastFanout();
        var ingest = BuildIngestPacket(0, 0, PacketPayload(0));
        var classification = new RtpLayerClassification(Hi, IngestSsrc, IsRepair: false, RtpLayerClassificationSource.RidExtension);
        fanout.Forward(in classification, ingest, canStartLayer: true, Array.Empty<BroadcastSubscriber>()).Should().Be(0);
    }

    // ---------------------------------------------------------------------------------------------
    // Helpers.
    // ---------------------------------------------------------------------------------------------
    private static SrtpProtectionProfile Profile => SrtpProtectionProfile.AeadAes128Gcm;

    private static SubscriberSeed[] SubscriberSeeds(int count)
    {
        var seeds = new SubscriberSeed[count];
        for (var i = 0; i < count; i++)
        {
            var key = new byte[Profile.MasterKeyLength];
            var salt = new byte[Profile.MasterSaltLength];
            RandomNumberGenerator.Fill(key);
            RandomNumberGenerator.Fill(salt);
            seeds[i] = new SubscriberSeed(0xA000_0000u + (uint)i, key, salt);
        }

        return seeds;
    }

    private static byte[] BuildIngestPacket(ushort sequenceNumber, uint timestamp, byte[] payload)
    {
        var header = new RtpHeader
        {
            Version = 2,
            PayloadType = 96,
            Ssrc = IngestSsrc,
            SequenceNumber = sequenceNumber,
            Timestamp = timestamp,
            Marker = false,
        };

        var buffer = new byte[header.HeaderLength + payload.Length];
        var written = header.WriteTo(buffer);
        payload.CopyTo(buffer.AsSpan(written));
        return buffer;
    }

    private static byte[] PacketPayload(int packet)
    {
        // Content varies per packet so a stale/cross-wired buffer would be caught by the decrypt check.
        var payload = new byte[1000];
        for (var i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)(packet * 31 + i * 7);
        }

        return payload;
    }

    private readonly record struct SubscriberSeed(uint OutboundSsrc, byte[] Key, byte[] Salt);

    /// <summary>A set of fan-out subscribers plus a matching decrypt context per subscriber.</summary>
    private sealed class SubscriberSet : IDisposable
    {
        public SubscriberSet(SubscriberSeed[] seeds)
        {
            var list = new List<BroadcastSubscriber>(seeds.Length);
            Decrypt = new SrtpDecryptContext[seeds.Length];
            for (var i = 0; i < seeds.Length; i++)
            {
                var seed = seeds[i];
                var forwarder = new RtpForwarder(seed.OutboundSsrc);
                forwarder.SelectLayer(Hi);
                var encrypt = new SrtpEncryptContext(Profile, new SrtpSessionKeys(seed.Key, seed.Salt));
                var endpoint = new IPEndPoint(IPAddress.Loopback, 40000 + i);
                list.Add(new BroadcastSubscriber(forwarder, encrypt, endpoint));
                Decrypt[i] = new SrtpDecryptContext(Profile, new SrtpSessionKeys(seed.Key, seed.Salt));
            }

            Subscribers = list;
        }

        public IReadOnlyList<BroadcastSubscriber> Subscribers { get; }

        public SrtpDecryptContext[] Decrypt { get; }

        public void Dispose()
        {
            foreach (var subscriber in Subscribers)
            {
                subscriber.Dispose();
            }

            foreach (var decrypt in Decrypt)
            {
                decrypt.Dispose();
            }
        }
    }
}
