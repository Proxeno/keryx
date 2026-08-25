using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Keryx;
using Keryx.Broadcast;
using Keryx.Rtp;
using Keryx.Rtp.Simulcast;
using Keryx.Srtp;

namespace Keryx.BroadcastLoadTest;

/// <summary>
/// The fan-out ceiling arms (B and C): drive the real SFU send engine flat out through a real
/// <see cref="BroadcastEndpoint"/> shared socket to N real loopback+SRTP sinks, ramping N until the box
/// saturates, and report the achieved throughput, the limiting resource, and the correctness of what the
/// sinks decoded. Arm B is the per-viewer path (<see cref="BroadcastFanout"/>, N encrypts); Arm C the
/// shared-key encrypt-once path (one encrypt, N byte-identical sends).
/// </summary>
internal static class FanoutCeilingArm
{
    private static readonly SimulcastLayerId Hi = SimulcastLayerId.Parse("hi");
    private static readonly SrtpProtectionProfile Profile = SrtpProtectionProfile.AeadAes128Gcm;
    private const uint BroadcastSsrc = 0xB0AD_0001u;

    // ---------------------------------------------------------------------------------------------
    // Arm B — per-viewer path: BroadcastFanout re-encrypts under each viewer's own key, batched send.
    // ---------------------------------------------------------------------------------------------
    public static async Task RunPerViewerAsync(MediaProfile profile, int[] viewerLevels, TimeSpan duration, int workers, int recvBufferBytes)
    {
        Header("Arm B: fan-out ceiling — PER-VIEWER path (N encrypts, batched sendmmsg)",
            "Each ingest packet is rewritten + SRTP-encrypted under every viewer's OWN key across a",
            $"{workers}-worker pool (real BroadcastFanout), then all N datagrams leave one shared socket in",
            "one SendBatch. N real loopback sinks receive and SRTP-decrypt (sampled).");

        PrintTableHeader();
        foreach (var n in viewerLevels)
        {
            var result = await RunLevelAsync(profile, n, duration, recvBufferBytes,
                (sinks, keys) => new PerViewerEngine(sinks, keys, workers), sharedKey: false);
            if (result is null)
            {
                Console.WriteLine($"   {n,7:N0} | (could not bind {n:N0} sinks on this host — fd limit; raise ulimit -n / run in Docker)");
                break;
            }

            PrintRow(profile, n, result);
        }

        Console.WriteLine();
    }

    // ---------------------------------------------------------------------------------------------
    // Arm C — shared-key path: one encrypt under a PublicBroadcastKey, N identical-ciphertext sends.
    // ---------------------------------------------------------------------------------------------
    public static async Task RunSharedKeyAsync(MediaProfile profile, int[] viewerLevels, TimeSpan duration, int recvBufferBytes)
    {
        Header("Arm C: fan-out ceiling — SHARED-KEY encrypt-once path (1 encrypt, N sends)",
            "Each ingest packet is rewritten ONCE onto the broadcast SSRC and SRTP-encrypted ONCE under a",
            "PublicBroadcastKey (the exact inner cost of SharedKeyBroadcastTier.Fanout), then N",
            "byte-identical datagrams leave one shared socket in one SendBatch. N real sinks decrypt under",
            "the shared key. This is the O(N)->O(1) crypto collapse; only the send path remains.");

        PrintTableHeader();
        foreach (var n in viewerLevels)
        {
            var result = await RunLevelAsync(profile, n, duration, recvBufferBytes,
                (sinks, keys) => new SharedKeyEngine(sinks, keys[0], profile), sharedKey: true);
            if (result is null)
            {
                Console.WriteLine($"   {n,7:N0} | (could not bind {n:N0} sinks on this host — fd limit; raise ulimit -n / run in Docker)");
                break;
            }

            PrintRow(profile, n, result);
        }

        Console.WriteLine();
    }

    // ---------------------------------------------------------------------------------------------
    // One (N viewers) level: build sinks + engine (with aligned keys), run flat out, collect metrics.
    // ---------------------------------------------------------------------------------------------
    private static async Task<LevelResult?> RunLevelAsync(
        MediaProfile profile,
        int viewerCount,
        TimeSpan duration,
        int recvBufferBytes,
        Func<IReadOnlyList<LoopbackSink>, SrtpSessionKeys[], IFanoutEngine> buildEngine,
        bool sharedKey)
    {
        await using var endpoint = new BroadcastEndpoint(new BroadcastEndpointOptions { MaxViewers = 1 });

        List<LoopbackSink> sinks = new(viewerCount);
        IFanoutEngine? engine = null;
        try
        {
            var keys = new SrtpSessionKeys[viewerCount];
            if (sharedKey)
            {
                // Every viewer shares one broadcast SSRC and ONE key: the single encrypt context and every
                // sink's decrypt context use it. (The production PublicBroadcastKey/SharedKeyBroadcastTier
                // mint this same random key material behind a public-content-asserting API and enforce the
                // §5.4 guardrails — covered by the integration suite; the rig measures the identical inner
                // crypto + send cost.)
                var shared = RandomSessionKeys();
                for (var i = 0; i < viewerCount; i++)
                {
                    keys[i] = shared;
                    sinks.Add(new LoopbackSink(BroadcastSsrc, Profile, shared, recvBufferBytes));
                }
            }
            else
            {
                for (var i = 0; i < viewerCount; i++)
                {
                    var keyBytes = new byte[Profile.MasterKeyLength];
                    var saltBytes = new byte[Profile.MasterSaltLength];
                    RandomNumberGenerator.Fill(keyBytes);
                    RandomNumberGenerator.Fill(saltBytes);
                    keys[i] = new SrtpSessionKeys(keyBytes, saltBytes);
                    sinks.Add(new LoopbackSink(0xA000_0000u + (uint)i, Profile, keys[i], recvBufferBytes));
                }
            }

            engine = buildEngine(sinks, keys);
        }
        catch (Exception ex) when (ex is SocketException or IOException)
        {
            engine?.Dispose();
            foreach (var s in sinks)
            {
                s.Dispose();
            }

            return null; // Ran out of file descriptors standing up N sinks — the host's socket ceiling.
        }

        using var stop = new CancellationTokenSource();
        var receivers = sinks.Select(s => s.ReceiveLoopAsync(stop.Token)).ToArray();

        try
        {
            var ingest = SyntheticIngest.Build(profile);

            // Warm: the first packet is the keyframe that promotes the forwarder(s) layer to active.
            SyntheticIngest.SetSequenceAndTimestamp(ingest, 0, 0);
            engine.Fanout(ingest, canStartLayer: true);
            endpoint.SendBatch(engine.Datagrams);
            await Task.Delay(50, CancellationToken.None);

            GC.Collect(2, GCCollectionMode.Forced, blocking: true);
            var before = MetricsSnapshot.Capture();
            var end = Stopwatch.GetTimestamp() + (long)(duration.TotalSeconds * Stopwatch.Frequency);
            long passes = 0, requested = 0, delivered = 0;
            ushort seq = 1;
            uint ts = 3000;
            while (Stopwatch.GetTimestamp() < end)
            {
                for (var i = 0; i < 32; i++)
                {
                    SyntheticIngest.SetSequenceAndTimestamp(ingest, seq++, ts);
                    ts += 3000;
                    requested += engine.Fanout(ingest, canStartLayer: false);
                    delivered += endpoint.SendBatch(engine.Datagrams);
                    passes++;
                }
            }

            var after = MetricsSnapshot.Capture();
            var delta = MetricsDelta.Between(before, after);

            // Let the sinks drain what is still in flight, then read their delivery+decode counters.
            await Task.Delay(200, CancellationToken.None);
            long received = 0, decrypted = 0, decryptFail = 0, foreign = 0;
            foreach (var s in sinks)
            {
                received += Interlocked.Read(ref s.Received);
                decrypted += Interlocked.Read(ref s.Decrypted);
                decryptFail += Interlocked.Read(ref s.DecryptFailures);
                foreign += Interlocked.Read(ref s.ForeignSsrc);
            }

            return new LevelResult(
                passes / delta.Wall.TotalSeconds,
                delivered / delta.Wall.TotalSeconds,
                requested,
                delivered,
                delta,
                received,
                decrypted,
                decryptFail,
                foreign);
        }
        finally
        {
            stop.Cancel();
            try
            {
                await Task.WhenAll(receivers).WaitAsync(TimeSpan.FromSeconds(5));
            }
            catch (Exception)
            {
                // Receive loops only ever fault on cancellation / socket close.
            }

            engine.Dispose();
            foreach (var s in sinks)
            {
                s.Dispose();
            }
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Reporting.
    // ---------------------------------------------------------------------------------------------
    private static void PrintTableHeader()
    {
        Console.WriteLine("   viewers |   passes/s |  delivered pkt/s |    egress |  drop% |  CPU | alloc MB/s | GC g0/g1/g2 | decode");
        Console.WriteLine("   --------+------------+------------------+-----------+--------+------+------------+-------------+-------");
    }

    private static void PrintRow(MediaProfile profile, int n, LevelResult r)
    {
        var gbps = r.DeliveredPps * profile.VideoPacketBytes * 8 / 1e9;
        var dropPct = r.Requested > 0 ? 100.0 * (r.Requested - r.Delivered) / r.Requested : 0;
        var decode = r.DecryptFailures == 0 && r.ForeignSsrc == 0 && r.Decrypted > 0
            ? "OK"
            : $"FAIL(df={r.DecryptFailures},fs={r.ForeignSsrc},dec={r.Decrypted})";
        Console.WriteLine(
            $"   {n,7:N0} | {r.PassesPerSec,10:N0} | {r.DeliveredPps,16:N0} | {gbps,6:F2} Gb | {dropPct,5:F1}% | {r.Delta.CpuCores,4:F1} | "
            + $"{r.Delta.AllocMBPerSec,10:F0} | {r.Delta.Gen0,3}/{r.Delta.Gen1,2}/{r.Delta.Gen2,1} | {decode}");

        // The real-time reading of this row: a viewer needs VideoPacketsPerSecond ingest packets/s. The
        // delivered datagram rate divided by that per-viewer rate is how many viewers this rung sustains.
        var perViewer = profile.VideoPacketsPerSecond;
        var sustainable = r.DeliveredPps / perViewer;
        var realTime = r.PassesPerSec >= perViewer;
        Console.WriteLine(
            $"           -> {sustainable:N0} viewer-equivalents @ {perViewer} pkt/s "
            + $"({(realTime ? $"these {n:N0} sinks kept up, {r.PassesPerSec / perViewer:F1}x real-time headroom" : $"engine-bound: {r.PassesPerSec:N0} passes/s < {perViewer} needed")}).");
    }

    private static void Header(string title, params string[] lines)
    {
        Console.WriteLine("-----------------------------------------------------------------");
        Console.WriteLine($" {title}");
        Console.WriteLine("-----------------------------------------------------------------");
        foreach (var l in lines)
        {
            Console.WriteLine($"  {l}");
        }

        Console.WriteLine();
    }

    private sealed record LevelResult(
        double PassesPerSec,
        double DeliveredPps,
        long Requested,
        long Delivered,
        MetricsDelta Delta,
        long Received,
        long Decrypted,
        long DecryptFailures,
        long ForeignSsrc);

    // ---------------------------------------------------------------------------------------------
    // Fan-out engines: the per-pass work under measurement, behind one interface so the level runner is
    // path-agnostic. Datagrams exposes the produced batch for BroadcastEndpoint.SendBatch.
    // ---------------------------------------------------------------------------------------------
    private interface IFanoutEngine : IDisposable
    {
        List<BroadcastDatagram> Datagrams { get; }

        int Fanout(byte[] ingestPacket, bool canStartLayer);
    }

    // Arm B engine: the real production BroadcastFanout + one BroadcastSubscriber per viewer, each keyed
    // to match its sink so the sink can decrypt.
    private sealed class PerViewerEngine : IFanoutEngine
    {
        private readonly BroadcastFanout _fanout;
        private readonly List<BroadcastSubscriber> _subscribers;
        private readonly RtpLayerClassification _classification =
            new(Hi, SyntheticIngest.UpstreamSsrc, IsRepair: false, RtpLayerClassificationSource.RidExtension);

        public PerViewerEngine(IReadOnlyList<LoopbackSink> sinks, SrtpSessionKeys[] keys, int maxDegreeOfParallelism)
        {
            _fanout = new BroadcastFanout(maxDegreeOfParallelism, parallelThreshold: 1);
            _subscribers = new List<BroadcastSubscriber>(sinks.Count);
            for (var i = 0; i < sinks.Count; i++)
            {
                var forwarder = new RtpForwarder(0xA000_0000u + (uint)i);
                forwarder.SelectLayer(Hi);
                var encrypt = new SrtpEncryptContext(Profile, keys[i]);
                _subscribers.Add(new BroadcastSubscriber(forwarder, encrypt, sinks[i].LocalEndPoint));
            }
        }

        public List<BroadcastDatagram> Datagrams { get; } = [];

        public int Fanout(byte[] ingestPacket, bool canStartLayer)
            => _fanout.Forward(in _classification, ingestPacket, canStartLayer, _subscribers, Datagrams);

        public void Dispose()
        {
            foreach (var s in _subscribers)
            {
                s.Dispose();
            }
        }
    }

    // Arm C engine: one encrypt under a PublicBroadcastKey, N identical-ciphertext datagrams. This mirrors
    // SharedKeyBroadcastTier.Fanout's inner cost exactly (one TryForward + one ProtectRtp per ingest
    // packet); the destinations come straight from the sinks rather than from enrolled ViewerSessions so
    // the ceiling can be pushed to N no heavyweight per-viewer handshake could reach on one box.
    private sealed class SharedKeyEngine : IFanoutEngine
    {
        private readonly SrtpEncryptContext _encrypt;
        private readonly RtpForwarder _forwarder;
        private readonly IPEndPoint[] _destinations;
        private readonly byte[] _rewrite;
        private readonly byte[] _cipher;
        private readonly RtpLayerClassification _classification =
            new(Hi, SyntheticIngest.UpstreamSsrc, IsRepair: false, RtpLayerClassificationSource.RidExtension);

        public SharedKeyEngine(IReadOnlyList<LoopbackSink> sinks, SrtpSessionKeys sharedKey, MediaProfile profile)
        {
            _encrypt = new SrtpEncryptContext(Profile, sharedKey);
            _forwarder = new RtpForwarder(BroadcastSsrc);
            _forwarder.SelectLayer(Hi);
            _destinations = sinks.Select(s => (IPEndPoint)s.LocalEndPoint).ToArray();
            var capacity = profile.VideoPacketBytes + 128;
            _rewrite = new byte[capacity];
            _cipher = new byte[capacity + Profile.RtpOverhead];
        }

        public List<BroadcastDatagram> Datagrams { get; } = [];

        public int Fanout(byte[] ingestPacket, bool canStartLayer)
        {
            Datagrams.Clear();
            if (!RtpHeader.TryParse(ingestPacket, out var header))
            {
                return 0;
            }

            var payload = ingestPacket.AsSpan(header.HeaderLength);
            if (_forwarder.TryForward(in _classification, in header, payload, canStartLayer, _rewrite, out var rewritten) != RtpForwardResult.Forwarded)
            {
                return 0;
            }

            int cipherLength;
            try
            {
                cipherLength = _encrypt.ProtectRtp(_rewrite.AsSpan(0, rewritten), _cipher);
            }
            catch (InvalidOperationException)
            {
                return 0; // reordered/duplicate index — drop, exactly as SharedKeyBroadcastTier does.
            }

            // One ciphertext, N datagrams pointing at the SAME memory — the encrypt-once fan-out.
            var shared = _cipher.AsMemory(0, cipherLength);
            foreach (var destination in _destinations)
            {
                Datagrams.Add(new BroadcastDatagram(shared, destination));
            }

            return Datagrams.Count;
        }

        public void Dispose() => _encrypt.Dispose();
    }

    private static SrtpSessionKeys RandomSessionKeys()
    {
        var keyBytes = new byte[Profile.MasterKeyLength];
        var saltBytes = new byte[Profile.MasterSaltLength];
        RandomNumberGenerator.Fill(keyBytes);
        RandomNumberGenerator.Fill(saltBytes);
        return new SrtpSessionKeys(keyBytes, saltBytes);
    }
}
