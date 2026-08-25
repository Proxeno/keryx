using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Keryx;
using Keryx.Core;
using Keryx.ScaleHarness;
using Keryx.Srtp;

// SFU fan-out scale harness. Models the broadcast data path (1 ingest -> N re-encrypted subscribers)
// directly, because N real PeerConnections at 10k is not stand-up-able; a separate arm measures real
// PeerConnection footprint at a moderate count. Runnable, prints real figures from this machine.
//
// Usage: dotnet run -c Release [--duration <seconds>] [--profile <name>] [--arms 1,2,3,4]

var duration = TimeSpan.FromSeconds(ArgValue(args, "--duration", 5));
var profileName = ArgString(args, "--profile", "AeadAes128Gcm");
var profile = ResolveProfile(profileName);
var arms = ArgList(args, "--arms", [1, 2, 3, 4]);
var cores = Environment.ProcessorCount;

Console.WriteLine("=================================================================");
Console.WriteLine(" Keryx SFU fan-out scale harness");
Console.WriteLine("=================================================================");
Console.WriteLine($"Machine        : {cores} logical cores, {RuntimeGb():F1} GB RAM, {System.Runtime.InteropServices.RuntimeInformation.OSArchitecture}");
Console.WriteLine($"Runtime        : .NET {Environment.Version}, ServerGC={System.Runtime.GCSettings.IsServerGC}");
Console.WriteLine($"SRTP profile   : {profile.Name}");
Console.WriteLine($"Packet size    : {Ingest.PacketSize} bytes (720p H.264, ~2 Mbps)");
Console.WriteLine($"Measure window : {duration.TotalSeconds:F0}s per throughput run");
Console.WriteLine();

if (arms.Contains(1))
{
    ThroughputArm(profile, duration, cores);
}

if (arms.Contains(2))
{
    FanOutMemoryArm(profile);
}

if (arms.Contains(3))
{
    RealPeerConnectionArm();
}

if (arms.Contains(4))
{
    SendToArm(duration);
}

Console.WriteLine("Done.");
return;

// -------------------------------------------------------------------------------------------------
// Arm 1 — throughput saturation: max forward+encrypt packets/sec, single core and all cores.
// -------------------------------------------------------------------------------------------------
static void ThroughputArm(SrtpProtectionProfile profile, TimeSpan duration, int cores)
{
    Console.WriteLine("-----------------------------------------------------------------");
    Console.WriteLine(" Arm 1: fan-out throughput (RtpForwarder.TryForward + SRTP encrypt)");
    Console.WriteLine("-----------------------------------------------------------------");

    var single = RunThroughput(1, duration, profile);
    Report("1 thread (single core)", single, 1);

    var saturated = RunThroughput(cores, duration, profile);
    Report($"{cores} threads (all cores)", saturated, cores);

    var perCore = saturated.aggregatePps / cores;
    var scaling = saturated.aggregatePps / (single.aggregatePps * cores);
    Console.WriteLine();
    Console.WriteLine($"  Per-core at saturation : {perCore:N0} pkt/s/core");
    Console.WriteLine($"  Scaling efficiency     : {scaling * 100:F1}% of linear over {cores} cores");
    Console.WriteLine($"  720p subscribers @300 pps: {saturated.aggregatePps / 300:N0} (all cores) / {single.aggregatePps / 300:N0} (one core)");
    Console.WriteLine($"  480p subscribers @200 pps: {saturated.aggregatePps / 200:N0} (all cores)");
    Console.WriteLine();

    static void Report(string label, (double aggregatePps, MetricsDelta m) r, int threads)
    {
        var m = r.m;
        Console.WriteLine($"  {label}:");
        Console.WriteLine($"    forward+encrypt   : {r.aggregatePps:N0} pkt/s   ({r.aggregatePps * Ingest.PacketSize / 1e9 * 8:F2} Gbps egress)");
        Console.WriteLine($"    CPU               : {m.CpuCores:F1} cores busy");
        Console.WriteLine($"    alloc rate        : {m.AllocMBPerSec:F2} MB/s   (Gen0={m.Gen0} Gen1={m.Gen1} Gen2={m.Gen2}, GC pause {m.GcPause.TotalMilliseconds:F1} ms)");
    }
}

static (double aggregatePps, MetricsDelta m) RunThroughput(int threads, TimeSpan duration, SrtpProtectionProfile profile)
{
    var counts = new long[threads];
    var workers = new Thread[threads];
    using var ready = new Barrier(threads + 1);
    var durationTicks = (long)(duration.TotalSeconds * Stopwatch.Frequency);

    for (var t = 0; t < threads; t++)
    {
        var index = t;
        workers[t] = new Thread(() =>
        {
            using var path = new FanOutPath(0xA000_0000u + (uint)index, profile);
            var upstream = 0x1000_0000u + (uint)index;
            path.Warm(upstream);

            ready.SignalAndWait();
            var end = Stopwatch.GetTimestamp() + durationTicks;
            ushort seq = 1;
            uint ts = 3000;
            long n = 0;
            while (Stopwatch.GetTimestamp() < end)
            {
                // Batch between clock reads so the timestamp probe is not the bottleneck.
                for (var i = 0; i < 2048; i++)
                {
                    path.ProcessOne(upstream, seq++, ts);
                    ts += 3000;
                    n++;
                }
            }

            counts[index] = n;
        })
        { IsBackground = true, Name = $"fanout-{index}" };
        workers[t].Start();
    }

    ready.SignalAndWait();
    var start = MetricsSnapshot.Capture();
    foreach (var w in workers)
    {
        w.Join();
    }

    var end = MetricsSnapshot.Capture();
    var delta = MetricsDelta.Between(start, end);
    long total = 0;
    foreach (var c in counts)
    {
        total += c;
    }

    var pps = total / delta.Wall.TotalSeconds;
    return (pps, delta);
}

// -------------------------------------------------------------------------------------------------
// Arm 2 — fan-out data-path memory: managed + working-set bytes per subscriber (forwarder + SRTP).
// -------------------------------------------------------------------------------------------------
static void FanOutMemoryArm(SrtpProtectionProfile profile)
{
    Console.WriteLine("-----------------------------------------------------------------");
    Console.WriteLine(" Arm 2: fan-out data-path memory per subscriber");
    Console.WriteLine("-----------------------------------------------------------------");
    Console.WriteLine("  (RtpForwarder + per-subscriber SrtpEncryptContext, warmed)");

    foreach (var n in (int[])[1_000, 10_000, 50_000])
    {
        GC.Collect(2, GCCollectionMode.Forced, blocking: true);
        var before = MetricsSnapshot.Capture(collectManaged: true);

        var paths = new List<FanOutPath>(n);
        for (var i = 0; i < n; i++)
        {
            var path = new FanOutPath(0xB000_0000u + (uint)i, profile);
            path.Warm(0x2000_0000u + (uint)i);
            paths.Add(path);
        }

        var after = MetricsSnapshot.Capture(collectManaged: true);
        var d = MetricsDelta.Between(before, after);
        Console.WriteLine(
            $"  N={n,6:N0}: managed +{d.ManagedBytes / 1e6,7:F1} MB ({(double)d.ManagedBytes / n,6:F0} B/sub), "
            + $"working set +{d.WorkingSetBytes / 1e6,7:F1} MB ({(double)d.WorkingSetBytes / n,6:F0} B/sub)");

        foreach (var p in paths)
        {
            p.Dispose();
        }

        GC.KeepAlive(paths);
    }

    Console.WriteLine();
}

// -------------------------------------------------------------------------------------------------
// Arm 3 — real PeerConnection footprint: object-graph bytes/PC after applying a remote offer, and
// thread growth once ICE gathering starts on a modest live count.
// -------------------------------------------------------------------------------------------------
static void RealPeerConnectionArm()
{
    Console.WriteLine("-----------------------------------------------------------------");
    Console.WriteLine(" Arm 3: real PeerConnection footprint");
    Console.WriteLine("-----------------------------------------------------------------");
    Console.WriteLine("  (construct + SetRemoteDescription; no live sockets on this sub-arm)");

    foreach (var k in (int[])[100, 500, 1_000])
    {
        GC.Collect(2, GCCollectionMode.Forced, blocking: true);
        var before = MetricsSnapshot.Capture(collectManaged: true);
        var pcs = new List<PeerConnection>(k);
        try
        {
            for (var i = 0; i < k; i++)
            {
                var pc = new PeerConnection(new PeerConnectionConfig
                {
                    BindAddress = IPAddress.Loopback,
                    Logger = NullLogger.Instance,
                });
                pc.SetRemoteDescriptionAsync(SdpOffer.Value, SdpType.Offer, CancellationToken.None)
                    .GetAwaiter().GetResult();
                pcs.Add(pc);
            }

            var after = MetricsSnapshot.Capture(collectManaged: true);
            var d = MetricsDelta.Between(before, after);
            Console.WriteLine(
                $"  K={k,5:N0}: managed +{d.ManagedBytes / 1e6,7:F1} MB ({(double)d.ManagedBytes / k / 1024,6:F1} KB/PC), "
                + $"working set +{d.WorkingSetBytes / 1e6,7:F1} MB ({(double)d.WorkingSetBytes / k / 1024,6:F1} KB/PC), "
                + $"threads +{d.ThreadCount}");
        }
        finally
        {
            foreach (var pc in pcs)
            {
                pc.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
        }
    }

    // Live sub-arm: start ICE gathering (opens sockets/timers) on a modest count to observe the
    // per-connection thread and working-set growth a live server pays on top of the object graph.
    const int live = 200;
    GC.Collect(2, GCCollectionMode.Forced, blocking: true);
    var liveBefore = MetricsSnapshot.Capture(collectManaged: true);
    var livePcs = new List<PeerConnection>(live);
    try
    {
        for (var i = 0; i < live; i++)
        {
            var pc = new PeerConnection(new PeerConnectionConfig
            {
                BindAddress = IPAddress.Loopback,
                Logger = NullLogger.Instance,
                TrickleIceCandidates = true,
            });
            pc.SetRemoteDescriptionAsync(SdpOffer.Value, SdpType.Offer, CancellationToken.None)
                .GetAwaiter().GetResult();
            _ = pc.CreateAnswerAsync(CancellationToken.None).GetAwaiter().GetResult();
            livePcs.Add(pc);
        }

        Thread.Sleep(1500); // let host-candidate gathering settle.
        var liveAfter = MetricsSnapshot.Capture(collectManaged: true);
        var d = MetricsDelta.Between(liveBefore, liveAfter);
        Console.WriteLine(
            $"  live K={live}: managed +{d.ManagedBytes / 1e6:F1} MB ({(double)d.ManagedBytes / live / 1024:F1} KB/PC), "
            + $"working set +{d.WorkingSetBytes / 1e6:F1} MB ({(double)d.WorkingSetBytes / live / 1024:F1} KB/PC), threads +{d.ThreadCount}");
        Console.WriteLine("  (includes ICE gathering: host-candidate sockets, timers)");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"  live sub-arm stopped early: {ex.GetType().Name}: {ex.Message}");
    }
    finally
    {
        foreach (var pc in livePcs)
        {
            pc.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
    }

    Console.WriteLine();
}

// -------------------------------------------------------------------------------------------------
// Arm 4 — sendto syscall rate: each forwarded packet is one datagram send. Characterises the
// per-core syscall ceiling that may bind before CPU. .NET exposes no sendmmsg/GSO batching.
// -------------------------------------------------------------------------------------------------
static void SendToArm(TimeSpan duration)
{
    Console.WriteLine("-----------------------------------------------------------------");
    Console.WriteLine(" Arm 4: UDP sendto syscall rate (single core)");
    Console.WriteLine("-----------------------------------------------------------------");

    using var receiver = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    receiver.Bind(new IPEndPoint(IPAddress.Loopback, 0));
    var dest = (IPEndPoint)receiver.LocalEndPoint!;

    using var sender = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    // A large send buffer so the sender does not block on the receiver draining; this measures the
    // syscall cost, not loopback delivery.
    sender.SendBufferSize = 1 << 24;
    var payload = new byte[Ingest.PacketSize];

    // Warm.
    for (var i = 0; i < 1000; i++)
    {
        try
        {
            sender.SendTo(payload, dest);
        }
        catch (SocketException)
        {
        }
    }

    var window = TimeSpan.FromSeconds(Math.Min(2, duration.TotalSeconds));
    var end = Stopwatch.GetTimestamp() + (long)(window.TotalSeconds * Stopwatch.Frequency);
    long sent = 0;
    long dropped = 0;
    var start = Stopwatch.GetTimestamp();
    while (Stopwatch.GetTimestamp() < end)
    {
        for (var i = 0; i < 1024; i++)
        {
            try
            {
                sender.SendTo(payload, dest);
                sent++;
            }
            catch (SocketException)
            {
                dropped++;
            }
        }
    }

    var elapsed = Stopwatch.GetElapsedTime(start);
    var rate = sent / elapsed.TotalSeconds;
    Console.WriteLine($"  sendto rate       : {rate:N0} datagram/s/core (1200 B), {dropped:N0} ENOBUFS");
    Console.WriteLine($"  subscribers/core if send-bound @300 pps: {rate / 300:N0}");
    Console.WriteLine("  note: managed .NET has no sendmmsg/GSO; one managed SendTo == one syscall.");
    Console.WriteLine();
}

// -------------------------------------------------------------------------------------------------
// Helpers.
// -------------------------------------------------------------------------------------------------
static double RuntimeGb()
{
    var info = GC.GetGCMemoryInfo();
    return info.TotalAvailableMemoryBytes / (1024.0 * 1024 * 1024);
}

static SrtpProtectionProfile ResolveProfile(string name) => name switch
{
    "AeadAes128Gcm" => SrtpProtectionProfile.AeadAes128Gcm,
    "AeadAes256Gcm" => SrtpProtectionProfile.AeadAes256Gcm,
    "Aes128CmHmacSha1_80" => SrtpProtectionProfile.Aes128CmHmacSha1_80,
    _ => SrtpProtectionProfile.AeadAes128Gcm,
};

static double ArgValue(string[] args, string name, double fallback)
{
    var i = Array.IndexOf(args, name);
    return i >= 0 && i + 1 < args.Length && double.TryParse(args[i + 1], NumberStyles.Any, CultureInfo.InvariantCulture, out var v)
        ? v
        : fallback;
}

static string ArgString(string[] args, string name, string fallback)
{
    var i = Array.IndexOf(args, name);
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : fallback;
}

static int[] ArgList(string[] args, string name, int[] fallback)
{
    var i = Array.IndexOf(args, name);
    if (i < 0 || i + 1 >= args.Length)
    {
        return fallback;
    }

    var parts = args[i + 1].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    var result = new List<int>();
    foreach (var p in parts)
    {
        if (int.TryParse(p, out var v))
        {
            result.Add(v);
        }
    }

    return result.Count > 0 ? result.ToArray() : fallback;
}

/// <summary>A minimal one-audio/one-video BUNDLE offer the footprint arm applies to each PeerConnection.</summary>
internal static class SdpOffer
{
    public static readonly string Value = string.Join("\r\n",
        "v=0",
        "o=- 4611731400430051336 2 IN IP4 127.0.0.1",
        "s=-",
        "t=0 0",
        "a=group:BUNDLE 0 1",
        "a=extmap-allow-mixed",
        "a=msid-semantic: WMS stream",
        "m=audio 9 UDP/TLS/RTP/SAVPF 111",
        "c=IN IP4 0.0.0.0",
        "a=rtcp:9 IN IP4 0.0.0.0",
        "a=ice-ufrag:hT7a",
        "a=ice-pwd:XKQVjJ9wRVWy3zNsL6mQ0pTb",
        "a=ice-options:trickle",
        "a=fingerprint:sha-256 75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24",
        "a=setup:actpass",
        "a=mid:0",
        "a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid",
        "a=sendrecv",
        "a=rtcp-mux",
        "a=rtpmap:111 opus/48000/2",
        "a=ssrc:1657320245 cname:JnQ3z0",
        "m=video 9 UDP/TLS/RTP/SAVPF 96",
        "c=IN IP4 0.0.0.0",
        "a=rtcp:9 IN IP4 0.0.0.0",
        "a=ice-ufrag:hT7a",
        "a=ice-pwd:XKQVjJ9wRVWy3zNsL6mQ0pTb",
        "a=ice-options:trickle",
        "a=fingerprint:sha-256 75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24",
        "a=setup:actpass",
        "a=mid:1",
        "a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid",
        "a=sendrecv",
        "a=rtcp-mux",
        "a=rtpmap:96 H264/90000",
        "a=rtcp-fb:96 nack",
        "a=ssrc:3204773231 cname:JnQ3z0",
        "");
}
