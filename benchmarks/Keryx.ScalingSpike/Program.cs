using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Keryx.ScalingSpike;
using Keryx.Srtp;

// SFU fan-out scaling spike. Measures the top levers over the SFU baseline (per-subscriber SRTP
// encrypt ~602k pkt/s/core, and sendto ~283k datagram/s/core as the tightest wall):
//
//   Arm A  Parallel per-subscriber SRTP fan-out across a worker pool (pure managed).
//   Arm B  Shared-key "encrypt-once" broadcast: encrypt once, copy the ciphertext N times.
//   Arm C  Batched sends via Linux sendmmsg(2) vs a SendTo loop (Linux only; run in Docker on macOS).
//
// Runnable, prints real figures from this machine. Arm C self-skips off Linux.
//
// Usage: dotnet run -c Release [--duration <seconds>] [--profile <name>] [--arms A,B,C]

var duration = TimeSpan.FromSeconds(ArgValue(args, "--duration", 4));
var profileName = ArgString(args, "--profile", "AeadAes128Gcm");
var profile = ResolveProfile(profileName);
var arms = ArgString(args, "--arms", "A,B,C").ToUpperInvariant();
var cores = Environment.ProcessorCount;

Console.WriteLine("=================================================================");
Console.WriteLine(" Keryx SFU fan-out scaling spike");
Console.WriteLine("=================================================================");
Console.WriteLine($"Machine        : {cores} logical cores, {RuntimeGb():F1} GB RAM, {RuntimeInformation.OSArchitecture}");
Console.WriteLine($"OS             : {RuntimeInformation.OSDescription.Trim()}");
Console.WriteLine($"Runtime        : .NET {Environment.Version}, ServerGC={System.Runtime.GCSettings.IsServerGC}");
Console.WriteLine($"SRTP profile   : {profile.Name}");
Console.WriteLine($"Packet size    : {Packets.PacketSize} bytes (720p H.264, ~2 Mbps @ ~300 pps)");
Console.WriteLine($"Measure window : {duration.TotalSeconds:F0}s per run");
Console.WriteLine();

if (arms.Contains('A'))
{
    ParallelSrtpArm(profile, duration, cores);
}

if (arms.Contains('B'))
{
    SharedKeyArm(profile, duration);
}

if (arms.Contains('C'))
{
    SendMmsgArm.Run(duration);
}

Console.WriteLine("Done.");
return;

// -------------------------------------------------------------------------------------------------
// Arm A — parallelise per-subscriber SRTP encrypt across a worker pool. Each worker owns a fixed
// slice of subscriber contexts and re-encrypts the ingest packet for each; we sweep the worker count
// and report the pkt/s scaling curve. Per-worker subscriber count is fixed so the sweep isolates
// core scaling (not per-thread working-set change).
// -------------------------------------------------------------------------------------------------
static void ParallelSrtpArm(SrtpProtectionProfile profile, TimeSpan duration, int cores)
{
    Console.WriteLine("-----------------------------------------------------------------");
    Console.WriteLine(" Arm A: parallel per-subscriber SRTP fan-out (worker pool)");
    Console.WriteLine("-----------------------------------------------------------------");
    Console.WriteLine("  Each worker owns 256 subscriber SRTP contexts and re-encrypts the");
    Console.WriteLine("  ingest packet for each in a tight loop. Sweep worker count -> pkt/s.");
    Console.WriteLine();

    const int subsPerWorker = 256;
    var widths = WorkerWidths(cores);

    double singleCorePps = 0;
    Console.WriteLine("   workers |        pkt/s |   pkt/s/core |  scaling vs 1 core");
    Console.WriteLine("   --------+--------------+--------------+-------------------");
    foreach (var w in widths)
    {
        var pps = RunParallelEncrypt(w, subsPerWorker, duration, profile);
        if (w == 1)
        {
            singleCorePps = pps;
        }

        var perCore = pps / w;
        var scaling = singleCorePps > 0 ? pps / (singleCorePps * w) : 1.0;
        Console.WriteLine(
            $"   {w,7} | {pps,12:N0} | {perCore,12:N0} | {scaling * 100,6:F1}% of linear");
    }

    Console.WriteLine();
}

static double RunParallelEncrypt(int workers, int subsPerWorker, TimeSpan duration, SrtpProtectionProfile profile)
{
    var counts = new long[workers];
    var threads = new Thread[workers];
    using var ready = new Barrier(workers + 1);
    var durationTicks = (long)(duration.TotalSeconds * Stopwatch.Frequency);

    for (var t = 0; t < workers; t++)
    {
        var index = t;
        threads[t] = new Thread(() =>
        {
            var subs = new Subscriber[subsPerWorker];
            for (var i = 0; i < subsPerWorker; i++)
            {
                var ssrc = 0xA000_0000u + (uint)(index * subsPerWorker + i);
                subs[i] = new Subscriber(profile, ssrc);
            }

            ready.SignalAndWait();
            var end = Stopwatch.GetTimestamp() + durationTicks;
            long n = 0;
            while (Stopwatch.GetTimestamp() < end)
            {
                for (var i = 0; i < subsPerWorker; i++)
                {
                    subs[i].EncryptOnce();
                    n++;
                }
            }

            counts[index] = n;
            foreach (var s in subs)
            {
                s.Dispose();
            }
        })
        { IsBackground = true, Name = $"srtp-{index}" };
        threads[t].Start();
    }

    ready.SignalAndWait();
    var start = Stopwatch.GetTimestamp();
    foreach (var th in threads)
    {
        th.Join();
    }

    var elapsed = Stopwatch.GetElapsedTime(start);
    long total = 0;
    foreach (var c in counts)
    {
        total += c;
    }

    return total / elapsed.TotalSeconds;
}

// -------------------------------------------------------------------------------------------------
// Arm B — shared-key "encrypt-once" broadcast. All N subscribers share ONE SRTP key, so the ingest
// packet is encrypted ONCE and the ciphertext is copied N times (no per-subscriber encrypt). This is
// the O(N)->O(1) crypto lever: it removes N-1 of every N encrypts. We measure it single-core against
// the per-subscriber-encrypt baseline so the crypto CPU eliminated is directly visible.
// -------------------------------------------------------------------------------------------------
static void SharedKeyArm(SrtpProtectionProfile profile, TimeSpan duration)
{
    Console.WriteLine("-----------------------------------------------------------------");
    Console.WriteLine(" Arm B: shared-key encrypt-once broadcast (single core)");
    Console.WriteLine("-----------------------------------------------------------------");
    Console.WriteLine("  Per-subscriber-encrypt: 1 encrypt per delivered packet.");
    Console.WriteLine("  Encrypt-once broadcast : 1 encrypt per frame + 1 ciphertext copy per sub.");
    Console.WriteLine();

    var window = TimeSpan.FromSeconds(Math.Max(1, duration.TotalSeconds));
    var overhead = profile.RtpOverhead;
    var cipherLen = Packets.PacketSize + overhead;

    // Baseline: per-subscriber encrypt rate on one core (each delivered packet costs one encrypt).
    var baselineSub = new Subscriber(profile, 0xC000_0000u);
    var baselinePps = TimedRate(window, batch: 512, () => baselineSub.EncryptOnce());
    baselineSub.Dispose();
    Console.WriteLine($"  per-subscriber encrypt        : {baselinePps,12:N0} pkt/s/core  (1 encrypt/pkt, the O(N) path)");

    // Copy-only asymptote: cost of one ciphertext copy per delivered packet (encrypt fully amortised).
    var cipher = new byte[cipherLen];
    RandomNumberGenerator.Fill(cipher);
    var subOut = new byte[cipherLen];
    var copyPps = TimedRate(window, batch: 4096, () => cipher.AsSpan().CopyTo(subOut));
    Console.WriteLine($"  copy-only asymptote (N->inf)  : {copyPps,12:N0} pkt/s/core  (1 memcpy/pkt, no crypto)");
    Console.WriteLine();

    // Encrypt-once broadcast at representative broadcast fan-outs: encrypt one shared packet per
    // frame, copy the ciphertext to N subscriber buffers; report delivered packets/s.
    Console.WriteLine("   N (subs) | encrypt-once pkt/s/core |  speedup vs per-sub encrypt | crypto CPU removed");
    Console.WriteLine("   ---------+-------------------------+-----------------------------+-------------------");
    foreach (var n in (int[])[100, 1_000, 10_000])
    {
        var shared = new SrtpEncryptContext(profile, RandomKeys(profile));
        var ingest = Packets.BuildRtpPacket(0xD000_0000u, sequenceNumber: 0, timestamp: 0);
        var sharedCipher = new byte[cipherLen];
        var outbufs = new byte[n][];
        for (var i = 0; i < n; i++)
        {
            outbufs[i] = new byte[cipherLen];
        }

        ushort seq = 0;
        uint ts = 0;
        var delivered = 0L;
        var end = Stopwatch.GetTimestamp() + (long)(window.TotalSeconds * Stopwatch.Frequency);
        var start = Stopwatch.GetTimestamp();
        while (Stopwatch.GetTimestamp() < end)
        {
            // One frame: encrypt once, then fan the ciphertext out to all N subscriber buffers.
            Packets.SetSequence(ingest, seq++);
            var written = shared.ProtectRtp(ingest, sharedCipher);
            ts += 3000;
            var src = sharedCipher.AsSpan(0, written);
            for (var i = 0; i < n; i++)
            {
                src.CopyTo(outbufs[i]);
            }

            delivered += n;
        }

        var elapsed = Stopwatch.GetElapsedTime(start);
        var pps = delivered / elapsed.TotalSeconds;
        var speedup = pps / baselinePps;
        // Fraction of crypto CPU removed: per-sub path spends 1 encrypt/pkt; encrypt-once spends
        // 1/N encrypt/pkt, i.e. (N-1)/N of the encrypts are gone.
        var cryptoRemoved = (n - 1) / (double)n;
        Console.WriteLine(
            $"   {n,8:N0} | {pps,23:N0} | {speedup,25:F1}x | {cryptoRemoved * 100,15:F2}%");

        shared.Dispose();
    }

    Console.WriteLine();
    Console.WriteLine("  => Encrypt-once collapses N encrypts to 1; the data path becomes a memcpy fan-out,");
    Console.WriteLine("     so throughput is bounded by memory bandwidth then by the sendto syscall rate,");
    Console.WriteLine("     not by SRTP CPU. Crypto stops being a per-subscriber cost.");
    Console.WriteLine();
}

// -------------------------------------------------------------------------------------------------
// Helpers.
// -------------------------------------------------------------------------------------------------

// Time a tight batched loop and return operations/second. The batch amortises the Stopwatch read.
static double TimedRate(TimeSpan window, int batch, Action op)
{
    // Warm.
    for (var i = 0; i < 1000; i++)
    {
        op();
    }

    var end = Stopwatch.GetTimestamp() + (long)(window.TotalSeconds * Stopwatch.Frequency);
    var start = Stopwatch.GetTimestamp();
    long n = 0;
    while (Stopwatch.GetTimestamp() < end)
    {
        for (var i = 0; i < batch; i++)
        {
            op();
        }

        n += batch;
    }

    return n / Stopwatch.GetElapsedTime(start).TotalSeconds;
}

static int[] WorkerWidths(int cores)
{
    var widths = new List<int>();
    for (var w = 1; w < cores; w *= 2)
    {
        widths.Add(w);
    }

    widths.Add(cores);
    return [.. widths];
}

static SrtpSessionKeys RandomKeys(SrtpProtectionProfile profile)
{
    var key = new byte[profile.MasterKeyLength];
    var salt = new byte[profile.MasterSaltLength];
    RandomNumberGenerator.Fill(key);
    RandomNumberGenerator.Fill(salt);
    return new SrtpSessionKeys(key, salt);
}

static double RuntimeGb() => GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / (1024.0 * 1024 * 1024);

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

/// <summary>One subscriber's re-encrypt state: its own SRTP context, a reusable RTP packet, output.</summary>
internal sealed class Subscriber : IDisposable
{
    private readonly SrtpEncryptContext _srtp;
    private readonly byte[] _packet;
    private readonly byte[] _output;
    private ushort _seq;

    public Subscriber(SrtpProtectionProfile profile, uint ssrc)
    {
        var key = new byte[profile.MasterKeyLength];
        var salt = new byte[profile.MasterSaltLength];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(salt);
        _srtp = new SrtpEncryptContext(profile, new SrtpSessionKeys(key, salt));
        _packet = Packets.BuildRtpPacket(ssrc, sequenceNumber: 0, timestamp: 0);
        _output = new byte[Packets.PacketSize + profile.RtpOverhead];
        _seq = 1;
    }

    /// <summary>Advances the sequence number (the context refuses a reused index) and encrypts.</summary>
    public void EncryptOnce()
    {
        Packets.SetSequence(_packet, _seq++);
        _srtp.ProtectRtp(_packet, _output);
    }

    public void Dispose() => _srtp.Dispose();
}
