using System.Diagnostics;
using System.Globalization;
using System.Runtime;
using System.Runtime.InteropServices;
using Keryx.BroadcastLoadTest;
using Keryx.Broadcast;

// =====================================================================================================
// Keryx end-to-end SFU broadcast load-test rig (broadcast-scale.md §6 "Load-test rig").
//
// Stands up ONE real SFU — a synthetic ingest source fanned out through a real BroadcastEndpoint (shared
// socket + BroadcastFanout + batched sendmmsg send) — and drives real viewers against it, ramping the
// viewer count until the box saturates and reporting the achieved single-box ceiling and the limiting
// resource. It measures BOTH egress paths at BOTH resolutions:
//
//   Arm A  Real viewer PeerConnections, per-viewer path. N recvonly PeerConnections each complete a real
//          ICE + DTLS-SRTP handshake over the endpoint's shared socket and decrypt real forwarded media
//          (PeerConnection.TryForwardRtp, each viewer's own key). Measures connection-setup throughput,
//          success rate, decode correctness, CPU/mem/GC. This is the honest real-connection number — and
//          on one box the SFU and the viewer PeerConnections compete for the same cores, so it saturates
//          well below the fan-out engine's ceiling (that gap is the multi-box story, printed at the end).
//
//   Arm B  Fan-out ceiling, per-viewer path. The real BroadcastFanout re-encrypts one ingest packet under
//          each of N viewers' own keys (N forward+encrypt across a worker pool) and the real
//          BroadcastEndpoint.SendBatch flushes the N datagrams out of one shared socket (one sendmmsg(2)
//          on Linux). N real loopback sinks receive and SRTP-decrypt. Pushes the fan-out engine flat out.
//
//   Arm C  Fan-out ceiling, shared-key encrypt-once path. One real SRTP encrypt per ingest packet under a
//          PublicBroadcastKey (the exact inner cost of SharedKeyBroadcastTier.Fanout), then N
//          byte-identical datagrams flushed via the same real SendBatch to N real sinks that decrypt
//          under the shared key. Collapses the O(N) crypto of Arm B to O(1) — the send path is all that
//          is left.
//
// Runnable, prints real figures from this machine. Run it in Docker/Linux for real sendmmsg numbers:
//   docker build -f benchmarks/Keryx.BroadcastLoadTest/loadtest-linux.Dockerfile -t keryx-loadtest .
//   docker run --rm --ulimit nofile=1048576:1048576 -v "$PWD":/work -w /work keryx-loadtest \
//       dotnet run --project benchmarks/Keryx.BroadcastLoadTest -c Release -- --arms A,B,C
//
// Usage: dotnet run -c Release [--arms A,B,C] [--profile 720p|480p] [--duration <s>]
//                              [--pc-viewers 50,100,250] [--viewers 500,1000,2000,4000]
//                              [--workers <n>] [--recv-buffer-kb <kb>]
// =====================================================================================================

var arms = ArgString(args, "--arms", "A,B,C").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
var profile = MediaProfile.Resolve(ArgString(args, "--profile", "720p"));
var duration = TimeSpan.FromSeconds(ArgValue(args, "--duration", 5));
var pcViewerLevels = ArgIntList(args, "--pc-viewers", [50, 100, 250]);
var viewerLevels = ArgIntList(args, "--viewers", [500, 1000, 2000, 4000]);
var workers = (int)ArgValue(args, "--workers", Environment.ProcessorCount);
var recvBufferBytes = (int)ArgValue(args, "--recv-buffer-kb", 256) * 1024;
var cores = Environment.ProcessorCount;

// One transient endpoint just to report whether the native sendmmsg fast path is active on this host.
bool nativeBatch;
await using (var probe = new BroadcastEndpoint(new BroadcastEndpointOptions { MaxViewers = 1 }))
{
    nativeBatch = probe.UsesNativeBatchSend;
}

Console.WriteLine("=================================================================");
Console.WriteLine(" Keryx end-to-end SFU broadcast load-test rig");
Console.WriteLine("=================================================================");
Console.WriteLine($"Machine        : {cores} logical cores, {RuntimeGb():F1} GB RAM, {RuntimeInformation.OSArchitecture}");
Console.WriteLine($"OS             : {RuntimeInformation.OSDescription.Trim()}");
Console.WriteLine($"Runtime        : .NET {Environment.Version}, ServerGC={GCSettings.IsServerGC}, Concurrent={GCSettings.LatencyMode}");
Console.WriteLine($"Batched send   : {(nativeBatch ? "native sendmmsg(2) (real syscall-batched egress)" : "managed SendTo fallback (run in Linux/Docker for native sendmmsg)")}");
Console.WriteLine($"Media profile  : {profile.Name} — {profile.VideoPacketBytes} B/pkt, {profile.VideoPacketsPerSecond} video pkt/s/viewer (+~{MediaProfile.AudioPacketsPerSecond} Opus pkt/s)");
Console.WriteLine($"Fan-out workers: {workers}");
Console.WriteLine($"Measure window : {duration.TotalSeconds:F0}s per throughput run");
Console.WriteLine();

if (arms.Contains("A", StringComparer.OrdinalIgnoreCase))
{
    await RealViewerArm.RunAsync(profile, pcViewerLevels, duration, cores);
}

if (arms.Contains("B", StringComparer.OrdinalIgnoreCase))
{
    await FanoutCeilingArm.RunPerViewerAsync(profile, viewerLevels, duration, workers, recvBufferBytes);
}

if (arms.Contains("C", StringComparer.OrdinalIgnoreCase))
{
    await FanoutCeilingArm.RunSharedKeyAsync(profile, viewerLevels, duration, recvBufferBytes);
}

PrintHonesty(cores, nativeBatch);
Console.WriteLine("Done.");
return;

static void PrintHonesty(int cores, bool nativeBatch)
{
    Console.WriteLine("-----------------------------------------------------------------");
    Console.WriteLine(" Single-box vs. multi-box — what this rig can and cannot show");
    Console.WriteLine("-----------------------------------------------------------------");
    Console.WriteLine("  Arm A is the true end-to-end number: real ICE+DTLS-SRTP viewers decoding real");
    Console.WriteLine("  media. But on ONE box the SFU egress and the viewer PeerConnections run on the");
    Console.WriteLine("  SAME cores, so Arm A saturates far below the engine ceiling Arms B/C show — the");
    Console.WriteLine("  viewers are stealing the cores the SFU needs. That is a measurement artifact of");
    Console.WriteLine("  co-location, not the SFU's limit.");
    Console.WriteLine();
    Console.WriteLine("  Arms B/C isolate the SFU send engine (real fan-out, real per-viewer/shared-key");
    Console.WriteLine("  SRTP, real sendmmsg) by replacing the heavyweight viewer PeerConnection with a");
    Console.WriteLine("  lightweight real UDP+SRTP sink. That shows the engine's true ceiling, but over");
    Console.WriteLine("  loopback, not a real NIC, and with the receivers still sharing this box's cores.");
    Console.WriteLine();
    Console.WriteLine("  Neither is the deployment ceiling. broadcast-scale.md §1.3 puts that at ~35k 720p");
    Console.WriteLine("  viewers on a 100 GbE NIC. Reaching it needs a TRUE MULTI-BOX RIG: several driver");
    Console.WriteLine("  machines each running thousands of real viewers, pointed at ONE SFU box over a");
    Console.WriteLine("  real NIC, so (a) the viewers' CPU is off the SFU's cores, (b) the bytes cross a");
    Console.WriteLine("  real NIC and DMA/IRQ path, and (c) the NIC bandwidth wall — not loopback — is the");
    Console.WriteLine("  thing that finally binds. A single box structurally cannot show the NIC wall.");
    if (!nativeBatch)
    {
        Console.WriteLine();
        Console.WriteLine("  NOTE: native sendmmsg is INACTIVE on this host (managed SendTo fallback). The");
        Console.WriteLine("  send-rate figures above are the fallback's; run in Linux/Docker for the real");
        Console.WriteLine($"  syscall-batched numbers. ({cores} cores measured here.)");
    }

    Console.WriteLine();
}

static double RuntimeGb()
{
    var info = GC.GetGCMemoryInfo();
    return info.TotalAvailableMemoryBytes / (1024.0 * 1024 * 1024);
}

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

static int[] ArgIntList(string[] args, string name, int[] fallback)
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
        if (int.TryParse(p, NumberStyles.Any, CultureInfo.InvariantCulture, out var v) && v > 0)
        {
            result.Add(v);
        }
    }

    return result.Count > 0 ? [.. result] : fallback;
}
