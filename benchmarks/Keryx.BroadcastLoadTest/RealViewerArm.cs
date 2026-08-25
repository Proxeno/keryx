using System.Diagnostics;
using System.Net;
using Keryx;
using Keryx.Broadcast;
using Keryx.Core;
using Keryx.Rtp;
using Keryx.Sdp;

namespace Keryx.BroadcastLoadTest;

/// <summary>
/// Arm A — the honest end-to-end number: N real viewer <see cref="PeerConnection"/>s, each completing a
/// real ICE + DTLS-SRTP handshake over the SFU's shared <see cref="BroadcastEndpoint"/> socket and
/// decrypting real media the egress forwards to it with its OWN per-viewer key
/// (<see cref="PeerConnection.TryForwardRtp"/> — the path stock browsers use today). Ramps N and reports
/// connection-setup throughput, success rate, per-viewer decode, and the CPU/mem/GC the live population
/// costs. On one box the SFU and the viewers share cores, so this saturates below the Arm B/C engine
/// ceiling — which is exactly the single-box-vs-multi-box point.
/// </summary>
internal static class RealViewerArm
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);
    private const int ConnectConcurrency = 32;

    public static async Task RunAsync(MediaProfile profile, int[] viewerLevels, TimeSpan duration, int cores)
    {
        Console.WriteLine("-----------------------------------------------------------------");
        Console.WriteLine(" Arm A: real viewer PeerConnections (real ICE+DTLS-SRTP, per-viewer key)");
        Console.WriteLine("-----------------------------------------------------------------");
        Console.WriteLine("  N recvonly viewers connect over the shared socket, then the egress forwards a");
        Console.WriteLine($"  paced {profile.VideoPacketsPerSecond} pkt/s/viewer stream (TryForwardRtp) and every viewer decodes it.");
        Console.WriteLine();

        foreach (var n in viewerLevels)
        {
            await RunLevelAsync(profile, n, duration);
        }

        Console.WriteLine();
    }

    private static async Task RunLevelAsync(MediaProfile profile, int viewerCount, TimeSpan duration)
    {
        await using var endpoint = new BroadcastEndpoint(new BroadcastEndpointOptions { MaxViewers = viewerCount });
        var viewers = new List<ConnectedViewer>(viewerCount);
        var setupMs = new List<double>(viewerCount);
        var failures = 0;

        var connectStart = Stopwatch.GetTimestamp();
        using (var gate = new SemaphoreSlim(ConnectConcurrency))
        {
            var tasks = new List<Task<ConnectedViewer?>>(viewerCount);
            for (var i = 0; i < viewerCount; i++)
            {
                await gate.WaitAsync();
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        return await ConnectViewerAsync(endpoint);
                    }
                    catch (Exception)
                    {
                        return null;
                    }
                    finally
                    {
                        gate.Release();
                    }
                }));
            }

            foreach (var t in tasks)
            {
                var viewer = await t;
                if (viewer is null)
                {
                    failures++;
                }
                else
                {
                    viewers.Add(viewer);
                    setupMs.Add(viewer.SetupMilliseconds);
                }
            }
        }

        var connectElapsed = Stopwatch.GetElapsedTime(connectStart);

        if (viewers.Count == 0)
        {
            Console.WriteLine($"  N={viewerCount,5:N0}: 0/{viewerCount} connected ({failures} failures) — host cannot stand up this many real PeerConnections.");
            return;
        }

        // Media phase: forward a paced per-viewer stream and count what each viewer decodes.
        GC.Collect(2, GCCollectionMode.Forced, blocking: true);
        var before = MetricsSnapshot.Capture(collectManaged: true);
        var (forwarded, targetRounds) = await ForwardPacedAsync(profile, viewers, duration);
        var after = MetricsSnapshot.Capture(collectManaged: true);
        var delta = MetricsDelta.Between(before, after);

        long received = 0;
        var decoding = 0;
        foreach (var v in viewers)
        {
            var got = Interlocked.Read(ref v.Received);
            received += got;
            if (got > 0)
            {
                decoding++;
            }
        }

        setupMs.Sort();
        var median = setupMs[setupMs.Count / 2];
        var p95 = setupMs[(int)(setupMs.Count * 0.95)];
        var connThroughput = viewers.Count / connectElapsed.TotalSeconds;
        var deliveryRatio = forwarded > 0 ? 100.0 * received / forwarded : 0;

        Console.WriteLine($"  N={viewerCount,5:N0}: {viewers.Count}/{viewerCount} connected ({failures} failed), setup {connThroughput:N0} conn/s "
            + $"(median {median:F0} ms, p95 {p95:F0} ms)");
        Console.WriteLine($"          media: {decoding}/{viewers.Count} viewers decoding, {deliveryRatio:F1}% of {forwarded:N0} forwarded packets delivered "
            + $"(target {targetRounds:N0} rounds @ {profile.VideoPacketsPerSecond} pkt/s)");
        Console.WriteLine($"          cost : CPU {delta.CpuCores:F1} cores, managed {delta.ManagedBytes / 1e6:F0} MB "
            + $"({(double)delta.ManagedBytes / viewers.Count / 1024:F1} KB/viewer), working set {delta.WorkingSetBytes / 1e6:F0} MB, "
            + $"threads +{delta.ThreadCount}, GC {delta.Gen0}/{delta.Gen1}/{delta.Gen2}, pause {delta.GcPause.TotalMilliseconds:F0} ms");

        foreach (var v in viewers)
        {
            await v.DisposeAsync();
        }
    }

    private static async Task<ConnectedViewer> ConnectViewerAsync(BroadcastEndpoint endpoint)
    {
        var start = Stopwatch.GetTimestamp();
        var viewer = new PeerConnection(NewConfig());
        var session = endpoint.AddViewer(NewConfig());
        var egress = session.Connection;

        var counter = new ConnectedViewer(viewer, session);
        viewer.OnRtpPacketReceived += (in RtpPacketInfo info, ReadOnlySpan<byte> payload) =>
        {
            if (info.Kind == MediaKind.Video)
            {
                Interlocked.Increment(ref counter.Received);
            }
        };

        // In-process string exchange of ICE candidates, exactly as the loopback and shared-socket tests do.
        viewer.OnLocalIceCandidate += (_, e) => egress.AddIceCandidate(e.Candidate, e.SdpMid);
        egress.OnLocalIceCandidate += (_, e) => viewer.AddIceCandidate(e.Candidate, e.SdpMid);

        var offer = await viewer.CreateOfferAsync();
        var recvonlyOffer = offer.Replace("a=sendonly", "a=recvonly", StringComparison.Ordinal);
        await egress.SetRemoteDescriptionAsync(recvonlyOffer, SdpType.Offer);
        var answer = await egress.CreateAnswerAsync();
        await viewer.SetRemoteDescriptionAsync(answer, SdpType.Answer);

        if (!await egress.WaitForConnectedAsync(ConnectTimeout) || !await viewer.WaitForConnectedAsync(ConnectTimeout))
        {
            await viewer.DisposeAsync();
            await session.Connection.DisposeAsync();
            throw new TimeoutException("viewer did not connect");
        }

        counter.SetupMilliseconds = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
        counter.PayloadType = egress.GetNegotiatedPayloadType(MediaKind.Video);
        return counter;
    }

    // Forward one packet per viewer per round, paced toward the profile's per-viewer packet rate, for the
    // measurement window. Returns the total packets forwarded and the number of rounds targeted.
    private static async Task<(long forwarded, long targetRounds)> ForwardPacedAsync(
        MediaProfile profile,
        List<ConnectedViewer> viewers,
        TimeSpan duration)
    {
        // Keep the forwarded payload comfortably under the egress MTU (default 1200) so the packetizer
        // never rejects it; the forwarded byte size is not the variable Arm A measures (connections are).
        var payload = new byte[Math.Min(profile.VideoPacketBytes - 12, 1000)];
        var roundIntervalMs = 1000.0 / profile.VideoPacketsPerSecond;
        var deadline = Stopwatch.GetTimestamp() + (long)(duration.TotalSeconds * Stopwatch.Frequency);
        var startTs = Stopwatch.GetTimestamp();
        long forwarded = 0;
        long round = 0;
        uint rtpTs = 1_000_000u;

        while (Stopwatch.GetTimestamp() < deadline)
        {
            foreach (var v in viewers)
            {
                if (v.PayloadType is { } pt && v.Session.Connection.TryForwardRtp(MediaKind.Video, payload, rtpTs, marker: true, pt))
                {
                    forwarded++;
                }
            }

            round++;
            rtpTs += 3000;

            // Pace to real time: sleep until this round's scheduled wall-clock slot.
            var scheduled = startTs + (long)(round * roundIntervalMs / 1000.0 * Stopwatch.Frequency);
            var now = Stopwatch.GetTimestamp();
            if (scheduled > now)
            {
                var ms = (int)Stopwatch.GetElapsedTime(now, scheduled).TotalMilliseconds;
                if (ms >= 1)
                {
                    await Task.Delay(ms);
                }
            }
        }

        return (forwarded, round);
    }

    private static PeerConnectionConfig NewConfig() => new()
    {
        BindAddress = IPAddress.Loopback,
        Logger = NullLogger.Instance,
        IceConnectTimeout = TimeSpan.FromSeconds(30),
        RtcpInterval = TimeSpan.FromSeconds(1),
    };

    private sealed class ConnectedViewer(PeerConnection viewer, ViewerSession session)
    {
        public PeerConnection Viewer { get; } = viewer;

        public ViewerSession Session { get; } = session;

        public double SetupMilliseconds;

        public byte? PayloadType;

        public long Received;

        public async ValueTask DisposeAsync()
        {
            await Viewer.DisposeAsync();
            await Session.Connection.DisposeAsync();
        }
    }
}
