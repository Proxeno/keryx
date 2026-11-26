using System.Net;
using System.Runtime.CompilerServices;
using BenchmarkDotNet.Attributes;
using Keryx;
using Keryx.Core;

namespace Keryx.Benchmarks;

/// <summary>
/// The two clock reads on the per-packet receive path. <c>MonotonicMicroseconds</c> (the exact
/// expression <c>PeerConnection.MonotonicMicroseconds</c> uses) is read up to twice per received
/// packet; <see cref="DateTimeOffset.UtcNow"/> is read once per received packet in the
/// reception-statistics path. Both are called often enough that their cost is part of the receive
/// budget, and neither allocates.
/// </summary>
[MemoryDiagnoser]
public class ClockReadBenchmarks
{
    /// <summary>Monotonic microseconds from <see cref="TimeProvider.System"/> (per received packet, up to twice).</summary>
    [Benchmark]
    public long MonotonicMicroseconds() =>
        (long)(TimeProvider.System.GetTimestamp() * (1_000_000.0 / TimeProvider.System.TimestampFrequency));

    /// <summary>Wall-clock Unix milliseconds (once per received packet in the reception-statistics path).</summary>
    [Benchmark]
    public ulong UtcNowUnixMilliseconds() => (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
}

/// <summary>
/// The cost of the send path's <c>lock (object)</c>: the app send thread takes it per outgoing
/// packet, while the receive loop takes the same lock for feedback and RTX sends (~100/s). The
/// contended case models that second thread holding the lock for roughly one SRTP protect of a
/// 1200-byte packet and then staying off it for ~10 ms, so the measured send is the occasional
/// wait an application sees rather than a pathological spin.
/// </summary>
[MemoryDiagnoser]
public class SendLockBenchmarks
{
    // The send-path lock the contention thread fights over, and a separate baseline lock nobody else
    // touches, so the uncontended measurement really is uncontended.
    private readonly object _sendLock = new();
    private readonly object _uncontendedLock = new();
    private long _counter;
    private byte[] _scratch = null!;
    private Thread? _contender;
    private volatile bool _stop;

    [GlobalSetup]
    public void Setup()
    {
        _scratch = new byte[1200];
        _stop = false;
        _contender = new Thread(Contend) { IsBackground = true, Name = "send-lock-feedback-contender" };
        _contender.Start();
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _stop = true;
        _contender?.Join();
        _contender = null;
    }

    /// <summary>The send-path lock with no other thread taking it.</summary>
    [Benchmark]
    public long UncontendedLock()
    {
        lock (_uncontendedLock)
        {
            return ++_counter;
        }
    }

    /// <summary>The same lock operation while the receive loop's feedback/RTX sender contends for it.</summary>
    [Benchmark]
    public long LockWithFeedbackContender()
    {
        lock (_sendLock)
        {
            return ++_counter;
        }
    }

    private void Contend()
    {
        var span = _scratch.AsSpan();
        while (!_stop)
        {
            lock (_sendLock)
            {
                // Roughly one SRTP protect's worth of work on a 1200-byte packet.
                span.Fill(0xA5);
                for (var i = 0; i < span.Length; i++)
                {
                    span[i] ^= 0x5A;
                }

                Consume(span[0]);
            }

            // ~100 feedback/RTX sends per second: off the send lock for ~10 ms between takes.
            Thread.Sleep(10);
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void Consume(byte value) => GC.KeepAlive(value);
}

/// <summary>
/// <see cref="PeerConnection.GetTransceiver"/> resolves a received packet's mid by scanning the
/// lock-free transceiver snapshot, so its cost grows linearly with the m-line count. This measures
/// the worst case — the last transceiver, which the scan reaches only after every other entry.
/// </summary>
/// <remarks>
/// The connection always builds its two legacy per-kind transceivers first, so a run with
/// <see cref="Transceivers"/> = N scans N + 2 entries.
/// </remarks>
[MemoryDiagnoser]
public class GetTransceiverBenchmarks
{
    [Params(2, 8, 32)]
    public int Transceivers { get; set; }

    private PeerConnection _connection = null!;
    private string _lastMid = null!;

    [GlobalSetup]
    public void Setup()
    {
        var config = new PeerConnectionConfig
        {
            BindAddress = IPAddress.Loopback,
            Logger = NullLogger.Instance,
        };
        _connection = new PeerConnection(config);

        for (var i = 0; i < Transceivers; i++)
        {
            _connection.AddTransceiver(MediaKind.Video);
        }

        // Mids are allocated when the next offer is built, so negotiate once to assign them all.
        _connection.CreateOfferAsync(CancellationToken.None).GetAwaiter().GetResult();
        _lastMid = _connection.Transceivers[^1].Mid!;
    }

    [GlobalCleanup]
    public void Cleanup() => _connection.DisposeAsync().AsTask().GetAwaiter().GetResult();

    /// <summary>Resolve the last transceiver's mid (linear-scan worst case).</summary>
    [Benchmark]
    public RtpTransceiver? GetTransceiver() => _connection.GetTransceiver(_lastMid);
}
