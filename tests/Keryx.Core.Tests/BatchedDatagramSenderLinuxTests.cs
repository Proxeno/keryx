using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace Keryx.Core.Tests;

/// <summary>
/// Validates <see cref="BatchedDatagramSender"/>'s real Linux <c>sendmmsg(2)</c> fast path and
/// reports its throughput against the managed fallback loop. These are meant to run in the Linux
/// container (see <c>tests/interop/sendmmsg-linux.Dockerfile</c> / <c>sendmmsg-linux-run.sh</c>),
/// where the native path is actually taken; off Linux there is no sendmmsg, so each test makes the
/// platform-appropriate assertion and returns.
/// </summary>
[Trait("Category", "SendmmsgLinux")]
public sealed class BatchedDatagramSenderLinuxTests
{
    private readonly ITestOutputHelper _output;

    public BatchedDatagramSenderLinuxTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void NativePath_SendsWholeBatch_ToDistinctLoopbackReceivers()
    {
        if (!OperatingSystem.IsLinux())
        {
            BatchedDatagramSender.NativeBatchSendSupported.Should().BeFalse("sendmmsg(2) is Linux-only");
            return;
        }

        const int batch = 32;
        var receivers = new Socket[batch];
        var dests = new IPEndPoint[batch];
        var payloads = new byte[batch][];
        try
        {
            for (var i = 0; i < batch; i++)
            {
                var r = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)
                {
                    ReceiveBufferSize = 1 << 20,
                    ReceiveTimeout = 5000,
                };
                r.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                receivers[i] = r;
                dests[i] = (IPEndPoint)r.LocalEndPoint!;
                payloads[i] = MakePayload(i, 200 + i);
            }

            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)
            {
                SendBufferSize = 1 << 22,
            };
            using var sender = new BatchedDatagramSender(socket);

            sender.UsesNativeBatchSend.Should().BeTrue("the native sendmmsg path must be active on Linux");

            var datagrams = new Datagram[batch];
            for (var i = 0; i < batch; i++)
            {
                datagrams[i] = new Datagram(payloads[i], dests[i]);
            }

            sender.Send(datagrams).Should().Be(batch);

            for (var i = 0; i < batch; i++)
            {
                var buffer = new byte[2048];
                var n = receivers[i].Receive(buffer);
                buffer.AsSpan(0, n).ToArray().Should().Equal(payloads[i],
                    $"receiver {i} must get exactly the payload sendmmsg addressed to it");
            }
        }
        finally
        {
            foreach (var r in receivers)
            {
                r?.Dispose();
            }
        }
    }

    [Fact]
    public void NativePath_SendsAllDatagrams_ReportsSpeedup()
    {
        if (!OperatingSystem.IsLinux())
        {
            BatchedDatagramSender.NativeBatchSendSupported.Should().BeFalse("sendmmsg(2) is Linux-only");
            return;
        }

        const int batch = 32;
        const int payloadSize = 1200; // Representative media-forwarding datagram.
        var window = TimeSpan.FromSeconds(2);

        var receivers = new Socket[batch];
        var dests = new IPEndPoint[batch];
        try
        {
            for (var i = 0; i < batch; i++)
            {
                var r = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)
                {
                    ReceiveBufferSize = 1 << 20,
                    ReceiveTimeout = 5000,
                };
                r.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                receivers[i] = r;
                dests[i] = (IPEndPoint)r.LocalEndPoint!;
            }

            var datagrams = new Datagram[batch];
            var payload = MakePayload(0x5A, payloadSize);
            for (var i = 0; i < batch; i++)
            {
                datagrams[i] = new Datagram(payload, dests[i]);
            }

            // Correctness: the native path delivers every datagram of a batch, byte-exact, to the
            // destination it was addressed to. This is the assertion; the timing below is only reported.
            using (var checkSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
            {
                using var checkSender = new BatchedDatagramSender(checkSocket);
                checkSender.UsesNativeBatchSend.Should().BeTrue();
                var distinct = new Datagram[batch];
                var distinctPayloads = new byte[batch][];
                for (var i = 0; i < batch; i++)
                {
                    distinctPayloads[i] = MakePayload(i, payloadSize);
                    distinct[i] = new Datagram(distinctPayloads[i], dests[i]);
                }

                checkSender.Send(distinct).Should().Be(batch);
                for (var i = 0; i < batch; i++)
                {
                    var buffer = new byte[2048];
                    var n = receivers[i].Receive(buffer);
                    buffer.AsSpan(0, n).ToArray().Should().Equal(distinctPayloads[i],
                        $"receiver {i} must get exactly the payload sendmmsg addressed to it");
                }
            }

            // Fallback loop (one sendto per datagram): forced via an unavailable syscall seam.
            using var fallbackSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)
            {
                SendBufferSize = 1 << 24,
            };
            using var fallbackSender = new BatchedDatagramSender(fallbackSocket, UnavailableSyscall.Instance);
            fallbackSender.UsesNativeBatchSend.Should().BeFalse();
            var fallbackRate = Measure(fallbackSender, datagrams, window);

            // Native sendmmsg batch path.
            using var nativeSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)
            {
                SendBufferSize = 1 << 24,
            };
            using var nativeSender = new BatchedDatagramSender(nativeSocket);
            nativeSender.UsesNativeBatchSend.Should().BeTrue();
            var nativeRate = Measure(nativeSender, datagrams, window);

            _output.WriteLine($"batch size                : {batch}");
            _output.WriteLine($"fallback SendTo loop      : {fallbackRate,14:N0} datagram/s");
            _output.WriteLine($"native sendmmsg batch     : {nativeRate,14:N0} datagram/s");
            _output.WriteLine($"speedup                   : {nativeRate / fallbackRate,13:F2}x");

            // The ratio is reported, not asserted: a measured number is not a CI merge gate, and a
            // shared runner can land native a few percent below the managed loop.
            nativeRate.Should().BeGreaterThan(0);
            fallbackRate.Should().BeGreaterThan(0);
        }
        finally
        {
            foreach (var r in receivers)
            {
                r?.Dispose();
            }
        }
    }

    private static double Measure(BatchedDatagramSender sender, ReadOnlySpan<Datagram> datagrams, TimeSpan window)
    {
        // Warm up.
        for (var i = 0; i < 200; i++)
        {
            sender.Send(datagrams);
        }

        var end = Stopwatch.GetTimestamp() + (long)(window.TotalSeconds * Stopwatch.Frequency);
        var start = Stopwatch.GetTimestamp();
        long datagramsSent = 0;
        while (Stopwatch.GetTimestamp() < end)
        {
            for (var i = 0; i < 64; i++)
            {
                datagramsSent += sender.Send(datagrams);
            }
        }

        return datagramsSent / Stopwatch.GetElapsedTime(start).TotalSeconds;
    }

    private static byte[] MakePayload(int seed, int length)
    {
        var payload = new byte[length];
        for (var i = 0; i < length; i++)
        {
            payload[i] = (byte)((seed * 31) + i);
        }

        return payload;
    }

    // Forces the managed fallback path on any OS by reporting the native syscall as unavailable.
    private sealed class UnavailableSyscall : IDatagramBatchSyscall
    {
        public static readonly UnavailableSyscall Instance = new();

        public bool IsAvailable => false;

        public int SendBatch(int fd, nint msgvec, uint vlen, out int errorCode) =>
            throw new InvalidOperationException("The unavailable syscall must never be invoked.");
    }
}
