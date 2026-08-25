using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace Keryx.ScalingSpike;

// -------------------------------------------------------------------------------------------------
// Arm C — batched UDP sends via Linux sendmmsg(2). macOS has no sendmmsg, so this arm self-skips off
// Linux; run it in a Linux container to get real numbers. It compares a managed Socket.SendTo loop
// (one syscall per datagram, the production path) against a single sendmmsg carrying a batch of B
// datagrams to B distinct destinations (modelling fan-out), for B in {1,8,16,32,64}.
//
// This is the ONE justified BCL-only exception the baseline calls out: .NET exposes no
// sendmmsg/GSO, so batching the fan-out send needs a narrow Linux P/Invoke.
// -------------------------------------------------------------------------------------------------
internal static unsafe class SendMmsgArm
{
    private const int PayloadSize = Packets.PacketSize;
    private const int AfInet = 2;

    // libc sendmmsg(2): sends vlen messages from msgvec in one syscall, returns messages sent.
    [DllImport("libc", SetLastError = true)]
    private static extern int sendmmsg(int sockfd, MMsgHdr* msgvec, uint vlen, int flags);

    public static void Run(TimeSpan duration)
    {
        Console.WriteLine("-----------------------------------------------------------------");
        Console.WriteLine(" Arm C: batched UDP sends (Linux sendmmsg) vs SendTo loop");
        Console.WriteLine("-----------------------------------------------------------------");

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            Console.WriteLine($"  Skipped: sendmmsg(2) is Linux-only (running on {RuntimeInformation.OSDescription.Trim()}).");
            Console.WriteLine("  Run this arm in a Linux container:");
            Console.WriteLine("    docker build -f benchmarks/Keryx.ScalingSpike/sendmmsg-linux.Dockerfile -t keryx-sendmmsg .");
            Console.WriteLine("    docker run --rm keryx-sendmmsg --arms C");
            Console.WriteLine();
            return;
        }

        const int maxBatch = 64;
        var window = TimeSpan.FromSeconds(Math.Max(1, duration.TotalSeconds));

        // Distinct destinations: bind maxBatch receiver sockets on loopback with large recv buffers so
        // datagrams are absorbed and no ICMP port-unreachable perturbs the sender.
        var receivers = new Socket[maxBatch];
        var dests = new IPEndPoint[maxBatch];
        for (var i = 0; i < maxBatch; i++)
        {
            var r = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)
            {
                ReceiveBufferSize = 1 << 20,
            };
            r.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            receivers[i] = r;
            dests[i] = (IPEndPoint)r.LocalEndPoint!;
        }

        using var sender = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)
        {
            SendBufferSize = 1 << 24,
        };
        var fd = (int)sender.Handle;

        // Baseline: managed Socket.SendTo loop (one syscall per datagram) over the destination set.
        var loopRate = SendToLoopRate(sender, dests, window);
        Console.WriteLine($"  SendTo loop (1 syscall/datagram) : {loopRate,12:N0} datagram/s/core   (baseline ref: ~283k)");
        Console.WriteLine();
        Console.WriteLine("   batch B | sendmmsg datagram/s/core |  syscalls/s | speedup vs SendTo loop");
        Console.WriteLine("   --------+--------------------------+-------------+-----------------------");

        var payload = (byte*)NativeMemory.Alloc(PayloadSize);
        new Span<byte>(payload, PayloadSize).Fill(0x5A);

        foreach (var b in (int[])[1, 8, 16, 32, 64])
        {
            var rate = SendMmsgRate(fd, payload, dests, b, window);
            var syscalls = rate / b;
            var speedup = rate / loopRate;
            Console.WriteLine(
                $"   {b,7} | {rate,24:N0} | {syscalls,11:N0} | {speedup,6:F2}x");
        }

        NativeMemory.Free(payload);
        foreach (var r in receivers)
        {
            r.Dispose();
        }

        Console.WriteLine();
        Console.WriteLine("  => sendmmsg amortises the syscall over B datagrams; the datagram/s ceiling");
        Console.WriteLine("     rises with B until it re-binds on per-datagram in-kernel copy/UDP cost.");
        Console.WriteLine();
    }

    private static double SendToLoopRate(Socket sender, IPEndPoint[] dests, TimeSpan window)
    {
        var payload = new byte[PayloadSize];
        // Warm.
        for (var i = 0; i < 1000; i++)
        {
            sender.SendTo(payload, dests[i % dests.Length]);
        }

        var end = Stopwatch.GetTimestamp() + (long)(window.TotalSeconds * Stopwatch.Frequency);
        var start = Stopwatch.GetTimestamp();
        long sent = 0;
        var d = 0;
        while (Stopwatch.GetTimestamp() < end)
        {
            for (var i = 0; i < 1024; i++)
            {
                sender.SendTo(payload, dests[d]);
                d = d + 1 == dests.Length ? 0 : d + 1;
                sent++;
            }
        }

        return sent / Stopwatch.GetElapsedTime(start).TotalSeconds;
    }

    private static double SendMmsgRate(int fd, byte* payload, IPEndPoint[] dests, int batch, TimeSpan window)
    {
        // Build the unmanaged mmsghdr / iovec / sockaddr arrays once; reuse every syscall.
        var iovecs = (IoVec*)NativeMemory.AllocZeroed((nuint)batch, (nuint)sizeof(IoVec));
        var addrs = (SockAddrIn*)NativeMemory.AllocZeroed((nuint)batch, (nuint)sizeof(SockAddrIn));
        var msgs = (MMsgHdr*)NativeMemory.AllocZeroed((nuint)batch, (nuint)sizeof(MMsgHdr));

        for (var i = 0; i < batch; i++)
        {
            var dest = dests[i % dests.Length];
            addrs[i].Family = AfInet;
            addrs[i].Port = HostToNetworkPort((ushort)dest.Port);
            addrs[i].Addr = AddrToUInt(dest.Address);

            iovecs[i].Base = (nint)payload;
            iovecs[i].Len = PayloadSize;

            msgs[i].Hdr.Name = (nint)(addrs + i);
            msgs[i].Hdr.NameLen = (uint)sizeof(SockAddrIn);
            msgs[i].Hdr.Iov = (nint)(iovecs + i);
            msgs[i].Hdr.IovLen = 1;
        }

        // Warm.
        for (var i = 0; i < 200; i++)
        {
            SendAll(fd, msgs, batch);
        }

        var end = Stopwatch.GetTimestamp() + (long)(window.TotalSeconds * Stopwatch.Frequency);
        var start = Stopwatch.GetTimestamp();
        long datagrams = 0;
        while (Stopwatch.GetTimestamp() < end)
        {
            for (var i = 0; i < 256; i++)
            {
                datagrams += SendAll(fd, msgs, batch);
            }
        }

        var elapsed = Stopwatch.GetElapsedTime(start);
        NativeMemory.Free(iovecs);
        NativeMemory.Free(addrs);
        NativeMemory.Free(msgs);
        return datagrams / elapsed.TotalSeconds;
    }

    // Send the whole batch, looping over partial sends and retrying EINTR/EAGAIN; returns datagrams sent.
    private static int SendAll(int fd, MMsgHdr* msgs, int batch)
    {
        var sent = 0;
        while (sent < batch)
        {
            var n = sendmmsg(fd, msgs + sent, (uint)(batch - sent), 0);
            if (n < 0)
            {
                var err = Marshal.GetLastPInvokeError();
                if (err is 4 or 11 or 105) // EINTR, EAGAIN, ENOBUFS: retry.
                {
                    continue;
                }

                throw new InvalidOperationException($"sendmmsg failed with errno {err}.");
            }

            sent += n;
        }

        return sent;
    }

    private static ushort HostToNetworkPort(ushort port) =>
        BitConverter.IsLittleEndian ? (ushort)((port >> 8) | (port << 8)) : port;

    private static uint AddrToUInt(IPAddress address)
    {
        Span<byte> bytes = stackalloc byte[4];
        address.TryWriteBytes(bytes, out _);
        return BitConverter.ToUInt32(bytes); // already network byte order (big-endian octets).
    }

    // Linux amd64/arm64 ABI struct layouts. Sequential layout with natural 8-byte alignment matches
    // the C definitions (verified against <sys/socket.h>, <bits/socket.h>).
    [StructLayout(LayoutKind.Sequential)]
    private struct IoVec
    {
        public nint Base;  // iov_base
        public nuint Len;  // iov_len
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MsgHdr
    {
        public nint Name;        // msg_name
        public uint NameLen;     // msg_namelen (socklen_t); 4 bytes natural padding follows.
        public nint Iov;         // msg_iov
        public nuint IovLen;     // msg_iovlen
        public nint Control;     // msg_control
        public nuint ControlLen; // msg_controllen
        public int Flags;        // msg_flags; struct rounds to 8-byte multiple.
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MMsgHdr
    {
        public MsgHdr Hdr; // msg_hdr
        public uint Len;   // msg_len (bytes sent, filled by kernel)
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct SockAddrIn
    {
        public ushort Family; // sin_family = AF_INET
        public ushort Port;   // sin_port (network order)
        public uint Addr;     // sin_addr (network order)
        public ulong Zero;    // sin_zero[8]
    }
}
