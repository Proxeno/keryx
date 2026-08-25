using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Keryx.Core;

/// <summary>
/// Sends a batch of datagrams over a single UDP socket in as few syscalls as possible.
/// </summary>
/// <remarks>
/// <para>
/// On Linux the batch is handed to the kernel with <c>sendmmsg(2)</c>, amortising the per-datagram
/// <c>sendto</c> syscall over the whole batch — the tightest wall on UDP fan-out throughput. On
/// every other platform, and on Linux when the native symbol cannot be resolved, the same batch is
/// sent with a managed <see cref="Socket.SendTo(ReadOnlySpan{byte}, SocketFlags, EndPoint)"/> loop:
/// identical behaviour, one syscall per datagram, no batching win. Availability is probed once.
/// </para>
/// <para>
/// <b>Thread-safety:</b> an instance is <i>not</i> thread-safe. It reuses per-instance marshalling
/// buffers on the hot path, so it matches the intended single-sender-per-socket usage: only one
/// thread may call <see cref="Send"/> on a given instance at a time. Different instances (over
/// different sockets) are independent.
/// </para>
/// <para>
/// The hot path allocates nothing per send: marshalling buffers grow on demand and are then reused,
/// and payloads are pinned in place (never copied). The sender does not own the socket; disposing it
/// frees only its native marshalling buffers and leaves the socket open.
/// </para>
/// </remarks>
public sealed unsafe class BatchedDatagramSender : IDisposable
{
    // Linux caps a single sendmmsg/sendmsg iovec batch at UIO_MAXIOV; larger batches are chunked.
    private const int MaxBatchPerSyscall = 1024;

    // sockaddr_in is 16 bytes, sockaddr_in6 is 28; every address slot is sized for the larger one.
    private const int AddrSlotBytes = 28;

    // Linux address-family constants (host byte order in sa_family).
    private const ushort AfInet = 2;
    private const ushort AfInet6 = 10;

    // errno values (Linux). EAGAIN == EWOULDBLOCK == 11.
    private const int EIntr = 4;
    private const int EAgain = 11;
    private const int ENoBufs = 105;

    private readonly Socket _socket;
    private readonly IDatagramBatchSyscall _syscall;
    private readonly bool _useNative;
    private readonly int _fd;

    // Native marshalling scratch, sized to _capacity messages and reused across sends. Only allocated
    // when the native path is active.
    private MMsgHdr* _msgs;
    private IoVec* _iovecs;
    private byte* _addrs;
    private MemoryHandle[] _pins = [];
    private int _capacity;
    private bool _disposed;

    /// <summary>Creates a sender over <paramref name="socket"/>, selecting the native path when available.</summary>
    /// <param name="socket">The UDP socket to send over. The sender does not take ownership of it.</param>
    public BatchedDatagramSender(Socket socket)
        : this(socket, NativeBatchSyscall.Shared)
    {
    }

    // Test seam: lets a fake syscall drive the native marshalling + partial-send/error loop on any OS.
    internal BatchedDatagramSender(Socket socket, IDatagramBatchSyscall syscall)
    {
        ArgumentNullException.ThrowIfNull(socket);
        ArgumentNullException.ThrowIfNull(syscall);
        _socket = socket;
        _syscall = syscall;
        _useNative = syscall.IsAvailable;
        if (_useNative)
        {
            _fd = (int)socket.Handle;
        }
    }

    /// <summary>True when this sender batches with the native <c>sendmmsg(2)</c> fast path.</summary>
    /// <remarks>False means the managed one-syscall-per-datagram fallback is in use.</remarks>
    public bool UsesNativeBatchSend => _useNative;

    /// <summary>True when the native <c>sendmmsg(2)</c> fast path is available on this OS/runtime.</summary>
    public static bool NativeBatchSendSupported => NativeBatchSyscall.Shared.IsAvailable;

    /// <summary>
    /// Sends the datagrams in <paramref name="datagrams"/>, in order, over the socket.
    /// </summary>
    /// <remarks>
    /// Returns the number of datagrams accepted by the kernel. A short return (&lt; the batch size)
    /// signals backpressure: the socket's send buffer is full (<c>EWOULDBLOCK</c>/<c>ENOBUFS</c>) and
    /// the caller should retry the un-sent tail later. Datagrams are handed to the kernel in order,
    /// so the accepted ones are always the leading prefix of the batch.
    /// </remarks>
    /// <param name="datagrams">The batch to send. Each entry's payload and destination are read in place.</param>
    /// <returns>The number of leading datagrams accepted for transmission.</returns>
    /// <exception cref="ObjectDisposedException">The sender has been disposed.</exception>
    /// <exception cref="SocketException">
    /// A datagram was rejected for a non-transient reason (e.g. oversized payload, <c>EMSGSIZE</c>).
    /// Any datagrams ahead of it in the batch were already sent.
    /// </exception>
    public int Send(ReadOnlySpan<Datagram> datagrams)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (datagrams.IsEmpty)
        {
            return 0;
        }

        return _useNative ? SendNative(datagrams) : SendFallback(datagrams);
    }

    // Managed fallback: one SendTo per datagram. Same ordering and backpressure contract as the
    // native path, just no syscall batching.
    private int SendFallback(ReadOnlySpan<Datagram> datagrams)
    {
        for (var i = 0; i < datagrams.Length; i++)
        {
            ref readonly var d = ref datagrams[i];
            try
            {
                _socket.SendTo(d.Payload.Span, SocketFlags.None, d.Destination);
            }
            catch (SocketException e) when (e.SocketErrorCode is SocketError.WouldBlock or SocketError.NoBufferSpaceAvailable)
            {
                return i; // Backpressure: send buffer full. Caller retries datagrams[i..].
            }
        }

        return datagrams.Length;
    }

    // Native fast path: marshal each chunk of up to MaxBatchPerSyscall datagrams into the reused
    // mmsghdr/iovec/sockaddr buffers, then drain the chunk with sendmmsg, looping over partial sends.
    private int SendNative(ReadOnlySpan<Datagram> datagrams)
    {
        var total = 0;
        var offset = 0;
        while (offset < datagrams.Length)
        {
            var chunk = Math.Min(datagrams.Length - offset, MaxBatchPerSyscall);
            EnsureCapacity(chunk);

            var pinned = 0;
            int sentInChunk;
            try
            {
                for (var i = 0; i < chunk; i++)
                {
                    Marshal(datagrams[offset + i], i);
                    pinned = i + 1;
                }

                sentInChunk = DrainChunk(chunk, offset);
            }
            finally
            {
                for (var i = 0; i < pinned; i++)
                {
                    _pins[i].Dispose();
                }
            }

            total += sentInChunk;
            if (sentInChunk < chunk)
            {
                return total; // Backpressure inside this chunk; stop, leaving the tail for the caller.
            }

            offset += chunk;
        }

        return total;
    }

    // Marshal one datagram into slot i of the reused native buffers: pin the payload, point an iovec
    // at it, write the destination sockaddr, and wire up the mmsghdr.
    private void Marshal(in Datagram datagram, int i)
    {
        if (datagram.Destination is not IPEndPoint endpoint)
        {
            throw new ArgumentException(
                $"The native batch path requires IPEndPoint destinations; got {datagram.Destination.GetType()}.",
                nameof(datagram));
        }

        var handle = datagram.Payload.Pin();
        _pins[i] = handle;

        _iovecs[i].Base = (nint)handle.Pointer;
        _iovecs[i].Len = (nuint)datagram.Payload.Length;

        var slot = _addrs + (i * AddrSlotBytes);
        var nameLen = WriteSockAddr(slot, endpoint);

        ref var msg = ref _msgs[i];
        msg.Hdr.Name = (nint)slot;
        msg.Hdr.NameLen = nameLen;
        msg.Hdr.Iov = (nint)(_iovecs + i);
        msg.Hdr.IovLen = 1;
        msg.Hdr.Control = nint.Zero;
        msg.Hdr.ControlLen = 0;
        msg.Hdr.Flags = 0;
        msg.Len = 0;
    }

    // Drain a marshalled chunk with repeated sendmmsg calls, advancing over partial sends. Returns
    // the number of datagrams from this chunk the kernel accepted; a short count means backpressure.
    // absoluteOffset is the chunk's index within the caller's batch, used only for error reporting.
    private int DrainChunk(int chunk, int absoluteOffset)
    {
        var sent = 0;
        while (sent < chunk)
        {
            var n = _syscall.SendBatch(_fd, (nint)(_msgs + sent), (uint)(chunk - sent), out var error);
            if (n > 0)
            {
                sent += n;
                continue;
            }

            if (n == 0)
            {
                break; // Defensive: no progress and no error; avoid spinning.
            }

            switch (error)
            {
                case EIntr:
                    continue; // Interrupted before sending anything; retry.
                case EAgain:
                case ENoBufs:
                    return sent; // Send buffer full; report backpressure.
                default:
                    // A non-transient rejection of the message now at the front of the window
                    // (datagrams[absoluteOffset + sent]); those ahead of it already went out.
                    throw new SocketException(error);
            }
        }

        return sent;
    }

    // Write an IPv4 (sockaddr_in) or IPv6 (sockaddr_in6) address into a native slot; returns the
    // socklen_t length the kernel should read. Field byte order matches the Linux ABI: sa_family is
    // host order, sin_port is network order, sin_addr octets are already network order.
    private static uint WriteSockAddr(byte* slot, IPEndPoint endpoint)
    {
        var port = HostToNetworkPort((ushort)endpoint.Port);
        if (endpoint.AddressFamily == AddressFamily.InterNetwork)
        {
            Unsafe.WriteUnaligned(slot + 0, AfInet);
            Unsafe.WriteUnaligned(slot + 2, port);
            var addr = new Span<byte>(slot + 4, 4);
            if (!endpoint.Address.TryWriteBytes(addr, out _))
            {
                throw new ArgumentException("IPv4 address did not serialise to 4 bytes.", nameof(endpoint));
            }

            new Span<byte>(slot + 8, 8).Clear(); // sin_zero
            return 16;
        }

        if (endpoint.AddressFamily == AddressFamily.InterNetworkV6)
        {
            Unsafe.WriteUnaligned(slot + 0, AfInet6);
            Unsafe.WriteUnaligned(slot + 2, port);
            Unsafe.WriteUnaligned(slot + 4, 0u); // sin6_flowinfo
            var addr = new Span<byte>(slot + 8, 16);
            if (!endpoint.Address.TryWriteBytes(addr, out _))
            {
                throw new ArgumentException("IPv6 address did not serialise to 16 bytes.", nameof(endpoint));
            }

            Unsafe.WriteUnaligned(slot + 24, (uint)endpoint.Address.ScopeId); // sin6_scope_id
            return 28;
        }

        throw new ArgumentException(
            $"Unsupported destination address family {endpoint.AddressFamily}.", nameof(endpoint));
    }

    private static ushort HostToNetworkPort(ushort port) =>
        BitConverter.IsLittleEndian ? (ushort)((port >> 8) | (port << 8)) : port;

    // Grow the reused native buffers to hold at least `needed` messages (capped at the syscall max).
    private void EnsureCapacity(int needed)
    {
        if (needed <= _capacity)
        {
            return;
        }

        FreeNative();
        _msgs = (MMsgHdr*)NativeMemory.AllocZeroed((nuint)needed, (nuint)sizeof(MMsgHdr));
        _iovecs = (IoVec*)NativeMemory.AllocZeroed((nuint)needed, (nuint)sizeof(IoVec));
        _addrs = (byte*)NativeMemory.AllocZeroed((nuint)needed, AddrSlotBytes);
        _pins = new MemoryHandle[needed];
        _capacity = needed;
    }

    private void FreeNative()
    {
        if (_msgs is not null)
        {
            NativeMemory.Free(_msgs);
            _msgs = null;
        }

        if (_iovecs is not null)
        {
            NativeMemory.Free(_iovecs);
            _iovecs = null;
        }

        if (_addrs is not null)
        {
            NativeMemory.Free(_addrs);
            _addrs = null;
        }

        _capacity = 0;
    }

    /// <summary>Frees the native marshalling buffers. Leaves the underlying socket open.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        FreeNative();
        GC.SuppressFinalize(this);
    }

    /// <summary>Releases native memory if <see cref="Dispose"/> was not called.</summary>
    ~BatchedDatagramSender() => FreeNative();
}
