using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Keryx.Core;

// -------------------------------------------------------------------------------------------------
// Native marshalling layer for BatchedDatagramSender's Linux fast path.
//
// This is the ONE narrow native-syscall exception the Keryx baseline allows: .NET exposes no
// sendmmsg(2)/GSO, so batching a UDP fan-out send into a single syscall needs a P/Invoke. Everything
// here is Linux amd64/arm64 ABI. The struct layouts are verified against <sys/socket.h>,
// <netinet/in.h> and <bits/socket.h>; they are only ever dereferenced by the kernel on Linux.
//
// The syscall itself sits behind IDatagramBatchSyscall so the marshalling and partial-send/error
// loop in BatchedDatagramSender can be unit-tested off Linux with a fake that inspects the fully
// marshalled mmsghdr/iovec/sockaddr the production code produced.
// -------------------------------------------------------------------------------------------------

/// <summary>iovec: a single scatter/gather buffer. Layout matches <c>struct iovec</c>.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct IoVec
{
    public nint Base; // iov_base
    public nuint Len; // iov_len
}

/// <summary>msghdr: one message header. Layout matches <c>struct msghdr</c> on Linux.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct MsgHdr
{
    public nint Name;        // msg_name (sockaddr*)
    public uint NameLen;     // msg_namelen (socklen_t); 4 bytes natural padding follows on 64-bit.
    public nint Iov;         // msg_iov (iovec*)
    public nuint IovLen;     // msg_iovlen
    public nint Control;     // msg_control
    public nuint ControlLen; // msg_controllen
    public int Flags;        // msg_flags; struct rounds to an 8-byte multiple.
}

/// <summary>mmsghdr: a message header plus the kernel-filled sent-byte count. Matches <c>struct mmsghdr</c>.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct MMsgHdr
{
    public MsgHdr Hdr; // msg_hdr
    public uint Len;   // msg_len (bytes sent, filled by the kernel)
}

/// <summary>
/// Sends a pre-marshalled batch of datagrams in as few syscalls as possible over a raw fd.
/// </summary>
/// <remarks>
/// Kept as a seam so the marshalling and partial-send/error handling in
/// <see cref="BatchedDatagramSender"/> can be exercised without a real kernel call.
/// </remarks>
internal interface IDatagramBatchSyscall
{
    /// <summary>True when this syscall can actually be issued on the current OS/runtime.</summary>
    bool IsAvailable { get; }

    /// <summary>
    /// Sends up to <paramref name="vlen"/> messages starting at <paramref name="msgvec"/>.
    /// </summary>
    /// <param name="fd">The socket file descriptor.</param>
    /// <param name="msgvec">Pointer to the first <see cref="MMsgHdr"/> to send.</param>
    /// <param name="vlen">Number of messages available at <paramref name="msgvec"/>.</param>
    /// <param name="errorCode">The <c>errno</c> value when the return value is negative; otherwise 0.</param>
    /// <returns>The number of messages accepted by the kernel, or a negative value on error.</returns>
    int SendBatch(int fd, nint msgvec, uint vlen, out int errorCode);
}

/// <summary>Linux <c>sendmmsg(2)</c> implementation of <see cref="IDatagramBatchSyscall"/>.</summary>
internal sealed partial class NativeBatchSyscall : IDatagramBatchSyscall
{
    /// <summary>Process-wide instance; availability is probed once.</summary>
    public static NativeBatchSyscall Shared { get; } = new();

    private static readonly bool Available = Probe();

    /// <inheritdoc/>
    public bool IsAvailable => Available;

    /// <inheritdoc/>
    [SupportedOSPlatform("linux")]
    public int SendBatch(int fd, nint msgvec, uint vlen, out int errorCode)
    {
        var n = SendMmsg(fd, msgvec, vlen, 0);
        errorCode = n < 0 ? Marshal.GetLastPInvokeError() : 0;
        return n;
    }

    // sendmmsg(2): transmits vlen messages from msgvec in a single syscall; returns the number of
    // messages sent, or -1 with errno set. msgvec is passed as nint so the declaration compiles on
    // every platform; it is only ever invoked on Linux behind the Probe() gate.
    [LibraryImport("libc", EntryPoint = "sendmmsg", SetLastError = true)]
    [SupportedOSPlatform("linux")]
    private static partial int SendMmsg(int sockfd, nint msgvec, uint vlen, int flags);

    private static bool Probe()
    {
        if (!OperatingSystem.IsLinux())
        {
            return false;
        }

        try
        {
            // vlen == 0 makes glibc return 0 without dereferencing msgvec or touching the fd, so this
            // is a side-effect-free check that the symbol resolves in the current runtime image.
            _ = SendMmsg(-1, nint.Zero, 0, 0);
            return true;
        }
        catch (DllNotFoundException)
        {
            return false;
        }
        catch (EntryPointNotFoundException)
        {
            return false;
        }
    }
}
