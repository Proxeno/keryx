using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Keryx.Core;

// -------------------------------------------------------------------------------------------------
// SO_REUSEPORT for the broadcast socket pool (broadcast-scale.md §2/§4).
//
// This is the SAME narrow Linux native-syscall exception the baseline allows for sendmmsg(2): the BCL
// exposes no way to set SO_REUSEPORT (Socket.SetSocketOption's SocketOptionName enum has no member for
// it, and passing a raw numeric value is not translated by the Unix PAL), so binding a pool of UDP
// sockets to ONE port — letting the kernel 5-tuple-hash inbound datagrams across them so a broadcast
// endpoint's fan-out sends and receives spread across cores while still advertising a single host:port
// — needs one setsockopt(2) P/Invoke. It is Linux-only, feature-detected, and touches no protocol layer.
//
// The SO_REUSEPORT (15) and SOL_SOCKET (1) constants are the asm-generic values used on amd64 and
// arm64 — the two architectures this stack's native fast paths target (matching the sendmmsg interop).
// A handful of older Linux ABIs (MIPS/SPARC/PARISC/ALPHA) number these differently; on any platform
// where the option cannot be set the caller falls back to a single socket, so a wrong or missing value
// degrades to correct single-socket behaviour, never to a broken bind.
// -------------------------------------------------------------------------------------------------

/// <summary>
/// Sets the Linux <c>SO_REUSEPORT</c> socket option, enabling a pool of UDP sockets to bind the same
/// address and port with the kernel load-balancing inbound datagrams across them by 5-tuple hash.
/// </summary>
internal static partial class ReusePortSocketOption
{
    private const int SolSocket = 1;    // Linux SOL_SOCKET (asm-generic).
    private const int SoReusePort = 15; // Linux SO_REUSEPORT (asm-generic; amd64/arm64).

    /// <summary>True when <c>SO_REUSEPORT</c> can be set on this OS (Linux only).</summary>
    public static bool IsSupported => OperatingSystem.IsLinux();

    /// <summary>
    /// Attempts to set <c>SO_REUSEPORT</c> on <paramref name="socket"/>. Must be called before
    /// <see cref="Socket.Bind"/>. Returns false — never throws — when the option is unavailable
    /// (non-Linux) or the syscall rejects it, so the caller can fall back to a single socket.
    /// </summary>
    /// <param name="socket">The UDP socket to enable port sharing on, before it is bound.</param>
    /// <returns>True when the option was set; false when it is unsupported or the syscall failed.</returns>
    public static bool TrySet(Socket socket)
    {
        ArgumentNullException.ThrowIfNull(socket);
        if (!OperatingSystem.IsLinux())
        {
            return false;
        }

        try
        {
            var one = 1;
            var handle = socket.Handle;
            var rc = SetSockOpt((int)handle, SolSocket, SoReusePort, ref one, sizeof(int));
            return rc == 0;
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

    // setsockopt(2): sets one socket option to an int value. Declared for every platform so the code
    // compiles anywhere; only ever invoked on Linux behind the IsSupported gate.
    [LibraryImport("libc", EntryPoint = "setsockopt", SetLastError = true)]
    [SupportedOSPlatform("linux")]
    private static partial int SetSockOpt(int sockfd, int level, int optname, ref int optval, uint optlen);
}
