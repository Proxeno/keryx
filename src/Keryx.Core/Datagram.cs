using System.Net;

namespace Keryx.Core;

/// <summary>
/// One outbound datagram in a batch: a payload plus the destination it is addressed to.
/// </summary>
/// <remarks>
/// The struct captures a <see cref="ReadOnlyMemory{T}"/> view of the payload and a reference to the
/// destination endpoint; it copies neither. The caller must keep both alive and unmodified for the
/// duration of the <see cref="BatchedDatagramSender.Send"/> call that consumes them.
/// </remarks>
public readonly struct Datagram
{
    /// <summary>Creates a datagram addressed to <paramref name="destination"/>.</summary>
    /// <param name="payload">The datagram body. May be empty (produces a zero-length datagram).</param>
    /// <param name="destination">
    /// The destination endpoint. Must be an <see cref="IPEndPoint"/> (IPv4 or IPv6) for the native
    /// batch path; the managed fallback accepts any endpoint the socket can address.
    /// </param>
    public Datagram(ReadOnlyMemory<byte> payload, EndPoint destination)
    {
        ArgumentNullException.ThrowIfNull(destination);
        Payload = payload;
        Destination = destination;
    }

    /// <summary>The datagram body.</summary>
    public ReadOnlyMemory<byte> Payload { get; }

    /// <summary>The destination endpoint.</summary>
    public EndPoint Destination { get; }
}
