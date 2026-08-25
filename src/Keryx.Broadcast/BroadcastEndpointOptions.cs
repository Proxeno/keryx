using System.Net;
using Keryx.Core;

namespace Keryx.Broadcast;

/// <summary>Configuration for a <see cref="BroadcastEndpoint"/>.</summary>
public sealed class BroadcastEndpointOptions
{
    /// <summary>
    /// The address and port to bind the shared UDP socket to. A port of 0 (the default) lets the OS
    /// pick an ephemeral port, discoverable afterwards via <see cref="BroadcastEndpoint.LocalEndPoint"/>.
    /// Bind a concrete address (e.g. loopback, or a specific NIC) so the advertised host candidate is
    /// reachable; a wildcard bind requires <see cref="AdvertisedAddress"/>.
    /// </summary>
    public IPEndPoint BindEndPoint { get; set; } = new(IPAddress.Loopback, 0);

    /// <summary>
    /// The address advertised to viewers as the shared socket's ICE host candidate. Null uses
    /// <see cref="BindEndPoint"/>'s address, which must then not be a wildcard (<c>0.0.0.0</c> /
    /// <c>::</c>) — there is no single reachable address to advertise for a wildcard bind.
    /// </summary>
    public IPAddress? AdvertisedAddress { get; set; }

    /// <summary>
    /// The maximum number of concurrent viewer sessions this endpoint will hold. A broadcast-level cap
    /// bounding fan-out state, the shared-socket analogue of a per-connection
    /// <see cref="PeerConnectionConfig.MaxMediaSections"/>. <see cref="BroadcastEndpoint.AddViewer"/>
    /// throws once the set is full.
    /// </summary>
    public int MaxViewers { get; set; } = 1024;

    /// <summary>
    /// The number of UDP sockets the endpoint shards its fan-out across (<c>broadcast-scale.md</c> §2/§4).
    /// The default of 1 is exactly today's single-socket behaviour. A larger pool spreads the fan-out send
    /// syscalls — the measured bottleneck — across that many cores: each shard owns its own socket, receive
    /// loop and batched sender, and each viewer's egress is pinned to one shard, so N shards drive N
    /// <c>sendmmsg</c> flushes in parallel per ingest packet.
    /// </summary>
    /// <remarks>
    /// The pool is bound to a <b>single advertised port</b> via Linux <c>SO_REUSEPORT</c> (all shard sockets
    /// share the port; the kernel 5-tuple-hashes inbound datagrams across them). Where <c>SO_REUSEPORT</c> is
    /// unavailable — macOS, Windows, or a kernel that rejects it — the endpoint <b>falls back to a single
    /// socket</b> regardless of this value (correctness holds everywhere; the multi-core scaling win is
    /// Linux-only). The effective pool size is observable on <see cref="BroadcastEndpoint.SocketPoolSize"/>.
    /// </remarks>
    public int SocketPoolSize { get; set; } = 1;

    /// <summary>
    /// The shared socket's send-buffer size in bytes (<c>SO_SNDBUF</c>), or null (the default) to leave the
    /// OS default in force. This is the primary lever against <see cref="BroadcastEndpoint.DroppedDatagrams"/>:
    /// a fan-out flushes many datagrams per <c>sendmmsg</c>, and when the send buffer fills the batch's tail
    /// is dropped rather than allowed to stall the fan-out. Size it to at least one full fan-out batch worth
    /// of MTU-sized datagrams — roughly <c>MaxViewers × 1500</c> bytes as an upper bound, less if peak
    /// concurrency is lower — so a burst is buffered instead of shed. The OS clamps the request to its
    /// configured maximum (<c>net.core.wmem_max</c> on Linux), so verify the effective size under load and
    /// watch <see cref="BroadcastEndpoint.DroppedDatagrams"/>.
    /// </summary>
    public int? SendBufferSize { get; set; }

    /// <summary>Diagnostics sink; defaults to a no-op logger.</summary>
    public IKeryxLogger Logger { get; set; } = NullLogger.Instance;

    internal BroadcastEndpointOptions Validate()
    {
        ArgumentNullException.ThrowIfNull(BindEndPoint);
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxViewers, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(SocketPoolSize, 1);
        if (SendBufferSize is { } sendBuffer)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(sendBuffer, 1);
        }

        if (AdvertisedAddress is null
            && (BindEndPoint.Address.Equals(IPAddress.Any) || BindEndPoint.Address.Equals(IPAddress.IPv6Any)))
        {
            throw new ArgumentException(
                "A wildcard BindEndPoint has no single reachable address to advertise; set AdvertisedAddress.",
                nameof(AdvertisedAddress));
        }

        return this;
    }
}
