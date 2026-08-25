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

    /// <summary>Diagnostics sink; defaults to a no-op logger.</summary>
    public IKeryxLogger Logger { get; set; } = NullLogger.Instance;

    internal BroadcastEndpointOptions Validate()
    {
        ArgumentNullException.ThrowIfNull(BindEndPoint);
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxViewers, 1);

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
