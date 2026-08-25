using System.Net;
using System.Net.Sockets;

namespace Keryx.Stun;

/// <summary>
/// One STUN server to query for a server-reflexive candidate, addressed by host name and port so a
/// <c>stun:</c> URL that names a host (rather than an IP literal) is resolved when gathering starts.
/// </summary>
/// <remarks>
/// This mirrors the shape a WebRTC <c>RTCIceServer</c> STUN entry carries and the resolution
/// behaviour of Keryx's TURN server options: an already-resolved
/// <see cref="EndPoint"/> wins when set, otherwise <see cref="Host"/>/<see cref="Port"/> are
/// resolved via DNS, preferring IPv4 (the family Keryx binds first) but falling back to IPv6 when a
/// host resolves to no IPv4 address. It exists so a STUN server can be configured by hostname, the
/// way a TURN server already can, instead of only as an <see cref="IPEndPoint"/>.
/// </remarks>
public sealed class StunServerOptions
{
    /// <summary>The default STUN port for plain UDP (RFC 5389 section 9).</summary>
    public const int DefaultPort = 3478;

    /// <summary>Creates an empty entry; set the properties before use.</summary>
    public StunServerOptions()
    {
    }

    /// <summary>Creates an entry for an already-resolved transport address.</summary>
    /// <param name="endPoint">The server's transport address.</param>
    public StunServerOptions(IPEndPoint endPoint)
    {
        ArgumentNullException.ThrowIfNull(endPoint);
        EndPoint = endPoint;
        Port = endPoint.Port;
    }

    /// <summary>Creates an entry for a host name that will be resolved when gathering starts.</summary>
    /// <param name="host">The server's host name or IP literal.</param>
    /// <param name="port">The server's port.</param>
    public StunServerOptions(string host, int port = DefaultPort)
    {
        Host = host;
        Port = port;
    }

    /// <summary>The server's host name or IP literal. Ignored when <see cref="EndPoint"/> is set.</summary>
    public string? Host { get; set; }

    /// <summary>The server's port. Ignored when <see cref="EndPoint"/> is set.</summary>
    public int Port { get; set; } = DefaultPort;

    /// <summary>
    /// The server's already-resolved transport address. When set it wins over
    /// <see cref="Host"/>/<see cref="Port"/> and no DNS lookup is performed.
    /// </summary>
    public IPEndPoint? EndPoint { get; set; }

    /// <summary>
    /// Resolves the server's transport address, performing a DNS lookup when only
    /// <see cref="Host"/> was supplied.
    /// </summary>
    /// <param name="cancellationToken">Cancels the lookup.</param>
    /// <returns>The first IPv4 address the host resolves to, or the first IPv6 address when it resolves to no IPv4, with <see cref="Port"/>.</returns>
    /// <exception cref="InvalidOperationException">The entry names no host and no endpoint, or the host does not resolve to an IP address.</exception>
    public async Task<IPEndPoint> ResolveAsync(CancellationToken cancellationToken = default)
    {
        Validate();
        if (EndPoint is { } endPoint)
        {
            return endPoint;
        }

        if (IPAddress.TryParse(Host, out var literal))
        {
            return new IPEndPoint(literal, Port);
        }

        // IPv4 is preferred - Keryx gathers an IPv4 host candidate first and pairs same-family - but
        // an IPv6-only STUN host still resolves rather than failing gathering outright.
        var addresses = await Dns.GetHostAddressesAsync(Host!, cancellationToken).ConfigureAwait(false);
        IPAddress? ipv6 = null;
        foreach (var address in addresses)
        {
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                return new IPEndPoint(address, Port);
            }

            if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                ipv6 ??= address;
            }
        }

        if (ipv6 is not null)
        {
            return new IPEndPoint(ipv6, Port);
        }

        throw new InvalidOperationException($"The STUN server host '{Host}' did not resolve to an IP address.");
    }

    /// <summary>Throws when the entry is not usable.</summary>
    /// <exception cref="InvalidOperationException">The entry names neither an endpoint nor a host, or its port is out of range.</exception>
    public void Validate()
    {
        if (EndPoint is null && string.IsNullOrWhiteSpace(Host))
        {
            throw new InvalidOperationException("A STUN server entry needs either an EndPoint or a Host.");
        }

        if (EndPoint is null && Port is <= 0 or > 65535)
        {
            throw new InvalidOperationException($"The STUN server port {Port} is outside 1-65535.");
        }
    }

    /// <summary>A short description of the server.</summary>
    public override string ToString() => $"stun:{EndPoint?.ToString() ?? $"{Host}:{Port}"}";
}
