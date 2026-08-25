using System.Net;
using System.Net.Sockets;
using Keryx.Stun;

namespace Keryx.Turn;

/// <summary>
/// One TURN server and the long-term credentials to authenticate against it with
/// (RFC 8656 section 7).
/// </summary>
/// <remarks>
/// This is the shape a WebRTC <c>RTCIceServer</c> entry carries: a <c>turn:</c> host and port, a
/// username and a credential. The client-to-server leg is UDP by default; set
/// <see cref="ClientTransport"/> to <see cref="TurnClientTransport.Tcp"/> or
/// <see cref="TurnClientTransport.Tls"/> to reach the server over a TCP (or TLS-over-TCP)
/// connection for networks that block UDP (RFC 5766 section 2.1).
/// </remarks>
public sealed class TurnServerOptions
{
    /// <summary>The default TURN port for plain UDP and TCP (RFC 8656 section 6).</summary>
    public const int DefaultPort = 3478;

    /// <summary>Creates an empty entry; set the properties before use.</summary>
    public TurnServerOptions()
    {
    }

    /// <summary>Creates an entry for an already-resolved transport address.</summary>
    /// <param name="endPoint">The server's transport address.</param>
    /// <param name="username">The long-term credential username.</param>
    /// <param name="credential">The long-term credential password.</param>
    public TurnServerOptions(IPEndPoint endPoint, string username, string credential)
    {
        ArgumentNullException.ThrowIfNull(endPoint);
        EndPoint = endPoint;
        Port = endPoint.Port;
        Username = username;
        Credential = credential;
    }

    /// <summary>Creates an entry for a host name that will be resolved when gathering starts.</summary>
    /// <param name="host">The server's host name or IP literal.</param>
    /// <param name="port">The server's port.</param>
    /// <param name="username">The long-term credential username.</param>
    /// <param name="credential">The long-term credential password.</param>
    public TurnServerOptions(string host, int port, string username, string credential)
    {
        Host = host;
        Port = port;
        Username = username;
        Credential = credential;
    }

    /// <summary>
    /// The server's host name or IP literal. Ignored when <see cref="EndPoint"/> is set.
    /// </summary>
    public string? Host { get; set; }

    /// <summary>The server's port. Ignored when <see cref="EndPoint"/> is set.</summary>
    public int Port { get; set; } = DefaultPort;

    /// <summary>
    /// The server's already-resolved transport address. When set it wins over
    /// <see cref="Host"/>/<see cref="Port"/> and no DNS lookup is performed.
    /// </summary>
    public IPEndPoint? EndPoint { get; set; }

    /// <summary>The long-term credential username (RFC 8656 section 9.1).</summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>The long-term credential password (RFC 8656 section 9.1).</summary>
    public string Credential { get; set; } = string.Empty;

    /// <summary>
    /// The protocol the server relays over to the far peer, carried as REQUESTED-TRANSPORT
    /// (RFC 8656 section 18.8). Keryx always relays over <see cref="TurnTransportProtocol.Udp"/> -
    /// the only value validation accepts - so this is independent of <see cref="ClientTransport"/>,
    /// which chooses how the client reaches the server.
    /// </summary>
    public TurnTransportProtocol Transport { get; set; } = TurnTransportProtocol.Udp;

    /// <summary>
    /// The transport for the client-to-server leg (RFC 5766 section 2.1). Defaults to
    /// <see cref="TurnClientTransport.Udp"/>, which allocates over the ICE agent's own socket;
    /// <see cref="TurnClientTransport.Tcp"/> and <see cref="TurnClientTransport.Tls"/> reach the
    /// server over a dedicated TCP (or TLS-over-TCP) connection for networks that block UDP.
    /// Whichever is used, the relayed candidate the server hands back is still a UDP address, so
    /// its ICE pairing is unchanged.
    /// </summary>
    public TurnClientTransport ClientTransport { get; set; } = TurnClientTransport.Udp;

    /// <summary>
    /// The host name to validate the server's certificate against and send as TLS SNI when
    /// <see cref="ClientTransport"/> is <see cref="TurnClientTransport.Tls"/>. Defaults to
    /// <see cref="Host"/>, falling back to the endpoint's IP literal; set it when the allocation is
    /// made against an <see cref="EndPoint"/> whose certificate names a different host.
    /// </summary>
    public string? TlsServerName { get; set; }

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

        // IPv4 is preferred - Keryx allocates an IPv4 relay - but an IPv6-only TURN host still
        // resolves rather than failing gathering outright.
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

        throw new InvalidOperationException($"The TURN server host '{Host}' did not resolve to an IP address.");
    }

    /// <summary>Throws when the entry is not usable.</summary>
    /// <exception cref="InvalidOperationException">The entry is incomplete or asks for an unimplemented transport.</exception>
    public void Validate()
    {
        if (EndPoint is null && string.IsNullOrWhiteSpace(Host))
        {
            throw new InvalidOperationException("A TURN server entry needs either an EndPoint or a Host.");
        }

        if (EndPoint is null && Port is <= 0 or > 65535)
        {
            throw new InvalidOperationException($"The TURN server port {Port} is outside 1-65535.");
        }

        if (Transport != TurnTransportProtocol.Udp)
        {
            throw new InvalidOperationException(
                $"Keryx allocates over UDP only; TURN transport {Transport} is not implemented.");
        }

        if (ClientTransport is not (TurnClientTransport.Udp or TurnClientTransport.Tcp or TurnClientTransport.Tls))
        {
            throw new InvalidOperationException($"Unknown TURN client transport {ClientTransport}.");
        }

        if (string.IsNullOrEmpty(Username) || string.IsNullOrEmpty(Credential))
        {
            throw new InvalidOperationException(
                "A TURN server entry needs a username and a credential: RFC 8656 section 9 requires long-term authentication on every Allocate.");
        }
    }

    /// <summary>A description that never reveals the credential.</summary>
    public override string ToString()
        => $"turn:{EndPoint?.ToString() ?? $"{Host}:{Port}"}?transport={ClientTransport.ToString().ToLowerInvariant()} (user {Username})";
}
