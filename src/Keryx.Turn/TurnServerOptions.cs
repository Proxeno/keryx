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
/// username, a credential and a transport. Only <see cref="TurnTransportProtocol.Udp"/> is
/// implemented; TURN over TCP (RFC 6062) and TURN over (D)TLS are rejected at validation rather
/// than silently downgraded.
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
    /// The transport between client and server. Only <see cref="TurnTransportProtocol.Udp"/> is
    /// implemented.
    /// </summary>
    public TurnTransportProtocol Transport { get; set; } = TurnTransportProtocol.Udp;

    /// <summary>
    /// Resolves the server's transport address, performing a DNS lookup when only
    /// <see cref="Host"/> was supplied.
    /// </summary>
    /// <param name="cancellationToken">Cancels the lookup.</param>
    /// <returns>The first IPv4 address the host resolves to, with <see cref="Port"/>.</returns>
    /// <exception cref="InvalidOperationException">The entry names no host and no endpoint, or the host does not resolve to IPv4.</exception>
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

        var addresses = await Dns.GetHostAddressesAsync(Host!, cancellationToken).ConfigureAwait(false);
        foreach (var address in addresses)
        {
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                return new IPEndPoint(address, Port);
            }
        }

        throw new InvalidOperationException($"The TURN server host '{Host}' did not resolve to an IPv4 address.");
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

        if (string.IsNullOrEmpty(Username) || string.IsNullOrEmpty(Credential))
        {
            throw new InvalidOperationException(
                "A TURN server entry needs a username and a credential: RFC 8656 section 9 requires long-term authentication on every Allocate.");
        }
    }

    /// <summary>A description that never reveals the credential.</summary>
    public override string ToString()
        => $"turn:{EndPoint?.ToString() ?? $"{Host}:{Port}"}?transport={Transport.ToString().ToLowerInvariant()} (user {Username})";
}
