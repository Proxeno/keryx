using System.Net.Security;
using System.Net.Sockets;
using Keryx.Core;
using Keryx.Stun;

namespace Keryx.Turn;

/// <summary>Tuning knobs for a <see cref="TurnClient"/>.</summary>
public sealed class TurnClientOptions
{
    /// <summary>
    /// The lifetime to ask for in the Allocate and Refresh LIFETIME attribute. The server may
    /// grant less or more; the granted value drives the refresh timer (RFC 8656 section 7.2).
    /// </summary>
    public TimeSpan RequestedLifetime { get; set; } = TimeSpan.FromSeconds(StunLifetimeAttribute.DefaultAllocationSeconds);

    /// <summary>
    /// How long before the granted lifetime expires the allocation is refreshed, as a fraction of
    /// that lifetime. The default of 0.5 gives RFC 8656 section 7.5's "well before expiry".
    /// </summary>
    public double RefreshFraction { get; set; } = 0.5;

    /// <summary>
    /// How often a permission is re-created. Permissions live 300 s and are not negotiable
    /// (RFC 8656 section 9); the RFC recommends refreshing every 4 minutes.
    /// </summary>
    public TimeSpan PermissionRefreshInterval { get; set; } = TimeSpan.FromSeconds(240);

    /// <summary>
    /// How often a channel binding is re-bound. Bindings live 600 s (RFC 8656 section 11.2), and
    /// re-binding at 8 minutes leaves two minutes of slack.
    /// </summary>
    public TimeSpan ChannelRefreshInterval { get; set; } = TimeSpan.FromSeconds(480);

    /// <summary>
    /// How often the maintenance loop wakes to check the refresh deadlines above. Small values
    /// cost nothing; the loop does no work when nothing is due.
    /// </summary>
    public TimeSpan MaintenanceInterval { get; set; } = TimeSpan.FromSeconds(1);

    /// <summary>
    /// True to bind a channel to every permitted peer and carry relayed datagrams as ChannelData;
    /// false to use Send indications, which need no channel but cost 36 bytes per packet
    /// (RFC 8656 sections 10 and 12).
    /// </summary>
    public bool UseChannelData { get; set; } = true;

    /// <summary>
    /// The address family to request for the relayed address, sent as REQUESTED-ADDRESS-FAMILY
    /// (RFC 8656 section 18.6). Null - the default - omits the attribute, which is today's wire
    /// behaviour and asks the server for its own default, an IPv4 relayed address (section 6.1).
    /// Set to <see cref="AddressFamily.InterNetworkV6"/> to request an IPv6 relay instead; only
    /// <see cref="AddressFamily.InterNetwork"/> and <see cref="AddressFamily.InterNetworkV6"/> are
    /// valid.
    /// </summary>
    public AddressFamily? RequestedAddressFamily { get; set; }

    /// <summary>Retransmission settings for the Allocate, Refresh, CreatePermission and ChannelBind transactions.</summary>
    public StunClientOptions? StunClientOptions { get; set; }

    /// <summary>
    /// Validates the server's certificate on a <see cref="TurnClientTransport.Tls"/> connection.
    /// Null - the default - applies the platform's standard chain-and-name validation. Supply a
    /// callback only to pin a certificate or trust a private CA; it is never used to disable
    /// validation wholesale.
    /// </summary>
    public RemoteCertificateValidationCallback? TlsCertificateValidationCallback { get; set; }

    /// <summary>Diagnostics sink; <see cref="NullLogger"/> when null.</summary>
    public IKeryxLogger? Logger { get; set; }

    internal TurnClientOptions Validate()
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(RequestedLifetime, TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(RefreshFraction, 0);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(RefreshFraction, 1);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(PermissionRefreshInterval, TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(ChannelRefreshInterval, TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(MaintenanceInterval, TimeSpan.Zero);
        if (RequestedAddressFamily is { } family && family is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
        {
            throw new ArgumentOutOfRangeException(
                nameof(RequestedAddressFamily), family, "Only InterNetwork and InterNetworkV6 can be requested.");
        }

        return this;
    }
}
