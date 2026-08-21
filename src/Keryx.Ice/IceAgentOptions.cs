using System.Net;
using System.Security.Cryptography;
using Keryx.Core;
using Keryx.Stun;
using Keryx.Turn;

namespace Keryx.Ice;

/// <summary>Generates the short-term credentials an ICE agent authenticates checks with.</summary>
/// <remarks>
/// RFC 8445 section 5.3 restricts both values to <c>ice-char</c> (ALPHA / DIGIT / "+" / "/") and
/// requires at least 24 bits of randomness in the ufrag and 128 bits in the password.
/// </remarks>
public static class IceCredentials
{
    private const string IceChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// <summary>Generates a random username fragment.</summary>
    /// <param name="length">Number of characters; RFC 8445 requires at least 4.</param>
    public static string NewUfrag(int length = 8) => NewIceString(length, 4);

    /// <summary>Generates a random password.</summary>
    /// <param name="length">Number of characters; RFC 8445 requires at least 22.</param>
    public static string NewPassword(int length = 24) => NewIceString(length, 22);

    private static string NewIceString(int length, int minimum)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(length, minimum);
        return string.Create(length, minimum, static (span, _) =>
        {
            for (var i = 0; i < span.Length; i++)
            {
                span[i] = IceChars[RandomNumberGenerator.GetInt32(IceChars.Length)];
            }
        });
    }
}

/// <summary>Configuration for an <see cref="IceAgent"/>.</summary>
public sealed class IceAgentOptions
{
    /// <summary>
    /// The role to start in. WebRTC offerers are controlling; a 487 role conflict may still flip
    /// this at runtime (RFC 8445 section 7.3.1.1).
    /// </summary>
    public IceRole Role { get; set; } = IceRole.Controlling;

    /// <summary>The local username fragment; generated when null.</summary>
    public string? LocalUfrag { get; set; }

    /// <summary>The local password; generated when null.</summary>
    public string? LocalPassword { get; set; }

    /// <summary>
    /// STUN servers to query for a server-reflexive candidate. Queried in order over the agent's
    /// own socket; failures are logged and skipped.
    /// </summary>
    public IList<IPEndPoint> StunServers { get; } = [];

    /// <summary>
    /// TURN servers to allocate a relayed candidate on. Each entry is allocated over the agent's
    /// own socket, so the relayed candidate's base is that socket and RFC 8445 section 5.1.1.2's
    /// <c>raddr</c>/<c>rport</c> come out right. Failures are logged and skipped.
    /// </summary>
    public IList<TurnServerOptions> TurnServers { get; } = [];

    /// <summary>
    /// The address to bind. Null binds <see cref="IPAddress.Any"/> and gathers a host candidate
    /// for every up, non-loopback IPv4 unicast address. Set it to gather exactly one address -
    /// including <see cref="IPAddress.Loopback"/>, which interface enumeration deliberately skips.
    /// </summary>
    public IPAddress? BindAddress { get; set; }

    /// <summary>Lowest port to bind, inclusive. Zero (with <see cref="MaxPort"/>) binds an ephemeral port.</summary>
    public int MinPort { get; set; }

    /// <summary>Highest port to bind, inclusive.</summary>
    public int MaxPort { get; set; }

    /// <summary>Diagnostics sink; <see cref="NullLogger"/> when null.</summary>
    public IKeryxLogger? Logger { get; set; }

    /// <summary>The tie-breaker advertised in ICE-CONTROLLING/ICE-CONTROLLED; random when null.</summary>
    public ulong? TieBreaker { get; set; }

    /// <summary>The check pacing interval, Ta in RFC 8445 section 14.2.</summary>
    public TimeSpan CheckInterval { get; set; } = TimeSpan.FromMilliseconds(50);

    /// <summary>The initial retransmission timeout for a connectivity check.</summary>
    public TimeSpan CheckRetransmissionTimeout { get; set; } = TimeSpan.FromMilliseconds(500);

    /// <summary>Total transmissions of a single connectivity check before its pair fails.</summary>
    public int MaxCheckTransmissions { get; set; } = 5;

    /// <summary>How often to re-check the selected pair, which doubles as a consent refresh.</summary>
    public TimeSpan KeepaliveInterval { get; set; } = TimeSpan.FromSeconds(2);

    /// <summary>Silence on the selected pair after which the agent reports <see cref="IceAgentState.Disconnected"/>.</summary>
    public TimeSpan DisconnectedTimeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>Silence on the selected pair after which the agent reports <see cref="IceAgentState.Failed"/>.</summary>
    public TimeSpan ConsentTimeout { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>How long checking may run without a single successful pair before the agent fails.</summary>
    public TimeSpan ConnectivityTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Retransmission settings for the STUN queries used to gather srflx candidates.</summary>
    public StunClientOptions? StunClientOptions { get; set; }

    /// <summary>
    /// Lifetime, refresh and data-path settings for the TURN allocations in
    /// <see cref="TurnServers"/>. The agent's <see cref="Logger"/> is used when the entry carries
    /// none of its own.
    /// </summary>
    public TurnClientOptions? TurnClientOptions { get; set; }

    internal IceAgentOptions Validate()
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(CheckInterval, TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(CheckRetransmissionTimeout, TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxCheckTransmissions, 1);
        ArgumentOutOfRangeException.ThrowIfNegative(MinPort);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(MaxPort, 65535);
        if (MinPort > 0 && MaxPort < MinPort)
        {
            throw new ArgumentException("MaxPort must be greater than or equal to MinPort.", nameof(MaxPort));
        }

        foreach (var turnServer in TurnServers)
        {
            turnServer.Validate();
        }

        return this;
    }
}
