using System.Net;
using System.Net.Sockets;
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

    /// <summary>
    /// How a controlling agent nominates the selected pair. Defaults to
    /// <see cref="IceNominationMode.Regular"/>, which freezes the selection after nominating so a
    /// later higher-priority success never flaps live media; controlled agents ignore this.
    /// </summary>
    public IceNominationMode NominationMode { get; set; } = IceNominationMode.Regular;

    /// <summary>The local username fragment; generated when null.</summary>
    public string? LocalUfrag { get; set; }

    /// <summary>The local password; generated when null.</summary>
    public string? LocalPassword { get; set; }

    /// <summary>
    /// STUN servers to query for a server-reflexive candidate, as already-resolved transport
    /// addresses. Queried in order over the agent's own socket; failures are logged and skipped. To
    /// configure a STUN server by host name (resolved via DNS when gathering starts), add a
    /// <see cref="StunServerOptions"/> to <see cref="StunServerHosts"/> instead - both lists are
    /// queried, this one first.
    /// </summary>
    public IList<IPEndPoint> StunServers { get; } = [];

    /// <summary>
    /// STUN servers to query for a server-reflexive candidate, addressed by host name and port and
    /// resolved via DNS when gathering starts. This mirrors <see cref="TurnServers"/>, which already
    /// accepts a host name: an entry whose <see cref="StunServerOptions.EndPoint"/> is set is used
    /// as-is, otherwise its <see cref="StunServerOptions.Host"/>/<see cref="StunServerOptions.Port"/>
    /// are resolved (IPv4 preferred). Queried after <see cref="StunServers"/>; failures - including a
    /// host that does not resolve - are logged and skipped.
    /// </summary>
    public IList<StunServerOptions> StunServerHosts { get; } = [];

    /// <summary>
    /// TURN servers to allocate a relayed candidate on. A default (UDP) entry is allocated over the
    /// agent's own socket, so the relayed candidate's base is that socket and RFC 8445 section
    /// 5.1.1.2's <c>raddr</c>/<c>rport</c> come out right. An entry whose
    /// <see cref="TurnServerOptions.ClientTransport"/> is <see cref="TurnClientTransport.Tcp"/> or
    /// <see cref="TurnClientTransport.Tls"/> instead allocates over a dedicated connection to the
    /// server (RFC 5766 section 2.1), for networks that block UDP; the relayed candidate it produces
    /// is still a UDP address and pairs like any other. Failures are logged and skipped.
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

    /// <summary>
    /// Whether a remote host candidate whose connection address is an mDNS <c>&lt;name&gt;.local</c>
    /// host name is resolved to an address and paired, instead of being dropped as unparsable.
    /// Browsers obfuscate host candidates this way by default, so this is on by default to keep
    /// same-LAN direct connections working; resolution runs off the intake path and any failure
    /// degrades gracefully to skipping the candidate (RFC 6762, draft mdns-ice-candidates).
    /// </summary>
    public bool ResolveMdnsCandidates { get; set; } = true;

    /// <summary>
    /// The resolver used for <c>.local</c> host candidates when <see cref="ResolveMdnsCandidates"/>
    /// is set. Null uses <see cref="MulticastMdnsResolver.Shared"/>; a test can supply a stub to
    /// route intake without a live multicast responder.
    /// </summary>
    public IMdnsResolver? MdnsResolver { get; set; }

    /// <summary>
    /// The greatest number of <c>.local</c> candidate resolutions that may be in flight at once. Each
    /// resolution opens one or two UDP sockets and sends a LAN multicast query, so this bounds socket
    /// use and multicast amplification. Names that arrive while every slot is busy queue for a slot
    /// rather than being dropped, so a legitimate burst is served a few at a time; the flood ceiling
    /// is <see cref="MaxPendingMdnsResolutions"/>. Kept small - a handful - by default.
    /// </summary>
    public int MaxConcurrentMdnsResolutions { get; set; } = 4;

    /// <summary>
    /// The greatest number of distinct <c>.local</c> names that may be awaiting resolution at once
    /// (running or queued for a concurrency slot). This is the flood ceiling: once reached, further
    /// distinct names are dropped cleanly instead of each spawning a queued task, so a hostile peer
    /// flooding distinct names cannot exhaust tasks. Generous next to a legitimate single-digit
    /// session, so a real burst is admitted in full and only a flood is turned away.
    /// </summary>
    public int MaxPendingMdnsResolutions { get; set; } = 32;

    /// <summary>
    /// How long a <c>.local</c> name that failed to resolve is remembered so an immediate re-signal
    /// of the same name is skipped instead of re-querying the LAN. Bounds query amplification from a
    /// peer repeating the same unresolvable name; short so a name that comes up later still retries.
    /// </summary>
    public TimeSpan MdnsNegativeCacheDuration { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// The greatest number of remote candidates a session retains. <c>_remoteCandidates</c> and the
    /// derived check list have no natural bound, and each add rebuilds pairs and asks each TURN
    /// allocation for a permission, so a hostile signalling peer trickling huge candidate counts
    /// drives CPU and memory growth. RFC 8445 permits limiting the set; additional remote candidates
    /// past the cap are dropped cleanly. The default dwarfs any legitimate session.
    /// </summary>
    public int MaxRemoteCandidates { get; set; } = 100;

    /// <summary>
    /// Whether an inbound datagram that demultiplexes as non-STUN (RFC 7983: DTLS, RTP or RTCP) must
    /// come from the selected pair's remote transport address once a pair has been selected, before
    /// it is handed to <see cref="IDatagramTransport.OnReceived"/>. DTLS and SRTP already
    /// authenticate their own traffic, so this is defense-in-depth - the same shape of check
    /// libwebrtc applies - not the only line: it cheaply drops UDP an off-path attacker injects at
    /// the socket before it ever reaches those layers. It has no effect before any pair is selected,
    /// when several candidate sources are legitimately still in play (RFC 8445 section 7.2), and it
    /// is re-evaluated against the current selection on every datagram, so peer-reflexive discovery,
    /// renomination and failover to a new pair all keep working as the selection moves. A relayed
    /// pair's remote address is the far side's relay - the value the selected pair already carries -
    /// so relayed traffic validates the same way as direct traffic. On by default; set false only if
    /// this ever rejects a legitimate path.
    /// </summary>
    public bool StrictInboundSourceValidation { get; set; } = true;

    /// <summary>
    /// Restricts connectivity checks (and everything <see cref="IceAgent.LocalCandidates"/> and
    /// <see cref="IceAgent.OnLocalCandidate"/> surface) to relayed candidates only, mirroring a browser's
    /// <c>iceTransportPolicy: "relay"</c>. Host and server-reflexive candidates are still bound and
    /// gathered internally - a host candidate is the required base a TURN allocation is computed
    /// from (RFC 8445 section 5.1.1.2) - they are simply never offered as a usable local candidate or
    /// paired against a remote one, so the only pair that can ever succeed routes through a
    /// <see cref="TurnServers"/> allocation. Requires at least one entry in <see cref="TurnServers"/>
    /// to be of any use: with none, gathering produces no candidates at all. Off by default.
    /// </summary>
    public bool RelayOnly { get; set; }

    /// <summary>
    /// Whether to also gather passive TCP host candidates (RFC 6544): a <see cref="TcpListener"/> is
    /// bound alongside the UDP socket and advertised as <c>a=candidate ... tcp ... tcptype passive</c>,
    /// connectivity checks and the datagram transport run over an accepted (or dialed) TCP connection
    /// using RFC 6544's two-byte length framing, so a session can traverse a TCP pair when UDP is
    /// blocked. Off by default, which keeps gathering UDP-only and every existing golden and interop
    /// exchange byte-identical. Only passive candidates are advertised; the agent still dials a remote
    /// <c>tcptype passive</c> candidate (acting as the active side), so two Keryx agents connect over
    /// TCP. Advertising this agent's own <c>active</c>/<c>so</c> candidates is deferred.
    /// </summary>
    public bool GatherTcpCandidates { get; set; }

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
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxConcurrentMdnsResolutions, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxPendingMdnsResolutions, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxRemoteCandidates, 1);
        ArgumentOutOfRangeException.ThrowIfNegative(MdnsNegativeCacheDuration.Ticks);
        ArgumentOutOfRangeException.ThrowIfNegative(MinPort);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(MaxPort, 65535);
        if (MinPort > 0 && MaxPort < MinPort)
        {
            throw new ArgumentException("MaxPort must be greater than or equal to MinPort.", nameof(MaxPort));
        }

        foreach (var stunServer in StunServerHosts)
        {
            stunServer.Validate();
        }

        foreach (var turnServer in TurnServers)
        {
            turnServer.Validate();
        }

        return this;
    }
}
