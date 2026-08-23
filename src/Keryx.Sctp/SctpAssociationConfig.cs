using Keryx.Core;

namespace Keryx.Sctp;

/// <summary>Configuration for an <see cref="SctpAssociation"/>.</summary>
/// <remarks>
/// Defaults match WebRTC practice: ports 5000/5000 (from the SDP <c>a=sctp-port</c> attribute) and
/// a 262144-byte message cap (from <c>a=max-message-size:262144</c>).
/// </remarks>
public sealed class SctpAssociationConfig
{
    /// <summary>Source port placed in the SCTP common header. WebRTC uses 5000.</summary>
    public int LocalPort { get; set; } = 5000;

    /// <summary>Destination port placed in the SCTP common header. WebRTC uses 5000.</summary>
    public int RemotePort { get; set; } = 5000;

    /// <summary>
    /// When true this endpoint sends INIT from <see cref="SctpAssociation.ConnectAsync"/>; when
    /// false it waits for the peer's INIT and replies with a cookie.
    /// </summary>
    public bool IsInitiator { get; set; }

    /// <summary>
    /// When true this endpoint allocates even data channel stream identifiers, per RFC 8832 §6 the
    /// rule for the DTLS client. In a typical Proxeno deployment Keryx is the DTLS <em>server</em>
    /// (the browser answers with <c>a=setup:active</c>), so this is usually false.
    /// </summary>
    public bool UsesEvenStreamIds { get; set; }

    /// <summary>Largest user message, in bytes, that may be sent or reassembled.</summary>
    public uint MaxMessageSize { get; set; } = 262144;

    /// <summary>
    /// When true (the default) this endpoint advertises RFC 8260 user-message interleaving (I-DATA)
    /// in its INIT/INIT ACK and uses it whenever the peer also advertises it, so a large message on
    /// one stream cannot head-of-line-block small messages on others. When false, or when the peer
    /// does not advertise I-DATA, data travels as classic DATA chunks.
    /// </summary>
    public bool EnableInterleaving { get; set; } = true;

    /// <summary>Destination for diagnostics.</summary>
    public IKeryxLogger Logger { get; set; } = NullLogger.Instance;

    /// <summary>Number of outbound streams requested in INIT.</summary>
    public ushort OutboundStreams { get; set; } = 1024;

    /// <summary>Maximum number of inbound streams accepted in INIT.</summary>
    public ushort InboundStreams { get; set; } = 1024;

    /// <summary>Local receive window advertised to the peer, in bytes.</summary>
    public uint ReceiveWindow { get; set; } = 1024 * 1024;

    /// <summary>Initial retransmission timeout, before any RTT sample has been taken.</summary>
    public TimeSpan InitialRto { get; set; } = TimeSpan.FromSeconds(1);

    /// <summary>Lower bound on the retransmission timeout.</summary>
    public TimeSpan MinRto { get; set; } = TimeSpan.FromMilliseconds(200);

    /// <summary>Upper bound on the retransmission timeout.</summary>
    public TimeSpan MaxRto { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>How often internal timers are evaluated. Also the resolution of every timeout.</summary>
    public TimeSpan TickInterval { get; set; } = TimeSpan.FromMilliseconds(50);

    /// <summary>How often a HEARTBEAT is sent once the association is established. Zero disables heartbeats.</summary>
    public TimeSpan HeartbeatInterval { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Maximum number of INIT, COOKIE ECHO or SHUTDOWN retransmissions before the association fails.</summary>
    public int MaxRetransmitAttempts { get; set; } = 8;

    /// <summary>Lifetime of a state cookie issued in INIT ACK.</summary>
    public TimeSpan CookieLifetime { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>Time source used for all timers. Replaceable so hosts and tests can control time.</summary>
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;
}

/// <summary>States of the SCTP association state machine (RFC 9260 §4).</summary>
public enum SctpAssociationState
{
    /// <summary>No association exists.</summary>
    Closed,

    /// <summary>INIT has been sent and INIT ACK is awaited.</summary>
    CookieWait,

    /// <summary>COOKIE ECHO has been sent and COOKIE ACK is awaited.</summary>
    CookieEchoed,

    /// <summary>The association is up and user data may flow.</summary>
    Established,

    /// <summary>A local shutdown was requested; queued data is being drained.</summary>
    ShutdownPending,

    /// <summary>SHUTDOWN has been sent and SHUTDOWN ACK is awaited.</summary>
    ShutdownSent,

    /// <summary>SHUTDOWN was received from the peer.</summary>
    ShutdownReceived,

    /// <summary>SHUTDOWN ACK has been sent and SHUTDOWN COMPLETE is awaited.</summary>
    ShutdownAckSent,
}

/// <summary>Lifecycle states of a <see cref="DataChannel"/>, mirroring <c>RTCDataChannelState</c>.</summary>
public enum DataChannelState
{
    /// <summary>The channel exists locally but its DCEP handshake has not completed.</summary>
    Connecting,

    /// <summary>The channel is usable.</summary>
    Open,

    /// <summary>A close was requested and is in progress.</summary>
    Closing,

    /// <summary>The channel is closed.</summary>
    Closed,
}
