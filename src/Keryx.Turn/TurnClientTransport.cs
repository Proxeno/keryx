namespace Keryx.Turn;

/// <summary>
/// The transport of the leg between the TURN client and the TURN server (RFC 8656 section 2.1).
/// </summary>
/// <remarks>
/// <para>
/// This is a different axis from REQUESTED-TRANSPORT (<see cref="Keryx.Stun.TurnTransportProtocol"/>),
/// which chooses how the <i>server</i> relays to the far peer. Keryx always relays to the peer over
/// UDP; this enum only chooses how the client reaches the server. Enterprise, hotel and mobile
/// networks routinely block UDP, and browsers fall back to TURN/TCP and TURN/TLS there
/// (RFC 5766 section 2.1), so the same is offered here as a fallback for the client-to-server leg.
/// </para>
/// <para>
/// Whichever transport is used, the relayed transport address the server hands back is still a UDP
/// address on the server, so the relayed ICE candidate and its pairing are unchanged - only the
/// client-to-server connection differs.
/// </para>
/// </remarks>
public enum TurnClientTransport
{
    /// <summary>Plain UDP (RFC 8656 section 2.1); the default, and the only zero-connection transport.</summary>
    Udp = 0,

    /// <summary>
    /// TCP (RFC 5766 section 2.1 and RFC 5389 section 7.2.2): STUN/TURN messages travel over one TCP
    /// connection to the server, reassembled from the byte stream. This is TURN <i>over</i> TCP, not
    /// the RFC 6062 TCP-relay extension - the relay to the far peer is still UDP.
    /// </summary>
    Tcp = 1,

    /// <summary>
    /// TLS over TCP (RFC 5766 section 2.1): the <see cref="Tcp"/> connection wrapped in TLS, for
    /// networks that only pass what looks like HTTPS. The relay to the far peer is still UDP.
    /// </summary>
    Tls = 2,
}
