namespace Keryx.Sctp;

/// <summary>SCTP chunk type identifiers (RFC 9260 §3.2 and extensions).</summary>
public enum SctpChunkType : byte
{
    /// <summary>Payload data (DATA).</summary>
    Data = 0,

    /// <summary>Association initiation (INIT).</summary>
    Init = 1,

    /// <summary>Initiation acknowledgement (INIT ACK).</summary>
    InitAck = 2,

    /// <summary>Selective acknowledgement (SACK).</summary>
    Sack = 3,

    /// <summary>Path/peer liveness probe (HEARTBEAT).</summary>
    Heartbeat = 4,

    /// <summary>Heartbeat acknowledgement (HEARTBEAT ACK).</summary>
    HeartbeatAck = 5,

    /// <summary>Ungraceful teardown (ABORT).</summary>
    Abort = 6,

    /// <summary>Graceful teardown request (SHUTDOWN).</summary>
    Shutdown = 7,

    /// <summary>Shutdown acknowledgement (SHUTDOWN ACK).</summary>
    ShutdownAck = 8,

    /// <summary>Operational error report (ERROR).</summary>
    Error = 9,

    /// <summary>State cookie echo (COOKIE ECHO).</summary>
    CookieEcho = 10,

    /// <summary>State cookie acknowledgement (COOKIE ACK).</summary>
    CookieAck = 11,

    /// <summary>Explicit congestion notification echo (ECNE). Not implemented by Keryx.</summary>
    Ecne = 12,

    /// <summary>Congestion window reduced (CWR). Not implemented by Keryx.</summary>
    Cwr = 13,

    /// <summary>Shutdown completion (SHUTDOWN COMPLETE).</summary>
    ShutdownComplete = 14,

    /// <summary>Authentication chunk (AUTH, RFC 4895). Not implemented by Keryx.</summary>
    Auth = 15,

    /// <summary>Interleaved payload data (I-DATA, RFC 8260). Not implemented by Keryx.</summary>
    IData = 64,

    /// <summary>Address configuration acknowledgement (ASCONF ACK). Not implemented by Keryx.</summary>
    AsconfAck = 128,

    /// <summary>Stream reconfiguration (RE-CONFIG, RFC 6525). Not implemented by Keryx.</summary>
    ReConfig = 130,

    /// <summary>Forward cumulative TSN (FORWARD TSN, RFC 3758).</summary>
    ForwardTsn = 192,

    /// <summary>Address configuration (ASCONF). Not implemented by Keryx.</summary>
    Asconf = 193,
}

/// <summary>Type codes for the TLV parameters carried by INIT, INIT ACK and HEARTBEAT chunks.</summary>
public enum SctpParameterType : ushort
{
    /// <summary>Opaque heartbeat payload echoed back by the peer.</summary>
    HeartbeatInfo = 1,

    /// <summary>IPv4 address parameter (never sent by Keryx; SCTP over DTLS is single-homed).</summary>
    IPv4Address = 5,

    /// <summary>IPv6 address parameter (never sent by Keryx; SCTP over DTLS is single-homed).</summary>
    IPv6Address = 6,

    /// <summary>State cookie produced by the responder in INIT ACK.</summary>
    StateCookie = 7,

    /// <summary>Reports a parameter the sender did not recognise.</summary>
    UnrecognizedParameter = 8,

    /// <summary>Requested cookie lifespan extension.</summary>
    CookiePreservative = 9,

    /// <summary>Host name address (deprecated).</summary>
    HostNameAddress = 11,

    /// <summary>Supported address types.</summary>
    SupportedAddressTypes = 12,

    /// <summary>List of chunk types the sender supports (0x8008), used to advertise FORWARD TSN.</summary>
    SupportedExtensions = 0x8008,

    /// <summary>Advertises RFC 3758 partial reliability support (0xC000 = 49152).</summary>
    ForwardTsnSupported = 0xC000,
}

/// <summary>Error cause codes carried by ABORT and ERROR chunks (RFC 9260 §3.3.10).</summary>
public enum SctpErrorCauseCode : ushort
{
    /// <summary>Invalid stream identifier.</summary>
    InvalidStreamIdentifier = 1,

    /// <summary>A mandatory parameter was missing.</summary>
    MissingMandatoryParameter = 2,

    /// <summary>The state cookie could not be validated.</summary>
    StaleCookieError = 3,

    /// <summary>Out of resources.</summary>
    OutOfResource = 4,

    /// <summary>Unresolvable address.</summary>
    UnresolvableAddress = 5,

    /// <summary>An unrecognised chunk type was received.</summary>
    UnrecognizedChunkType = 6,

    /// <summary>A mandatory parameter had an invalid value.</summary>
    InvalidMandatoryParameter = 7,

    /// <summary>One or more parameters were not recognised.</summary>
    UnrecognizedParameters = 8,

    /// <summary>No user data was supplied in a DATA chunk.</summary>
    NoUserData = 9,

    /// <summary>A COOKIE ECHO arrived while the association was shutting down.</summary>
    CookieReceivedWhileShuttingDown = 10,

    /// <summary>Restart of an association with new addresses.</summary>
    RestartWithNewAddresses = 11,

    /// <summary>Upper layer initiated abort, with an optional reason string.</summary>
    UserInitiatedAbort = 12,

    /// <summary>The requested protocol violates the association's state.</summary>
    ProtocolViolation = 13,
}

/// <summary>
/// Payload Protocol Identifiers used by WebRTC data channels (RFC 8831 §8, RFC 8832 §8.1).
/// </summary>
public static class SctpPpid
{
    /// <summary>Data Channel Establishment Protocol (DCEP) control message.</summary>
    public const uint Dcep = 50;

    /// <summary>UTF-8 encoded string payload.</summary>
    public const uint String = 51;

    /// <summary>Binary payload (deprecated partial-delivery variant).</summary>
    public const uint BinaryPartial = 52;

    /// <summary>Binary payload.</summary>
    public const uint Binary = 53;

    /// <summary>String payload (deprecated partial-delivery variant).</summary>
    public const uint StringPartial = 54;

    /// <summary>Terminating fragment of a deprecated partial string payload.</summary>
    public const uint StringPartialEnd = 55;

    /// <summary>Empty string payload; the single byte on the wire is padding and must be discarded.</summary>
    public const uint StringEmpty = 56;

    /// <summary>Empty binary payload; the single byte on the wire is padding and must be discarded.</summary>
    public const uint BinaryEmpty = 57;
}
