namespace Keryx.Stun;

/// <summary>
/// STUN attribute type codes. Values below 0x8000 are comprehension-required; values at or above
/// 0x8000 are comprehension-optional (RFC 5389 section 15).
/// </summary>
public enum StunAttributeType : ushort
{
    /// <summary>MAPPED-ADDRESS (RFC 5389 section 15.1).</summary>
    MappedAddress = 0x0001,

    /// <summary>USERNAME (RFC 5389 section 15.3).</summary>
    Username = 0x0006,

    /// <summary>MESSAGE-INTEGRITY (RFC 5389 section 15.4).</summary>
    MessageIntegrity = 0x0008,

    /// <summary>ERROR-CODE (RFC 5389 section 15.6).</summary>
    ErrorCode = 0x0009,

    /// <summary>UNKNOWN-ATTRIBUTES (RFC 5389 section 15.9).</summary>
    UnknownAttributes = 0x000A,

    /// <summary>CHANNEL-NUMBER (RFC 8656 section 18.1).</summary>
    ChannelNumber = 0x000C,

    /// <summary>LIFETIME (RFC 8656 section 18.2).</summary>
    Lifetime = 0x000D,

    /// <summary>XOR-PEER-ADDRESS (RFC 8656 section 18.3).</summary>
    XorPeerAddress = 0x0012,

    /// <summary>DATA (RFC 8656 section 18.4).</summary>
    Data = 0x0013,

    /// <summary>REALM (RFC 5389 section 15.7).</summary>
    Realm = 0x0014,

    /// <summary>NONCE (RFC 5389 section 15.8).</summary>
    Nonce = 0x0015,

    /// <summary>
    /// MESSAGE-INTEGRITY-SHA256 (RFC 8489 section 14.6). Recognised so that a server offering it
    /// is not reported as sending an unknown comprehension-required attribute; Keryx keys
    /// long-term credentials with MD5 and HMAC-SHA1 only, which RFC 8489 still permits.
    /// </summary>
    MessageIntegritySha256 = 0x001C,

    /// <summary>PASSWORD-ALGORITHM (RFC 8489 section 14.12).</summary>
    PasswordAlgorithm = 0x001D,

    /// <summary>USERHASH (RFC 8489 section 14.4).</summary>
    Userhash = 0x001E,

    /// <summary>XOR-MAPPED-ADDRESS (RFC 5389 section 15.2).</summary>
    XorMappedAddress = 0x0020,

    /// <summary>XOR-RELAYED-ADDRESS (RFC 8656 section 18.5).</summary>
    XorRelayedAddress = 0x0016,

    /// <summary>REQUESTED-ADDRESS-FAMILY (RFC 8656 section 18.6).</summary>
    RequestedAddressFamily = 0x0017,

    /// <summary>EVEN-PORT (RFC 8656 section 18.7).</summary>
    EvenPort = 0x0018,

    /// <summary>REQUESTED-TRANSPORT (RFC 8656 section 18.8).</summary>
    RequestedTransport = 0x0019,

    /// <summary>DONT-FRAGMENT (RFC 8656 section 18.9); a zero-length flag attribute.</summary>
    DontFragment = 0x001A,

    /// <summary>RESERVATION-TOKEN (RFC 8656 section 18.10).</summary>
    ReservationToken = 0x0022,

    /// <summary>ADDITIONAL-ADDRESS-FAMILY (RFC 8656 section 18.11).</summary>
    AdditionalAddressFamily = 0x8000,

    /// <summary>ADDRESS-ERROR-CODE (RFC 8656 section 18.12).</summary>
    AddressErrorCode = 0x8001,

    /// <summary>ICMP (RFC 8656 section 18.13).</summary>
    Icmp = 0x8004,

    /// <summary>PRIORITY (RFC 8445 section 16.1).</summary>
    Priority = 0x0024,

    /// <summary>USE-CANDIDATE (RFC 8445 section 16.1); a zero-length flag attribute.</summary>
    UseCandidate = 0x0025,

    /// <summary>PASSWORD-ALGORITHMS (RFC 8489 section 14.11).</summary>
    PasswordAlgorithms = 0x8002,

    /// <summary>SOFTWARE (RFC 5389 section 15.10).</summary>
    Software = 0x8022,

    /// <summary>ALTERNATE-SERVER (RFC 5389 section 15.11).</summary>
    AlternateServer = 0x8023,

    /// <summary>FINGERPRINT (RFC 5389 section 15.5).</summary>
    Fingerprint = 0x8028,

    /// <summary>ICE-CONTROLLED (RFC 8445 section 16.1).</summary>
    IceControlled = 0x8029,

    /// <summary>ICE-CONTROLLING (RFC 8445 section 16.1).</summary>
    IceControlling = 0x802A,
}
