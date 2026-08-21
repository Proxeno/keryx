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

    /// <summary>REALM (RFC 5389 section 15.7).</summary>
    Realm = 0x0014,

    /// <summary>NONCE (RFC 5389 section 15.8).</summary>
    Nonce = 0x0015,

    /// <summary>XOR-MAPPED-ADDRESS (RFC 5389 section 15.2).</summary>
    XorMappedAddress = 0x0020,

    /// <summary>PRIORITY (RFC 8445 section 16.1).</summary>
    Priority = 0x0024,

    /// <summary>USE-CANDIDATE (RFC 8445 section 16.1); a zero-length flag attribute.</summary>
    UseCandidate = 0x0025,

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
