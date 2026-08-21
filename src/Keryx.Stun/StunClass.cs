namespace Keryx.Stun;

/// <summary>
/// The class of a STUN message, encoded in bits C1 and C0 of the message type
/// (RFC 5389 section 6).
/// </summary>
public enum StunClass
{
    /// <summary>A request; expects a success or error response with the same transaction id.</summary>
    Request = 0b00,

    /// <summary>An indication; generates no response.</summary>
    Indication = 0b01,

    /// <summary>A successful response to a request.</summary>
    SuccessResponse = 0b10,

    /// <summary>An error response to a request; carries an ERROR-CODE attribute.</summary>
    ErrorResponse = 0b11,
}
