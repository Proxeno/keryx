namespace Keryx.Stun;

/// <summary>
/// The method of a STUN message: the 12 M bits of the message type (RFC 5389 section 6).
/// </summary>
/// <remarks>
/// Only Binding is defined by RFC 5389 itself. Values outside this enumeration are preserved
/// verbatim when decoding so that unknown methods can be recognised and rejected by the caller.
/// </remarks>
public enum StunMethod : ushort
{
    /// <summary>The Binding method (0x001), RFC 5389 section 3.</summary>
    Binding = 0x001,
}
