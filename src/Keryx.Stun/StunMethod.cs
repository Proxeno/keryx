namespace Keryx.Stun;

/// <summary>
/// The method of a STUN message: the 12 M bits of the message type (RFC 5389 section 6).
/// </summary>
/// <remarks>
/// Only Binding is defined by RFC 5389 itself; the remaining values are the TURN methods of
/// RFC 8656 section 18. Values outside this enumeration are preserved verbatim when decoding so
/// that unknown methods can be recognised and rejected by the caller.
/// </remarks>
public enum StunMethod : ushort
{
    /// <summary>The Binding method (0x001), RFC 5389 section 3.</summary>
    Binding = 0x001,

    /// <summary>The TURN Allocate method (0x003), RFC 8656 section 18.</summary>
    Allocate = 0x003,

    /// <summary>The TURN Refresh method (0x004), RFC 8656 section 18.</summary>
    Refresh = 0x004,

    /// <summary>The TURN Send method (0x006), indication only, RFC 8656 section 18.</summary>
    Send = 0x006,

    /// <summary>The TURN Data method (0x007), indication only, RFC 8656 section 18.</summary>
    Data = 0x007,

    /// <summary>The TURN CreatePermission method (0x008), RFC 8656 section 18.</summary>
    CreatePermission = 0x008,

    /// <summary>The TURN ChannelBind method (0x009), RFC 8656 section 18.</summary>
    ChannelBind = 0x009,
}
