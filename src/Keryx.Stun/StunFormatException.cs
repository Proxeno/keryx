namespace Keryx.Stun;

/// <summary>
/// Thrown when a byte sequence is well-sized but is not a structurally valid STUN message
/// (bad magic cookie, misaligned length, unknown message class, and so on).
/// </summary>
/// <remarks>
/// Truncation is reported as <see cref="Keryx.Core.ByteBufferException"/> instead; both are caught
/// by <see cref="StunMessage.TryDecode"/>.
/// </remarks>
public sealed class StunFormatException : Exception
{
    /// <summary>Creates the exception with a human-readable description of the violated rule.</summary>
    public StunFormatException(string message)
        : base(message)
    {
    }
}

/// <summary>Thrown when a STUN transaction receives no response within its retransmission budget.</summary>
public sealed class StunTimeoutException : Exception
{
    /// <summary>Creates the exception with a human-readable description of the transaction that timed out.</summary>
    public StunTimeoutException(string message)
        : base(message)
    {
    }
}

/// <summary>Thrown when a STUN server answers a request with an error response.</summary>
public sealed class StunErrorResponseException : Exception
{
    /// <summary>Creates the exception from the received ERROR-CODE attribute.</summary>
    /// <param name="code">The error code.</param>
    /// <param name="reason">The reason phrase.</param>
    public StunErrorResponseException(int code, string reason)
        : base($"STUN error response {code} {reason}")
    {
        Code = code;
        Reason = reason;
    }

    /// <summary>The error code, for example 401 or 487.</summary>
    public int Code { get; }

    /// <summary>The reason phrase.</summary>
    public string Reason { get; }
}
