namespace Keryx.Sdp;

/// <summary>
/// Raised when an SDP document violates a rule Keryx enforces, for example an answer whose
/// m-sections do not line up with the offer. The parser itself never throws this: it is tolerant by
/// design and skips anything it cannot interpret.
/// </summary>
public sealed class SdpException : Exception
{
    /// <summary>Creates an exception with no message.</summary>
    public SdpException()
    {
    }

    /// <summary>Creates an exception with a message.</summary>
    /// <param name="message">Description of the violation.</param>
    public SdpException(string message)
        : base(message)
    {
    }

    /// <summary>Creates an exception with a message and an underlying cause.</summary>
    /// <param name="message">Description of the violation.</param>
    /// <param name="innerException">The underlying cause.</param>
    public SdpException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
