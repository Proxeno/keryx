namespace Keryx.Core;

/// <summary>
/// Thrown when a read or write would fall outside a packet buffer's bounds — for reads, the
/// signal that a received packet is truncated or malformed.
/// </summary>
public sealed class ByteBufferException : Exception
{
    /// <summary>Creates the exception with a human-readable description of the violated bound.</summary>
    public ByteBufferException(string message)
        : base(message)
    {
    }
}
