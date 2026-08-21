namespace Keryx.Dtls;

/// <summary>Severity of a TLS/DTLS alert (RFC 5246 §7.2).</summary>
public enum DtlsAlertLevel : byte
{
    /// <summary>Advisory; the connection may continue.</summary>
    Warning = 1,

    /// <summary>The connection is torn down immediately.</summary>
    Fatal = 2,
}

/// <summary>Alert descriptions defined by RFC 5246 §7.2 and RFC 7627.</summary>
public enum DtlsAlertDescription : byte
{
    /// <summary>The sender will not send any more data on this connection.</summary>
    CloseNotify = 0,

    /// <summary>An inappropriate message was received.</summary>
    UnexpectedMessage = 10,

    /// <summary>A record failed its integrity check.</summary>
    BadRecordMac = 20,

    /// <summary>A message could not be decoded.</summary>
    DecodeError = 50,

    /// <summary>A cryptographic operation failed (for example a signature did not verify).</summary>
    DecryptError = 51,

    /// <summary>The peer's protocol version is not supported.</summary>
    ProtocolVersion = 70,

    /// <summary>No cipher suite, curve or signature algorithm in common.</summary>
    HandshakeFailure = 40,

    /// <summary>The peer certificate was corrupt or failed the expected-fingerprint check.</summary>
    BadCertificate = 42,

    /// <summary>The peer did not provide a certificate when one was required.</summary>
    CertificateRequired = 116,

    /// <summary>An internal error unrelated to the peer or protocol.</summary>
    InternalError = 80,

    /// <summary>The handshake did not conform to a negotiated extension (RFC 7627).</summary>
    IllegalParameter = 47,

    /// <summary>An extension was sent that the sender does not support.</summary>
    UnsupportedExtension = 110,

    /// <summary>The peer requires a feature that is not enabled.</summary>
    InsufficientSecurity = 71,

    /// <summary>A user cancelled the handshake.</summary>
    UserCanceled = 90,

    /// <summary>Renegotiation was refused.</summary>
    NoRenegotiation = 100,
}

/// <summary>Raised when a DTLS connection fails, either locally or because of a peer alert.</summary>
public sealed class DtlsException : Exception
{
    /// <summary>Creates an exception with a message and no associated alert.</summary>
    /// <param name="message">Human-readable failure description.</param>
    public DtlsException(string message)
        : base(message)
    {
    }

    /// <summary>Creates an exception with a message and an inner cause.</summary>
    /// <param name="message">Human-readable failure description.</param>
    /// <param name="innerException">The underlying cause.</param>
    public DtlsException(string message, Exception? innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates an exception carrying the alert that describes (or caused) the failure.</summary>
    /// <param name="message">Human-readable failure description.</param>
    /// <param name="alert">The alert sent to, or received from, the peer.</param>
    /// <param name="fromPeer">True when the alert was received rather than generated locally.</param>
    public DtlsException(string message, DtlsAlertDescription alert, bool fromPeer = false)
        : base(message)
    {
        Alert = alert;
        AlertFromPeer = fromPeer;
    }

    /// <summary>Creates an exception carrying an alert and an inner cause.</summary>
    /// <param name="message">Human-readable failure description.</param>
    /// <param name="alert">The alert sent to, or received from, the peer.</param>
    /// <param name="innerException">The underlying cause.</param>
    public DtlsException(string message, DtlsAlertDescription alert, Exception? innerException)
        : base(message, innerException)
    {
        Alert = alert;
    }

    /// <summary>The alert associated with the failure, if any.</summary>
    public DtlsAlertDescription? Alert { get; }

    /// <summary>True when <see cref="Alert"/> was received from the peer rather than generated locally.</summary>
    public bool AlertFromPeer { get; }
}
