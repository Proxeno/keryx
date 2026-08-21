namespace Keryx.Dtls;

/// <summary>Which side of the DTLS handshake this endpoint plays.</summary>
/// <remarks>
/// In WebRTC the roles come from the SDP <c>a=setup</c> attribute: <c>setup:active</c> is the DTLS
/// client (it sends the ClientHello) and <c>setup:passive</c> is the DTLS server. An offerer that
/// signals <c>setup:actpass</c> becomes the server once the answerer picks <c>setup:active</c>.
/// </remarks>
public enum DtlsRole
{
    /// <summary>Sends the ClientHello and drives the handshake (SDP <c>a=setup:active</c>).</summary>
    Client,

    /// <summary>Waits for a ClientHello (SDP <c>a=setup:passive</c> / <c>actpass</c>).</summary>
    Server,
}

/// <summary>Lifecycle of a <see cref="DtlsTransport"/>.</summary>
public enum DtlsTransportState
{
    /// <summary>Constructed; the handshake has not been started.</summary>
    New,

    /// <summary>The handshake is in progress.</summary>
    Connecting,

    /// <summary>The handshake completed; application data may flow.</summary>
    Connected,

    /// <summary>Closed cleanly (a <c>close_notify</c> was sent or received).</summary>
    Closed,

    /// <summary>Torn down by a fatal alert, a verification failure, or a timeout.</summary>
    Failed,
}
