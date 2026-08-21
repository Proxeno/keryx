namespace Keryx;

/// <summary>
/// The lifecycle of a <see cref="PeerConnection"/>, mirroring <c>RTCPeerConnectionState</c>.
/// </summary>
public enum PeerConnectionState
{
    /// <summary>Constructed. No description has been exchanged and no transport is running.</summary>
    New,

    /// <summary>A remote description has been applied and the ICE/DTLS/SCTP sequence is running.</summary>
    Connecting,

    /// <summary>ICE and DTLS are up; media and data may flow.</summary>
    Connected,

    /// <summary>The selected ICE pair has gone quiet but has not yet timed out for good.</summary>
    Disconnected,

    /// <summary>The connection cannot be established or has been torn down by an error.</summary>
    Failed,

    /// <summary><see cref="PeerConnection.CloseAsync"/> has completed. Terminal.</summary>
    Closed,
}

/// <summary>Which half of the JSEP offer/answer exchange a session description is.</summary>
public enum SdpType
{
    /// <summary>An offer.</summary>
    Offer,

    /// <summary>An answer to a previously received offer.</summary>
    Answer,
}

/// <summary>The kind of media an m-section carries.</summary>
public enum MediaKind
{
    /// <summary>The m-section carries no recognised media (an unmatched payload type).</summary>
    Unknown,

    /// <summary>An <c>m=audio</c> section.</summary>
    Audio,

    /// <summary>An <c>m=video</c> section.</summary>
    Video,

    /// <summary>An <c>m=application</c> (SCTP data channel) section.</summary>
    Application,
}
