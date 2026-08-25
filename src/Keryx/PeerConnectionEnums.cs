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

/// <summary>
/// The JSEP signaling state of a <see cref="PeerConnection"/> (RFC 8829 §3.2), mirroring
/// <c>RTCSignalingState</c>. Keryx produces and applies descriptions through
/// <see cref="PeerConnection.CreateOfferAsync(System.Threading.CancellationToken)"/> / <see cref="PeerConnection.CreateAnswerAsync"/> /
/// <see cref="PeerConnection.SetRemoteDescriptionAsync"/>; each moves the machine between these states.
/// There is deliberately no public <c>SetLocalDescription</c> (session-model.md §4.1).
/// </summary>
public enum SignalingState
{
    /// <summary>No offer/answer exchange is in progress; the last one (if any) completed.</summary>
    Stable,

    /// <summary>A local offer has been created and applied, awaiting the remote answer.</summary>
    HaveLocalOffer,

    /// <summary>A remote offer has been applied, awaiting the local answer.</summary>
    HaveRemoteOffer,

    /// <summary>The connection has been closed. Terminal.</summary>
    Closed,
}

/// <summary>Which half of the JSEP offer/answer exchange a session description is.</summary>
public enum SdpType
{
    /// <summary>An offer.</summary>
    Offer,

    /// <summary>An answer to a previously received offer.</summary>
    Answer,

    /// <summary>
    /// A rollback (JSEP §4.1.8.2, <c>RTCSdpType</c> <c>"rollback"</c>): discards a proposed-but-not-yet-
    /// answered remote offer and returns <see cref="SignalingState"/> to <see cref="SignalingState.Stable"/>.
    /// Passed to <see cref="PeerConnection.SetRemoteDescriptionAsync"/> to roll back a remote offer (a local
    /// offer is rolled back with <see cref="PeerConnection.Rollback"/>); the SDP text is ignored.
    /// </summary>
    Rollback,
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
