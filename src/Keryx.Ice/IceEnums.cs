namespace Keryx.Ice;

/// <summary>Which of the two ICE agents drives nomination (RFC 8445 section 6.1.1).</summary>
public enum IceRole
{
    /// <summary>The agent nominates the pair to use. In WebRTC this is the offerer.</summary>
    Controlling,

    /// <summary>The agent waits to be told which pair was nominated.</summary>
    Controlled,
}

/// <summary>How a candidate's transport address was learned (RFC 8445 section 5.1.1).</summary>
public enum IceCandidateType
{
    /// <summary>A local interface address; SDP token <c>host</c>.</summary>
    Host,

    /// <summary>A reflexive address learned from a STUN server; SDP token <c>srflx</c>.</summary>
    ServerReflexive,

    /// <summary>A reflexive address learned from a peer's connectivity check; SDP token <c>prflx</c>.</summary>
    PeerReflexive,

    /// <summary>An address allocated on a TURN relay; SDP token <c>relay</c>.</summary>
    Relayed,
}

/// <summary>The lifecycle of an <see cref="IceAgent"/>.</summary>
public enum IceAgentState
{
    /// <summary>Created; gathering has not started.</summary>
    New,

    /// <summary>Binding the socket and collecting local candidates.</summary>
    Gathering,

    /// <summary>Running connectivity checks; no pair has succeeded yet.</summary>
    Checking,

    /// <summary>At least one pair has succeeded and the transport is usable.</summary>
    Connected,

    /// <summary>The selected pair has stopped answering but has not yet timed out for good.</summary>
    Disconnected,

    /// <summary>No pair can be used and none is expected to become usable.</summary>
    Failed,

    /// <summary>The agent has been closed; its socket is shut and no events will follow.</summary>
    Closed,
}

/// <summary>The state of a candidate pair in the check list (RFC 8445 section 6.1.2.6).</summary>
public enum IceCandidatePairState
{
    /// <summary>Not yet eligible to be checked.</summary>
    Frozen,

    /// <summary>Eligible to be checked and waiting its turn.</summary>
    Waiting,

    /// <summary>A check has been sent and no response has arrived yet.</summary>
    InProgress,

    /// <summary>A check produced a valid success response; the pair is usable.</summary>
    Succeeded,

    /// <summary>The check was answered with an error or exhausted its retransmissions.</summary>
    Failed,
}
