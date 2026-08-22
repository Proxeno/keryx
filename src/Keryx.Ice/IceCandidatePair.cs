using System.Net;

namespace Keryx.Ice;

/// <summary>
/// A local/remote candidate pair on an agent's check list, with the RFC 8445 section 6.1.2.3
/// pair priority that orders checks.
/// </summary>
public sealed class IceCandidatePair
{
    /// <summary>Creates a pair and computes its priority for <paramref name="role"/>.</summary>
    /// <param name="local">The local candidate.</param>
    /// <param name="remote">The remote candidate.</param>
    /// <param name="role">The local agent's role, which decides which priority is G and which is D.</param>
    public IceCandidatePair(IceCandidate local, IceCandidate remote, IceRole role)
    {
        ArgumentNullException.ThrowIfNull(local);
        ArgumentNullException.ThrowIfNull(remote);

        Local = local;
        Remote = remote;
        State = IceCandidatePairState.Waiting;
        RecomputePriority(role);
    }

    /// <summary>The local candidate.</summary>
    public IceCandidate Local { get; }

    /// <summary>The remote candidate.</summary>
    public IceCandidate Remote { get; }

    /// <summary>The pair priority; higher pairs are checked first.</summary>
    public ulong Priority { get; private set; }

    /// <summary>The pair's position in the check state machine.</summary>
    public IceCandidatePairState State { get; internal set; }

    /// <summary>True once the controlling agent has nominated this pair with USE-CANDIDATE.</summary>
    public bool Nominated { get; internal set; }

    /// <summary>The remote transport address checks and media are sent to.</summary>
    public IPEndPoint RemoteEndPoint => Remote.EndPoint;

    /// <summary>
    /// Set when a controlled agent has seen USE-CANDIDATE for this pair but its own check has not
    /// succeeded yet (RFC 8445 section 7.3.1.5).
    /// </summary>
    internal bool NominateOnSuccess { get; set; }

    /// <summary>The concatenation of the two foundations, used to group pairs (RFC 8445 section 6.1.2.6).</summary>
    internal string FoundationPair => $"{Local.Foundation}|{Remote.Foundation}";

    /// <summary>
    /// Recomputes <see cref="Priority"/> after a role change; a 487 role conflict re-orders the
    /// whole check list (RFC 8445 section 7.2.5.1).
    /// </summary>
    /// <param name="role">The local agent's role.</param>
    internal void RecomputePriority(IceRole role)
        => Priority = role == IceRole.Controlling
            ? IcePriority.ComputePair(Local.Priority, Remote.Priority)
            : IcePriority.ComputePair(Remote.Priority, Local.Priority);

    /// <inheritdoc />
    public override string ToString()
        => $"{Local.EndPoint} -> {Remote.EndPoint} ({Local.Type}/{Remote.Type}) prio={Priority} {State}{(Nominated ? " nominated" : string.Empty)}";
}
