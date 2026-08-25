using Keryx.Core;

namespace Keryx;

/// <content>
/// The JSEP signaling state machine (Epic D, PR 4). Replaces the historical <c>_isOfferer</c> bool with
/// a real <see cref="SignalingState"/> tracked on the existing create-offer / create-answer /
/// apply-offer / apply-answer methods — there is deliberately no public <c>SetLocalDescription</c>
/// (session-model.md §4.1). Adds <see cref="OnNegotiationNeeded"/>, raised (coalesced, only in
/// <see cref="SignalingState.Stable"/>) when the transceiver set changes in a way that requires
/// (re)negotiation. The machinery is shaped so PR 5 (renegotiation) and PR 6 (rollback) slot in without
/// a breaking change: the transitions already model the full JSEP state set and the negotiation-needed
/// slot is the JSEP <c>[[NegotiationNeeded]]</c> flag.
/// </content>
public sealed partial class PeerConnection
{
    /// <summary>
    /// The JSEP signaling state (RFC 8829 §3.2), reflecting where this connection is in the offer/answer
    /// exchange. Starts at <see cref="SignalingState.Stable"/> and returns there once each exchange
    /// completes; <see cref="SignalingState.Closed"/> after <see cref="CloseAsync"/>.
    /// </summary>
    public SignalingState SignalingState
    {
        get
        {
            lock (_lock)
            {
                return _signalingState;
            }
        }
    }

    /// <summary>
    /// Raised whenever <see cref="SignalingState"/> changes. Fired outside the connection lock, so a
    /// handler may read connection state; the terminal value is <see cref="SignalingState.Closed"/>.
    /// </summary>
    public event EventHandler<SignalingState>? OnSignalingStateChanged;

    /// <summary>
    /// Raised when the set of transceivers changes in a way that requires (re)negotiation — for example
    /// after <see cref="AddTransceiver"/> / <see cref="AddTrack"/> adds a track before the connection is
    /// negotiated (JSEP negotiation-needed, RFC 8829 §5.2, session-model.md §4.1). It is coalesced (one
    /// event covers a burst of changes) and only fires in <see cref="SignalingState.Stable"/>; a change
    /// made while an exchange is in flight is re-checked when the machine returns to
    /// <see cref="SignalingState.Stable"/>. In this release it signals intent — the driver still
    /// negotiates through the existing single-shot flow; the renegotiation flow lands in a later PR.
    /// </summary>
    public event EventHandler? OnNegotiationNeeded;

    /// <summary>Logs and raises <see cref="OnSignalingStateChanged"/>. Must be called with the lock released.</summary>
    private void RaiseSignalingStateChanged(SignalingState state)
    {
        _logger.Log(KeryxLogLevel.Debug, $"Signaling state: {state}.");
        OnSignalingStateChanged?.Invoke(this, state);
    }

    /// <summary>
    /// Clears the pending negotiation-needed intent once a local description that reflects the current
    /// transceiver set has been applied (session-model.md §4.1). Must be called while holding the lock.
    /// </summary>
    private void MarkLocalDescriptionAppliedLocked()
    {
        foreach (var transceiver in _transceivers)
        {
            transceiver.NegotiationPending = false;
        }

        _negotiationNeeded = false;
    }

    /// <summary>
    /// Runs the JSEP negotiation-needed check (RFC 8829 §5.2, session-model.md §4.1): if any non-stopped
    /// transceiver is still pending negotiation and the machine is <see cref="SignalingState.Stable"/>,
    /// raise <see cref="OnNegotiationNeeded"/> — but only once per pending change set (the
    /// <c>[[NegotiationNeeded]]</c> slot coalesces bursts). A change made while an exchange is in flight
    /// is deferred; the caller re-invokes this when the machine returns to Stable. A no-op change (nothing
    /// pending) neither raises the event nor leaves the slot set. The event is raised with the lock
    /// released so a handler may call back into the connection.
    /// </summary>
    private void UpdateNegotiationNeeded()
    {
        bool fire;
        lock (_lock)
        {
            if (_closed != 0 || _signalingState != SignalingState.Stable)
            {
                return;
            }

            var needed = false;
            foreach (var transceiver in _transceivers)
            {
                if (!transceiver.Stopped && transceiver.NegotiationPending)
                {
                    needed = true;
                    break;
                }
            }

            if (!needed)
            {
                _negotiationNeeded = false;
                return;
            }

            if (_negotiationNeeded)
            {
                // Already signalled for this pending change set — coalesce.
                return;
            }

            _negotiationNeeded = true;
            fire = true;
        }

        if (fire)
        {
            OnNegotiationNeeded?.Invoke(this, EventArgs.Empty);
        }
    }
}
