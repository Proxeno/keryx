using Keryx.Core;
using Keryx.Dtls;
using Keryx.Sdp;

namespace Keryx;

/// <content>
/// The JSEP signaling state machine (Epic D, PR 4). Replaces the historical <c>_isOfferer</c> bool with
/// a real <see cref="SignalingState"/> tracked on the existing create-offer / create-answer /
/// apply-offer / apply-answer methods — there is deliberately no public <c>SetLocalDescription</c>
/// (session-model.md §4.1). Adds <see cref="OnNegotiationNeeded"/>, raised (coalesced, only in
/// <see cref="SignalingState.Stable"/>) when the transceiver set changes in a way that requires
/// (re)negotiation. Epic D PR 6 completes the machine with rollback (JSEP §4.1.8.2, session-model.md §4.4):
/// <see cref="PeerConnection.Rollback"/> discards a pending local offer and <see cref="SetRemoteDescriptionAsync"/>
/// with <see cref="SdpType.Rollback"/> discards a pending remote offer, each restoring the last-stable
/// transceiver set from <see cref="_rollbackSnapshot"/>; the same restore resolves glare (a remote offer
/// arriving in <see cref="SignalingState.HaveLocalOffer"/>).
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

    /// <summary>
    /// Rolls back a proposed-but-not-yet-answered <b>local</b> offer (JSEP §4.1.8.2, session-model.md §4.4):
    /// discards the pending offer, returns <see cref="SignalingState"/> to <see cref="SignalingState.Stable"/>,
    /// and restores the transceiver set to its pre-offer shape — a provisionally assigned <c>a=mid</c> is
    /// reverted to null and each transceiver's <see cref="RtpTransceiver.Direction"/> and pending-negotiation
    /// state are restored. Application-added transceivers are kept (they revert to not-yet-negotiated); a
    /// transceiver auto-created only to satisfy the rolled-back offer would be dropped. No SRTP or transport
    /// work happens until an answer is applied, so a rollback before <see cref="SignalingState.Stable"/> has
    /// nothing to tear down. Roll a pending <b>remote</b> offer back with
    /// <see cref="SetRemoteDescriptionAsync"/> and <see cref="SdpType.Rollback"/> instead.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The connection is closed.</exception>
    /// <exception cref="InvalidOperationException">
    /// No local offer is pending — a rollback is only valid from <see cref="SignalingState.HaveLocalOffer"/>
    /// (JSEP rejects a rollback from any other state).
    /// </exception>
    public void Rollback()
    {
        ObjectDisposedException.ThrowIf(_closed != 0, this);

        lock (_lock)
        {
            if (_signalingState != SignalingState.HaveLocalOffer)
            {
                throw new InvalidOperationException(
                    $"Cannot roll back in the {_signalingState} state; a local offer must be pending. "
                    + "Roll a pending remote offer back with SetRemoteDescriptionAsync(rollback).");
            }

            RollbackToStableLocked();
        }

        RaiseSignalingStateChanged(SignalingState.Stable);

        // A rolled-back offer leaves any application-added transceiver pending again, so re-run the
        // negotiation-needed check (session-model.md §4.1): the app still needs to (re)negotiate them.
        UpdateNegotiationNeeded();
    }

    /// <summary>
    /// Rolls back a pending <b>remote</b> offer (the <see cref="SdpType.Rollback"/> path of
    /// <see cref="SetRemoteDescriptionAsync"/>, session-model.md §4.4): discards the offer applied by the
    /// last <see cref="SetRemoteDescriptionAsync"/>, returns to <see cref="SignalingState.Stable"/>, drops
    /// any transceiver auto-created for one of the offered m-lines, and reverts the provisional mid /
    /// direction of the transceivers the offer bound. Only valid from
    /// <see cref="SignalingState.HaveRemoteOffer"/>.
    /// </summary>
    private Task RollbackRemoteOffer()
    {
        lock (_lock)
        {
            if (_signalingState != SignalingState.HaveRemoteOffer)
            {
                throw new InvalidOperationException(
                    $"Cannot roll back a remote offer in the {_signalingState} state; a remote offer must be pending. "
                    + "Roll a pending local offer back with Rollback().");
            }

            RollbackToStableLocked();
        }

        RaiseSignalingStateChanged(SignalingState.Stable);
        UpdateNegotiationNeeded();
        return Task.CompletedTask;
    }

    /// <summary>
    /// Restores the last-stable state captured in <see cref="_rollbackSnapshot"/> and returns the machine to
    /// <see cref="SignalingState.Stable"/> (session-model.md §4.4). Must be called while holding the lock and
    /// only from a pending state, where the snapshot is non-null. Restores the descriptions, the o= version,
    /// the remote fingerprint / DTLS role / SCTP port, the inbound route tables, and the transceiver set:
    /// transceivers auto-created by the rolled-back offer are dropped, and every surviving transceiver's
    /// provisional mid, direction and pending-negotiation flag are reverted. The single BUNDLE transport,
    /// DTLS and SRTP context are untouched (there was none to change before an answer).
    /// </summary>
    private void RollbackToStableLocked()
    {
        if (_rollbackSnapshot is not { } snapshot)
        {
            // Defensive: a pending state always carries a snapshot. Nothing to restore, so just settle.
            _signalingState = SignalingState.Stable;
            return;
        }

        _localDescription = snapshot.LocalDescription;
        _remoteDescription = snapshot.RemoteDescription;
        Interlocked.Exchange(ref _sessionVersion, snapshot.SessionVersion);
        _remoteFingerprint = snapshot.RemoteFingerprint;
        _dtlsRole = snapshot.DtlsRole;
        _remoteSctpPort = snapshot.RemoteSctpPort;
        Volatile.Write(ref _routeTable, snapshot.RouteTable);
        Volatile.Write(ref _rtxSsrcToMediaSsrc, snapshot.RtxSsrcToMediaSsrc);
        Volatile.Write(ref _simulcastByMid, snapshot.SimulcastByMid);

        // Rebuild the transceiver set to exactly the pre-offer members (dropping any auto-created for the
        // rolled-back offer), each with its pre-offer provisional mid, direction and pending flag restored.
        RestoreTransceiversLocked(snapshot.Transceivers);

        _signalingState = SignalingState.Stable;
        _rollbackSnapshot = null;
    }

    /// <summary>
    /// Captures the state that a rollback must be able to restore (session-model.md §4.4). Called under the
    /// lock at the moment the machine leaves <see cref="SignalingState.Stable"/> for a pending offer, before
    /// that offer mutates any of it.
    /// </summary>
    private SignalingSnapshot CaptureStableSnapshotLocked()
    {
        var transceivers = new List<TransceiverSnapshot>(_transceivers.Count);
        foreach (var transceiver in _transceivers)
        {
            transceivers.Add(new TransceiverSnapshot(
                transceiver,
                transceiver.Mid,
                transceiver.Direction,
                transceiver.NegotiationPending));
        }

        return new SignalingSnapshot(
            _localDescription,
            _remoteDescription,
            Interlocked.Read(ref _sessionVersion),
            _remoteFingerprint,
            _dtlsRole,
            _remoteSctpPort,
            Volatile.Read(ref _routeTable),
            Volatile.Read(ref _rtxSsrcToMediaSsrc),
            Volatile.Read(ref _simulcastByMid),
            transceivers);
    }

    /// <summary>The connection lock, exposed so a <see cref="RtpTransceiver"/> can serialise its own
    /// state transitions (e.g. <see cref="RtpTransceiver.Stop"/>) against the negotiation machinery.</summary>
    internal object NegotiationLock => _lock;

    /// <summary>Re-runs the negotiation-needed check after a transceiver dirties the set (e.g. a
    /// <see cref="RtpTransceiver.Stop"/>); raises <see cref="OnNegotiationNeeded"/> when appropriate.</summary>
    internal void RaiseNegotiationNeeded() => UpdateNegotiationNeeded();

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
                // A transceiver is pending whenever its current state (added, or stopped) is not yet
                // reflected in a generated local description — a stop needs a renegotiation just as an
                // add does, to re-emit the slot as a rejected section (session-model.md §4.2).
                if (transceiver.NegotiationPending)
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

    /// <summary>
    /// The last-stable state a rollback restores (session-model.md §4.4): the applied descriptions, the o=
    /// version, the remote fingerprint / DTLS role / SCTP port, the inbound route tables, and a per-member
    /// snapshot of the transceiver set (the members themselves plus their provisional mid, direction and
    /// pending-negotiation flag). Route-table and rtx/simulcast maps are captured by reference — they are
    /// swapped whole, never mutated in place, so the captured reference stays a valid immutable value.
    /// </summary>
    private sealed record SignalingSnapshot(
        SessionDescription? LocalDescription,
        SessionDescription? RemoteDescription,
        long SessionVersion,
        SdpFingerprint? RemoteFingerprint,
        DtlsRole DtlsRole,
        int? RemoteSctpPort,
        RouteTable RouteTable,
        Dictionary<uint, uint> RtxSsrcToMediaSsrc,
        Dictionary<string, SimulcastReceiveTracker> SimulcastByMid,
        List<TransceiverSnapshot> Transceivers);

    /// <summary>
    /// A single transceiver's pre-offer state (session-model.md §4.4). Only the fields a pending offer can
    /// mutate before it is answered are captured: the provisional <c>a=mid</c>, the desired direction, and
    /// the pending-negotiation flag. The negotiated codec, current direction and wired sender are settled
    /// only by an answer — which ends the rollback window — so they are never in flight here.
    /// </summary>
    private sealed record TransceiverSnapshot(
        RtpTransceiver Transceiver,
        string? Mid,
        MediaDirection Direction,
        bool NegotiationPending);
}
