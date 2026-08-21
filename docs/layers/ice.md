# Keryx.Ice — design notes

A full (not ice-lite) RFC 8445 agent scoped to what a single-BUNDLE, rtcp-mux WebRTC session
needs: one UDP socket, component 1, host + server-reflexive candidates.

## Decisions

- **One socket per agent.** BUNDLE means media, RTCP and data all share it. The agent consumes
  STUN internally (via `LooksLikeStun`) and surfaces every other packet — DTLS from the very first
  one — through the `IDatagramTransport` it exposes for the selected pair.
- Candidate strings parse/format Chrome's exact syntax, tolerating and ignoring trailing key-value
  extensions (`generation`, `network-cost`, ...), including `raddr`/`rport` for srflx.
- Connectivity checks per RFC 8445: pair priority formula (validated against real Chrome values),
  triggered checks, role-conflict resolution in both directions (ICE-CONTROLLING/ICE-CONTROLLED +
  487), peer-reflexive discovery from integrity-valid checks from unknown sources, keepalives on
  the selected pair, and a consent-style timeout driving Disconnected/Failed.

## Simplifications (documented, deliberate)

- **Aggressive nomination** (USE-CANDIDATE on every check as controlling) rather than regular
  nomination.
- IPv4-only pairing; srflx via STUN only (no TURN, no relay candidates); no candidate-pair
  freezing; one local socket means one pair per remote candidate; component 1 only.
- No SASLprep on credentials (ASCII in practice; inherited from Keryx.Stun).

## Testing

48 tests, including a real two-agent UDP loopback: gather, exchange credentials/candidates,
connect, and pass datagrams both directions over the exposed transport; role-conflict and
priority-math suites.
