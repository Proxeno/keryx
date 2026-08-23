# Keryx.Sctp — design notes

SCTP over DTLS (RFC 8831) with DCEP (RFC 8832): the data-channel layer, sized for WebRTC rather
than for kernel-grade SCTP.

## Decisions

- Chunk set: INIT/INIT-ACK, COOKIE-ECHO/ACK (self-contained HMAC-protected cookie), DATA, SACK
  (gap blocks + dup TSNs), HEARTBEAT(-ACK), ABORT, SHUTDOWN family, ERROR, and
  **FORWARD-TSN (RFC 3758)** — partial reliability is load-bearing here: `maxRetransmits: 0`
  channels (game controller input) send once and abandon, and the association must stay healthy.
- CRC32c implemented by hand (table-driven) — `System.IO.Hashing` is a NuGet package and shipping
  libraries take none.
- Reliability: T3-rtx with RFC 6298-style RTT estimation, fast retransmit, peer a_rwnd respected,
  fragmentation/reassembly (B/E flags) for messages beyond the DTLS MTU, ordered delivery per
  stream SSN, unordered (U=1) bypass.
- DCEP: DATA_CHANNEL_OPEN/ACK with the full channel-type matrix (reliable/partial-reliable ×
  ordered/unordered), label/protocol, and the RFC 8832 stream-parity rule (DTLS client side uses
  even stream ids — wired from the resolved DTLS role, since Keryx is usually the DTLS *server*).
  Channels can be created before the association exists (queued, opened on establish), matching
  how an offerer sets up channels before negotiation.
- Browser-shaped surface: `SctpAssociation` + `DataChannel` (`OnOpen`, `OnMessage(isBinary,
  payload)`, `BufferedAmount`, `Send`/`SendText`).

## Simplifications (documented, deliberate)

- Congestion control is honest-but-simplified slow start/congestion avoidance, not a tuned stack.
- INIT collision handled for the simple case only (our deployments have a known initiator).

## Stream reset (RFC 6525 RE-CONFIG)

- Advertised in INIT/INIT-ACK via the Supported Extensions parameter (chunk type 130) and
  negotiated per association; a reset is only driven when the peer advertised it too.
- Closing a `DataChannel` drives an outgoing RE-CONFIG carrying an Outgoing SSN Reset Request for
  its stream once that stream's data has been acknowledged (queued behind in-flight data, one
  request outstanding at a time). The identifier is freed on the Re-configuration Response and
  reused by the next channel, so a long-lived peer that opens/closes many channels does not
  exhaust the id space.
- A peer-initiated reset resets the matching incoming stream, closes the mirror channel, and is
  answered with a Re-configuration Response; a request whose Sender's Last Assigned TSN has not yet
  been received is deferred until it has.

## Testing

58 tests: CRC32c check vectors (cited), codec round-trips for every chunk incl. padding rules and
the RE-CONFIG parameters, DCEP byte vectors, and loopback association suites over in-memory
transports: fragmentation (large messages), unordered delivery under reordering, maxRetransmits=0
abandonment under loss with continued flow (FORWARD-TSN), reliable delivery through drops,
shutdown/abort, and stream reset (RE-CONFIG advertised in INIT, channels closed then their ids
reused, peer-initiated reset answered).
