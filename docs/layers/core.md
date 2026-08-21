# Keryx.Core — design notes

The smallest layer, and deliberately boring: primitives every other layer builds on.

## Decisions

- **`ByteReader`/`ByteWriter` are `ref struct`s over caller-owned spans.** No allocation, no
  hidden growth; a writer that runs out of room throws `ByteBufferException`, same as a reader
  hitting truncated input. That single exception type is the stack-wide signal for
  "malformed/oversized wire data" and is distinct from `ArgumentOutOfRangeException`
  (programmer error, e.g. negative counts).
- **Big-endian only.** Every protocol in this stack is network byte order; the readers exist so
  no other file ever calls `BinaryPrimitives` directly with an endianness choice to get wrong.
- **`ByteWriter.Reserve`/`Patch`** exist because most wire formats (STUN, RTCP, SCTP, DTLS
  records) carry a length field that is only known after the body is written. `Patch` validates in
  64-bit arithmetic so adversarial windows cannot wrap the bounds check.
- **`IDatagramTransport`** is the inter-layer seam: unreliable, message-oriented, bidirectional.
  Contract points that matter: `OnReceived` may fire on arbitrary threads; the span passed to the
  handler is valid only for the duration of the call (copy to retain); `Send` is best-effort.
- **`IKeryxLogger`** instead of `Microsoft.Extensions.Logging` keeps the shipping libraries at
  zero NuGet dependencies. Hosts write a ~10-line adapter to their logger; `NullLogger` is the
  default everywhere.

## Testing

123 unit tests: every read/write width against hand-computed vectors, truncation at every
boundary, Reserve/Patch round-trips, logger semantics.
