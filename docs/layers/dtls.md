# Keryx.Dtls — design notes

DTLS 1.2 (RFC 6347) for WebRTC: the handshake state machine, record layer and DTLS-SRTP keying
export, written from scratch against the RFCs with all cryptographic primitives supplied by
`System.Security.Cryptography`.

> ## ⚠ Security-review status
> **This implementation has NOT received an independent security review.** It is
> correctness-focused and verifies everything the RFCs require (see below), but do not deploy it
> to production until it has been reviewed. See `SECURITY.md` at the repository root.

## What it implements

- Record layer with epochs, 48-bit sequence numbers, the RFC 6347 anti-replay window, silent
  discard of undecryptable records, multiple records per datagram, and AES-128-GCM protection
  (RFC 5288 nonce/AAD construction).
- Cipher suites: `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (what Chrome negotiates against our
  P-256 certificate); ECDHE on P-256.
- Full handshake in both roles (server is the common case: Keryx offers `setup:actpass`, browsers
  answer `active`). Mutual authentication: CertificateRequest is sent, and the peer's
  **CertificateVerify signature over the handshake transcript is verified**, as is the
  **Finished verify_data** — both are hard failures on mismatch.
- Extended master secret (RFC 7627) when the peer offers it (BoringSSL does), renegotiation_info,
  handshake fragmentation/reassembly with out-of-order buffering, flight retransmission with
  exponential backoff.
- use_srtp (RFC 5764) negotiation and the RFC 5705 exporter
  (`EXTRACTOR-dtls_srtp`) for SRTP keying material.
- **Fingerprint pinning:** the WebRTC trust anchor. `DtlsConfig.ExpectedRemoteFingerprintSha256`
  (from the remote SDP `a=fingerprint`) is checked during the handshake; mismatch aborts with
  `bad_certificate`. Self-signed peer certificates are otherwise accepted, per the WebRTC model.
- `DtlsCertificate.GenerateSelfSigned()`: ECDSA P-256 via `CertificateRequest`, with the SDP-ready
  SHA-256 fingerprint string.

## Decisions and simplifications

- **No HelloVerifyRequest/cookie exchange as server.** ICE has already validated the peer address
  by the time DTLS starts, which is why WebRTC stacks (including BoringSSL peers) skip it.
- TLS 1.2 PRF (P_SHA256) implemented once and tested against published vectors; both classic and
  extended-master-secret key schedules use it, as does the exporter.
- No session resumption, no renegotiation, no DTLS 1.0 compatibility, no RSA key exchange.
- Not constant-time beyond what the BCL primitives provide; handshake-path comparisons that guard
  secrets use `CryptographicOperations.FixedTimeEquals`.

## Testing

96 tests: PRF vectors and key-schedule seed-order/label assertions, ECDHE point validation,
record round-trips, replay-window unit tests, fragmentation/reassembly (including the pathological
one-byte-fragment CPU case and the slot-exhaustion case), and a full client↔server loopback suite
over in-memory transports — including lossy transports (first flight dropped each direction, heavy
uniform loss), tampered Finished/CertificateVerify, wrong and blank pinned fingerprint (both roles),
replayed records, exporter equality on both sides, timeout behavior, and an adversarial suite
(DTLS 1.0 downgrade, injected/duplicate ClientHello, forged epoch-0 records). The structured
internal security review that produced the adversarial suite is written up in `../../SECURITY-REVIEW.md`.
