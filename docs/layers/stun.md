# Keryx.Stun — design notes

RFC 5389 STUN messages plus the small client ICE needs.

## Decisions

- **Attribute model:** typed classes for the attributes WebRTC exercises (XOR-MAPPED-ADDRESS v4/v6,
  MESSAGE-INTEGRITY, FINGERPRINT, ERROR-CODE, USERNAME, PRIORITY, USE-CANDIDATE,
  ICE-CONTROLLING/ICE-CONTROLLED, SOFTWARE, UNKNOWN-ATTRIBUTES); anything else is preserved raw so
  unknown attributes round-trip.
- **The dummy-length rule** (the classic STUN implementation trap): MESSAGE-INTEGRITY and
  FINGERPRINT are computed over the message with the header length field temporarily set to cover
  up to and including the attribute being computed. Implemented once, used on both the encode and
  validate paths, and locked in by the RFC 5769 vectors.
- **`LooksLikeStun`** classifier (first two bits zero + magic cookie + sane length) is the demux
  primitive the ICE agent uses to split STUN from DTLS/RTP on the shared socket (RFC 7983).
- **`StunClient` is socket-agnostic:** it is given a way to send and is fed received datagrams, so
  ICE can run it over the same socket it gathers host candidates on. A convenience overload owns a
  `UdpClient` for standalone use. Retransmission follows RFC 5389 §7.2.1 (RTO doubling).

## Simplifications

- No SASLprep (RFC 5389 §15.4): ice-ufrag/pwd from browsers are ASCII; documented as a gap.
- Long-term credentials implement exactly enough (MD5 key derivation) to pass the RFC 5769 §2.4
  vector; there is no 401/nonce retry dance (not needed without TURN).

## Testing

42 tests. All four RFC 5769 vectors (§2.1, §2.2, §2.3, §2.4) parse AND re-encode byte-exactly;
round-trips; truncation rejection.
