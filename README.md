# Keryx

A from-scratch WebRTC stack for .NET. No native dependencies, no third-party protocol libraries:
STUN, ICE, SDP, RTP/RTCP, DTLS 1.2, SRTP and SCTP are implemented in this repository against the
RFCs, with cryptographic primitives supplied exclusively by `System.Security.Cryptography`.

> **Status: pre-release (0.x), under active development.** APIs will change. See
> [Verification status](#verification-status) for an honest statement of what works today.

## Why

Keryx exists because shipping WebRTC from a .NET server currently means choosing between native
wrappers or libraries whose licenses or API surfaces don't fit an Apache-2.0 product. Keryx is
Apache-2.0 from the first commit and treats the pain points we hit in production as first-class
API requirements, for example:

- **Typed RTCP feedback.** PLI, FIR, NACK and transport-cc arrive as dedicated events, and
  `a=rtcp-fb` lines are emitted natively per negotiated codec — no SDP string-splicing between
  `createOffer` and `setLocalDescription`, no parsing raw compound RTCP packets in application code.
- **A codec-agnostic packetizer seam.** H.264 (packetization-mode=1, STAP-A/FU-A) and Opus ship
  in-box; community codecs implement one interface.
- **Layered, independently testable packages.** Each protocol layer is its own NuGet package with
  no upward dependencies; `Keryx` composes them into an `RTCPeerConnection`-style API.

## Packages

| Package | Contents |
| --- | --- |
| `Keryx` | Composition root: the peer connection API. Reference this to get the whole stack. |
| `Keryx.Core` | Binary readers/writers, transport + logging abstractions. |
| `Keryx.Stun` | STUN (RFC 5389) messages and client. |
| `Keryx.Sdp` | SDP / JSEP offer-answer subset. |
| `Keryx.Rtp` | RTP, RTCP, typed feedback, H.264/Opus packetizers. |
| `Keryx.Dtls` | DTLS 1.2 handshake + record layer, DTLS-SRTP keying export. |
| `Keryx.Srtp` | SRTP/SRTCP protection (RFC 3711). |
| `Keryx.Ice` | ICE agent (RFC 8445 subset). |
| `Keryx.Sctp` | SCTP over DTLS + data channels (DCEP). |

## Security

The DTLS implementation is written for correctness against RFC 6347 and validates the full
handshake (CertificateVerify, Finished MAC, certificate fingerprint against the SDP
`a=fingerprint`), but it has **not yet received an independent security review**. Do not deploy it
in production until it has. Cipher primitives (AES-GCM, AES-CTR, HMAC, ECDHE, X.509) are the
platform's, never hand-rolled.

## Verification status

Updated as the stack lands; claims here are backed by tests in this repository.

- [ ] RFC test vectors: STUN (RFC 5769), SRTP (RFC 3711), SCTP CRC32c, RTP header edge cases
- [ ] Loopback integration: Keryx-to-Keryx over real UDP (ICE, DTLS, SRTP media, data channels)
- [ ] Chrome interop: headless Chrome negotiates with Keryx, decodes Keryx-sent H.264, data channel round-trips
- [ ] Benchmarks vs SIPSorcery (see `bench/`)

## License

Apache-2.0. See [LICENSE](LICENSE).
