# Keryx (PeerConnection) — design notes

The composition root: an `RTCPeerConnection`-shaped API that wires ICE, DTLS, SRTP, RTP/RTCP and
SCTP together. Everything below it is policy-free; this layer owns the policy.

## The connection driver

`SetRemoteDescriptionAsync(answer)` validates the answer with `SdpNegotiator`, applies remote ICE
credentials/candidates and then runs one background task through the sequence:

1. **DTLS before ICE finishes.** The `DtlsTransport` is constructed over a demux wrapper
   immediately; its first flight is buffered/retransmitted until ICE nominates a pair, closing the
   race between the first successful check and the peer's ClientHello.
2. ICE connected → DTLS handshake, with the role resolved from the answer's `a=setup` (browsers
   answer `active`, making Keryx the DTLS **server**) and the peer fingerprint pinned from
   `a=fingerprint`.
3. `ExportKeyingMaterial("EXTRACTOR-dtls_srtp")` → RFC 5764 §4.2 split → one SRTP context per
   direction covering every SSRC in the bundle. The exporter block is zeroed after the split.
4. SCTP over the DTLS application-data transport, with `IsInitiator`/`UsesEvenStreamIds` wired
   from the DTLS role per RFC 8832 §6. Channels created before negotiation are materialized here;
   their DCEP OPENs are the first DATA on the wire.
5. RTCP loop (SR + SDES each second per active track), state → Connected.

## Demux (RFC 7983 / RFC 5761)

The ICE transport surfaces all non-STUN traffic. First byte 20–63 → DTLS; 128–191 → RTP/SRTP,
with the RFC 5761 payload-type range picking SRTCP vs SRTP. SCTP is not demuxed here — it rides
inside DTLS application data.

## Hot path

`SendVideoFrame` packetizes straight into each track's single reusable datagram buffer
(payloadizer writes at the header offset, `SrtpEncryptContext.ProtectRtp` encrypts in place):
zero allocations per frame. Outbound media and RTCP share one send lock; inbound runs on the ICE
receive thread.

## Typed RTCP feedback

The founding feature: inbound SRTCP compound packets dispatch to `OnPictureLossIndication`,
`OnFullIntraRequest`, `OnNack` (bitmask pre-expanded), `OnTransportCcFeedback` and
`OnReceiverReport` (with LSR/DLSR round-trip arithmetic). `a=rtcp-fb` lines are emitted natively
from the codec configuration — `nack pli` and `ccm fir` by default for H.264, never bare `nack`.

## Honest limitations (current)

- No RTX/NACK retransmission (NACKs surface as events only — hence no bare `nack` offered).
- No bandwidth estimation, pacing, REMB generation, or `a=extmap` support (no outbound TWCC
  sequence numbers).
- The answerer role is minimal and recvonly — it exists to prove the stack against itself; the
  offerer path is the production shape. No renegotiation, no ICE restart.
- No jitter buffer on the receive surface; `OnRtpPacketReceived` is a raw seam.
- Inbound RTCP BYE is logged, not acted on.
