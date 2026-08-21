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
from the codec configuration — `nack`, `nack pli` and `ccm fir` by default for H.264.
`SendPictureLossIndication`, `SendFullIntraRequest` and `SendNack` cover the other direction.

## Retransmission (RFC 4588)

Video is offered with bare `nack` and, per video codec, a generated `rtx` entry on the next free
dynamic payload type; a second SSRC is published through `a=ssrc-group:FID` under the same cname.
The configured `SdpCodec` list is copied, never mutated, so building an offer twice is idempotent.

RTX is treated as negotiated **only** when the answer keeps an `rtx` codec whose `apt` names the
media codec that was chosen. An answer that echoes bare `nack` but drops `rtx` disables
retransmission: resending on the media SSRC would corrupt its sequence numbering, so Keryx does
nothing rather than something wrong.

Once negotiated, each video packet is captured into an `RtpSendHistory` *before*
`ProtectRtp` encrypts the same buffer in place. An inbound Generic NACK is expanded entry by entry
on the ICE receive loop and served under the send lock — the same lock `SendVideoFrame` takes, which
is what serialises the repair stream's sequence numbering and the SRTP context both streams share.
The history has its own lock, so a NACK never tears a slab a frame is being written into. The media
stream gives back the two bytes the OSN costs, so a repair packet still fits the negotiated MTU.

Defaults: a 512-packet / 1 s / 1 MB history, a 50 ms minimum interval between two resends of the
same sequence number, and a 250 kB/s retransmission budget with a 64 kB burst — all on
`PeerConnectionConfig`. `GetStats().Video.Retransmission` reports NACKs received, packets requested,
packets and bytes retransmitted, history misses and suppressed requests.

Audio is deliberately excluded: browsers do not negotiate RTX for Opus, whose in-band FEC repairs
isolated loss without a round trip. Keryx's offer and its negotiator both preserve
`useinbandfec=1`.

## Sender-side link quality

Reception report blocks naming this endpoint's own SSRCs are folded into
`GetStats().Video.Quality` / `.Audio.Quality` as an `OutboundStreamQuality`: fraction lost as a
0–1 double, signed cumulative loss, extended highest sequence number, interarrival jitter (raw and
converted with the negotiated clock rate), and RFC 3550 §6.4.1 LSR/DLSR round-trip time. Blocks
about any other source are ignored. The raw `OnReceiverReport` event still fires alongside.

## Honest limitations (current)

- No ULPFEC or RED, and no retransmission for audio.
- No bandwidth estimation, pacing, REMB generation, or `a=extmap` support (no outbound TWCC
  sequence numbers).
- The answerer role is minimal and recvonly — it exists to prove the stack against itself; the
  offerer path is the production shape. No renegotiation, no ICE restart.
- No jitter buffer on the receive surface; `OnRtpPacketReceived` is a raw seam.
- Inbound RTCP BYE is logged, not acted on.
