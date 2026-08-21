# Keryx.Sdp — design notes

A lossless SDP model with typed accessors and JSEP helpers on top.

## Decisions

- **Losslessness first.** `SessionDescription` keeps an ordered, verbatim attribute list per
  section; parse→serialize of a Chrome offer or answer is byte-identical (CRLF normalized). Typed
  accessors (`Mid`, `GetRtcpFeedbackEntries`, `Fingerprint`, `SctpPort`, ...) read/write that list
  rather than shadowing it, so nothing is ever dropped by parsing.
- **`a=rtcp-fb` is a first-class citizen** (`RtcpFeedback`, per-pt and wildcard) because the
  inability to emit `nack pli`/`ccm fir` natively is a founding reason this stack exists.
  H.264 defaults emit `nack pli`, `ccm fir`, `transport-cc` — and never bare `nack`, which
  promises generic retransmission we do not implement; bare `nack` is opt-in.
- **`SdpOfferBuilder`** produces the exact Chrome-conventional offer shape (BUNDLE, rtcp-mux,
  `setup:actpass`, per-section ICE/fingerprint, `m=application` with `sctp-port`). Codec entries
  (`SdpCodec`) are fully caller-configurable — community codecs slot in without touching this
  layer.
- **`SdpNegotiator`** validates a JSEP answer against the offer (m-line count/order/protocol/mid)
  and reports per-mid negotiated state (intersected codecs in offer order, directions from the
  offerer's point of view, remote credentials/fingerprint/setup, sctp parameters). It reports;
  the PeerConnection layer decides.
- Candidate lines are carried as raw strings — `Keryx.Ice` owns candidate syntax.

## Simplifications

- Simulcast (`a=simulcast`, `a=rid`) and `a=ice-lite` survive as raw attributes, not typed.
- Unknown *line types* (not attributes) re-emit at the end of their section; unknown attributes
  keep their exact position.

## Testing

186 tests: byte-identical round-trips of realistic Chrome offer/answer documents, line-level
assertions on built offers, negotiation/validation matrices, hostile-input tolerance.
