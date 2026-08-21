# Keryx.Sdp — design notes

A lossless SDP model with typed accessors and JSEP helpers on top.

## Decisions

- **Losslessness first.** `SessionDescription` keeps an ordered, verbatim attribute list per
  section; parse→serialize of a Chrome offer or answer is byte-identical (CRLF normalized). Typed
  accessors (`Mid`, `GetRtcpFeedbackEntries`, `Fingerprint`, `SctpPort`, ...) read/write that list
  rather than shadowing it, so nothing is ever dropped by parsing.
- **`a=rtcp-fb` is a first-class citizen** (`RtcpFeedback`, per-pt and wildcard) because the
  inability to emit `nack pli`/`ccm fir` natively is a founding reason this stack exists.
  H.264 defaults emit `nack`, `nack pli`, `ccm fir`, `transport-cc`, in Chrome's order. Bare `nack`
  promises generic retransmission, so it travels with an RFC 4588 `rtx` entry: `SdpCodec.Rtx`
  renders `a=rtpmap:<pt> rtx/<clock>` plus `a=fmtp:<pt> apt=<media pt>`, and `SsrcGroup.FidSemantics`
  binds the repair SSRC to the media SSRC (RFC 5576 §4.2). A caller assembling its own m-section
  keeps the two in step, or drops bare `nack` from the feedback list.
- **`SdpOfferBuilder`** produces the exact Chrome-conventional offer shape (BUNDLE, rtcp-mux,
  `setup:actpass`, per-section ICE/fingerprint, `m=application` with `sctp-port`). Codec entries
  (`SdpCodec`) are fully caller-configurable — community codecs slot in without touching this
  layer.
- **`SdpNegotiator`** validates a JSEP answer against the offer (m-line count/order/protocol/mid)
  and reports per-mid negotiated state (intersected codecs in offer order, directions from the
  offerer's point of view, remote credentials/fingerprint/setup, sctp parameters). It reports;
  the PeerConnection layer decides. `NegotiatedCodec.IsRtx` / `GetAssociatedPayloadType()` and
  `NegotiatedMedia.FindRtxCodec(pt)` express the RFC 4588 §8.1 `apt` binding, and fmtp strings —
  Opus `useinbandfec=1` and `minptime`, H.264 `packetization-mode` — pass through both directions
  untouched, falling back to the offer's when the answer omits them.
- Candidate lines are carried as raw strings — `Keryx.Ice` owns candidate syntax.

## Simplifications

- Simulcast (`a=simulcast`, `a=rid`) and `a=ice-lite` survive as raw attributes, not typed.
- Unknown *line types* (not attributes) re-emit at the end of their section; unknown attributes
  keep their exact position.

## Testing

186 tests: byte-identical round-trips of realistic Chrome offer/answer documents, line-level
assertions on built offers, negotiation/validation matrices, hostile-input tolerance.
