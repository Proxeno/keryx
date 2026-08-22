# Simulcast transport primitives

Status: implemented (EWI-1250). Follow-up chain steps 1–5 landed; the BWE seam (step 6) stays an
app-side concern. See the "Follow-up PR breakdown" below for per-step status.

Keryx is the WebRTC transport stack under the vuefix broadcast platform: a creator ingests one video
source encoded at several qualities (simulcast), and the platform fans those out to many viewers, each
receiving the one quality their link can sustain. The Selective Forwarding Unit (SFU) that does the
fan-out is a **vuefix application concern**. Keryx supplies only the transport primitives the SFU is
built from.

## Scope and the Keryx/vuefix boundary

Keryx owns, and this document specifies:

1. **Negotiation** — parsing and emitting `a=rid` (RFC 8851), `a=simulcast` (RFC 8853), and the
   RID / repaired-RID / MID RTP header extensions (RFC 8852, RFC 8285).
2. **Ingest demux** — mapping each incoming RTP packet to its simulcast layer by RID, with an SSRC
   fallback once the binding is learned, exposed as per-layer streams.
3. **Forwarding primitives** — per-subscriber SSRC / sequence-number / timestamp rewrite, and
   keyframe-request (PLI/FIR) routing and coalescing back to the correct upstream layer.

Keryx explicitly does **not** own:

- **Layer selection.** Which layer each viewer receives, driven by that viewer's bandwidth estimate
  (EWI-1248), is decided in vuefix. Keryx forwards the layer the app selects and exposes the signals
  (switch pending, keyframe needed) the app needs to drive the decision.
- **Fan-out / routing topology.** Keryx has no notion of "subscribers" as a set, no SFU router, no
  subscription table. The app owns a `RtpForwarder` per subscriber output and pumps packets through.
- **Congestion control policy.** Keryx surfaces transport-cc / REMB / RR feedback (already present);
  turning that into a target bitrate and a chosen layer is app policy.

The dividing line in one sentence: **Keryx classifies, rewrites, and routes keyframe requests for the
layer the app names; the app names the layer.**

## 1. Negotiation

### RIDs and simulcast (`Keryx.Sdp`)

A simulcast video m-section declares one RID per layer and one `a=simulcast` line binding them into a
send (or recv) list:

```
m=video 9 UDP/TLS/RTP/SAVPF 96 97
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=extmap:2 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id
a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id
a=rid:hi send max-width=1280;max-height=720
a=rid:mid send max-width=640;max-height=360
a=rid:lo send max-width=320;max-height=180
a=simulcast:send hi;mid;lo
```

New SDP types, following the existing house style (`sealed record`, `TryParse(string?, out T?)`
that never throws, `ToAttributeValue()`, `ToString()` prefixed with `a=`):

- `SdpRid(string Id, RidDirection Direction, IReadOnlyList<SdpRidRestriction> Restrictions)` — one
  `a=rid` line. Restrictions (`max-width`, `max-fps`, `pt`, …) are preserved verbatim; Keryx does not
  interpret them. `IsValidId` enforces the RFC 8851 `rid-id` grammar (1–255 of `[A-Za-z0-9-_]`).
- `SdpSimulcast(IReadOnlyList<SdpSimulcastStream> Send, IReadOnlyList<SdpSimulcastStream> Recv)` — the
  `a=simulcast` line. A stream is an ordered `SdpSimulcastAlternative` list (`,` alternatives), the
  line a `;`-separated stream list; the `~` paused marker is preserved. `Reversed()` swaps the
  directions to build the answerer's view.
- `RtpHeaderExtensionUri` — the well-known extension URIs (MID, RID, repaired-RID, …).

`MediaDescription` gains `GetRids()` / `AddRid()` and a `Simulcast` get/set property over its raw
attribute list, exactly like the existing `GetExtMaps()` / `Msid` accessors. `SdpMediaOffer` gains a
`Rids` list and a `Simulcast` property, and `SdpOfferBuilder` emits them.

### Offer/answer rules (follow-up PR 1)

- The **ingest** peer connection (creator → Keryx) receives an offer whose video section is
  `a=simulcast:send …`. Keryx answers `recv` with the RIDs it accepts, dropping any it will not (an
  answerer MAY remove offered RIDs, RFC 8853 §5.2). `SdpSimulcast.Reversed()` provides the direction
  swap; the *pruning* of unwanted RIDs is the one selection-shaped decision made here, and it is a
  capability decision (codec/resolution support), not a per-viewer bandwidth decision.
- The RID and MID header extensions must be negotiated (`a=extmap`) for demux to work; repaired-RID is
  negotiated when RTX is offered.
- Parsing is hostile-input safe: every `TryParse` returns `false` rather than throwing, matching the
  wire-parsing rule for the rest of the stack.

## 2. Ingest demux

All simulcast layers of one source share **one payload type** and arrive **bundled on one transport**,
so the existing payload-type → `RtpRoute` map in `PeerConnection.HandleRtp` cannot separate them. Layers
are told apart by the RID string each packet carries in the RFC 8852 `rtp-stream-id` header extension.

`RtpHeader.TryGetExtension(id, out ReadOnlySpan<byte>)` already exposes RFC 8285 one-byte elements, so
the demux reads the RID with no new parsing on the hot path.

New types in `Keryx.Rtp.Simulcast`:

- `SimulcastLayerId` — a layer identifier storing the RID as inline ASCII bytes (`[InlineArray]`), so
  classifying a packet allocates nothing. Bounded to 16 bytes (the one-byte header-extension limit,
  which is the only form `RtpHeader` parses). `Matches(ReadOnlySpan<byte>)` compares against a raw
  extension body without materialising a string.
- `RtpStreamIdentifier` — allocation-free, never-throwing readers for the RID, repaired-RID and MID
  elements given their negotiated element ids (`RtpStreamIdentifierExtensions`).
- `SimulcastClassifier` — the demux primitive. `TryClassify(in RtpHeader, out RtpLayerClassification)`:
  1. A **repaired-RID** element ⇒ the packet is RTX for that layer (`IsRepair = true`).
  2. A **RID** element ⇒ media for that layer; the classifier **learns** `SSRC → layer`.
  3. Neither ⇒ resolve by the **learned SSRC** (browsers stop tagging RID after the first seconds,
     RFC 8852 §3).
  4. Unknown untagged SSRC ⇒ `false`; the caller drops or briefly buffers until a RID arrives.

`RtpLayerClassification(LayerId, Ssrc, IsRepair, Source)` carries the result; `Source` records whether
the layer came from the RID extension, the repaired-RID extension, or a learned SSRC, for stats.

On the peer connection, `RtpPacketInfo` gains an optional `Rid` so the existing `OnRtpPacketReceived`
callback can carry the layer without the handler re-parsing the header (populated once the RID extmap
id is resolved, PR 2/3). The classifier itself is transport-agnostic and unit-tested in isolation.

## 3. Forwarding primitives

### Per-subscriber rewrite — `RtpForwarder`

One `RtpForwarder` produces one subscriber's outbound stream from whichever layer the app has selected.
It rewrites three fields so the subscriber sees a single coherent RTP stream even as the source layer
changes underneath it:

- **SSRC** → a stable per-subscriber outbound SSRC.
- **Sequence number** → contiguous across layer switches, gaps within a layer preserved (so the
  subscriber's loss detection and NACK still work). Implemented via a per-segment offset re-based to
  `highestOutSeq + 1` at each switch.
- **Timestamp** → a monotonic outbound timeline. Baseline scaffold pins the offset; correct
  cross-layer alignment from the RTCP sender-report wall-clock mapping is a `// TODO` (PR 4).

A switch must land on a **decodable boundary** (a keyframe of the target layer), which only a
codec-aware caller can detect. So the forwarder separates a **desired** layer (`SelectLayer`, set by
the app from BWE) from the **active** layer it is forwarding, and promotes desired → active only when
`TryForward(..., canStartLayer: true, ...)` offers a keyframe packet of the desired layer. Until then it
keeps forwarding the active layer so the picture never freezes. `IsSwitchPending` tells the app to
request a keyframe upstream. Non-selected layers and repair packets return `Dropped`.

`RtpForwarder` holds codec knowledge nowhere: the caller supplies `canStartLayer` from its
depacketizer, and layer selection comes from the app. It is a pure transport rewriter.

### Keyframe-request routing — `KeyframeRequestCoalescer`

A subscriber's decoder asks for a keyframe (PLI/FIR) against the SSRC **it** receives — the forwarder's
outbound SSRC — which is unrelated to the creator's upstream layer SSRC. The coalescer maps
`outbound SSRC → layer → learned upstream SSRC` (`BindOutput`, `SetLayerUpstreamSsrc`) and, on
`TryResolveUpstream(outboundSsrc, now, out upstreamSsrc)`, returns the upstream SSRC to ask **and**
whether asking now is allowed under a minimum interval. Coalescing keys on the upstream SSRC, so a
storm of requests from many viewers of a popular layer — or a wave of layer switches — collapses to one
upstream ask, protecting the creator's encoder from a keyframe flood.

The coalescer builds and sends no RTCP: the app issues the request through the existing peer-connection
primitives (`SendPictureLossIndication(ssrc)` / `SendFullIntraRequest(ssrc)`) using the returned SSRC.

## 4. How per-subscriber BWE (EWI-1248) drives selection, from the app side

The BWE work lands a per-subscriber downlink bandwidth estimate (from transport-cc / REMB / RR, all
already surfaced by Keryx). The vuefix SFU runs, per subscriber, a loop Keryx never participates in:

1. Read the subscriber's current estimate (EWI-1248).
2. Pick the highest layer whose advertised `a=rid` bitrate/resolution fits the estimate (plus
   hysteresis to avoid flapping). **This is the layer-selection policy — app-only.**
3. Call `forwarder.SelectLayer(layerId)`.
4. While `forwarder.IsSwitchPending`, ask Keryx for a keyframe on the desired layer's upstream SSRC
   (via the classifier's `GetMediaSsrc(layerId)` and the coalescer), so the switch can land promptly.
5. Feed every classified ingest packet to each subscriber's `forwarder.TryForward(...)`, supplying
   `canStartLayer` from the depacketizer, and send the `Forwarded` bytes.

Keryx supplies steps 3–5's mechanism (`SimulcastClassifier`, `RtpForwarder`,
`KeyframeRequestCoalescer`, and the existing PLI/FIR senders) and the inputs to steps 1–2 (the feedback
events and the advertised RID restrictions). It supplies none of the decision in step 2.

## Files

New (`Keryx.Sdp`): `SdpRid.cs`, `SdpSimulcast.cs`, `RtpHeaderExtensionUri.cs`.
Changed (`Keryx.Sdp`): `SdpAttributeNames.cs`, `MediaDescription.cs`, `SdpMediaOffer.cs`,
`SdpOfferBuilder.cs`.
New (`Keryx.Rtp.Simulcast`): `SimulcastLayerId.cs`, `RtpStreamIdentifier.cs`,
`RtpLayerClassification.cs`, `SimulcastClassifier.cs`, `RtpForwarder.cs`,
`KeyframeRequestCoalescer.cs`.
Changed (`Keryx`): `PeerConnectionEvents.cs` (`RtpPacketInfo.Rid`).

## Follow-up PR breakdown (in order)

1. **SDP negotiation wiring** — *done.* `SdpNegotiator.AnswerSimulcast` echoes `a=simulcast` with
   directions reversed, prunes RIDs a capability predicate rejects, keeps `a=rid` restrictions verbatim,
   and echoes the RID/repaired-RID/MID extmaps; `PeerConnection.BuildAnswer` applies it, gated by
   `PeerConnectionConfig.EnableSimulcast`. Returns a `SimulcastAnswer`.
2. **Header-extension resolution** — *done.* `ApplyRemoteOffer` resolves the negotiated MID/RID/
   repaired-RID extmap ids per simulcast mid; `HandleRtp` populates `RtpPacketInfo.Rid`; the ids are
   exposed via `PeerConnection.TryGetSimulcastExtensions` / `SimulcastMids`.
3. **Ingest demux integration** — *done.* `HandleRtp` drives a per-mid `SimulcastClassifier` (learning
   the SSRC↔layer binding so the RID survives after browsers stop tagging); per-layer receive counts
   via `GetSimulcastLayerStats`, and the classifier itself via `GetSimulcastClassifier`.
4. **Forwarder completion** — *done.* Cross-layer timestamp alignment from the RTCP-SR wall-clock
   mapping (`RtpForwarder.RecordSenderReport`, fed by the new `PeerConnection.OnSenderReport`), egress
   RID/repaired-RID stripping and MID rewrite (`RtpEgressExtensions`), keyframe-gated switching kept.
5. **Keyframe routing completion** — *done.* Deferred-request firing (`TryTakeDeferred`), per-upstream
   FIR command-sequence (`NextFirCommandSequence`), wired to the PLI/FIR senders via
   `PeerConnection.SendCoalescedKeyframeRequest` / `SendDeferredKeyframeRequests`.
6. **BWE seam (EWI-1248)** — document and implement the vuefix-side selection loop against the Keryx
   primitives (in the app, not in Keryx). *Deliberately out of scope for Keryx.*
