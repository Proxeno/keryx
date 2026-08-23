# Generic transceiver / session model

Status: **proposal, owner review pending. No implementation.** This document proposes turning
Keryx's purpose-shaped media API (one fixed video m-line, one fixed audio m-line, one data
channel, offerer-centric, no renegotiation) into an `RTCRtpTransceiver`-shaped session model:
`AddTrack` / `AddTransceiver`, dynamic mids, N m-lines of any kind, per-transceiver
direction / codec / SSRC, renegotiation, and rollback — **without breaking the two shipping
consumers on the 0.2.0 API** (Proxeno, and the vuefix SFU).

The through-line: today the media API is keyed by `MediaKind` (there is exactly one video thing
and one audio thing); the target keys everything by **transceiver** (an ordered set of media
objects, each with its own mid, direction, codec and SSRC). The legacy per-kind API survives as a
thin shim that resolves "the video thing" to "the first video transceiver".

---

## 1. Current state — the real constraints

### 1.1 Everything is single-per-kind, allocated at construction

`PeerConnection`'s identity fields are scalar, one per role, fixed the moment the object is built
(`src/Keryx/PeerConnection.cs:66-72`):

```csharp
private readonly string _videoTrackId;
private readonly string _audioTrackId;
private readonly uint _videoSsrc;
private readonly uint _videoRtxSsrc;
private readonly uint _audioSsrc;
private readonly uint _rtcpSenderSsrc;
```

They are assigned once in the constructor (`PeerConnection.cs:101-108`), before any negotiation,
alongside the two per-kind forwarder handles `_videoForwarder` / `_audioForwarder`. There is no
collection of media objects anywhere — the "set of things this connection sends/receives" is these
named fields.

The mids are configuration constants, not allocated (`src/Keryx/PeerConnectionConfig.cs:271-277`):

```csharp
public string VideoMid { get; set; } = "0";
public string AudioMid { get; set; } = "1";
public string ApplicationMid { get; set; } = "2";
```

The advertised codec set is likewise two flat lists on the config,
`VideoCodecs` / `AudioCodecs` (`PeerConnectionConfig.cs:71,78`), each defaulting to a single codec
(H.264, Opus). A single codec is *negotiated* per kind and stored in the scalar
`_negotiatedVideo` / `_negotiatedAudio` (`src/Keryx/PeerConnection.Media.cs:38-39`), each an
`NegotiatedTrack` record (`PeerConnection.cs:1475-1479`).

### 1.2 Offer / answer walk fixed sections

`BuildOffer` (`PeerConnection.cs:797-847`) hard-codes the section list: *if* `VideoCodecs` is
non-empty add one `SdpMediaOffer.Video(_config.VideoMid, …)`; *if* `AudioCodecs` is non-empty add
one `SdpMediaOffer.Audio(_config.AudioMid, …)`; then one `AddDataChannel(_config.ApplicationMid, …)`.
Video is always offered `sendonly` (the `SdpMediaOffer.Rtp` factory sets `MediaDirection.SendOnly`,
`src/Keryx.Sdp/SdpMediaOffer.cs:144`). There is no way to express "two video m-lines" or "a
recvonly video m-line" through this builder.

`BuildAnswer` (`PeerConnection.cs:950-1157`) mirrors the offer's sections by index and, per section,
negotiates one direction from the offered one. The one non-trivial rule
(`PeerConnection.cs:986-990`): a `recvonly` offer is answered `sendonly` — the SFU subscriber shape,
where Keryx becomes the sender — and every other offered direction answers `recvonly`. When the
negotiated direction sends, it wires the single send track by picking the primary codec and its rtx,
writing `_negotiatedVideo` / `_negotiatedAudio` (`PeerConnection.cs:1124-1136`) and publishing the
one per-kind SSRC. Two sending video sections would both try to claim `_videoSsrc` / `_negotiatedVideo`.

### 1.3 Inbound demux is keyed by payload type, globally

`ApplyRemoteOffer` (`PeerConnection.cs:1159-1249`) and `ApplyAnswer` (`PeerConnection.cs:1303-1440`)
both build one dictionary, `_routes : Dictionary<byte, RtpRoute>` (`PeerConnection.Media.cs:46`),
where `RtpRoute` is `(string Mid, MediaKind Kind, uint ClockRate, bool IsRtx)`
(`PeerConnection.cs:1469`). Inbound packets are demuxed **by payload type alone**
(`PeerConnection.Media.cs:899-901`):

```csharp
var payloadType = packet.Header.PayloadType;
var routes = Volatile.Read(ref _routes);
var route = routes.TryGetValue(payloadType, out var found) ? found : new RtpRoute(…, MediaKind.Unknown);
```

This is the hard structural constraint on N m-lines: **payload types are only unique per m-line,
not across a BUNDLE.** Two video m-lines that both use pt 96 collide in `_routes`. The MID header
extension — already parsed and negotiated for simulcast (`_simulcastByMid`,
`PeerConnection.Media.cs:47`, and `ToStreamExtensions`, `PeerConnection.cs:1275-1301`) — is the
BUNDLE demux key WebRTC actually uses (RFC 8843 §9.2), but the media path does not consult it; only
the simulcast layer classifier does.

### 1.4 Send / forward / introspection are all `switch (kind)`

- `SendVideoFrame(annexB, ts)` (`PeerConnection.Media.cs:115`) → `_videoTrack`.
- `SendAudioFrame(opus, ts)` (`PeerConnection.Media.cs:146`) → `_audioTrack`.
- `TryForwardRtp(kind, payload, ts, marker, pt)` (`PeerConnection.Media.cs:199-238`) → `switch`
  over `_videoTrack` / `_audioTrack`.
- `GetForwarder(kind)` (`PeerConnection.Media.cs:250`) → `_videoForwarder` / `_audioForwarder`.
- Introspection: `GetNegotiatedPayloadType(kind)` (`:277`), `GetLocalSsrc(kind)` (`:291`),
  `GetRemoteSsrc(kind)` (`:305`), `NegotiatedVideoRtxPayloadType` (`:262`), and the properties
  `VideoSsrc` / `AudioSsrc` (`PeerConnection.cs:229,238`).

Every one of these is "the video/audio thing," resolved through the single scalar field.

The actual wire work lives in the private `TrackSender` (`PeerConnection.Media.cs:1614-1816`):
payloadizer, sequence/timestamp state, reusable datagram buffer, optional `RtxRetransmitter`. Its
`SendFrame` / `ForwardRtp` / `Retransmit` are the primitives a transceiver's sender would keep
using unchanged. `CreateTrackSenders` (`PeerConnection.Media.cs:739-819`) builds at most one
`TrackSender` per kind from the scalar `_negotiatedVideo` / `_negotiatedAudio`.

### 1.5 SDP builder is single-shot and never versions

`SdpOfferBuilder` (`src/Keryx.Sdp/SdpOfferBuilder.cs`) already takes an ordered
`IList<SdpMediaOffer> Media` (`:56`) and BUNDLEs *whatever* sections it is handed
(`SetBundleGroup(Media.Select(m => m.Mid))`, `:122`) — so the SDP layer is **not** the thing that
hard-codes three sections; `BuildOffer` / `BuildAnswer` are. But `SessionVersion` is a fixed `"2"`
(`SdpOfferBuilder.cs:23`) and nothing increments it: there is no second offer. `SdpNegotiator`
(`src/Keryx.Sdp/SdpNegotiator.cs`) validates JSEP alignment (same count, order, media types, mids;
`:19-74`) and interprets the answer into `NegotiatedMedia` (`src/Keryx.Sdp/NegotiatedMedia.cs`),
which is already per-m-section and carries direction, codecs, ssrcs, setup, candidates. The
negotiator is close to reusable as-is; it is `PeerConnection`'s consumption of it that collapses to
two scalars.

### 1.6 One transport, one SRTP context, no renegotiation, offerer-centric

- **Signaling "state" is two nullable fields and a bool**: `_localDescription`,
  `_remoteDescription` (`PeerConnection.cs:81-82`), `_isOfferer` (`:86`). `CreateOfferAsync`
  throws if `_localDescription` already exists (`:329-338`) — a second offer is impossible.
- **One BUNDLE transport, one DTLS handshake, one SRTP context.** The SRTP context is derived
  once from the RFC 5705 DTLS exporter in `RunConnectionAsync` (`PeerConnection.Media.cs:635-659`)
  and never re-derived. DTLS renegotiation is explicitly refused
  (`src/Keryx.Dtls/DtlsTransport.cs:811,982`). **This is load-bearing for the design: because
  max-bundle multiplexes every m-line onto one transport, adding or removing m-lines in a
  renegotiation does not touch DTLS or SRTP at all** — the keys stay valid, sequence spaces
  continue. Only an ICE restart / new handshake would rekey, and Keryx does neither today.
- **ICE candidates carry `sdpMid` for diagnostics only** (`AddIceCandidate`,
  `PeerConnection.cs:449-453`: "Recorded for diagnostics only: this connection is max-bundle …").
  `LocalIceCandidateEventArgs` exposes `SdpMid` but **no `sdpMLineIndex`**
  (`src/Keryx/PeerConnectionEvents.cs:14-33`). With one bundled transport a single mid is enough;
  the JSEP `RTCIceCandidateInit` shape browsers emit and expect carries `sdpMLineIndex`, and a peer
  that keys candidates by index needs Keryx to both emit and accept it.

### 1.7 Simulcast is already mid-keyed (the template to follow)

`_simulcastByMid : Dictionary<string, SimulcastReceiveTracker>` (`PeerConnection.Media.cs:47`) and
its accessors — `SimulcastMids` (`:316`), `GetSimulcastClassifier(mid)` (`:346`),
`GetSimulcastLayerStats(mid)` (`:355`) — are the one part of the media API that is already keyed by
**mid**, not kind. The transceiver model generalises exactly this shape to the whole media path.

---

## 2. Proposed public API

### 2.1 The transceiver, sender, receiver

New public types in the `Keryx` assembly, following house style (sealed, doc-commented, no throw on
the hot path):

```csharp
public sealed class RtpTransceiver
{
    /// <summary>The negotiated a=mid, or null until the first offer/answer assigns one.</summary>
    public string? Mid { get; }

    /// <summary>audio or video. Fixed at creation; a transceiver never changes kind.</summary>
    public MediaKind Kind { get; }

    /// <summary>The direction the app wants (settable before the next negotiation).</summary>
    public RtpTransceiverDirection Direction { get; set; }

    /// <summary>The direction actually negotiated (RFC 8829), null before negotiation settles.</summary>
    public RtpTransceiverDirection? CurrentDirection { get; }

    public RtpSender Sender { get; }
    public RtpReceiver Receiver { get; }

    /// <summary>The primary codec negotiated for this m-line, null before it settles.</summary>
    public NegotiatedCodec? NegotiatedCodec { get; }

    /// <summary>Marks the transceiver stopped; the next offer emits a rejected (port 0) m-line.</summary>
    public void Stop();

    public bool Stopped { get; }
}

public sealed class RtpSender
{
    /// <summary>The local SSRC this sender owns; stable for the transceiver's life.</summary>
    public uint Ssrc { get; }

    /// <summary>The RFC 4588 rtx repair SSRC, when retransmission is negotiated for this m-line.</summary>
    public uint? RtxSsrc { get; }

    /// <summary>The negotiated send payload type, null before negotiation settles.</summary>
    public byte? PayloadType { get; }

    /// <summary>Packetize + send one codec frame (Annex B for H.264, one Opus packet, …).</summary>
    public int SendFrame(ReadOnlySpan<byte> frame, uint rtpTimestamp);

    /// <summary>Forward one already-packetized payload verbatim (the SFU egress path).</summary>
    public bool TryForwardRtp(ReadOnlySpan<byte> payload, uint rtpTimestamp, bool marker, byte payloadType);
}

public sealed class RtpReceiver
{
    /// <summary>The remote sender's SSRC, learned from inbound RTP; null until one arrives.</summary>
    public uint? Ssrc { get; }

    /// <summary>The negotiated receive payload type(s) for this m-line.</summary>
    public IReadOnlyList<byte> PayloadTypes { get; }
}
```

`RtpSender` is a public face over the existing private `TrackSender`
(`PeerConnection.Media.cs:1614`) — `SendFrame` / `ForwardRtp` move onto it unchanged; the sender
just holds the reference. `RtpReceiver` is where per-mid receive state (the simulcast tracker, the
remote-SSRC snapshot, the reception stats) attaches, generalising `_remoteVideoSsrc` /
`_remoteAudioSsrc` (`PeerConnection.Media.cs:52-53`).

`RtpTransceiverDirection` is a new enum mirroring the WebRTC one (`SendRecv`, `SendOnly`,
`RecvOnly`, `Inactive`, `Stopped`) — distinct from the SDP-layer `MediaDirection`
(`src/Keryx.Sdp/MediaDirection.cs`) which stays the wire representation the two map onto.

### 2.2 PeerConnection surface

```csharp
public sealed partial class PeerConnection
{
    /// <summary>Adds a transceiver for a media kind with an explicit direction. Valid before or
    /// between negotiations; the mid is allocated when the next offer is built.</summary>
    public RtpTransceiver AddTransceiver(MediaKind kind,
        RtpTransceiverDirection direction = RtpTransceiverDirection.SendRecv,
        RtpTransceiverInit? init = null);

    /// <summary>Convenience: add a sendrecv (or sendonly) transceiver already wired to send the
    /// given codecs. The AddTrack of this model.</summary>
    public RtpTransceiver AddTrack(MediaKind kind, IReadOnlyList<SdpCodec> codecs);

    /// <summary>Every transceiver, in mid/m-line order. The data channel is not a transceiver.</summary>
    public IReadOnlyList<RtpTransceiver> Transceivers { get; }

    public RtpTransceiver? GetTransceiver(string mid);
}

public sealed class RtpTransceiverInit
{
    public IList<SdpCodec> Codecs { get; }          // per-transceiver codec preference list
    public string? Mid { get; set; }                 // pin a mid (e.g. legacy "0"); else allocated
    public bool EnableRetransmission { get; set; }   // per-transceiver rtx, defaults to config
    public IList<SdpRid> SimulcastLayers { get; }    // send-simulcast declaration, if any
}
```

`AddTransceiver` allocates the sender's SSRC (and rtx SSRC) at the point of the call — the same
`NewSsrc()` the constructor uses today (`PeerConnection.cs:690`) — so `sender.Ssrc` is stable and
readable immediately, preserving the current guarantee that `VideoSsrc` is known before connect.

### 2.3 How the legacy API maps on

| Legacy member | Resolves to |
| --- | --- |
| `SendVideoFrame(annexB, ts)` | first `Video` transceiver whose `Sender.PayloadType` is set → `Sender.SendFrame` |
| `SendAudioFrame(opus, ts)` | first `Audio` transceiver → `Sender.SendFrame` |
| `TryForwardRtp(kind, …)` | first sending transceiver of `kind` → `Sender.TryForwardRtp` |
| `GetForwarder(kind)` | a stable handle bound to the first-of-kind transceiver's sender |
| `GetNegotiatedPayloadType(kind)` | first-of-kind `transceiver.Sender.PayloadType` |
| `GetLocalSsrc(kind)` / `VideoSsrc` / `AudioSsrc` | first-of-kind `transceiver.Sender.Ssrc` |
| `GetRemoteSsrc(kind)` | first-of-kind `transceiver.Receiver.Ssrc` |
| `NegotiatedVideoRtxPayloadType` | first video transceiver's negotiated rtx pt |
| `SimulcastMids` / `GetSimulcastClassifier(mid)` | already mid-keyed; unchanged |

"First of kind" is exact and stable because the constructor, in legacy mode, creates the video
transceiver at mid `"0"` before the audio transceiver at mid `"1"` (see §5). So for every existing
single-video/single-audio consumer, "the first video transceiver" *is* the only video transceiver,
and every legacy call resolves to the identical `TrackSender` it does today.

---

## 3. Dynamic mids, N m-lines, BUNDLE, and candidate indices

### 3.1 Mid allocation

A monotonically increasing per-session mid counter, seeded past any pinned mids. When the app calls
`AddTransceiver`, the transceiver is created with `Mid == null`; the mid is assigned when the next
offer is *built*, in insertion order, skipping mids already claimed (so a legacy transceiver pinned
to `"0"` keeps it and the counter starts the free ones after). This matches JSEP: mids are strings,
opaque, assigned by the offerer, echoed by the answerer.

An answerer that receives an offer creates a transceiver per offered m-line it accepts, adopting the
**offered** mid verbatim (the answer must echo it — `SdpNegotiator.Validate` already enforces this,
`SdpNegotiator.cs:52-59`).

### 3.2 m-line ordering and recycling (JSEP §5.2.1)

JSEP fixes the m-line order for the life of the session: once a section is at index *i*, index *i*
always carries that mid (or a rejected placeholder). The design honours this by keeping
`Transceivers` append-only in m-line order and never reordering. A `Stop()`ped transceiver is not
removed; its slot emits a rejected `m=… 0 …` section (port 0, the shape `BuildAnswer` already
produces for a codec-less section, `PeerConnection.cs:1056-1069`). Recycling a stopped slot for a
new transceiver of the same kind is a **later** optimisation, explicitly out of scope for the first
cut — new transceivers always append.

### 3.3 BUNDLE

Unchanged in spirit: `SdpOfferBuilder.SetBundleGroup` already bundles every section it is handed
(`SdpOfferBuilder.cs:120-123`). With N sections the group is `BUNDLE 0 1 2 … n`. Keryx stays
max-bundle: one ICE transport, one DTLS, one SRTP context, regardless of m-line count. This is what
keeps the SRTP lifecycle trivial under renegotiation (§4.3).

### 3.4 Inbound demux must become mid-first

This is the one internal rewrite N m-lines *forces* (§1.3). Replace the global
`_routes : Dictionary<byte, RtpRoute>` with a per-transceiver resolution:

1. **Read the MID RTP header extension** (RFC 8843 §9.2) if present → transceiver by mid. The
   parsing already exists (`ToStreamExtensions`, `PeerConnection.cs:1275-1301`); it just needs to be
   consulted on the media path, not only the simulcast path, and the MID extmap negotiated on every
   m-line (browsers send it).
2. **Fall back to payload type** within the still-unambiguous case (single m-line per kind, the
   legacy shape) — so nothing regresses for existing sessions where PTs *are* unique.
3. **Fall back to the SSRCs declared in the remote SDP** (`a=ssrc`) mapping SSRC → mid, for peers
   that signal SSRCs and send no MID extension.

The route value grows from `(Mid, Kind, ClockRate, IsRtx)` to also carry the resolved transceiver
handle, so `HandleRtp` (`PeerConnection.Media.cs:882`) dispatches to `transceiver.Receiver` instead
of writing the two scalar `_remoteVideoSsrc` / `_remoteAudioSsrc` fields. `RtpPacketInfo.Mid`
(`PeerConnectionEvents.cs:257-265`) already exists to carry the mid out to handlers — it becomes
reliably populated rather than best-effort.

### 3.5 `sdpMLineIndex` on candidates

With N m-lines the trickle-ICE candidate shape must carry the m-line index, not just the mid:

- **Emit**: add `SdpMLineIndex` (int) to `LocalIceCandidateEventArgs`
  (`PeerConnectionEvents.cs:14`), set to the index of the mid the candidate is scoped to (0 under
  max-bundle — the first mid — but now *computed*, not implied).
- **Accept**: add an optional `sdpMLineIndex` parameter to `AddIceCandidate`
  (`PeerConnection.cs:453`). Under max-bundle it still applies to the one transport, so the value is
  recorded (and used to resolve the mid when `sdpMid` is absent) rather than driving separate
  transports. This is a small, self-contained change that can land independently and ahead of the
  rest (§6) because it does not depend on the transceiver refactor — it only depends on *emitting a
  correct index*, which needs the m-line order, which the session already has.

---

## 4. Renegotiation and rollback

### 4.1 Signaling state machine

Introduce the JSEP signaling states as a real field, replacing the `_isOfferer` bool + null checks
(`PeerConnection.cs:86,329-338`):

```csharp
public enum SignalingState { Stable, HaveLocalOffer, HaveRemoteOffer, Closed }
public SignalingState SignalingState { get; }
public event EventHandler<SignalingState>? OnSignalingStateChanged;
public event EventHandler? OnNegotiationNeeded;   // raised when AddTransceiver/Stop dirties state
```

Transitions (RFC 8829 §3.2):

- `stable` + `CreateOffer` / `SetLocalDescription(offer)` → `have-local-offer`
- `have-local-offer` + `SetRemoteDescription(answer)` → `stable`
- `stable` + `SetRemoteDescription(offer)` → `have-remote-offer`
- `have-remote-offer` + `CreateAnswer` / `SetLocalDescription(answer)` → `stable`
- any non-stable + rollback → `stable`

`CreateOfferAsync` (`PeerConnection.cs:323`) stops being once-only: from `stable` it builds an offer
that reflects the *current* transceiver set (including ones added since the last negotiation) and
bumps `SessionVersion` (`SdpOfferBuilder.cs:23`) — the field exists precisely for this and is the
one JSEP requires to increment per renegotiation.

Making `SetLocalDescription` explicit (today it is a side effect of `CreateOffer`/`CreateAnswer`
assigning `_localDescription`, `PeerConnection.cs:349-353,402-406`) is part of this: the state
machine needs the local apply as a distinct step to model `have-local-offer`.

### 4.2 Repeat offer/answer, adding and removing m-lines

A renegotiation offer re-emits every existing section **at its fixed index with its fixed mid**
(§3.2), plus any appended transceivers, plus rejected placeholders for stopped ones. `SdpNegotiator`
already validates count/order/mid alignment (`SdpNegotiator.cs:33-60`) — that validation becomes
*more* important, not less, and mostly already holds. The per-section `NegotiatedMedia`
(`NegotiatedMedia.cs`) is applied to the matching transceiver by index/mid, updating its
`CurrentDirection` and `NegotiatedCodec` in place.

Direction changes on an existing transceiver (e.g. `sendrecv` → `inactive` to pause) flow through
the same per-section direction negotiation `BuildAnswer` already does
(`PeerConnection.cs:986-990`), now driven by `transceiver.Direction` instead of a hard-coded rule.

### 4.3 SRTP / RTP context survives renegotiation untouched

The key simplification, restated as a guarantee: **a renegotiation that only adds/removes/repoints
m-lines does not re-run DTLS and does not re-derive SRTP.** Because everything is one BUNDLE
transport, the SRTP context (`_srtp`, `PeerConnection.Media.cs`, derived at
`PeerConnection.Media.cs:635-659`) and every stream's sequence/timestamp/rtx state stay valid across
the exchange. A newly added transceiver's `TrackSender` is built (`CreateTrackSenders`,
`PeerConnection.Media.cs:739`) against the *existing* SRTP context. Nothing rekeys. This is why the
transceiver model is achievable without touching the DTLS layer's no-renegotiation stance
(`DtlsTransport.cs:811,982`): SRTP rekeying and DTLS renegotiation are a *separate, later* concern
(§6) that only an ICE restart forces.

### 4.4 Rollback

Rollback (`SetLocalDescription(rollback)` / `SetRemoteDescription(rollback)`) returns a non-stable
state to `stable`, discarding the pending description. Concretely: keep the last stable
`_localDescription` / `_remoteDescription` and the transceiver snapshot; on rollback, restore them
and drop any transceiver that existed *only* to satisfy the pending offer (a receiver-side
transceiver auto-created for an offered m-line that is now being rolled back). Transceivers added by
the application are not destroyed — they revert to "not yet negotiated." Because no SRTP/transport
work happens until an answer is applied and the driver starts, rollback before `stable` has no
transport-teardown to undo; it is a pure description/transceiver-set revert.

---

## 5. Migration and back-compat

Both shipping consumers (Proxeno, vuefix SFU) are on the 0.2.0 per-kind API. **Nothing they call may
change signature or semantics.** The strategy is *the legacy API as a thin shim over the new model*,
introduced in one internal refactor with no public break, then the new API added on top.

### 5.1 Legacy construction becomes sugar for `AddTransceiver`

The constructor keeps reading `_config.VideoCodecs` / `_config.AudioCodecs` /
`VideoMid`/`AudioMid`/`ApplicationMid` exactly as today (`PeerConnection.cs:99-108`,
`PeerConnectionConfig.cs:71,78,271-277`), but instead of setting scalar fields it calls the new
internal path:

- non-empty `VideoCodecs` → `AddTransceiver(Video, SendOnly, init{ Mid="0", Codecs=VideoCodecs })`
- non-empty `AudioCodecs` → `AddTransceiver(Audio, SendOnly, init{ Mid="1", Codecs=AudioCodecs })`
- data channel section stays pinned at mid `"2"`

The pre-allocated `_videoSsrc` / `_audioSsrc` / `_videoRtxSsrc` become the SSRCs of those two
transceivers' senders, so `VideoSsrc` / `AudioSsrc` (`PeerConnection.cs:229,238`) return the same
values in the same order. `BuildOffer` / `BuildAnswer` are rewritten to walk `Transceivers` instead
of the two `if` blocks, but for the legacy transceiver set they emit **byte-identical** SDP
(same mids, same order, same directions, same codecs). This is the correctness anchor: a golden-SDP
test asserts the offer/answer for the default config is unchanged.

### 5.2 The legacy methods delegate

`SendVideoFrame` / `SendAudioFrame` / `TryForwardRtp` / `GetForwarder` / the introspection accessors
keep their exact signatures (`PeerConnection.Media.cs:115,146,199,250,262-310`) and become
one-liners resolving "first of kind" (§2.3). `GetForwarder(kind)` still returns a stable handle for
the connection's life — it binds to the first-of-kind transceiver, whose identity never changes in
the legacy shape. The subscriber-egress path the SFU drives (`TryForwardRtp`, `IRtpForwarder`) is
semantically identical because it still forwards onto the one video/audio send SSRC.

### 5.3 Phased rollout

1. **Internal refactor, no public change** (§5.1–5.2): introduce `RtpTransceiver` internally, make
   the legacy API a shim, prove byte-identical SDP and green tests. Ship as a **patch** (0.2.x) —
   consumers see nothing.
2. **Additive public API** (§2): expose `AddTransceiver` / `Transceivers` / `RtpSender` etc. Ship as
   a **minor** (0.3.0) — purely additive, consumers opt in when ready.
3. **Renegotiation + rollback** (§4): additive; the single-shot path still works. Minor bump.

Deprecation of the per-kind methods is **not** proposed here — they remain the ergonomic path for
the single-track case indefinitely.

---

## 6. Phasing into landable PRs

Ordered by dependency. Each is independently reviewable and shippable.

**PR 0 — `sdpMLineIndex` on candidates.** Add `SdpMLineIndex` to `LocalIceCandidateEventArgs`, an
optional index param to `AddIceCandidate`. Self-contained, no transceiver dependency. *Unblocks*:
correct trickle-ICE for any multi-m-line peer; prerequisite for non-bundled fallback later.
(`PeerConnectionEvents.cs:14`, `PeerConnection.cs:453,739-740`.)

**PR 1 — mid-first inbound demux.** Replace PT-keyed `_routes` with mid → transceiver-ish resolution
(MID extension, PT fallback, SSRC fallback), consuming the MID extension already parsed for
simulcast. No public API change; behaviour identical for single-m-line-per-kind. *Unblocks*: N
m-lines of the same kind; multi-codec-per-m-line demux. (`PeerConnection.Media.cs:46,882-901`;
`PeerConnection.cs:1159-1249,1303-1440`.)

**PR 2 — internal transceiver model + legacy shim.** Introduce `RtpTransceiver` / `RtpSender` /
`RtpReceiver` internally; constructor builds the legacy two transceivers; `BuildOffer`/`BuildAnswer`
walk `Transceivers`; legacy methods delegate. Golden-SDP test locks byte-identical output.
*Dependency*: PR 1. Ships as 0.2.x. (`PeerConnection.cs:797-1157`; `PeerConnection.Media.cs:36-39,
739-819,1614`.)

**PR 3 — public `AddTransceiver` / `Transceivers` / sender & receiver surface.** Expose the model;
allow N transceivers of any kind/direction from the offerer and, on the answerer, auto-create
transceivers for accepted offered m-lines. *Dependency*: PR 2. Ships as 0.3.0. *Unblocks*: recvonly
video ingest without the recvonly-offer trick; multiple published tracks.

**PR 4 — signaling state machine + explicit `SetLocalDescription` + `OnNegotiationNeeded`.**
Replace `_isOfferer`; model `stable`/`have-local-offer`/`have-remote-offer`. *Dependency*: PR 3.
(`PeerConnection.cs:81-86,323-442`.)

**PR 5 — renegotiation (repeat offer/answer, add/remove/repoint m-lines, `SessionVersion` bump).**
*Dependency*: PR 4. Proves the SRTP-survives-untouched guarantee (§4.3) with a test that adds a
second video transceiver mid-session and asserts the SRTP context object is unchanged. *Unblocks*:
adding tracks after connect; pausing via direction change.

**PR 6 — rollback.** `SetLocalDescription(rollback)` / `SetRemoteDescription(rollback)`.
*Dependency*: PR 5.

**Beyond this chain (explicitly deferred, noted for what they unblock):**

- **ICE restart** — needs the signaling machine (PR 4) plus ICE credential re-gather and, on a new
  DTLS handshake, SRTP re-derivation. This is the *only* path that rekeys SRTP; the DTLS layer's
  no-renegotiation stance (`DtlsTransport.cs:811,982`) means an ICE restart implies a fresh handshake
  on the new transport, not in-place DTLS renegotiation.
- **Multi-codec per transceiver** — needs PR 1 (demux) + a per-transceiver negotiated-codec *list*
  instead of the single `NegotiatedCodec`; the scalar `_negotiatedVideo`/`_negotiatedAudio`
  (`PeerConnection.Media.cs:38-39`) is what currently forbids it.
- **SRTP rekeying** — only ICE-restart / DTLS-rehandshake forces it; ordinary renegotiation (PR 5)
  deliberately avoids it (§4.3).
- **m-line recycling** of stopped slots — a compaction optimisation on top of PR 5/6.

---

## 7. Open questions for the owner

1. **Answerer auto-create policy (PR 3).** When a remote offer adds an m-line, should Keryx
   auto-create a transceiver (browser behaviour) or require the app to have pre-added a matching one?
   Auto-create is more WebRTC-faithful but means the app learns of new inbound tracks via an event
   (`OnTransceiver`?) rather than by having asked for them.

2. **Does the SFU want per-subscriber renegotiation, or is add-track-before-connect enough?** If the
   vuefix SFU only ever adds tracks before the first offer, PR 5/6 (renegotiation/rollback) can be
   deprioritised behind PR 3 and the multi-track ingest work. This changes the ordering materially.

3. **`RtpTransceiverDirection` vs reusing SDP `MediaDirection`.** Introduce a distinct
   transceiver-direction enum (proposed, matches WebRTC and keeps `Stopped` off the wire type), or
   overload the existing `MediaDirection` (`src/Keryx.Sdp/MediaDirection.cs`)? A distinct enum is
   cleaner but adds a public type and a mapping.

4. **Data channel as a transceiver, or kept separate?** This proposal keeps the SCTP m-line outside
   `Transceivers` (it is `application`, not `audio`/`video`). Confirm that is the intended boundary;
   the alternative is a unified "media description" list, which is more general but blurs the media
   vs data distinction the current code keeps clean.

5. **Multi-codec urgency.** Is single-negotiated-codec-per-m-line acceptable through PR 3, or is
   multi-codec (e.g. offering H.264 *and* VP8 and letting the peer pick) needed sooner? It changes
   whether `NegotiatedCodec` is scalar or a list from the start.

6. **Version strategy.** Is a 0.2.x patch for the invisible internal refactor (PR 2) acceptable, or
   should the whole chain land behind a single 0.3.0 minor to avoid churn on consumers?
</content>
</invoke>
