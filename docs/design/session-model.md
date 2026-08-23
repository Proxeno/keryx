# Generic transceiver / session model

Status: **reviewed and resolved — implementable spec. No implementation yet.** This document turns
Keryx's purpose-shaped media API (one fixed video m-line, one fixed audio m-line, one data
channel, offerer-centric, no renegotiation) into an `RTCRtpTransceiver`-shaped session model:
`AddTrack` / `AddTransceiver`, dynamic mids, N m-lines of any kind, per-transceiver
direction / codec / SSRC, renegotiation, and rollback — **without breaking the two shipping
consumers on the 0.2.0 API** (Proxeno, and the vuefix SFU). The open questions in §8 are decided;
implementation follows this spec as written.

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
Video and audio are always offered `sendonly` (the `SdpMediaOffer.Rtp` factory sets
`MediaDirection.SendOnly`, `src/Keryx.Sdp/SdpMediaOffer.cs:144`). There is no way to express "two
video m-lines" or "a recvonly video m-line" through this builder.

`BuildAnswer` (`PeerConnection.cs:950-1157`) mirrors the offer's sections by index and, per section,
negotiates one direction from the offered one. **The direction rule is dynamic, not a fixed local
capability** (`PeerConnection.cs:986-990`): a `recvonly` offer is answered `sendonly` — the SFU
subscriber shape, where Keryx becomes the sender — and every other offered direction answers
`recvonly` (the SFU broadcaster-ingest shape). This matters for the shim: the same `PeerConnection`,
with the same config, answers as a *sender* or a *receiver* depending on what was offered, so the
legacy behaviour cannot be reproduced by giving the auto-created transceiver one fixed direction
(see §5.3). When the negotiated direction sends, it wires the single send track by picking the
primary codec and its rtx, writing `_negotiatedVideo` / `_negotiatedAudio`
(`PeerConnection.cs:1124-1136`) and publishing the one per-kind SSRC. Two sending video sections
would both try to claim `_videoSsrc` / `_negotiatedVideo`.

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

### 1.5 The RTCP path is just as scalar as the media path

This was missing from the first draft and is in scope for the internal refactor (§6, PR 2),
because every one of these resolves "whose packet is this" through the per-kind scalars:

- `ServeNack` (`PeerConnection.Media.cs:1273-1304`) serves a NACK **only** when
  `nack.MediaSsrc == _videoSsrc`, out of `_videoTrack`'s history. A NACK against a second video
  sender's SSRC would be silently dropped.
- `IngestReportBlocks` (`PeerConnection.Media.cs:1311-1353`) classifies report blocks by
  `block.SourceSsrc == _videoSsrc / _audioSsrc` and writes the two scalar `_videoQuality` /
  `_audioQuality` snapshots.
- `SendRtcpReports` / `SendReportFor` (`PeerConnection.Media.cs:1388-1449`) iterate exactly
  `_videoTrack` and `_audioTrack`; `BuildReportBlocksFor` groups inbound stats by kind, one report
  compound per kind. `TrySendGoodbye` (`:1451`) walks the same two fields.

With N senders, RTCP dispatch must become **SSRC-keyed**: a read-mostly snapshot
`Dictionary<uint, RtpSender>` mapping every local media *and RTX* SSRC to its sender, consulted by
`ServeNack` and `IngestReportBlocks`, and the report loop iterates `Transceivers`. For the legacy
two-transceiver set this is behaviour-identical (same SSRCs resolve to the same senders).

### 1.6 SDP builder is single-shot and never versions

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

### 1.7 One transport, one SRTP context, no renegotiation, offerer-centric

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
  (Verified against the code: the claim holds, with one implementation consequence — the driver
  runs once, so a transceiver added *after* connect gets its `TrackSender` built at answer-apply
  time against the existing `_srtp`, not by re-running the driver; see §4.3.)
- **ICE candidates carry `sdpMid` for diagnostics only** (`AddIceCandidate`,
  `PeerConnection.cs:449-453`: "Recorded for diagnostics only: this connection is max-bundle …").
  `LocalIceCandidateEventArgs` exposes `SdpMid` but **no `sdpMLineIndex`**
  (`src/Keryx/PeerConnectionEvents.cs:14-33`). With one bundled transport a single mid is enough;
  the JSEP `RTCIceCandidateInit` shape browsers emit and expect carries `sdpMLineIndex`, and a peer
  that keys candidates by index needs Keryx to both emit and accept it.

### 1.8 Simulcast is already mid-keyed (the template to follow)

`_simulcastByMid : Dictionary<string, SimulcastReceiveTracker>` (`PeerConnection.Media.cs:47`) and
its accessors — `SimulcastMids` (`:316`), `GetSimulcastClassifier(mid)` (`:346`),
`GetSimulcastLayerStats(mid)` (`:355`) — are the one part of the media API that is already keyed by
**mid**, not kind. The transceiver model generalises exactly this shape to the whole media path.

### 1.9 What the shipping consumers actually call (the back-compat surface)

Verified against the consuming code, this is the exact surface that must not change:

- **Proxeno** (offerer, single video + audio + two data channels): `PeerConnectionConfig` defaults,
  `CreateOfferAsync`, `SetRemoteDescriptionAsync(answer)`, `AddIceCandidate(candidate, sdpMid)`,
  `CreateDataChannel`, `SendVideoFrame`, `SendAudioFrame`, `OnConnectionStateChanged`,
  `OnPictureLossIndication`, `OnFullIntraRequest`, `OnReceiverReport`, `CloseAsync`.
- **vuefix SFU** (broadcaster PCs answer browser `sendrecv`/`sendonly` offers as receivers;
  per-viewer subscriber PCs answer browser `recvonly` offers as senders):
  `SetRemoteDescriptionAsync(offer)`, `CreateAnswerAsync`, `SetRemoteDescriptionAsync(answer)`,
  `AddIceCandidate`, `OnRtpPacketReceived` (+ `RtpPacketInfo.Kind/Mid/Rid`),
  `TryForwardRtp(kind, …)`, `GetNegotiatedPayloadType(kind)`, `GetRemoteSsrc(kind)`,
  `SendPictureLossIndication`, the simulcast mid-keyed accessors.

Both use the *dynamic* answerer direction rule of §1.2 — the broadcaster PC and the subscriber PC
run the **same code with the same config** and diverge purely on the offered direction. Preserving
that rule under the transceiver model is a hard requirement (§5.3).

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
    public MediaDirection Direction { get; set; }

    /// <summary>The direction actually negotiated (RFC 8829), null before negotiation settles.</summary>
    public MediaDirection? CurrentDirection { get; }

    public RtpSender Sender { get; }
    public RtpReceiver Receiver { get; }

    /// <summary>The primary codec negotiated for this m-line, null before it settles.</summary>
    public NegotiatedCodec? NegotiatedCodec { get; }   // Keryx.Sdp.NegotiatedCodec — no new type

    /// <summary>Marks the transceiver stopped; the next offer emits a rejected (port 0) m-line.</summary>
    public void Stop();

    public bool Stopped { get; }
}

public sealed class RtpSender : IRtpForwarder
{
    /// <summary>The media kind this sender emits (IRtpForwarder member).</summary>
    public MediaKind Kind { get; }

    /// <summary>The local SSRC this sender owns; stable for the transceiver's life.</summary>
    public uint Ssrc { get; }

    /// <summary>The RFC 4588 rtx repair SSRC, when retransmission is negotiated for this m-line.</summary>
    public uint? RtxSsrc { get; }

    /// <summary>The negotiated send payload type, null before negotiation settles.</summary>
    public byte? PayloadType { get; }

    /// <summary>The negotiated rtx payload type, null when the peer kept no repair codec.</summary>
    public byte? RtxPayloadType { get; }

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

Decisions folded into this shape (rationale in §8):

- **`Direction` reuses `Keryx.Sdp.MediaDirection`** — no new `RtpTransceiverDirection` enum. The
  existing enum carries exactly the four values with exactly the right point-of-view semantics
  ("expressed from the owning endpoint's point of view", `src/Keryx.Sdp/MediaDirection.cs`), the
  SDP types are already load-bearing in the public config surface (`SdpCodec`, `SdpRid`), and the
  intersection helpers (`SdpDirection.Negotiate/Reverse/Sends/Receives`) apply unchanged. The
  browser quirk of `"stopped"`-as-a-direction is deliberately not copied: stopped state is the
  `Stopped` bool + `Stop()`, which is the honest model (a stopped transceiver has no direction).
- **`RtpSender` implements `IRtpForwarder`.** The SFU's hot fan-out loop holds an `IRtpForwarder`
  today; making the sender *be* one means `GetForwarder(kind)` can eventually resolve to the
  sender itself, and new-API consumers hold the sender directly with zero adapter objects.
  `SendFrame` / `TryForwardRtp` live on `RtpSender` (not the transceiver, not the connection):
  they take the connection's `_sendLock` and check `_srtp` exactly as the current public entry
  points do (`PeerConnection.Media.cs:124-133`), so the never-throws / returns-false-when-not-ready
  contract is unchanged.
- **`NegotiatedCodec` is `Keryx.Sdp.NegotiatedCodec`**, the type `SdpNegotiator` already produces
  per m-section — not a new type. The rtx payload type, which the internal `NegotiatedTrack`
  carries today, surfaces as `RtpSender.RtxPayloadType` (the legacy
  `NegotiatedVideoRtxPayloadType` shims onto it).
- `RtpSender` is a public face over the existing private `TrackSender`
  (`PeerConnection.Media.cs:1614`) — `SendFrame` / `ForwardRtp` move onto it unchanged; the sender
  holds the reference (null until negotiation wires it; the public members return 0/false/null
  until then). `RtpReceiver` is where per-mid receive state (the simulcast tracker, the remote-SSRC
  snapshot, the reception stats) attaches, generalising `_remoteVideoSsrc` / `_remoteAudioSsrc`
  (`PeerConnection.Media.cs:52-53`).
- All senders still serialise on the **one** `_sendLock`: the SRTP context is a single stream of
  protect operations and the transport-wide sequence space
  (`NextTransportWideSequenceNumber`, `PeerConnection.Media.cs:1527`) is BUNDLE-global. N
  transceivers do not get per-sender locks.

### 2.2 PeerConnection surface

```csharp
public sealed partial class PeerConnection
{
    /// <summary>Adds a transceiver for a media kind with an explicit direction. Valid before or
    /// between negotiations; the mid is allocated when the next offer is built.</summary>
    public RtpTransceiver AddTransceiver(MediaKind kind,
        MediaDirection direction = MediaDirection.SendRecv,
        RtpTransceiverInit? init = null);

    /// <summary>Convenience: add a sendonly transceiver already wired to send the given codecs.
    /// The AddTrack of this model.</summary>
    public RtpTransceiver AddTrack(MediaKind kind, IReadOnlyList<SdpCodec> codecs);

    /// <summary>Every transceiver, in m-line order. The data channel is not a transceiver.</summary>
    public IReadOnlyList<RtpTransceiver> Transceivers { get; }

    public RtpTransceiver? GetTransceiver(string mid);

    /// <summary>Raised when applying a remote offer creates a transceiver this application did not
    /// add (RFC 8829 §5.10 auto-create). Raised before CreateAnswerAsync builds the answer, so a
    /// handler may set Direction / attach to the Receiver first.</summary>
    public event EventHandler<RtpTransceiver>? OnTransceiver;
}

public sealed class RtpTransceiverInit
{
    public IList<SdpCodec> Codecs { get; }          // per-transceiver codec preference list
    public string? Mid { get; set; }                 // preferred mid when THIS side offers (e.g.
                                                     // legacy "0"); ignored when binding to a
                                                     // remote offer's m-line, whose mid wins
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
| `SendVideoFrame(annexB, ts)` | first `Video` transceiver → `Sender.SendFrame` |
| `SendAudioFrame(opus, ts)` | first `Audio` transceiver → `Sender.SendFrame` |
| `TryForwardRtp(kind, …)` | first transceiver of `kind` → `Sender.TryForwardRtp` |
| `GetForwarder(kind)` | a stable handle bound to the first-of-kind transceiver's sender |
| `GetNegotiatedPayloadType(kind)` | first-of-kind `transceiver.Sender.PayloadType` |
| `GetLocalSsrc(kind)` / `VideoSsrc` / `AudioSsrc` | first-of-kind `transceiver.Sender.Ssrc` |
| `GetRemoteSsrc(kind)` | first-of-kind `transceiver.Receiver.Ssrc` |
| `NegotiatedVideoRtxPayloadType` | first video `transceiver.Sender.RtxPayloadType` |
| `SimulcastMids` / `GetSimulcastClassifier(mid)` | already mid-keyed; unchanged |

"First of kind" is exact and stable because the constructor, in legacy mode, creates the video
transceiver before the audio transceiver (see §5). So for every existing single-video/single-audio
consumer, "the first video transceiver" *is* the only video transceiver, and every legacy call
resolves to the identical `TrackSender` it does today. The legacy per-kind methods are **not**
deprecated — they remain the ergonomic path for the single-track case indefinitely.

---

## 3. Dynamic mids, N m-lines, BUNDLE, and candidate indices

### 3.1 Mid allocation

A monotonically increasing per-session mid counter, seeded past any pinned mids. When the app calls
`AddTransceiver`, the transceiver is created with `Mid == null`; the mid is assigned when the next
offer is *built*, in insertion order, skipping mids already claimed (so a legacy transceiver pinned
to `"0"` keeps it and the counter starts the free ones after). This matches JSEP: mids are strings,
opaque, assigned by the offerer, echoed by the answerer.

`RtpTransceiverInit.Mid` is a *preference that applies only when this side builds the offer*. When
this side is the answerer, the offered mid always wins (§3.2): a transceiver bound to a remote
offer's m-line adopts the offered mid, even if it was constructed with a pinned one. This is what
keeps the legacy answerer identical — today `BuildAnswer` already echoes offered mids verbatim and
`_negotiatedVideo.Mid` records the *offered* mid, not `_config.VideoMid`
(`PeerConnection.cs:970,1124-1128`).

### 3.2 Binding remote m-lines to transceivers (RFC 8829 §5.10)

When a remote offer is applied, each RTP m-line is resolved to a transceiver by the JSEP rule:

1. If a local transceiver is already **associated** with the m-line's mid, it is updated in place.
2. Otherwise the m-line **binds to the first non-stopped, unassociated local transceiver of the
   same kind** (in `Transceivers` order), which adopts the offered mid.
3. Otherwise a transceiver is **auto-created** for the m-line and `OnTransceiver` is raised.

This single rule is what makes the legacy answerer shim fall out for free: in legacy mode the
constructor has already created one video and one audio transceiver (carrying the pre-allocated
`_videoSsrc` / `_audioSsrc`), so a browser's video+audio offer binds to them — the answer publishes
exactly the SSRCs `VideoSsrc` / `AudioSsrc` promised before negotiation, as today. Auto-creation
only happens for m-lines beyond what the local side prepared.

The **direction** of a transceiver that binds or auto-creates during offer-apply defaults to the
complement rule the answerer implements today (`PeerConnection.cs:986-990`):

- offered `recvonly` → local `SendOnly` (the peer wants media; become the sender — SFU subscriber)
- offered `sendrecv` / `sendonly` / `inactive` → local `RecvOnly` (intersection yields `recvonly`
  for the first two and `inactive` for the last, exactly today's answers)

An application that pre-added a transceiver with an explicit `Direction` keeps it — binding never
overwrites an app-set direction, and a handler of `OnTransceiver` may change the direction before
`CreateAnswerAsync` runs. With this default, `BuildAnswer`'s hard-coded rule becomes the uniform
JSEP intersection `SdpDirection.Negotiate(transceiver.Direction, offeredDirection)` with **zero
behaviour change** for both vuefix shapes (broadcaster ingest and subscriber egress) — this is the
correctness anchor for the answerer half of the golden tests (§5.4).

### 3.3 m-line ordering and recycling (JSEP §5.2.1)

JSEP fixes the m-line order for the life of the session: once a section is at index *i*, index *i*
always carries that mid (or a rejected placeholder). The design honours this by keeping
`Transceivers` append-only in m-line order and never reordering. A `Stop()`ped transceiver is not
removed; its slot emits a rejected `m=… 0 …` section (port 0, the shape `BuildAnswer` already
produces for a codec-less section, `PeerConnection.cs:1056-1069`). Recycling a stopped slot for a
new transceiver of the same kind is a **later** optimisation, explicitly out of scope for the first
cut — new transceivers always append.

### 3.4 BUNDLE

Unchanged in spirit: `SdpOfferBuilder.SetBundleGroup` already bundles every section it is handed
(`SdpOfferBuilder.cs:120-123`). With N sections the group is `BUNDLE 0 1 2 … n`. Keryx stays
max-bundle: one ICE transport, one DTLS, one SRTP context, regardless of m-line count. This is what
keeps the SRTP lifecycle trivial under renegotiation (§4.3).

### 3.5 Inbound demux becomes mid-first

This is the one internal rewrite N m-lines *forces* (§1.3). Replace the global
`_routes : Dictionary<byte, RtpRoute>` with a layered resolution:

1. **Read the MID RTP header extension** (RFC 8843 §9.2) if present → transceiver by mid. The
   parsing already exists (`ToStreamExtensions`, `PeerConnection.cs:1275-1301`); it is consulted on
   the media path, not only the simulcast path, and the header extensions are parsed **once** per
   packet, feeding both the route resolution and the simulcast classifier.
2. **Fall back to the SSRCs declared in the remote SDP** (`a=ssrc`, plus `a=ssrc-group:FID`
   members for RTX) mapping SSRC → mid, learned at description-apply time and sticky thereafter
   (an SSRC that once resolved keeps its transceiver).
3. **Fall back to payload type** within the still-unambiguous case (single m-line per kind — the
   legacy shape) — so nothing regresses for existing sessions where PTs *are* unique, including
   peers that send neither the MID extension nor `a=ssrc` lines.

The route value grows from `(Mid, Kind, ClockRate, IsRtx)` to also carry the resolved transceiver
handle, so `HandleRtp` (`PeerConnection.Media.cs:882`) dispatches to `transceiver.Receiver` instead
of writing the two scalar `_remoteVideoSsrc` / `_remoteAudioSsrc` fields. `RtpPacketInfo.Mid`
(`PeerConnectionEvents.cs:257-265`) already exists to carry the mid out to handlers — it becomes
reliably populated rather than best-effort.

**Extmap emission timing**: consuming the MID extension when a peer negotiated it (browsers offer
it on every m-line) lands with the demux rewrite (PR 1) and changes no Keryx-emitted SDP. *Offering*
the MID extmap on every RTP m-line from our side begins in PR 3 (0.3.0), where multiple same-kind
m-lines first become expressible — keeping PR 1/PR 2's "byte-identical SDP" guarantee strict, and
making the one deliberate SDP addition land in the same minor release as the feature that needs it.

### 3.6 `sdpMLineIndex` on candidates

With N m-lines the trickle-ICE candidate shape must carry the m-line index, not just the mid:

- **Emit**: add `SdpMLineIndex` (int) to `LocalIceCandidateEventArgs`
  (`PeerConnectionEvents.cs:14`), set to the index of the mid the candidate is scoped to (0 under
  max-bundle — the first mid — but now *computed*, not implied). The existing two-parameter public
  constructor **stays**; a new overload adds the index — appending an optional parameter to the
  existing constructor would be binary-breaking for a 0.2.x patch.
- **Accept**: add an optional `sdpMLineIndex` parameter to `AddIceCandidate`
  (`PeerConnection.cs:453`). Under max-bundle it still applies to the one transport, so the value is
  recorded (and used to resolve the mid when `sdpMid` is absent) rather than driving separate
  transports. This is a small, self-contained change that can land independently and ahead of the
  rest (§6) because it does not depend on the transceiver refactor — it only depends on *emitting a
  correct index*, which needs the m-line order, which the session already has. The candidate-mid
  selection in `EnsureIceLocked` (`PeerConnection.cs:735-737`) moves off the config mids to "first
  m-line's mid" at the same time.

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

- `stable` + `CreateOfferAsync` → `have-local-offer`
- `have-local-offer` + `SetRemoteDescriptionAsync(answer)` → `stable`
- `stable` + `SetRemoteDescriptionAsync(offer)` → `have-remote-offer`
- `have-remote-offer` + `CreateAnswerAsync` → `stable`
- any non-stable + rollback → `stable`

**No public `SetLocalDescription` is introduced.** Keryx's `CreateOfferAsync` /
`CreateAnswerAsync` remain create-and-apply — both shipping consumers depend on that flow, it is
the ergonomic shape for a library (the modern browser API converged on parameterless
`setLocalDescription()` for the same reason), and the state machine transitions perfectly well on
the existing methods. Splitting create from apply adds a public API surface, a new failure mode
(created-but-never-applied descriptions), and migration churn, and buys nothing this stack needs —
Keryx never produces an offer it does not intend to apply. If a concrete need appears later
(offer-options preview), it can be added additively.

`CreateOfferAsync` (`PeerConnection.cs:323`) stops being once-only: from `stable` it builds an offer
that reflects the *current* transceiver set (including ones added since the last negotiation).
Glare is an error until rollback lands: `SetRemoteDescriptionAsync(offer)` in `have-local-offer`
throws.

### 4.2 Repeat offer/answer, adding and removing m-lines

A renegotiation offer re-emits every existing section **at its fixed index with its fixed mid**
(§3.3), plus any appended transceivers, plus rejected placeholders for stopped ones. Three
`o=`-line rules (RFC 8829 §5.2.2): the **session id stays constant** for the connection's life, the
**`SessionVersion` increments** per generated description (`SdpOfferBuilder.cs:23` — the field
exists precisely for this), and a renegotiation offer **does not re-gather ICE**: the existing
credentials and candidates are re-emitted (an ICE restart is a separate, deferred feature; §7).

`SdpNegotiator` already validates count/order/mid alignment (`SdpNegotiator.cs:33-60`) — that
validation becomes *more* important, not less, and mostly already holds. The per-section
`NegotiatedMedia` (`NegotiatedMedia.cs`) is applied to the matching transceiver by index/mid,
updating its `CurrentDirection` and `NegotiatedCodec` in place.

Description application becomes **incremental, not wholesale**: today `ApplyAnswer` /
`ApplyRemoteOffer` rebuild `_routes` from scratch and overwrite the negotiated scalars — a
mid-session re-apply must instead update each transceiver in place and must not disturb live
senders' sequence/timestamp/rtx state or the pinned `_sendTransportCcExtensionId` (the
transport-wide sequence space is BUNDLE-global and mid-session; the id fixed by the first
negotiation stays fixed).

Direction changes on an existing transceiver (e.g. `sendrecv` → `inactive` to pause) flow through
the same per-section direction intersection (§3.2), now driven by `transceiver.Direction`.

### 4.3 SRTP / RTP context survives renegotiation untouched

The key simplification, restated as a guarantee: **a renegotiation that only adds/removes/repoints
m-lines does not re-run DTLS and does not re-derive SRTP.** Because everything is one BUNDLE
transport, the SRTP context (`_srtp`, derived at `PeerConnection.Media.cs:635-659`) and every
stream's sequence/timestamp/rtx state stay valid across the exchange. The connection driver runs
once; a transceiver added after connect has its `TrackSender` built at answer-apply time (the
`CreateTrackSenders` logic, `PeerConnection.Media.cs:739`, refactored to per-transceiver so it can
run both from the driver and from a mid-session apply) against the *existing* SRTP context. Nothing
rekeys. This is why the transceiver model is achievable without touching the DTLS layer's
no-renegotiation stance (`DtlsTransport.cs:811,982`): SRTP rekeying and DTLS renegotiation are a
*separate, later* concern (§7) that only an ICE restart forces.

### 4.4 Rollback

Rollback (`SetRemoteDescriptionAsync(sdp: rollback)` and a local `Rollback()` for a pending local
offer) returns a non-stable state to `stable`, discarding the pending description. Concretely: keep
the last stable `_localDescription` / `_remoteDescription` and the transceiver snapshot; on
rollback, restore them and drop any transceiver that existed *only* to satisfy the pending offer
(one auto-created for an offered m-line that is now being rolled back). Transceivers added by the
application are not destroyed — they revert to "not yet negotiated" (`Mid` returns to null if the
rolled-back offer assigned it). Because no SRTP/transport work happens until an answer is applied
and the driver starts, rollback before `stable` has no transport-teardown to undo; it is a pure
description/transceiver-set revert. Neither shipping consumer can hit glare (Proxeno always offers,
each vuefix PC always answers), which is why rollback is last in the phasing and may trail
indefinitely without blocking anything.

---

## 5. Migration and back-compat

Both shipping consumers (Proxeno, vuefix SFU) are on the 0.2.0 per-kind API (§1.9). **Nothing they
call may change signature or semantics.** The strategy is *the legacy API as a thin shim over the
new model*, introduced in one internal refactor with no public break, then the new API added on top.

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
values. `BuildOffer` / `BuildAnswer` are rewritten to walk `Transceivers` instead of the two `if`
blocks, but for the legacy transceiver set they emit **byte-identical** SDP (same mids, same order,
same directions, same codecs).

### 5.2 The legacy methods delegate

`SendVideoFrame` / `SendAudioFrame` / `TryForwardRtp` / `GetForwarder` / the introspection accessors
keep their exact signatures (`PeerConnection.Media.cs:115,146,199,250,262-310`) and become
one-liners resolving "first of kind" (§2.3). `GetForwarder(kind)` still returns a stable handle for
the connection's life — it binds to the first-of-kind transceiver, whose identity never changes in
the legacy shape. The subscriber-egress path the SFU drives (`TryForwardRtp`, `IRtpForwarder`) is
semantically identical because it still forwards onto the one video/audio send SSRC. Per-kind
stats (`VideoStats` / `AudioStats` inside `GetStats`) resolve first-of-kind the same way; a
per-transceiver stats list is additive in PR 3.

### 5.3 The answerer shim: binding, mids, and the direction rule

The subtle half of back-compat is the answerer, and §3.1–3.2 carry it:

- The constructor-created legacy transceivers exist *before* `SetRemoteDescriptionAsync(offer)`,
  so a browser's video+audio offer **binds** to them (rule 2 of §3.2) — they adopt the *offered*
  mids (the pinned `"0"`/`"1"` apply only to self-built offers, matching today, where `BuildAnswer`
  echoes offered mids) and keep their pre-allocated SSRCs, so an answer publishes the same
  `a=ssrc` values `VideoSsrc`/`AudioSsrc` promised.
- The **complement-direction default** of §3.2 reproduces `BuildAnswer`'s dynamic rule exactly:
  browser `sendrecv` offer → bound transceiver `RecvOnly` → answer `recvonly` (vuefix broadcaster
  ingest, unchanged); browser `recvonly` offer → bound transceiver `SendOnly` → answer `sendonly`
  with the send track wired (vuefix subscriber egress, unchanged). This rule is *mandatory*: giving
  legacy transceivers any one fixed direction would silently flip one of the two shipped answerer
  shapes.

### 5.4 The correctness anchors (tests that gate PR 2)

1. **Golden offer SDP**: default config offer is byte-identical before/after the refactor.
2. **Golden answer SDP ×3**: answers to a captured browser `sendrecv` offer, `recvonly` offer, and
   simulcast offer are byte-identical before/after.
3. **RTCP dispatch parity**: NACK service, report-block ingestion and sender-report emission
   resolve through the SSRC-keyed dispatch (§1.5) to the same senders as the scalar fields did —
   asserted by the existing retransmission/loopback tests staying green.
4. **Introspection parity**: every §2.3 legacy member returns the identical value pre/post refactor
   across offerer and answerer flows.

### 5.5 Phased rollout

1. **Internal refactor, no public change** (§5.1–5.4): introduce `RtpTransceiver` internally, make
   the legacy API a shim, prove byte-identical SDP and green tests. Ships as **0.2.x** — consumers
   see nothing.
2. **Additive public API** (§2): expose `AddTransceiver` / `Transceivers` / `RtpSender` etc. Ships
   as **0.3.0** — purely additive, consumers opt in when ready.
3. **Renegotiation machinery** (§4): additive; the single-shot path still works. Ships as **0.4.0**.

---

## 6. Phasing into landable PRs

Ordered by dependency. Each is independently reviewable and shippable. Renegotiation/rollback are
deliberately *behind* the public API: neither shipping consumer needs them (the SFU adds tracks
before connect and opens one PC per viewer — verified in the gateway code), so PR 3 is the payoff
milestone and PRs 4–6 land at leisure.

**PR 0 — `sdpMLineIndex` on candidates** *(0.2.x)*. Add `SdpMLineIndex` to
`LocalIceCandidateEventArgs` via a new constructor overload (keep the existing one — binary
compat), an optional index param on `AddIceCandidate`, and compute the emitted index/mid from the
m-line order instead of the config mids. Self-contained, no transceiver dependency.
(`PeerConnectionEvents.cs:14`, `PeerConnection.cs:453,735-740`.)

**PR 1 — mid-first inbound demux** *(0.2.x)*. Replace PT-keyed `_routes` with the layered
resolution of §3.5 (MID extension → remote-SDP SSRC map → PT fallback), parsing header extensions
once per packet and sharing the result with the simulcast classifier. No public API change, no
emitted-SDP change; behaviour identical for single-m-line-per-kind. *Unblocks*: N m-lines of the
same kind; multi-codec-per-m-line demux. (`PeerConnection.Media.cs:46,882-901`;
`PeerConnection.cs:1159-1249,1303-1440`.)

**PR 2 — internal transceiver model + legacy shim + SSRC-keyed RTCP dispatch** *(0.2.x)*.
Introduce `RtpTransceiver` / `RtpSender` / `RtpReceiver` internally; constructor builds the legacy
transceivers; `BuildOffer`/`BuildAnswer` walk `Transceivers` with the §3.2 binding + direction
rules; legacy methods delegate; RTCP NACK/report/goodbye paths key on the local-SSRC → sender map
(§1.5). Gated by the four §5.4 anchors. *Dependency*: PR 1.
(`PeerConnection.cs:797-1157`; `PeerConnection.Media.cs:36-39,739-819,1273-1353,1388-1494,1614`.)

**PR 3 — public `AddTransceiver` / `AddTrack` / `Transceivers` / sender & receiver surface +
`OnTransceiver`** *(0.3.0)*. Expose the model; N transceivers of any kind/direction from the
offerer; answerer binding/auto-create per §3.2 with the `OnTransceiver` event; offer the MID
extmap on every RTP m-line (§3.5); additive per-transceiver stats list on `GetStats`.
*Dependency*: PR 2. *Unblocks*: recvonly video ingest without the recvonly-offer trick; multiple
published tracks; SFU multi-track subscriber PCs (add-before-connect).

**PR 4 — signaling state machine + `OnNegotiationNeeded`** *(0.4.0 chain)*. Replace `_isOfferer`;
model `stable`/`have-local-offer`/`have-remote-offer` on the *existing* create/apply methods — no
public `SetLocalDescription` (§4.1). *Dependency*: PR 3. (`PeerConnection.cs:81-86,323-442`.)

**PR 5 — renegotiation** *(0.4.0)*. Repeat offer/answer; add/remove/repoint m-lines; constant
session id + `SessionVersion` bump; no ICE re-gather; incremental description apply (§4.2);
mid-session `TrackSender` creation against the live SRTP context (§4.3). *Dependency*: PR 4.
Proves the SRTP-survives-untouched guarantee with a test that adds a second video transceiver
mid-session and asserts the SRTP context object is unchanged while both senders stream.

**PR 6 — rollback** *(0.4.x, lowest priority)*. `SetRemoteDescriptionAsync(rollback)` + local
`Rollback()` (§4.4). *Dependency*: PR 5. May trail indefinitely; nothing shipped needs glare
handling.

---

## 7. Explicitly deferred (noted for what they unblock)

- **ICE restart** — needs the signaling machine (PR 4) plus ICE credential re-gather and, on a new
  DTLS handshake, SRTP re-derivation. This is the *only* path that rekeys SRTP; the DTLS layer's
  no-renegotiation stance (`DtlsTransport.cs:811,982`) means an ICE restart implies a fresh
  handshake on the new transport, not in-place DTLS renegotiation.
- **Multi-codec per transceiver** — needs PR 1 (demux) + a negotiated-codec *list* on the
  transceiver instead of the scalar `NegotiatedCodec`. Note the receive side is already
  multi-codec-tolerant (`_routes` admits every acceptable PT); it is the send side that is scalar.
- **SRTP rekeying** — only ICE-restart / DTLS-rehandshake forces it; ordinary renegotiation (PR 5)
  deliberately avoids it (§4.3).
- **m-line recycling** of stopped slots — a compaction optimisation on top of PR 5/6.

---

## 8. Decisions (resolved)

Formerly the open questions; each is decided here and reflected in the body above.

1. **Answerer auto-create — RESOLVED: yes, via the JSEP §5.10 binding rule (§3.2), with
   `OnTransceiver` for auto-created ones.** Binding-then-auto-create (rather than always-create) is
   what lets the legacy constructor-made transceivers claim a browser offer's m-lines and keep
   their pre-allocated SSRCs — auto-create alone would have broken the answerer's published-SSRC
   guarantee. The event fires before `CreateAnswerAsync` so a handler can set direction first.

2. **SFU needs only add-track-before-connect — RESOLVED: yes; renegotiation drops behind the
   public API.** Verified in the vuefix gateway: one PC per viewer, one `CreateAnswerAsync`, no
   second negotiation anywhere. PR 3 (0.3.0) is the payoff milestone; PRs 4–6 are a follow-on
   chain (0.4.0) with rollback last and non-blocking.

3. **Direction enum — RESOLVED: reuse `Keryx.Sdp.MediaDirection`; no new enum.** It has exactly
   the right four values and point-of-view semantics, the SDP types are already public API surface
   (`SdpCodec` in the config), and `SdpDirection.Negotiate/Reverse` apply unchanged. `Stopped` is
   correctly a bool on the transceiver, not a fifth direction — the browser's
   `"stopped"`-as-direction is a quirk not worth copying.

4. **Data channel — RESOLVED: stays outside `Transceivers`.** It is `m=application` with no
   sender/receiver/codec/SSRC semantics; the browser API models it outside transceivers too. The
   only interaction is m-line ordering, which the internal section list (transceivers + the one
   application section) handles.

5. **Codec scalar vs list — RESOLVED: scalar `NegotiatedCodec` through PR 3**, typed as the
   existing `Keryx.Sdp.NegotiatedCodec` (no new type), with `RtpSender.RtxPayloadType` alongside.
   The receive path already tolerates multiple PTs per m-line; only the send path is scalar, and
   neither consumer needs send-side multi-codec today. The list upgrade is additive later
   (a `NegotiatedCodecs` list whose first element the scalar property mirrors).

6. **Versioning — RESOLVED: PR 0–2 as 0.2.x patches, PR 3 as 0.3.0, PR 4–5 as 0.4.0, PR 6 as
   0.4.x.** The invisible refactor is semver-legal as a patch and both consumers are in-house;
   the two deliberate surface changes (public model; MID extmap in offers) land together in 0.3.0.
   Binary compatibility is held even in patches (constructor overload rather than added optional
   parameter, §3.6).

Decisions on gaps the first draft missed:

7. **RTCP dispatch generalisation — RESOLVED: in scope for PR 2.** `ServeNack`,
   `IngestReportBlocks`, the report loop and the RTCP BYE all resolve senders through the scalar
   per-kind fields today (§1.5); they move to a local-SSRC → sender snapshot in the same refactor,
   or a second video sender would get no NACK service, no quality snapshot and no sender reports.

8. **Answerer direction policy — RESOLVED: the complement-direction default (§3.2) is the
   binding/auto-create default in all modes.** It reproduces the shipped dynamic rule exactly and
   remains overridable per transceiver via `Direction` (before answering) — strictly more capable
   than today with zero behaviour change by default.

9. **`RtpSender` implements `IRtpForwarder`, and `SendFrame`/`TryForwardRtp` live on the sender —
   RESOLVED: yes.** The SFU fan-out contract (never throws, false when not ready, stable handle)
   is preserved by construction, and new-API consumers need no adapter object.

10. **No public `SetLocalDescription` — RESOLVED (§4.1).** Create-and-apply stays; the signaling
    state machine transitions on the existing methods. Additive later if ever needed.

11. **MID extmap emission — RESOLVED: consume from PR 1, emit from PR 3 (§3.5)** — keeps the
    byte-identical-SDP gate strict through the invisible phase.
