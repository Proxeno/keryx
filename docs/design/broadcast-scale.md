# Broadcast fan-out at scale

Status: **proposed design — no implementation.** §5 (shared-key encrypt-once broadcast) **requires
explicit owner sign-off before any code lands**; everything else is implementable as specified once
the §6 phasing decisions are taken. This document designs the path from today's SFU shape (one
`PeerConnection` per viewer, one socket per connection, one encrypt per delivered packet) to
Twitch/concert-style broadcast: **one ingest → tens of thousands of viewers at 480p–720p**, pushed
until the limiting resource is the NIC itself.

Every number in this document is measured, on this codebase, by the harnesses in
`benchmarks/Keryx.Benchmarks`, `benchmarks/Keryx.ScaleHarness`, and `benchmarks/Keryx.ScalingSpike`
(see `benchmarks/README.md`). The design is a straight line through those measurements: the walls
are known, the levers are measured, and each section below spends exactly one lever.

The through-line: today every per-viewer cost is O(N) in three currencies — crypto CPU, send
syscalls, and sockets. The measured data says **syscalls bind first, crypto second, and the NIC
last**. So the architecture, in priority order: put many viewers on one socket so sends can batch
(§2), batch them (§3), parallelise the remaining per-viewer crypto (§4), and — for the public
broadcasts where it is safe — collapse N encrypts to one (§5).

---

## 1. The scaling ladder — measured baseline, levers, and the wall

### 1.1 The unit costs

All figures at the ~1200-byte target packet size, single core, `AEAD_AES_128_GCM`, 0 alloc/op on
the steady path:

| Per-packet operation | Measured rate | Source |
| --- | --- | --- |
| SRTP-GCM protect (encrypt) | **~602k pkt/s/core** | `Keryx.Benchmarks` `SrtpBenchmarks` |
| Managed `Socket.SendTo` (1 syscall/datagram) | **~283k datagram/s/core** | `Keryx.ScaleHarness` arm 4 |
| Forward-rewrite (`RtpForwarder.TryForward`) | negligible vs the above | `Keryx.Benchmarks` `ForwardBenchmarks` |
| Ingest receive path (post-SRTP) | negligible; O(1) in viewers | `Keryx.Benchmarks` `ReceivePathBenchmarks` |
| Fan-out state per subscriber (forwarder + SRTP context) | **~7 KB** | `Keryx.ScaleHarness` arm 2 |

A 720p viewer is ~2 Mbps of media at **~300 pkt/s** (the harnesses' model, `Keryx.ScalingSpike`
`Program.cs:32`), ~2.88 Mbps on the wire with RTP/SRTP/UDP/IP overhead.

So per core, today's per-viewer data path (one forward + one encrypt + one `SendTo` per delivered
packet) serves:

- **crypto ceiling**: 602k / 300 ≈ **2,000 viewers/core**
- **send ceiling**: 283k / 300 ≈ **940 viewers/core**

**The send syscall is the tightest wall — it binds a full 2.1× before crypto does.** This ordering
drives the whole design: an architecture that only parallelises encryption doubles down on the
resource that was never the bottleneck. I/O first.

Memory is not on the ladder at all: ~7 KB/subscriber is ~70 MB at 10k viewers and ~245 MB at 35k.
(The *full* per-viewer `PeerConnection` object graph measured by ScaleHarness arm 3 is larger, but
still not a wall; the per-viewer *socket*, measured by the same arm's live variant, is the resource
§2 exists to eliminate.)

### 1.2 The measured levers

`Keryx.ScalingSpike` measured each lever in isolation:

| Lever | Measured effect | Spike arm |
| --- | --- | --- |
| Parallel per-subscriber SRTP (worker pool, each worker owns its contexts) | **~linear scaling** with core count on homogeneous cores | Arm A |
| Shared-key encrypt-once (1 encrypt + N ciphertext copies) | **48–87× reduction in crypto cost** at N = 100–10,000; the path degenerates to memcpy | Arm B |
| `sendmmsg(2)` batched sends vs `SendTo` loop | **1.74× datagram rate**, **39× fewer syscalls** at batch 64 | Arm C (Linux) |

### 1.3 The end wall, and the ladder

The wall that no software lever moves: **NIC bandwidth**. At ~2.88 Mbps/720p viewer:

| NIC | Viewer ceiling (720p) |
| --- | --- |
| 10 GbE | ~3,500 |
| 25 GbE | ~8,700 |
| **100 GbE** | **~35,000** |

The ladder, with the CPU budget at each rung for a 10k-viewer / 3M pkt/s broadcast:

| Rung | Sends | Crypto | Binding resource |
| --- | --- | --- | --- |
| Today (per-viewer PC, `SendTo` loop) | ~10.6 cores | ~5.0 cores | send syscalls |
| + shared socket (§2) + sendmmsg (§3) | ~6.1 cores | ~5.0 cores | roughly balanced |
| + parallel SRTP shards (§4) | ~6.1 cores | ~5.0 cores, now actually parallel | CPU, scaling ~linearly |
| + shared-key encrypt-once (§5, public broadcasts only) | ~6.1 cores | **~0.02 cores** | send syscalls again |
| ceiling | — | — | **NIC: ~35k viewers / 100 GbE** |

At the 35k NIC ceiling (10.5M pkt/s) the batched-send path needs ~21 cores and per-viewer-key
crypto ~17 — both comfortably inside one modern socketed box. **The design goal is therefore
concrete and finite: reach the NIC wall on one box with cores to spare.** Beyond it is multi-box
sharding, deferred to §7.

---

## 2. Shared-socket fan-out transport — the architectural crux

### 2.1 Today: one viewer = one connection = one socket, so nothing can batch

The current composition gives every viewer their own transport stack, bottom to top:

- `PeerConnection` lazily builds its own `IceAgent` (`src/Keryx/PeerConnection.cs:1057-1088`).
- The agent creates and binds **its own UDP socket** (`src/Keryx.Ice/IceAgent.cs:862-890` — one
  dual-mode socket per agent, its own ephemeral port, its own receive loop) and every outbound
  datagram is one `socket.SendTo` on that private socket (`IceAgent.cs:2579`).
- DTLS, and the SRTP context derived from its RFC 5705 exporter
  (`src/Keryx/PeerConnection.Media.cs:743-760`), are likewise per-connection.

This is exactly right for a peer, and structurally wrong for a broadcaster. With N viewers there
are N sockets, N ports, N receive loops — and, decisively, **per ingest packet the N outbound
datagrams are spread one-per-socket across N sockets, so no single socket ever holds more than one
datagram to send.** `sendmmsg` batches datagrams *on one socket*; against the current model it has
nothing to batch (`vlen == 1` everywhere). The §1.2 send lever is unreachable without an
architectural change. That change is this section.

### 2.2 The design: a `BroadcastEndpoint` — one (or a few) sockets, demuxed by 5-tuple

Introduce a server-side broadcast transport, tentatively `Keryx.Broadcast` (composition decision in
§6): a **`BroadcastEndpoint`** owning a small fixed set of UDP sockets — one per send worker (§4),
all bound to one well-known port via `SO_REUSEPORT` — through which **every viewer of the broadcast
is served**. Single-port multiplexing is the standard production-SFU shape (mediasoup, Janus,
LiveKit all converged on it); Keryx's layering makes it unusually cheap to adopt, because the seam
already exists:

> `Keryx.Core.IDatagramTransport` (`src/Keryx.Core/IDatagramTransport.cs:15`) is "an unreliable,
> message-oriented, bidirectional pipe". ICE exposes its selected pair as one; DTLS consumes one.
> Nothing above ICE knows about sockets.

**Inbound demux (the receive loop, one per socket, O(1) in viewer count):**

1. **By 5-tuple**: source `IPEndPoint` → `ViewerSession`, via a read-mostly snapshot dictionary.
   Viewers are NAT'd; their reflexive address is learned exactly as ICE learns it today.
2. **First contact**: a packet from an unknown source is, per ICE, a STUN Binding request; demux it
   by the **USERNAME attribute's local ufrag** (each viewer's session has a unique local ufrag from
   its SDP answer) → bind that 5-tuple to the viewer, then fall into rule 1. Non-STUN from unknown
   sources is dropped.
3. Within a viewer's session, the existing RFC 7983 first-byte classification (STUN / DTLS / SRTP —
   `docs/architecture.md`, "The wire path") routes to that viewer's ICE / DTLS / SRTP handling,
   unchanged.

**Outbound**: each `ViewerSession` carries its confirmed remote endpoint; a send is
`(payload, endpoint)` enqueued on the shared socket owned by the viewer's shard — which is what
finally gives one socket **N datagrams per ingest packet** to hand to §3.

**Per-viewer layers over the shared socket:**

- **ICE** — the one layer that genuinely changes. `IceAgent` owns socket creation, binding, and the
  receive loop; that ownership must invert. Add an **ICE endpoint-session mode** to `Keryx.Ice`: an
  `IceEndpointSession` that performs the server side of connectivity checks (answer Binding
  requests, validate ufrag/password, nominate) over datagrams *handed to it* by the
  `BroadcastEndpoint`, and emits candidates advertising the shared port. Functionally this is
  ICE-lite from the viewer's perspective (one host/server-reflexive candidate at a fixed port,
  controlled role), which is precisely the SFU shape and what browsers exercise against every
  production SFU. The full `IceAgent` remains untouched for peer use and for the ingest leg.
- **DTLS** — unchanged in code, changed in plumbing: each viewer runs their own `DtlsTransport`
  handshake over a per-viewer `SharedSocketTransport : IDatagramTransport` (writes go to the shared
  socket tagged with the viewer's endpoint; reads are the demuxed datagrams). Every viewer still
  gets their **own certificate verification, own handshake, own exported keys**.
- **SRTP** — unchanged: per-viewer `SrtpEncryptContext` from that viewer's DTLS exporter. §5 is a
  separate, opt-in departure; the shared *socket* does not weaken any cryptographic boundary — it
  only changes which file descriptor the ciphertext leaves through.
- **SCTP / data channels** — unchanged, riding the viewer's DTLS as today.

**State isolation**: all per-viewer state — ICE session, DTLS, SRTP, forwarder, pacer, congestion
controller, RTCP state — lives in one `ViewerSession` object owned by **exactly one** shard worker
(§4). The only cross-viewer shared objects are the socket fds and the demux snapshot. No per-viewer
lock is needed anywhere on the hot path, because ownership replaces locking (§4.2).

### 2.3 Contrast

| | Per-viewer socket (today) | Shared socket |
| --- | --- | --- |
| Sockets / ports / receive loops | N | K (≈ send workers), fixed |
| Outbound datagrams per socket per ingest packet | 1 — **nothing to batch** | ~N/K — **the sendmmsg batch** |
| Receive/decrypt/packetize of ingest | O(1) (one ingest PC) | O(1), unchanged |
| Viewer-inbound processing | N loops for ~keepalives + RTCP | 1 loop per socket, 5-tuple demux |
| ICE | full agent per viewer, own socket | endpoint session per viewer, shared socket |
| DTLS / SRTP / keys | per viewer | per viewer, **unchanged** |
| Firewall/ops surface | N ephemeral ports | one advertised media port |

The ingest leg (broadcaster → SFU) stays a completely ordinary `PeerConnection`. This design is
about the egress fan-out only.

---

## 3. Batched sends — `sendmmsg` on the shared socket

### 3.1 The primitive

The spike proved the mechanism end-to-end on Linux (`Keryx.ScalingSpike/SendMmsgArm.cs`): one
`sendmmsg(2)` call carrying B datagrams to B *distinct destinations* — the exact fan-out shape —
measured **1.74×** the `SendTo` loop's datagram rate with **39× fewer syscalls** at B=64. The ABI
struct layouts (`mmsghdr`/`msghdr`/`iovec`/`sockaddr_in`, `SendMmsgArm.cs:206-240`) are validated
by that spike on amd64 and arm64 and carry over as written.

Productionised as an internal `Keryx.Core` primitive (the layer that already owns the transport
seam), roughly:

```csharp
internal readonly record struct DatagramBatchEntry(ReadOnlyMemory<byte> Payload, IPEndPoint Destination);

internal interface IBatchDatagramSender
{
    /// <summary>Sends the batch; returns datagrams actually sent. Never throws on the hot path.</summary>
    int SendBatch(ReadOnlySpan<DatagramBatchEntry> batch);
}
```

- **P/Invoke boundary**: one `[DllImport("libc")] sendmmsg` (Linux-only), wrapped in a class that
  pre-allocates and reuses the unmanaged `mmsghdr`/`iovec`/`sockaddr` arrays per socket (as the
  spike does — zero per-call allocation). This is the **one deliberate exception** to the
  pure-managed rule, exactly as the baseline analysis called it (`SendMmsgArm.cs:14-15`): the BCL
  exposes no `sendmmsg` or GSO, and the syscall wall is the tightest wall. The exception is narrow
  (one syscall, one file, feature-detected), optional (see fallback), and does not touch any
  protocol layer.
- **Managed fallback**: a `SendTo`-loop implementation behind the same interface. Selection is
  runtime feature detection at endpoint construction — non-Linux, or a first call failing
  `ENOSYS`/`EOPNOTSUPP`, permanently selects the fallback. Behaviour is identical; only the rate
  differs. macOS dev boxes run the fallback natively and the real path in the container the spike
  already ships (`sendmmsg-linux.Dockerfile`).
- **Partial sends and errors**: `sendmmsg` may send a prefix; retry the remainder, treating
  `EINTR`/`EAGAIN`/`ENOBUFS` as retry-with-bounded-spin and anything else as drop-and-count (a
  broadcast fan-out must never let one viewer's error stall the batch — same never-throws contract
  as the send path today). `vlen` is capped (`UIO_MAXIOV` = 1024; in practice the shard's viewer
  slice per flush, typically 64–512).

### 3.2 How it plugs into the shared-socket path

Per ingest packet, each shard worker (§4) produces its slice of per-viewer datagrams into a
per-worker batch buffer and flushes it with **one** `SendBatch` on **its own** shared socket. Batch
composition is natural, not timer-driven: the batch *is* "this ingest packet, for my viewers" —
there is no added latency beyond the encrypt loop itself, and flush granularity equals ingest
packet granularity (~300/s), far below any pacing concern.

### 3.3 UDP-GSO: the other batching axis, deliberately secondary

`UDP_SEGMENT` (GSO) batches differently: **one large buffer, kernel-segmented into equal-size
datagrams, all to one destination**. That is the wrong shape for the N-destination fan-out — it
cannot spread one payload across N viewers. It is the *right* shape for per-viewer packet trains:
a keyframe's FU-A run or a pacer burst to a single viewer. The two compose (each `msghdr` in a
`sendmmsg` batch can carry its own GSO cmsg and destination), but GSO brings real caveats — equal
segment sizes with only the last short, driver/NIC dependence, silent fallback costs — for a win
on a path (`per-viewer trains`) that is not the measured bottleneck. **Decision: `sendmmsg`
multi-destination batching is the primary and only committed mechanism; GSO is a measured-later
optimisation** behind the same `IBatchDatagramSender` seam, adopted only if a spike shows the
per-viewer-train win justifies it.

---

## 4. Parallel per-subscriber SRTP — sharded ownership feeding the batch

### 4.1 The pipeline

Arm A measured the worker-pool encrypt scaling **~linear on homogeneous cores** — per-subscriber
SRTP is embarrassingly parallel *provided each context has exactly one owner*. The broadcast data
path becomes a two-stage pipeline:

**Stage 1 — ingest (one thread, O(1) in N):** receive → SRTP unprotect → depacketize/classify
(simulcast layer, keyframe flag) — the path `ReceivePathBenchmarks` measures as negligible — then
publish an immutable, ref-counted `IngestPacketView` to each shard's SPSC ring. One decrypt, one
parse, regardless of viewer count.

**Stage 2 — shards (K workers, K ≈ physical cores budgeted for egress):** each shard owns a fixed
slice of `ViewerSession`s and, per ingest packet, runs for each viewer:

1. pacer/congestion gate (below) — skip or queue if over budget;
2. forward-rewrite onto the viewer's SSRC/sequence space (`RtpForwarder.TryForward`,
   `src/Keryx.Rtp/Simulcast/RtpForwarder.cs:46`) including per-viewer TWCC extension stamping;
3. SRTP protect under the viewer's own `SrtpEncryptContext`;
4. append `(ciphertext, viewerEndpoint)` to the shard's batch;

then one `SendBatch` flush on the shard's socket (§3.2). Steady-state allocation is zero: the
forward/encrypt/output buffers are per-viewer and reused, exactly as `Keryx.ScaleHarness`'s
`FanOutPath` models.

### 4.2 Thread-safety by ownership, not locking

`SrtpEncryptContext` (`src/Keryx.Srtp/SrtpEncryptContext.cs:20`) is deliberately not thread-safe —
it owns sequence/ROC state and refuses index reuse. The same is true of the forwarder, pacer, and
congestion controller. The rule is therefore structural: **every `ViewerSession` is owned by
exactly one shard; no session object is ever touched from two threads.** Viewer add/remove is a
message to the owning shard, not a cross-thread mutation; the shard applies it between flushes.
This replaces the per-connection `_sendLock` that serialises today's `PeerConnection` send path
(`src/Keryx/PeerConnection.Media.cs:31`) — that lock exists because API callers race the
connection; a shard has no racing callers. Viewer-inbound traffic (RTCP, NACKs, keepalives)
demuxed by §2 is likewise routed to the owning shard's ring, so RTCP state shares the same single
owner.

One measured caveat from Arm A carried into capacity planning: "~linear" was measured on
homogeneous cores. On hybrid parts (P/E cores) shard placement should pin to one core class or
size slices per-core, or tail latency follows the slowest shard.

### 4.3 Composition with pacing and congestion control

Per-viewer congestion state (`PacketPacer`, `GccCongestionController` —
`src/Keryx.Rtp/CongestionControl/`) lives inside the `ViewerSession`, evaluated at step 1 *before*
encrypt — a congested viewer costs no crypto and no batch slot; its packets queue in its own pacer
or its simulcast tier is stepped down. Crucially, **a slow viewer drops out of the batch rather
than stalling it**: the batch is composed only of viewers cleared to send now. TWCC feedback
arrives on the shard that owns the viewer, so estimator state needs no synchronisation. RTX
retransmission serves NACKs from the viewer's own send history on the owning shard, off the
batch path.

---

## 5. Shared-key encrypt-once broadcast mode — **owner sign-off required**

Arm B measured the prize: encrypt once and the per-viewer crypto cost collapses by **48–87×**
(N = 100–10k), leaving a memcpy-rate fan-out bounded only by §3's send path and the NIC. This
section specifies the mechanism, the API, and — most importantly — the security boundary. **This
mode must not exist in the codebase until the owner has signed off on §5.4 as written.**

### 5.1 The mechanism — and the honest interop verdict first

**Standard WebRTC cannot do this.** DTLS-SRTP (RFC 5764) derives each connection's SRTP keys from
that connection's DTLS handshake via the RFC 5705 exporter — which is exactly what Keryx does
today (`src/Keryx/PeerConnection.Media.cs:743-760`). Two viewers' keys are distinct by
construction; no signaling extension, SDP trick, or server behaviour can make two stock browsers
derive the same SRTP key. Nor can a browser accept an externally supplied key: no browser API
reaches the SRTP layer (Encoded Transform / insertable streams operate on encoded frames *above*
packetization — usable for app-layer E2EE, not for replacing transport keys). RFC 8870 (EKT), the
IETF's design for exactly this shared-key-conference shape, ships in no browser.

**Verdict: shared-key mode is not interoperable with stock browsers, and this design does not
pretend otherwise.** It requires a client whose SRTP layer accepts an injected key — i.e. a
Keryx-based client (native apps, embedded players, server-side components) or any custom stack
with the same hook. The signaling extension is Keryx-defined (below), not a standard.

Two consequences make the mode valuable anyway:

1. **Hybrid service is first-class.** A broadcast serves both populations simultaneously: stock
   browsers on the per-viewer path (§2–§4, full standard interop), shared-key clients on the
   encrypt-once path. One shared-key encrypt per packet plus per-viewer encrypts only for the
   browser population.
2. **Relay legs are custom clients by definition.** In the multi-box tree of §7, SFU→relay and
   relay→relay hops are Keryx↔Keryx: encrypt-once applies to the entire distribution tree even
   when every leaf viewer is a stock browser. A relay holding the broadcast key does **zero
   crypto** for shared-key downstream legs — its whole job is §3's batched copy.

**Key establishment, concretely:**

- The SFU mints one random SRTP master key + salt per broadcast **per epoch** (epoch = monotonic
  counter; rotation on demand, e.g. stream restart — *not* on viewer join/leave, which public
  content does not need). The key is generated fresh, never derived from any peer's DTLS exporter,
  and never reused across broadcasts.
- Each shared-key viewer connects exactly as today: full ICE, full per-viewer DTLS handshake. The
  handshake is not wasted — it authenticates the transport, keys the data channel, and keys the
  *delivery channel for the broadcast key*.
- The broadcast key `{epoch, profile, key, salt}` is delivered to the viewer over an
  **authenticated, confidential channel that already exists per viewer**: the viewer's data
  channel (DTLS-protected, in-band, no signaling-server trust required beyond what it already
  has), or equivalently the application's TLS signaling. A Keryx-defined message, not SDP.
- The viewer's client installs it via the opt-in API (§5.3); the broadcast m-lines' *receive*
  direction then uses the shared key instead of the DTLS-exported key. Everything else on that
  connection (data channel, RTCP-mux SRTCP — see §5.5, any upstream media) stays on the
  connection's own DTLS-derived keys.
- Epoch rotation: the new key is delivered on the same channel, the SFU switches at a signaled
  RTP timestamp boundary, and clients hold both epochs across the switch. (SRTP MKI is not
  implemented in Keryx and is not needed for this; epoch signaling is out-of-band.)

### 5.2 What encrypt-once collapses — the full composition

With every shared-key viewer of a tier receiving **byte-identical ciphertext**, the per-viewer
pipeline of §4 collapses further than crypto alone:

- **One packetize, one encrypt** per ingest packet per simulcast tier: all shared-key viewers of a
  tier share one broadcast SSRC and one sequence space. The per-viewer `RtpForwarder` rewrite
  disappears from this path too — there is nothing per-viewer left in the packet.
- **N sends from one buffer**: the `sendmmsg` batch entries all point at the *same* ciphertext
  (the spike's Arm C already models exactly this — B `iovec`s sharing one payload pointer). Not
  even Arm B's per-viewer memcpy survives; the measured 48–87× is the *floor* of the win.
- So the full stack composes to: **one decrypt (ingest), one packetize, one encrypt, N batch
  entries, ~N/1024 syscalls** — per packet, per tier. The remaining O(N) work is address arrays
  and the kernel's per-datagram cost. That is the NIC wall, reached.

The honest costs of identical ciphertext:

- **No per-viewer header rewrites** — so no per-viewer TWCC stamping, hence **no per-viewer GCC on
  shared-key legs**. Per-viewer adaptation becomes **tier selection**: each simulcast tier is its
  own shared-key stream (own SSRC, own encrypt-once), and a viewer's receiver reports / REMB move
  them between tiers. This is the cable-channel model, and it is the right model for broadcast:
  one viewer's radio conditions must never shape the shared stream.
- **No per-viewer RTX**: RFC 4588 needs per-viewer RTX sequence numbers. NACKs on shared-key legs
  are served by **verbatim resend** of the original shared ciphertext from a single shared history
  buffer (duplicate-safe by SRTP replay semantics on the receiver). Cheaper than today, and
  per-viewer: only the NACKing viewer gets the resend.

### 5.3 The opt-in API — shaped so the boundary is hard to cross by accident

The security property (§5.4) must be enforced by the API's shape, not by documentation. The design
principles: **the word "public" is unavoidable at every call site; the key type cannot be
constructed from any per-connection secret; and the mode composes only with send-only broadcast
legs.**

```csharp
namespace Keryx.Broadcast;

/// <summary>
/// One broadcast's shared SRTP key. Every viewer of the broadcast receives THIS key and can
/// decrypt — and, holding the key, forge — the broadcast media. Creating one is an assertion
/// that the content is public. See docs/design/broadcast-scale.md §5.4.
/// </summary>
public sealed class PublicBroadcastKey : IDisposable
{
    /// <summary>Mints a fresh random key for a PUBLIC broadcast. The only constructor.</summary>
    public static PublicBroadcastKey CreateForPublicContent(SrtpProtectionProfile profile);

    public int Epoch { get; }
    public PublicBroadcastKey RotateEpoch();

    /// <summary>Exports the key material for delivery to a viewer over their data channel.</summary>
    public PublicBroadcastKeyExport Export();
}
```

- **Server side**: the shared key is a property of the `BroadcastEndpoint`'s send tier, not of any
  `PeerConnection`/`ViewerSession` — `broadcastTier.UseSharedKey(PublicBroadcastKey)`. A
  `ViewerSession` is *enrolled* into the shared-key tier, and enrollment **throws** unless the
  session's RTP surface is exclusively send-only broadcast transceivers (a viewer leg). A session
  with any receiving m-line — anything that could carry a viewer's mic or camera — cannot enroll.
  There is deliberately **no** per-`PeerConnection` "use shared key" switch: the mode exists only
  inside the broadcast fan-out component, so the ordinary API cannot reach it at all.
- **Client side**: `PeerConnectionConfig.InstallPublicBroadcastReceiveKey(PublicBroadcastKeyExport)`
  applies to *receive* directions of broadcast m-lines only; the connection's own DTLS keys remain
  in force for everything else. The type system carries the word "public" to the client too.
- **No mixing**: one `PublicBroadcastKey` binds to exactly one broadcast tier set; enrolling a
  session into two different broadcasts' shared keys, or installing a shared key alongside a
  private receive m-line, throws. There is no code path by which a DTLS-derived key and a shared
  key can swap roles.

### 5.4 The security boundary — the paragraph the sign-off is for

**This mode is for public broadcasts only. It must never be used for private rooms, 1:1 calls, or
any room where different participants have different rights to the media. The API makes that hard
to do by accident (§5.3); this section makes it impossible to misunderstand.**

What the mode changes: today, SRTP gives each viewer a pairwise confidentiality and integrity
channel with the SFU. Under the shared key, **every enrolled viewer holds the key that decrypts
the broadcast — and, because SRTP AEAD is symmetric, the key that can forge valid broadcast
packets.** The guarantees become group guarantees:

- **Confidentiality**: gone *within the viewer set*, by design — every viewer can decrypt. This is
  precisely why the mode is public-content-only: for a public broadcast, "any viewer can read the
  stream" is the product, not a leak. (Transport encryption still holds against pure on-path
  observers who are not enrolled viewers — but enrollment is open for public content, so treat
  confidentiality as nil. Equivalent trust model to a public HLS/DASH CDN.)
- **Integrity/authenticity**: degrades from "this packet came from the SFU" to "this packet came
  from *someone holding the broadcast key*". A malicious viewer who can also spoof or occupy the
  network path to another viewer (off-path spoofing of the SFU's 5-tuple plus a plausible
  sequence/ROC window, or on-path position) could inject forged media into that viewer's player.
  Stated plainly and not minimised: **shared-key mode trades per-viewer media authentication for
  scale.** Mitigations that remain: receivers only accept the established 5-tuple, replay windows
  hold, and epoch rotation bounds exposure — but a keyholder-forgery is cryptographically valid
  and this design does not claim otherwise.

Threat model — what an attacker gains and does not gain:

| Attacker | Gains | Does **not** gain |
| --- | --- | --- |
| Enrolled viewer (or anyone who obtains the broadcast key) | Watch the public stream (which they already could); forge broadcast media toward a viewer **if** they also have the network position for it | The ingest leg (broadcaster→SFU stays on its own DTLS-SRTP keys — the SFU decrypt/re-encrypt boundary is intact); any other broadcast's key; any per-viewer-path viewer's keys; any viewer's data channel, upstream media, or signaling identity; anything after epoch rotation |
| On-path observer, not enrolled | Nothing beyond joining as a viewer would give | — |
| Compromised relay box (§7) | Same as an enrolled viewer for that broadcast | Private sessions on the same box (never shared-key); other broadcasts' keys |

Hard rules, restated as invariants the implementation must enforce and tests must pin:

1. A shared key is never derived from, or mixed with, any connection's DTLS-exported material.
2. A session with any receiving media m-line can never be enrolled (no participant media ever
   rides a shared key).
3. Private/1:1/mixed-privacy rooms have no API path to this mode; it lives only in the broadcast
   fan-out component, behind a type whose name asserts public content.
4. The mode is off by default everywhere, forever; enabling it is a per-broadcast, explicit,
   server-side act.

### 5.5 SRTCP under the shared key

RTCP sender reports for the broadcast stream are group-addressed in content but still delivered
per-viewer; they ride the shared key (encrypt-once applies to SR compounds too). Viewer→SFU RTCP
(receiver reports, NACK, REMB) rides each viewer's own DTLS-derived SRTCP context, unchanged —
feedback is per-viewer and private. This split falls out naturally: shared key for the shared
direction, per-viewer keys for the per-viewer direction.

---

## 6. Phasing — landable increments

Ordered by dependency and by decision-weight; each lands independently. The two owner decision
gates are marked. Versioning follows the session-model precedent: internal/additive work in 0.x
minors, the shared-key mode gated separately.

**PR 1 — batched-send primitive** *(no owner gate; the one P/Invoke exception should be
acknowledged in review)*. `IBatchDatagramSender` in `Keryx.Core`: `sendmmsg` implementation
(Linux, feature-detected), managed `SendTo` fallback, partial-send/error semantics per §3.1, spike
ABI structs productionised. Used by nothing yet; correctness tests both paths, and a Linux CI job
runs the real syscall (the spike's Dockerfile becomes the lane). *Unblocks: PR 4.*

**PR 2 — parallel fan-out shards over today's per-viewer legs.** The §4 pipeline (ingest publish,
shard ownership, per-viewer pacer/forward/encrypt) driving existing per-viewer sockets. Wins the
crypto-scaling lever immediately (Arm A ~linear) with zero protocol change and no interop
surface; sends remain per-socket `SendTo` (nothing to batch yet — the honest limitation, stated in
§2.1). *Unblocks: PR 3 slots into stage 2.*

**PR 3 — shared-socket `BroadcastEndpoint`** *(owner decision: API shape + packaging — new
`Keryx.Broadcast` assembly vs. inside `Keryx`; and the `IceEndpointSession` addition to
`Keryx.Ice`)*. 5-tuple demux, ufrag first-contact binding, `SharedSocketTransport`, ICE
endpoint-session mode, per-viewer DTLS/SRTP over the shared socket (§2.2). **Interop-gated**: the
CI browser lanes (Chrome, Firefox — `.github/workflows/ci.yml:25,58`) and the pion lane
(`ci.yml:127`) each grow a shared-port variant, so "a stock browser connects to the shared port,
completes ICE+DTLS, and plays media" is CI-enforced, not asserted.

**PR 4 — batches wired in.** Per-shard `SendBatch` flush on the shared socket (§3.2). Small once
PR 1 + PR 3 exist; the measured 1.74×/39× lever is collected here.

**PR 5 — shared-key encrypt-once mode** *(**hard owner gate: §5.4 sign-off before implementation
begins**)*. `PublicBroadcastKey`, tier enrollment + guardrail throws (§5.3), key delivery message,
epoch rotation, shared send history for NACK resend, SRTCP split (§5.5). Tests pin the four §5.4
invariants (each guardrail throw is a test), plus a two-Keryx-client end-to-end proving identical
ciphertext delivery and epoch rotation. `SECURITY-REVIEW.md` gains this threat model. Custom-client
only; the browser lanes are untouched by construction.

**Load-test rig (parallel to PRs 2–5).** `Keryx.ScaleHarness` grows an end-to-end arm: real
`BroadcastEndpoint`, N loopback viewers, asserting pkt/s, alloc/steady-state-zero, and shard
scaling against the §1 model. True 10k+ over real NICs needs multiple driver boxes (as
`benchmarks/README.md` already notes); the rig should make "viewers/box at the measured ladder
rung" a tracked number per release, not a one-off spike.

Decision summary for the owner: **(a)** §5 sign-off (the gate); **(b)** packaging/API shape of the
broadcast component and the `Keryx.Ice` endpoint-session addition (PR 3); **(c)** acceptance of
the single `sendmmsg` P/Invoke as the standing exception to pure-managed (PR 1).

---

## 7. Explicitly deferred / open questions

- **GPU crypto offload** — deferred, with the bar stated: the arithmetic says it never earns its
  complexity *below the single-box NIC wall*. At the 35k/100GbE ceiling, per-viewer-key crypto is
  ~17 cores (§1.3) — real but affordable — and shared-key mode removes it entirely for the
  broadcast case that scales. GPU AES-GCM would add PCIe round-trips and batching latency against
  a ~1200-byte/packet, latency-sensitive path, to save cores that the box has. Revisit only if a
  concrete deployment is simultaneously per-viewer-key-only (no shared-key sign-off), beyond ~25k
  viewers, and core-constrained — and then benchmark against simply adding cores.
- **Multi-NIC / multi-box sharding past the NIC wall** — the shape is a distribution tree: origin
  SFU → fan-out relays, viewers attached to relays. §5.1's observation does the heavy lifting:
  relay legs are Keryx↔Keryx, so encrypt-once covers the whole tree and a relay is almost pure
  §3 send capacity. Open questions: viewer→relay assignment and rebalancing, cross-tier RTCP/NACK
  aggregation (serve NACKs at the nearest tier holding history), tier-switch signaling latency
  through the tree, and key/epoch distribution to relays (trivial mechanically — same delivery
  channel — but the relay compromise row of §5.4's table applies). Multi-NIC single-box (one
  `BroadcastEndpoint` socket-set per NIC/NUMA node) is the same design one level down and needs no
  new decisions, only shard-to-NIC affinity.
- **io_uring / AF_XDP** — the rungs past `sendmmsg` on the syscall axis (amortise further; bypass
  the kernel UDP stack). Behind the same `IBatchDatagramSender` seam when the measured need
  appears; neither is justified before the shared-socket path exists and `sendmmsg`'s measured
  ceiling is actually reached in production.
- **Stock-browser shared-ciphertext delivery** — if a standards path ever opens (EKT in browsers,
  or MoQ/WebTransport-shaped broadcast making per-viewer TLS the only crypto), §5's verdict should
  be revisited; the encrypt-once architecture (one packetize, shared history, tier model) carries
  over intact.
- **GSO adoption** — per §3.3: measure per-viewer-train wins behind the existing seam before
  committing.
