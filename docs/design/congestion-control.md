# Send-side congestion control (GCC)

Status: landed. The delay-based estimator, AIMD, loss controller, pacer, transport-cc stamping on
media, RTX and FEC repair packets, and the PeerConnection feedback/send wiring are implemented and
unit-tested. The encoder-facing target and the adaptive FEC overhead are exposed on
`PeerConnection`; see [Repair traffic and FEC](#repair-traffic-and-fec-ewi-1386).

## Goal

Produce a **target send bitrate** for the media pipeline from what the peer tells us about the packets
we sent, and smooth outbound bursts toward that target. This is the send-side of Google Congestion
Control (draft-ietf-rmcat-gcc-02): a delay-based estimator over transport-wide congestion control
(transport-cc / TWCC) feedback, a loss-based controller over RTCP reception reports, a REMB fallback
for older peers, and a leaky-bucket pacer.

All components live in `src/Keryx.Rtp/CongestionControl/`, namespace `Keryx.Rtp.CongestionControl`,
BCL-only. Time is injected via `TimeProvider` (the same pattern as `RtpSendHistory`,
`RtxRetransmitter`, `SctpAssociation`), so everything is deterministic under a test clock.

## Inputs (from the real code)

- **`RtcpTransportCcFeedback`** — parses transport-cc into `TransportCcPacketStatus`
  entries, each with `Received`, `SequenceNumber` and `ArrivalTimeMicroseconds` on the receiver clock.
  This is the delay-based estimator's input.
- **`RtcpReceiverEstimatedMaxBitrate`** (REMB) — a receiver-side estimate; interim fallback and cap.
- **Reception-report loss** — `OutboundStreamQuality.FractionLost` (0..1), already ingested in
  `PeerConnection.Media.cs`.

## Interface

`ICongestionController` is the seam the encoder rate controller (proxeno-server/Kiln) consumes:

```csharp
long TargetBitrateBitsPerSecond { get; }
event EventHandler<TargetBitrateChangedEventArgs>? TargetBitrateChanged;
void OnPacketSent(ushort transportSequenceNumber, long sendTimeMicroseconds, int payloadSizeBytes);
void OnTransportFeedback(RtcpTransportCcFeedback feedback);
void OnReportedLoss(double fractionLost);
void OnReceiverEstimatedMaxBitrate(RtcpReceiverEstimatedMaxBitrate remb);
```

`GccCongestionController` is the shipped implementation. It is single-threaded by contract: drive one
instance from a single RTCP receive loop. It exposes only the target and the change event; it never
touches the send path. Kiln subscribes to `TargetBitrateChanged` and retunes the codec.

## Delay-based estimator (draft-ietf-rmcat-gcc-02 §5)

Pipeline, one stage per file:

1. **`SendTimeHistory`** — a power-of-two ring keyed by the low bits of the transport-wide sequence
   number, recording `(sendTime, size)` per packet. Allocation-free; evicts entries older than its
   capacity (feedback only ever names recent sequence numbers). Populated by `OnPacketSent`.
2. **Delay-variation recovery** — for each *received* packet in a feedback packet, pair its
   `ArrivalTimeMicroseconds` with its recorded send time and compute
   `d = (arrival_i − arrival_{i−1}) − (send_i − send_{i−1})`: the change in one-way queuing delay.
3. **`TrendlineEstimator`** — accumulates `d`, exponentially smooths it, and least-squares-fits a line
   to the smoothed accumulated delay over a sliding window (default 20 samples). The scaled slope
   (`min(N,60) · slope · gain`) is the trend.
4. **`OveruseDetector`** — compares the trend against an **adaptive threshold** (kUp/kDown adaptation,
   clamped 6..600) and requires the trend to stay over the threshold for ≥10 ms before declaring
   `Overusing`, so a single spike does not trip it. Emits `Normal` / `Underusing` / `Overusing`.
5. **`AimdRateController`** — turns the verdict into a bitrate: multiplicative **decrease**
   (`rate = β · reference`, β = 0.85, `reference` = measured throughput when it is the bottleneck,
   else the current estimate) on `Overusing`; time-proportional multiplicative **increase**
   (`×1.08/s`, capped at `1.5 × throughput`) on `Normal`; **hold** on `Underusing`. Clamped to
   `[Min, Max]`.

Throughput is estimated per feedback batch from received bytes over the arrival span and fed to the
rate controller so increase and decrease both respect what the receiver is actually acknowledging.

## Loss-based controller (draft-ietf-rmcat-gcc-02 §6)

`LossBasedBandwidthEstimator`, a coarse rule over the RR loss fraction:
`< 2%` → `×1.08`; `> 10%` → `×(1 − 0.5·loss)`; middle band → hold. It only becomes a real cap once it
has seen at least one loss report (`HasSample`).

## Arbitration and REMB fallback

`GccCongestionController.Recompute` (draft-ietf-rmcat-gcc-02: loss and REMB may only *lower* the
delay-based estimate):

- **Transport-cc fresh** (feedback within `RembTimeToLive`): `target = min(delay, lossCap)`, then
  capped by a fresh REMB.
- **No fresh transport-cc, fresh REMB**: fall back to `min(remb, lossCap)` — the older-peer path.
- **Neither**: loss-based estimate if it has samples, else the delay-based value (start bitrate).

`lossCap` is `+∞` until a loss report arrives, so an idle loss controller never pins the delay ramp.
The target is clamped to `[Min, Max]`; the change event fires only when the target moves past
`ChangeNotificationThreshold` (default 1%), so subscribers are not woken by noise.

## Pacer (draft-ietf-rmcat-gcc-02 §5.6)

`PacketPacer` is a leaky bucket (the same token-bucket shape as `RtxRetransmitter`'s budget). The
bucket drains at `target × pacingFactor` (default 2.5) and is capped so a short idle cannot bank an
unbounded burst. Callers ask `TryConsume(bytes)` before sending and reschedule after
`TimeUntilNextSend(bytes)` when refused. `SetTargetBitrate` retargets it from the controller's change
event.

## PeerConnection wiring (landed)

- **Feedback in**: in `PeerConnection.Media.cs` `DispatchRtcp`, `RtcpTransportCcFeedback` routes to
  `OnTransportFeedback`, RR loss (from `IngestReportBlocks`) to `OnReportedLoss`, and
  `RtcpReceiverEstimatedMaxBitrate` to `OnReceiverEstimatedMaxBitrate`. The controller is exposed as
  `PeerConnection.CongestionController`, and `TargetBitrateChanged` is forwarded to callers.
- **Sends out**: outbound packets are stamped with transport-wide sequence numbers and
  `OnPacketSent(seq, sendTimeMicros, size)` is called from the send path (`TrackSender.EmitPacket`,
  `TrackSender.Retransmit` and `FecEmitter.EmitPending`); the send loop is gated through
  `PacketPacer`.

The per-sequence send-time table is `SendTimeHistory`; the estimator and its tests no longer wait on
it.

## Repair traffic and FEC (EWI-1386)

### One transport-wide sequence space

Every outbound RTP packet — media, RFC 4588 RTX repairs and RFC 5109/8627 FEC repair packets —
shares the connection's single transport-wide sequence space. All three paths draw from
`NextTransportWideSequenceNumber`, stamp the transport-cc header extension, and record the packet
through `OnPacketSent` before it reaches the wire. The delay-based estimator's send history, the
acknowledged-throughput figure and the pacer therefore account for repair traffic too.

Before this change FEC repairs were invisible to congestion control: the target was derived from
media plus RTX only, while the wire carried up to ~10% more (one repair per ten media packets). The
estimator now sees the true send rate, including the repairs it caused.

### Encoder budget

`TargetBitrateBitsPerSecond` on the controller is the **whole-transport** target: media plus RTX plus
FEC. The consumer of the budget is the application's encoder. For a protection group of `N` media
packets, the nominal repair share is `1 / (N + 1)` of all sent packets, so the budget an encoder
should be tuned to is

```
PeerConnection.MediaTargetBitrateBitsPerSecond = target × (1 − 1/(N+1))
```

`PeerConnection.VideoFecGroupSize` and `VideoFecOverheadFraction` expose the current `N` and its
overhead; `PeerConnection.FecProtectionChanged` fires on the RTCP receive loop whenever `N` moves, so
an encoder can retune. There is no bandwidth allocator in Keryx — these properties are the seam.

### Adaptive group size

`FecProtectionOptions` sets the bounds and defaults (`InitialGroupSize` 10, `MinGroupSize` 3,
`MaxGroupSize` 15, `RelaxAfterReports` 5, adaptive on by default). `FecProtectionController` maps a
smoothed loss fraction onto a group size:

| smoothed loss | group size |
| --- | --- |
| `< 1%` | `MaxGroupSize` (default 15) |
| `< 3%` | 10 |
| `< 6%` | 6 |
| `< 10%` | 4 |
| `>= 10%` | 3 |

The tier result is clamped to `[MinGroupSize, MaxGroupSize]`. The loss sample is exponentially
smoothed with a fast attack (`α = 0.5` when the sample is above the estimate) and a slow decay
(`α = 0.125`), so a burst is reflected at once but a single lucky report does not declare the path
calm.

Tightening is immediate: a smaller target than the current group is applied on the report that shows
it, because unprotected loss is already visible. Relaxing is deliberately slow and stepwise: the
sample must sit a fifth below a threshold (`Tier(loss × 1.25)` must exceed the current size) before
calm is counted, and `RelaxAfterReports` consecutive calm reports buy exactly one step up the ladder
`{3, 4, 6, 10, MaxGroupSize}`. That hysteresis stops a path hovering at a threshold from flapping and
keeps the overhead an encoder reads stable. The controller counts reports, not time, so it is fully
deterministic.

The input is the reception report for the **media SSRC** (`OutboundStreamQuality.FractionLost`). Its
loss is the pre-recovery loss of exactly the packets FEC protects. Transport-cc loss is the wrong
signal: it is transport-wide and mixes in audio, RTX repairs and the repair packets themselves.

The controller runs on the RTCP receive loop and is not thread-safe. It publishes the new group size
to the send path with a volatile write; the send path reads it per media packet, and a group that
already holds at least the new size is closed by the very next media packet.

### MTU

A repair packet is the media packet plus the FEC header (and, for ULPFEC, the RED primary-block byte)
plus the repair's own transport-cc extension. The media payload budget reserves exactly that much
(`FecEmitter.MediaPayloadReserve`), so a repair never exceeds the datagram budget even when the media
payload was filled to its maximum. The RTX two-byte reserve applies independently, so both reserves
are subtracted when FEC and RTX are on together.

### Interaction with the loss-based controller

Above 10% loss the loss-based controller cuts the transport target while FEC is at its most
protective (group 3, one repair per three media packets, 25% of all packets). The encoder budget
shrinks on both counts — the target falls and the FEC share rises. That is intended: the two
mechanisms address different timescales (FEC repairs isolated loss without a round trip; GCC avoids
persistent congestion), and the floor is `MinGroupSize`, so FEC never escalates without bound.

## Per-subscriber use in the SFU

The interface is per-sending-transport by design. In the SFU each downstream subscriber has its own
transport-cc feedback loop, so the SFU holds **one `GccCongestionController` per subscriber**. Each
subscriber's target drives that subscriber's simulcast/SVC layer selection; the publisher-facing rate
(what the encoder produces) is the max over subscribers, or a configured cap, with per-subscriber
forwarding choosing the highest layer that fits its own target.

## Follow-up PR breakdown

1. **This PR** — components + working delay-based estimator + synthetic-feedback tests + this doc.
2. **PR2** — PeerConnection feedback dispatch hooks + REMB dispatch case + controller property.
3. **PR3** — consume the outbound transport-cc sequence numbers; `OnPacketSent` from the send path;
   insert `PacketPacer` into the send loop.
4. **PR4** — Kiln encoder rate controller subscribes to `TargetBitrateChanged`.
5. **PR5** — per-subscriber controller instances + layer allocation in the SFU.
