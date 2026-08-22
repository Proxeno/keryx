# Send-side congestion control (GCC)

Status: scaffold landed (EWI-1248). Delay-based estimator + AIMD + loss controller + pacer are
implemented and unit-tested against synthetic feedback. PeerConnection wiring and send-time
correlation are deferred to follow-up PRs (they depend on EWI-1247's outbound transport-cc sequence
numbers).

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

- **`RtcpTransportCcFeedback`** (EWI-1247) — parses transport-cc into `TransportCcPacketStatus`
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

## PeerConnection wiring (deferred — PR2/PR3)

- **Feedback in** (PR2): in `PeerConnection.Media.cs` `DispatchRtcp`, route
  `case RtcpTransportCcFeedback` → `OnTransportFeedback`, RR loss (from `IngestReportBlocks`) →
  `OnReportedLoss`, and add a `case RtcpReceiverEstimatedMaxBitrate` (not currently dispatched) →
  `OnReceiverEstimatedMaxBitrate`. Expose the controller as a `PeerConnection` property so callers can
  subscribe to `TargetBitrateChanged`.
- **Sends out** (PR3): once EWI-1247 stamps outbound packets with transport-cc sequence numbers, call
  `OnPacketSent(seq, sendTimeMicros, size)` from the send path (`TrackSender.SendFrame`) and gate the
  send loop through `PacketPacer`.

These are split out because they depend on EWI-1247's per-sequence send-time table, which lands
separately; the estimator and its tests do not block on it.

## Per-subscriber use in the SFU (EWI-1250)

The interface is per-sending-transport by design. In the SFU each downstream subscriber has its own
transport-cc feedback loop, so the SFU holds **one `GccCongestionController` per subscriber**. Each
subscriber's target drives that subscriber's simulcast/SVC layer selection; the publisher-facing rate
(what the encoder produces) is the max over subscribers, or a configured cap, with per-subscriber
forwarding choosing the highest layer that fits its own target.

## Follow-up PR breakdown

1. **This PR** — components + working delay-based estimator + synthetic-feedback tests + this doc.
2. **PR2** — PeerConnection feedback dispatch hooks + REMB dispatch case + controller property.
3. **PR3** — consume EWI-1247 outbound sequence numbers; `OnPacketSent` from the send path; insert
   `PacketPacer` into the send loop.
4. **PR4** — Kiln encoder rate controller subscribes to `TargetBitrateChanged`.
5. **PR5 (EWI-1250)** — per-subscriber controller instances + layer allocation in the SFU.
