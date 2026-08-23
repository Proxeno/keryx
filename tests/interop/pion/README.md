# pion reference-implementation interop peer

`pion-peer` is the Go/[pion](https://github.com/pion/webrtc) counterpart to the headless-Chrome
interop fixture (`tests/Keryx.IntegrationTests/assets/chrome-client.html`). It gives Keryx a
second, non-browser peer implementation to handshake against, so bugs that a single peer would
mask surface in CI. The C# side lives in `PionInteropTests.cs` / `PionPeer.cs`.

## What's covered (first cut)

One role, one handshake, media + data in **both directions**:

- **Role:** `answer` — Keryx is the offerer, pion answers (mirrors the Chrome fixture's default
  `role=answer`). The reverse role (pion offers, Keryx answers) is **not** implemented yet; the
  `-role` flag exists as the seam to add it.
- **Media (Keryx -> pion):** pion receives Keryx's sendonly H.264 track, counts inbound RTP
  packets and frames (marker bits), and sends periodic PLIs so Keryx emits a keyframe to lock on.
- **Data (Keryx -> pion -> Keryx):** pion accepts the `controller` and `telemetry` data channels
  Keryx opens and echoes every `ping:N` back as `echo:N`, so the message round-trips.

The test asserts, over an HTTP signaling shim identical in shape to the Chrome one: pion reports
`connectionState == connected`, inbound video packets/frames climb, and both channels echo; and
Keryx's own stats show video packets sent and the `echo:` replies arriving back on its channels.

## Loopback / CI constraints

ICE is pinned to **127.0.0.1 host candidates only** — loopback candidate explicitly included, all
other IPs filtered out, UDP4 only, no STUN/TURN, no mDNS — so DTLS-SRTP/ICE runs on a headless
runner exactly like the Chrome job.

## Building / running

    go mod tidy      # resolves + pins deps, writes go.sum
    go build -o pion-peer .
    ./pion-peer -signal http://127.0.0.1:7984 -role answer -port-min 7800 -port-max 7899

In CI the `pion-interop` job (`.github/workflows/ci.yml`) does the `go mod tidy` + `go build` and
points the tests at the binary via `KERYX_PION_PEER`, with `KERYX_REQUIRE_PION=1` so a missing Go
toolchain or peer is a build failure, not a silent skip. Local dev without Go skips gracefully; the
`PionPeer` helper will otherwise `go build` the peer on demand.
