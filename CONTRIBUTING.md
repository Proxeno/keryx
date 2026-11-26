# Contributing to Keryx

Thanks for considering a contribution. Keryx is a from-scratch WebRTC stack; the bar for changes
is correctness against the RFCs, proven by tests.

## Building

- .NET SDK 10.0+ (`dotnet build Keryx.slnx`)
- `dotnet test Keryx.slnx` runs everything except the trait-gated suites:
  - `--filter "Category=ChromeInterop"` runs the browser interop tests; they need Google Chrome
    installed (override the path with `KERYX_CHROME_PATH`).
  - `--filter "Category=FirefoxInterop"` and `--filter "Category=PionInterop"` run the Firefox
    and pion interop tests (`KERYX_FIREFOX_PATH`; a Go toolchain, or a prebuilt peer through
    `KERYX_PION_PEER`).
  - `--filter "Category=TurnRelayInterop"` runs the TURN relay interop tests against a local
    coturn.
  - `--filter "Category=SharedPortChromeInterop"`, `SharedPortFirefoxInterop` and
    `SharedPortPionInterop` run the same peers against a shared-port `BroadcastEndpoint`.
  - `--filter "Category=Soak"` runs the five-minute lossy-link soak (`KERYX_SOAK_SECONDS`
    shortens it).
- The coturn interop tests (`Category=TurnInterop`, in the default run) start a local `turnserver`
  (override the path with `KERYX_TURNSERVER_PATH`) and print `SKIPPED` when it is missing. They
  use fixed ports 7700-7715; `Keryx.IntegrationTests` binds random UDP ports in 7900-7999, so a
  new fixed-port test server must avoid both ranges.
- Every interop suite skips locally when its tool is missing. CI sets `KERYX_REQUIRE_CHROME`,
  `KERYX_REQUIRE_FIREFOX`, `KERYX_REQUIRE_PION`, `KERYX_REQUIRE_TURN_RELAY` or
  `KERYX_REQUIRE_COTURN` to `1`, which turns a missing tool into a failure.

## CI jobs

`.github/workflows/ci.yml` runs:

- `build-test`: Release build and every test except the browser, pion, TURN relay and soak
  categories, with coturn installed and `KERYX_REQUIRE_COTURN=1`.
- `browser-interop` (Chrome), `firefox-interop`, `pion-interop` and `turn-relay-interop`.
- `shared-port-chrome-interop`, `shared-port-firefox-interop` and `shared-port-pion-interop`:
  the same peers against one `BroadcastEndpoint` with a two-socket pool.

## Ground rules

1. **Layering is law.** `src/` projects depend only on `Keryx.Core` (exceptions: `Keryx.Ice` →
   `Keryx.Stun` and `Keryx.Turn`, `Keryx.Turn` → `Keryx.Stun`) and never on each other or upward.
   `Keryx` composes the layers and `Keryx.Broadcast` sits on top of it. If your change needs a sideways dependency,
   the design is wrong — bytes and small records cross layers, types do not.
2. **Zero NuGet dependencies in `src/`.** The BCL only. Crypto primitives come from
   `System.Security.Cryptography`; hand-rolled cipher implementations will not be merged.
3. **Warnings are errors, and public members need XML docs** (`CS1591` fails the build). Write
   docs that say something — what the RFC calls the thing, what the caller must guarantee.
4. **Wire parsers never throw on hostile input.** Truncation/malformation is a `false` from
   `TryParse`, a dropped packet, or a logged warning — never an unhandled exception. Fuzz-shaped
   tests welcome.
5. **Cite the RFC.** Tests that verify protocol behavior name the RFC and section
   (`// RFC 3711 §3.3.1`) so reviewers can check the claim against the source.

## Adding a codec packetizer

Implement `Keryx.Rtp.IRtpPayloadizer` in your own assembly — that seam is public and stable-ish
(pre-1.0). Add an `SdpCodec` describing the rtpmap/fmtp/rtcp-fb lines you need and pass it in the
`PeerConnection` codec configuration. Nothing in Keryx hardcodes a codec beyond the in-box defaults (H.264, VP8, VP9, AV1, Opus; PCMU, PCMA and G.722 packetize through `OctetAudioPacketizer` when you supply their `SdpCodec`).

## Security-sensitive code

Changes under `src/Keryx.Dtls` and `src/Keryx.Srtp` get extra scrutiny: include RFC citations for
every behavioral claim in the PR description, and never weaken a verification step (fingerprint
pinning, CertificateVerify, Finished, auth tags, replay windows) even temporarily. See
`SECURITY.md` for the current review status.

## Style

- Small, single-purpose commits with imperative subjects and a body that explains *why*.
- Tests live in the layer's own test project; integration-level tests in
  `tests/Keryx.IntegrationTests`.
- Benchmarks (`benchmarks/`) must keep input parity between Keryx and the baseline, and say exactly
  what each side measures.

## License of contributions

Keryx is licensed under Apache-2.0, and contributions are accepted under the same license: when
you open a pull request, you agree that your contribution is licensed under Apache-2.0
(inbound = outbound). You keep the copyright to your work — there is no copyright assignment.

We use the [Developer Certificate of Origin](https://developercertificate.org/) (DCO). Sign off
every commit:

```
git commit -s
```

That appends a `Signed-off-by: Your Name <you@example.com>` line certifying that you wrote the
contribution (or otherwise have the right to submit it) and that it may be distributed under the
project's license.
