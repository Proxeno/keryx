# Contributing to Keryx

Thanks for considering a contribution. Keryx is a from-scratch WebRTC stack; the bar for changes
is correctness against the RFCs, proven by tests.

## Building

- .NET SDK 10.0+ (`dotnet build Keryx.slnx`)
- `dotnet test Keryx.slnx` runs everything except Chrome interop tests
  (`--filter "Category=ChromeInterop"` runs those; they need Google Chrome installed).

## Ground rules

1. **Layering is law.** `src/` projects depend only on `Keryx.Core` (exception: `Keryx.Ice` →
   `Keryx.Stun`) and never on each other or upward. If your change needs a sideways dependency,
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
`PeerConnection` codec configuration. Nothing in Keryx hardcodes H.264 or Opus beyond defaults.

## Security-sensitive code

Changes under `src/Keryx.Dtls` and `src/Keryx.Srtp` get extra scrutiny: include RFC citations for
every behavioral claim in the PR description, and never weaken a verification step (fingerprint
pinning, CertificateVerify, Finished, auth tags, replay windows) even temporarily. See
`SECURITY.md` for the current review status.

## Style

- Small, single-purpose commits with imperative subjects and a body that explains *why*.
- Tests live in the layer's own test project; integration-level tests in
  `tests/Keryx.IntegrationTests`.
- Benchmarks (`bench/`) must keep input parity between Keryx and the baseline, and say exactly
  what each side measures.

## License

By contributing you agree your contributions are licensed under Apache-2.0, the project license.
