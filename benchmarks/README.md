# Keryx performance harness

Two console projects, deliberately **outside the CI test suite** (they are `Exe` projects, so
`dotnet test Keryx.slnx` never runs them). Both build as part of `dotnet build Keryx.slnx -c Release`.

## `Keryx.Benchmarks` — BenchmarkDotNet micro-benchmarks

Hot per-packet paths at the ~1200-byte target packet size, with `[MemoryDiagnoser]` for allocs/op.

| Class | What it measures |
| --- | --- |
| `SrtpBenchmarks` | SRTP protect (encrypt) and unprotect (decrypt) throughput for `AEAD_AES_128_GCM`, `AEAD_AES_256_GCM`, and `AES_CM_HMAC_SHA1_80`. The headline pkt/s/core that drives subscribers/core. |
| `PacketizeBenchmarks` | `H264Packetizer.Packetize` for a 720p P-frame (FU-A) and keyframe (STAP-A + FU-A). |
| `ForwardBenchmarks` | `RtpForwarder.TryForward` — the per-subscriber SFU rewrite primitive. |
| `ReceivePathBenchmarks` | `ProcessDecryptedRtp` — the full post-SRTP receive path for one ingest source. |

Run:

```bash
dotnet run -c Release --project benchmarks/Keryx.Benchmarks -- --filter '*'
# faster, lower-precision:
dotnet run -c Release --project benchmarks/Keryx.Benchmarks -- --filter '*Srtp*' --job short
```

The benchmark host reaches two internal seams via `InternalsVisibleTo` (added to `Keryx.Srtp` and
`Keryx`): the SRTP transform layer (pure-crypto decrypt, no replay window in the loop) and
`PeerConnection.DeliverDecryptedRtpForTest` (the same seam the integration tests use). No production
logic changed.

## `Keryx.ScaleHarness` — SFU fan-out scale test

Models the broadcast data path directly (1 ingest → N re-encrypted subscribers), because standing up
N real `PeerConnection`s at 10k is not feasible. Four arms:

1. **Throughput** — max `TryForward` + per-subscriber SRTP encrypt pkt/s, single core and all cores,
   with CPU/GC/alloc.
2. **Fan-out memory** — managed + working-set bytes per subscriber for the forwarder + SRTP context.
3. **Real PeerConnection footprint** — object-graph bytes/PC after applying a remote offer, plus a
   modest live arm that starts ICE gathering to show thread/socket growth.
4. **sendto rate** — single-core UDP `SendTo` datagram/s; each forwarded packet is one syscall, and
   managed .NET exposes no `sendmmsg`/GSO batching.

Run:

```bash
dotnet run -c Release --project benchmarks/Keryx.ScaleHarness -- --duration 5
# options: --profile AeadAes256Gcm  --arms 1,4
```

Numbers are single-machine; a true 10k+ load test needs multiple driver boxes (see the PR
description / report).
