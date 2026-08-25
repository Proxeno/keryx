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

## `Keryx.BroadcastLoadTest` — end-to-end SFU broadcast load-test rig

Where `Keryx.ScaleHarness` models the fan-out data path, this rig stands up **one real SFU** — a
synthetic 720p/480p ingest source fanned out through a real `BroadcastEndpoint` (shared socket +
`BroadcastFanout` + batched `sendmmsg` send) — and drives **real viewers** against it over real UDP,
ramping the viewer count until the box saturates. Three arms, both egress paths, both resolutions:

- **Arm A — real viewer `PeerConnection`s (per-viewer path).** N recvonly viewers each complete a
  real ICE + DTLS-SRTP handshake over the endpoint's shared socket and decrypt real media the egress
  forwards with each viewer's own key (`PeerConnection.TryForwardRtp`). Reports connection-setup
  throughput, success rate, per-viewer decode, and CPU/mem/GC. The honest end-to-end number — and,
  because the SFU and the viewers share this box's cores, it saturates well below the engine ceiling.
- **Arm B — fan-out ceiling, per-viewer path.** The real `BroadcastFanout` re-encrypts one ingest
  packet under each of N viewers' own keys across a worker pool, and `BroadcastEndpoint.SendBatch`
  flushes the N datagrams in one `sendmmsg(2)` (Linux). N real loopback+SRTP sinks receive and decrypt.
- **Arm C — fan-out ceiling, shared-key encrypt-once path.** One SRTP encrypt per ingest packet, then
  N byte-identical datagrams through the same batched send — the O(N)→O(1) crypto collapse of §5.

The rig auto-reports the machine specs, whether native `sendmmsg` is active, and — honestly — what a
true multi-box rig would still add that a single box cannot show (the NIC wall).

Run (native `sendmmsg` needs Linux; use the Dockerfile on macOS):

```bash
dotnet run -c Release --project benchmarks/Keryx.BroadcastLoadTest -- --arms A,B,C --duration 5
# options: --profile 480p  --pc-viewers 100,250,500  --viewers 1000,5000,10000  --workers 16

docker build -f benchmarks/Keryx.BroadcastLoadTest/loadtest-linux.Dockerfile -t keryx-loadtest .
docker run --rm --ulimit nofile=1048576:1048576 -v "$PWD":/work -w /work keryx-loadtest \
    dotnet run --project benchmarks/Keryx.BroadcastLoadTest -c Release -- --arms A,B,C
```

Arms B/C isolate the SFU send engine with lightweight real UDP+SRTP sinks; Arm A is the real-connection
ceiling. Neither shows the ~35k/100 GbE NIC wall — that needs multiple driver boxes against one SFU over
a real NIC (see the PR description / report).
