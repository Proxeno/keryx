# Keryx.Rtp — design notes

Pure packet logic: RTP, RTCP (including typed feedback), and the packetizer seam. No sockets, no
crypto, no threads — and on the per-packet hot path, no allocation.

## Decisions

- **`RtpHeader.TryParse` never throws on wire data** and is tested at every truncation boundary,
  with CSRC lists, header extensions (including RFC 8285 one-byte elements) and padding.
- **`RtpHeader` splits hot and cold.** The common shape — no CSRC list, no header extension —
  serializes and parses through a straight-line path that moves the twelve fixed bytes as one
  64-bit plus one 32-bit big-endian word behind a single length check; CSRC lists and extensions
  go through separate `[MethodImpl(NoInlining)]` helpers so their code never bloats the hot path.
  Defensive validation (CSRC/extension length invariants) also moved to the cold path, where it
  is the only place those invariants can be violated — the throwing behaviour of `WriteTo` and
  `TryWriteTo` is unchanged. `WriteTo`/`TryWriteTo`/`TryParse` are `AggressiveInlining` so callers
  can promote the `ref struct` and drop stores to header fields they never read; that is worth
  ~2.3 ns per header round trip on Apple silicon, measured.
- **Annex B start-code scanning is vectorized.** `AnnexB.IndexOfStartCode` delegates to
  `MemoryExtensions.IndexOf` on the three-byte pattern rather than testing one byte at a time; on
  a 25 KB access unit that is the difference between 8.2 µs and 0.85 µs of packetization.
- **`RtpStreamSender`** owns per-stream sequence/timestamp/counter state (single-writer by
  contract) and builds packets into caller buffers so the send path stays copy-light.
- **RTCP is typed all the way down:** SR/RR/SDES/BYE plus first-class feedback — PLI, FIR,
  GenericNack (with PID/BLP expansion to sequence numbers), transport-cc (full chunk parser:
  run-length and 1/2-bit status vectors with receive deltas), REMB parse. The
  `RtcpCompoundReader` walks compound buffers robustly, skipping unknown packet types.
  RFC 5761 PT-range demux (`IsRtcp`) lives here.
- **Retransmission is packet logic, not transport policy.** `RtpSendHistory` is a ring of recently
  sent packets keyed by sequence number, backed by one preallocated arena (`capacity × maxPacketSize`)
  so the steady state allocates nothing; it evicts on ring wrap, on age, and on a byte budget, and it
  applies the per-packet resend rate limit at lookup time. A private lock guards it because packets
  are stored from the send thread while NACKs are looked up on the RTCP receive loop — the critical
  section is a bounds check and one `memcpy`, so a lock-free design would buy nothing here.
  `RtxRetransmitter` turns a hit into an RFC 4588 §4 packet on the repair stream's own SSRC, payload
  type and sequence-number space (only the timestamp and marker bit come from the original), bounded
  by a token-bucket bandwidth budget. `RtxPacket` holds the payload format itself — the two-octet OSN
  prefix — plus the inverse, so a repair packet can be decapsulated back to the original.
- **The packetizer seam (`IRtpPayloadizer`)** is the community-codec extension point: frame in,
  MTU-bounded payloads out, marker on the last payload of the frame. `H264Packetizer`
  (RFC 6184 packetization-mode=1: single NAL / STAP-A aggregation / FU-A fragmentation) and
  `OpusPacketizer` (RFC 7587) prove it for video and audio. An `H264Depacketizer` reassembles
  Annex B access units — used by the loopback tests to verify byte-identity of what a receiver
  would see.

## Testing

RTP header edge-case matrix, round-trips for every RTCP type, NACK bitmap vectors, hand-built
transport-cc vectors mixing chunk kinds, golden STAP-A byte layouts, FU-A fragment/reassemble
identity on oversized NALs, marker placement, RFC 4588 §4 packet rules, send-history eviction by
wrap/age/bytes across the 65535→0 sequence seam, resend rate limiting and the retransmission
bandwidth budget, and a concurrent store/lookup soak. RFC sections cited per test.
