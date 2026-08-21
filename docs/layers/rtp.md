# Keryx.Rtp — design notes

Pure packet logic: RTP, RTCP (including typed feedback), and the packetizer seam. No sockets, no
crypto, no threads — and on the per-packet hot path, no allocation.

## Decisions

- **`RtpHeader.TryParse` never throws on wire data** and is tested at every truncation boundary,
  with CSRC lists, header extensions (including RFC 8285 one-byte elements) and padding.
- **`RtpStreamSender`** owns per-stream sequence/timestamp/counter state (single-writer by
  contract) and builds packets into caller buffers so the send path stays copy-light.
- **RTCP is typed all the way down:** SR/RR/SDES/BYE plus first-class feedback — PLI, FIR,
  GenericNack (with PID/BLP expansion to sequence numbers), transport-cc (full chunk parser:
  run-length and 1/2-bit status vectors with receive deltas), REMB parse. The
  `RtcpCompoundReader` walks compound buffers robustly, skipping unknown packet types.
  RFC 5761 PT-range demux (`IsRtcp`) lives here.
- **The packetizer seam (`IRtpPayloadizer`)** is the community-codec extension point: frame in,
  MTU-bounded payloads out, marker on the last payload of the frame. `H264Packetizer`
  (RFC 6184 packetization-mode=1: single NAL / STAP-A aggregation / FU-A fragmentation) and
  `OpusPacketizer` (RFC 7587) prove it for video and audio. An `H264Depacketizer` reassembles
  Annex B access units — used by the loopback tests to verify byte-identity of what a receiver
  would see.

## Testing

192 tests: RTP header edge-case matrix, round-trips for every RTCP type, NACK bitmap vectors,
hand-built transport-cc vectors mixing chunk kinds, golden STAP-A byte layouts, FU-A
fragment/reassemble identity on oversized NALs, marker placement. RFC sections cited per test.
