# Keryx.Rtp

RTP packet model, RTCP (SR/RR/SDES/BYE) and first-class typed RTCP feedback (PLI, FIR, NACK, transport-cc), plus media packetizers for H.264 (STAP-A/FU-A), VP8, VP9, AV1, Opus and octet-per-tick audio (`OctetAudioPacketizer`: PCMU, PCMA, G.722) behind a generic packetizer interface, ULPFEC/FlexFEC with adaptive protection, RTX retransmission, and the GCC congestion controller and pacer.

Part of [Keryx](https://github.com/Proxeno/keryx), a from-scratch WebRTC stack for .NET licensed under Apache-2.0.
