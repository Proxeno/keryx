# Keryx.Sctp

SCTP over DTLS for WebRTC data channels, including DCEP channel negotiation, ordered/unordered delivery, partial reliability (maxRetransmits) and RFC 8260 user-message interleaving (I-DATA) so a large message on one stream cannot head-of-line-block small messages on others.

Part of [Keryx](https://github.com/Proxeno/keryx), a from-scratch WebRTC stack for .NET licensed under Apache-2.0.
