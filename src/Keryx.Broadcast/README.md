# Keryx.Broadcast

Shared-socket broadcast fan-out transport: a `BroadcastEndpoint` serves many viewers over one UDP socket, demultiplexing inbound datagrams to per-viewer `ViewerSession`s by 5-tuple (learned from each viewer's first STUN Binding request), so per-ingest-packet fan-out has a single socket to batch on. Each viewer keeps its own ICE session, DTLS handshake and per-viewer SRTP keys — only the socket is shared. `BroadcastEndpointOptions.SocketPoolSize` scales the send path across N sockets via Linux `SO_REUSEPORT` (a single-socket fallback elsewhere), and `BroadcastEndpoint.GetShardStatistics()` exposes per-shard sent/dropped/control/receive counters.

See [`docs/design/broadcast-scale.md`](https://github.com/Proxeno/keryx/blob/main/docs/design/broadcast-scale.md) §2.

Part of [Keryx](https://github.com/Proxeno/keryx), a from-scratch WebRTC stack for .NET licensed under Apache-2.0.
