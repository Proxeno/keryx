# Keryx.Core

Core primitives shared by every Keryx layer: big-endian binary readers/writers, the datagram transport contract, logging abstractions, a `sendmmsg` batched datagram sender with a managed fallback, and the `SO_REUSEPORT` socket option helper. No dependencies beyond the BCL.

Part of [Keryx](https://github.com/Proxeno/keryx), a from-scratch WebRTC stack for .NET licensed under Apache-2.0.
