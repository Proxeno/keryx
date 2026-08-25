using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("Keryx.IntegrationTests")]

// Keryx.Broadcast's shared-key SFU tier (broadcast-scale.md §5) mints its encrypt-once SRTP context
// from a PublicBroadcastKey; the key bytes reach the SRTP layer only through this internal seam, never
// a public accessor.
[assembly: InternalsVisibleTo("Keryx.Broadcast")]

// Benchmark harness drives the post-SRTP receive path (ProcessDecryptedRtp) through the same
// test-only seam the integration tests use, to measure per-packet receive cost and allocations.
[assembly: InternalsVisibleTo("Keryx.Benchmarks")]
