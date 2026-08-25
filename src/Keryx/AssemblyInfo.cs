using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("Keryx.IntegrationTests")]

// Benchmark harness drives the post-SRTP receive path (ProcessDecryptedRtp) through the same
// test-only seam the integration tests use, to measure per-packet receive cost and allocations.
[assembly: InternalsVisibleTo("Keryx.Benchmarks")]
