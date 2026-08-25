#!/usr/bin/env bash
# Runs the BatchedDatagramSender Linux fast-path validation inside a real Linux container, where the
# native sendmmsg(2) path is actually taken (macOS has no sendmmsg). It builds the solution and runs
# the Category=SendmmsgLinux tests, which assert a batch sent via sendmmsg arrives correctly at
# distinct loopback receivers and report native-vs-fallback datagrams/s.
#
# Build the image (from repo root; the ScalingSpike Dockerfile is a plain .NET 10 SDK image):
#   docker build -f benchmarks/Keryx.ScalingSpike/sendmmsg-linux.Dockerfile -t keryx-sendmmsg .
# Run (mounts the working tree so code changes need no image rebuild):
#   docker run --rm -v "$PWD":/work -w /work keryx-sendmmsg bash tests/interop/sendmmsg-linux-run.sh
#
# Pass extra `dotnet test` arguments through, e.g. --filter to select a single test.
set -euo pipefail

echo "=== Kernel ==="
uname -a

echo "=== Build ==="
dotnet build Keryx.slnx --configuration Release

echo "=== Run BatchedDatagramSender Linux (sendmmsg) tests ==="
# --logger 'console;verbosity=detailed' surfaces the throughput report the perf test writes.
dotnet test tests/Keryx.Core.Tests/Keryx.Core.Tests.csproj \
  --configuration Release --no-build \
  --filter "Category=SendmmsgLinux" \
  --logger 'console;verbosity=detailed' "$@"
