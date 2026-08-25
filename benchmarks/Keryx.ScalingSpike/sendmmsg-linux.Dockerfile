# Runs Arm C (Linux sendmmsg batched-send benchmark) on a real Linux kernel, which macOS cannot do
# natively. The base .NET 10 SDK image is Ubuntu 24.04 — the same distro as the GitHub ubuntu-latest
# runner and the target deployment. On Apple Silicon the default arm64 image runs natively in Docker
# Desktop's Linux VM (no QEMU), so the syscall-rate numbers are real, not emulated.
#
# Build (from repo root):
#   docker build -f benchmarks/Keryx.ScalingSpike/sendmmsg-linux.Dockerfile -t keryx-sendmmsg .
# Run (mounts the working tree so code changes need no image rebuild):
#   docker run --rm -v "$PWD":/work -w /work keryx-sendmmsg \
#       dotnet run --project benchmarks/Keryx.ScalingSpike -c Release -- --arms C
FROM mcr.microsoft.com/dotnet/sdk:10.0
WORKDIR /work
