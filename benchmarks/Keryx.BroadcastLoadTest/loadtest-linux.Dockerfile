# Runs the end-to-end SFU broadcast load-test rig on a real Linux kernel, so the batched egress uses the
# real sendmmsg(2) syscall (which macOS cannot do natively) and the syscall/CPU numbers are realistic.
# The base .NET 10 SDK image is Ubuntu 24.04 — the same distro as the GitHub ubuntu-latest runner and the
# target deployment. On Apple Silicon the default arm64 image runs natively in Docker Desktop's Linux VM
# (no QEMU), so the numbers are real, not emulated.
#
# Build (from repo root):
#   docker build -f benchmarks/Keryx.BroadcastLoadTest/loadtest-linux.Dockerfile -t keryx-loadtest .
# Run (mounts the working tree so code changes need no image rebuild; raise the fd limit so thousands of
# viewer sinks can bind):
#   docker run --rm --ulimit nofile=1048576:1048576 -v "$PWD":/work -w /work keryx-loadtest \
#       dotnet run --project benchmarks/Keryx.BroadcastLoadTest -c Release -- --arms A,B,C
FROM mcr.microsoft.com/dotnet/sdk:10.0
WORKDIR /work
