# Reproduces the GitHub Actions `firefox-interop` lane locally on Linux, so the ICE/DTLS behaviour
# that only shows up on a real Linux runner (not macOS) can be diagnosed in a container. It mirrors
# what .github/workflows/ci.yml installs: the .NET 10 SDK, a headless Firefox, and the runtime bits
# Firefox needs; the OpenH264 GMP is downloaded at run time exactly as the CI warm-up step does.
#
# The base .NET 10 SDK image is Ubuntu 24.04 — the same distro as the GitHub `ubuntu-latest` runner.
# Mozilla's APT repository ships real Firefox packages for amd64 only (its arm64 "firefox" is just
# Ubuntu's snap stub, which does not run in a container), so build for amd64 to match the x64 CI
# runner exactly — under QEMU on an arm64 host:
#   docker build --platform linux/amd64 -f tests/interop/firefox-linux.Dockerfile -t keryx-ff-linux .
# Run (mounts the working tree so you can iterate on code without rebuilding the image):
#   docker run --platform linux/amd64 --rm -v "$PWD":/work -w /work keryx-ff-linux \
#       bash tests/interop/firefox-linux-run.sh
FROM mcr.microsoft.com/dotnet/sdk:10.0

# Latest Firefox from Mozilla's own APT repository (the same channel browser-actions/setup-firefox
# tracks). Pin the repo so apt prefers it over Ubuntu's snap transition package; Firefox's own
# Depends pull in the shared libraries a headless launch needs.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends wget gnupg ca-certificates procps; \
    install -d -m 0755 /etc/apt/keyrings; \
    wget -qO- https://packages.mozilla.org/apt/repo-signing-key.gpg > /etc/apt/keyrings/packages.mozilla.org.asc; \
    echo "deb [signed-by=/etc/apt/keyrings/packages.mozilla.org.asc] https://packages.mozilla.org/apt mozilla main" \
        > /etc/apt/sources.list.d/mozilla.list; \
    printf 'Package: *\nPin: origin packages.mozilla.org\nPin-Priority: 1000\n' \
        > /etc/apt/preferences.d/mozilla; \
    apt-get update; \
    apt-get install -y firefox; \
    rm -rf /var/lib/apt/lists/*; \
    firefox --version

ENV KERYX_FIREFOX_PATH=/usr/bin/firefox
