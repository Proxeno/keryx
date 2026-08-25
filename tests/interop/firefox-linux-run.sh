#!/usr/bin/env bash
# Runs the Firefox interop lane inside the Linux repro container (see firefox-linux.Dockerfile),
# mirroring the .github/workflows/ci.yml `firefox-interop` job: build, warm the OpenH264 GMP into a
# template profile, then run the FirefoxInterop tests fail-not-skip. Pass extra `dotnet test`
# arguments through, e.g. a --filter to run a single test.
set -euo pipefail

FF="${KERYX_FIREFOX_PATH:-/usr/bin/firefox}"

echo "=== Firefox version ==="
"$FF" --version

echo "=== Warm up OpenH264 GMP ==="
PROFILE="${HOME:-/root}/keryx-ff-gmp"
mkdir -p "$PROFILE"
cat > "$PROFILE/user.js" <<'EOF'
user_pref("media.gmp-gmpopenh264.enabled", true);
user_pref("media.gmp-gmpopenh264.autoupdate", true);
user_pref("media.gmp-manager.updateEnabled", true);
user_pref("toolkit.telemetry.enabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("app.update.enabled", false);
EOF
"$FF" --headless --no-remote --new-instance --profile "$PROFILE" about:blank &
FF_PID=$!
# Wait for the plugin file AND the registration pref: Firefox only loads a GMP whose version is
# recorded in prefs.js, and that write lands after the download, so killing on the file alone leaves
# a profile that ignores the plugin. Require both before killing.
for _ in $(seq 1 40); do
  if ls "$PROFILE"/gmp-gmpopenh264/*/libgmpopenh264.* >/dev/null 2>&1 \
     && grep -q 'gmp-gmpopenh264.version' "$PROFILE/prefs.js" 2>/dev/null; then
    echo "OpenH264 GMP downloaded and registered."
    break
  fi
  sleep 2
done
sleep 2
kill "$FF_PID" 2>/dev/null || true
export KERYX_FIREFOX_GMP_DIR="$PROFILE"
grep 'gmp-gmpopenh264.version' "$PROFILE/prefs.js" 2>/dev/null \
  || echo "OpenH264 GMP not registered after warm-up (tests will fetch on demand)"

echo "=== Build ==="
dotnet build Keryx.slnx --configuration Release

echo "=== Run FirefoxInterop tests ==="
export KERYX_REQUIRE_FIREFOX=1
dotnet test Keryx.slnx --configuration Release --no-build --filter "Category=FirefoxInterop" "$@"
