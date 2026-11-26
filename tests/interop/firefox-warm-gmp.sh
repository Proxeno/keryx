#!/usr/bin/env bash
# Warms the OpenH264 GMP into a template Firefox profile for the interop lanes; see ci.yml.
# Usage: firefox-warm-gmp.sh <firefox-path>
set -u
FF="$1"
PROFILE="$HOME/keryx-ff-gmp"
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
# Wait for the plugin file AND the registration pref: Firefox only loads a GMP whose version
# is recorded in prefs.js, and that write lands after the download, so killing on the file
# alone leaves a profile that ignores the plugin (BrowserLauncher copies prefs.js to register
# it in each test profile). Require both before killing.
for i in $(seq 1 40); do
  if ls "$PROFILE"/gmp-gmpopenh264/*/libgmpopenh264.* >/dev/null 2>&1 \
     && grep -q 'gmp-gmpopenh264.version' "$PROFILE/prefs.js" 2>/dev/null; then
    echo "OpenH264 GMP downloaded and registered."
    break
  fi
  sleep 2
done
sleep 2
kill "$FF_PID" 2>/dev/null || true
echo "KERYX_FIREFOX_GMP_DIR=$PROFILE" >> "$GITHUB_ENV"
grep 'gmp-gmpopenh264.version' "$PROFILE/prefs.js" 2>/dev/null || echo "OpenH264 GMP not registered after warm-up (tests will fetch on demand)"
