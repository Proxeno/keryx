#!/usr/bin/env bash
# Wait until every given package version is listed on nuget.org.
#
# nuget.org accepts a push before the version is visible in the flat container
# feed, so a publish step that returns success does not mean consumers can
# restore the package yet. Poll the flat-container index for each id until the
# version appears, or fail once the shared deadline passes.
#
# Usage: wait-nuget-index.sh <version> <id>...
#
# Environment overrides (for local testing):
#   WAIT_TIMEOUT        total seconds across all ids (default 1200)
#   WAIT_INTERVAL       seconds between polls (default 30)
#   NUGET_FLAT_CONTAINER  flat-container base URL
#                       (default https://api.nuget.org/v3-flatcontainer)
set -euo pipefail

wait_timeout=${WAIT_TIMEOUT:-1200}
wait_interval=${WAIT_INTERVAL:-30}
flat_container=${NUGET_FLAT_CONTAINER:-https://api.nuget.org/v3-flatcontainer}

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <version> <id>..." >&2
  exit 2
fi

version=$1
shift
version_lower=$(printf '%s' "$version" | tr '[:upper:]' '[:lower:]')
total=$#

deadline=$((SECONDS + wait_timeout))
pending=("$@")

while :; do
  still=()
  for id in "${pending[@]}"; do
    id_lower=$(printf '%s' "$id" | tr '[:upper:]' '[:lower:]')
    url="$flat_container/$id_lower/index.json"
    # -f makes curl exit non-zero on the 404 that means "not indexed yet".
    if body=$(curl -fsS --max-time 20 "$url" 2>/dev/null) &&
      printf '%s' "$body" | jq -e --arg v "$version_lower" '.versions | index($v)' >/dev/null 2>&1; then
      echo "indexed: $id $version"
    else
      still+=("$id")
    fi
  done

  if [ "${#still[@]}" -eq 0 ]; then
    echo "All $total package(s) at $version are indexed on nuget.org."
    exit 0
  fi

  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "Timed out after ${wait_timeout}s waiting for nuget.org to index $version." >&2
    echo "Missing: ${still[*]}" >&2
    exit 1
  fi

  pending=("${still[@]}")
  echo "not yet indexed (${#pending[@]}): ${pending[*]}; retrying in ${wait_interval}s"
  remaining=$((deadline - SECONDS))
  sleep_for=$wait_interval
  if [ "$sleep_for" -gt "$remaining" ]; then
    sleep_for=$remaining
  fi
  if [ "$sleep_for" -lt 1 ]; then
    sleep_for=1
  fi
  sleep "$sleep_for"
done
