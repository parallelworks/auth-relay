#!/usr/bin/env bash
# Wrapper that runs pcsc/stdio_bridge.py with PWRELAY_BRIDGE_DEBUG
# exported. Used as the `remote:` command in the p11-kit module config
# when we want byte-level RPC traces.
#
# Why a wrapper script (not env in the module config itself): p11-kit's
# `remote: |<cmd>` parser doesn't handle env-var assignments before the
# command — the resulting module silently disappears from
# `p11-kit list-modules`. Spawning a real script with `exec` works
# because p11-kit just spawns it; the script handles its own env.

set -e

# Log path — fixed so anyone can `tail -f` it during a sign attempt.
export PWRELAY_BRIDGE_DEBUG="${PWRELAY_BRIDGE_DEBUG:-/tmp/pwrelay-bridge.log}"

HERE="$(cd "$(dirname "$0")" && pwd)"
PY=""
for cand in python3 python; do
  if command -v "$cand" >/dev/null 2>&1; then
    PY=$(command -v "$cand"); break
  fi
done
[ -z "$PY" ] && { echo "stdio_bridge: no python3 on PATH" >&2; exit 1; }

# Critical: exec so we replace ourselves with python — preserves
# the stdin/stdout p11-kit-proxy is talking through.
exec "$PY" "$HERE/stdio_bridge.py" "$@"
