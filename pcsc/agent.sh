#!/usr/bin/env bash
# CAC / PIV laptop-side agent (Phase 2 of the design — minimal first draft).
#
# What it does today
#   Wraps p11-kit-server around the local OpenSC PKCS#11 module so the
#   user's plugged-in CAC card is exposed over a Unix socket.
#   Then bridges that socket to a TCP port that pw ssh -R can carry to
#   the VDI side.
#
# Status: works for happy-path local-loopback testing; integration with
#   pwrelay (i.e., auto-spawn this agent alongside the FIDO agent) is
#   still TODO. See docs/cac-relay-design.md.
#
# Usage:
#   bash pcsc/agent.sh                       # default port 7888
#   PW_CAC_PORT=7900 bash pcsc/agent.sh      # override port
#
# Prereqs on the laptop:
#   - OpenSC installed (Mac: brew install opensc; Linux: distro package)
#   - p11-kit (typically pre-installed; Mac: brew install p11-kit)
#   - socat (Mac: brew install socat; Linux: distro package)
#   - A CCID-class USB smartcard reader with a CAC card inserted

set -euo pipefail

PORT="${PW_CAC_PORT:-7888}"
HERE="$(cd "$(dirname "$0")" && pwd)"

err() { printf '%s\n' "[pcsc-agent error] $*" >&2; }
say() { printf '%s\n' "[pcsc-agent] $*"; }

# ---- prereq checks --------------------------------------------------------

for cmd in p11-kit socat; do
  command -v "$cmd" >/dev/null 2>&1 || {
    err "$cmd not on PATH. Install via your package manager (brew/apt/yum)."
    exit 1
  }
done

# Find OpenSC's PKCS#11 module. Locations vary by OS / install method.
OPENSC_MOD=""
for cand in \
    /opt/homebrew/lib/opensc-pkcs11.so \
    /usr/local/lib/opensc-pkcs11.so \
    /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
    /usr/lib64/opensc-pkcs11.so \
    /usr/lib/opensc-pkcs11.so; do
  if [[ -f "$cand" ]]; then
    OPENSC_MOD="$cand"
    break
  fi
done
if [[ -z "$OPENSC_MOD" ]]; then
  err "couldn't find opensc-pkcs11.so. Install OpenSC and retry."
  err "  Mac:   brew install opensc"
  err "  Linux: apt install opensc  (or dnf install opensc, etc.)"
  exit 1
fi
say "using OpenSC PKCS#11 module: $OPENSC_MOD"

# ---- start p11-kit server -------------------------------------------------
#
# p11-kit server picks its socket path itself (under XDG_RUNTIME_DIR by
# default, or under --socket-base) and prints it on stdout as
#   P11_KIT_SERVER_ADDRESS=unix:path=/the/actual/path;
# We capture that line and use the path it announces — don't try to
# hardcode/guess the path.

WORK_DIR="${TMPDIR:-/tmp}/pwrelay-cac-$$"
mkdir -p "$WORK_DIR"
STDOUT_FILE="$WORK_DIR/server.out"
trap 'rm -rf "$WORK_DIR"; jobs -p | xargs -r kill 2>/dev/null' EXIT INT TERM

say "starting p11-kit server (socket-base: $WORK_DIR)"
# --foreground keeps it attached so $! is the actual server PID (without
# this flag p11-kit daemonizes and outlives the script).
p11-kit server \
    --foreground \
    --name pwrelay-cac \
    --socket-base "$WORK_DIR" \
    --provider "$OPENSC_MOD" \
    "pkcs11:" \
    > "$STDOUT_FILE" 2>&1 &
P11_PID=$!

SOCKET=""
for _ in $(seq 1 50); do  # up to ~10s
  if grep -q '^P11_KIT_SERVER_ADDRESS=' "$STDOUT_FILE" 2>/dev/null; then
    SOCKET=$(grep -m1 '^P11_KIT_SERVER_ADDRESS=' "$STDOUT_FILE" \
              | sed -E 's|^P11_KIT_SERVER_ADDRESS=unix:path=([^;]+);?.*|\1|')
    [[ -S "$SOCKET" ]] && break
  fi
  if ! kill -0 "$P11_PID" 2>/dev/null; then
    err "p11-kit server exited early. Output:"
    sed 's/^/  /' "$STDOUT_FILE" >&2
    exit 1
  fi
  sleep 0.2
done

if [[ -z "$SOCKET" || ! -S "$SOCKET" ]]; then
  err "p11-kit server didn't print P11_KIT_SERVER_ADDRESS in ~10s. Output:"
  sed 's/^/  /' "$STDOUT_FILE" >&2
  kill "$P11_PID" 2>/dev/null || true
  exit 1
fi
say "p11-kit server up (pid $P11_PID); socket: $SOCKET"

# ---- bridge to TCP --------------------------------------------------------

say "bridging Unix socket -> 127.0.0.1:$PORT (socat)"
socat TCP-LISTEN:"$PORT",bind=127.0.0.1,reuseaddr,fork UNIX-CONNECT:"$SOCKET" &
SOCAT_PID=$!
say "socat bridge up (pid $SOCAT_PID)"
say "agent ready — point a pw ssh -R $PORT:127.0.0.1:$PORT at this laptop"
say "(this terminal stays attached; Ctrl+C to stop. pwrelay up --cac spawns this for you.)"

wait $P11_PID $SOCAT_PID
