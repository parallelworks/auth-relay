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

SOCKET_DIR="${TMPDIR:-/tmp}/pwrelay-cac-$$"
mkdir -p "$SOCKET_DIR"
trap 'rm -rf "$SOCKET_DIR"; jobs -p | xargs -r kill 2>/dev/null' EXIT INT TERM
SOCKET="$SOCKET_DIR/p11.sock"

say "starting p11-kit server on Unix socket: $SOCKET"
p11-kit server --provider "$OPENSC_MOD" --name pwrelay-cac &
P11_PID=$!
# p11-kit server prints "P11_KIT_SERVER_ADDRESS=..." on its stdout; the
# Unix socket path is inside that env var. Wait for the server to be
# ready by probing.
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if [[ -S "$SOCKET" ]]; then break; fi
  sleep 0.3
done
if [[ ! -S "$SOCKET" ]]; then
  err "p11-kit server didn't create $SOCKET in 3s"
  kill "$P11_PID" 2>/dev/null || true
  exit 1
fi
say "p11-kit server up (pid $P11_PID)"

# ---- bridge to TCP --------------------------------------------------------

say "bridging Unix socket -> 127.0.0.1:$PORT (socat)"
socat TCP-LISTEN:"$PORT",bind=127.0.0.1,reuseaddr,fork UNIX-CONNECT:"$SOCKET" &
SOCAT_PID=$!
say "socat bridge up (pid $SOCAT_PID)"
say "agent ready — point a pw ssh -R $PORT:127.0.0.1:$PORT at this laptop"

wait $P11_PID $SOCAT_PID
