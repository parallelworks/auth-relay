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
#
# Collect ALL missing prereqs in one pass and print a single block with the
# exact install command. Avoids the "install one, hit the next, install
# the next, hit another" loop.

missing_pkgs=()
missing_cmds=()

# CLI tools.
for cmd in p11-kit socat; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    missing_cmds+=("$cmd")
    missing_pkgs+=("$cmd")
  fi
done

# OpenSC PKCS#11 module — locations vary by OS / install method.
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
  missing_cmds+=("opensc-pkcs11.so")
  missing_pkgs+=("opensc")
fi

if (( ${#missing_cmds[@]} > 0 )); then
  cat >&2 <<EOF
============================================================
 CAC relay can't start — missing prereqs on this laptop:
   - ${missing_cmds[*]}

 Install them with ONE of these:
   macOS (Homebrew):   brew install ${missing_pkgs[*]}
   Debian / Ubuntu:    sudo apt install ${missing_pkgs[*]}
   RHEL / Fedora:      sudo dnf install ${missing_pkgs[*]}

 Then re-run:   ./pwrelay up <resource> --cac
============================================================
EOF
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

say "starting p11-kit server (provider: $OPENSC_MOD)"
# --foreground keeps it attached so $! is the actual server PID (without
# this flag p11-kit daemonizes and outlives the script).
#
# We deliberately do NOT pass --socket-base — older p11-kit versions
# (notably Homebrew's macOS build) don't recognize it. Letting p11-kit
# pick the socket location is fine: it announces the chosen path via
# P11_KIT_SERVER_ADDRESS= on its stdout, which we parse below.
p11-kit server \
    --foreground \
    --name pwrelay-cac \
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
