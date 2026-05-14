#!/usr/bin/env bash
# CAC / PIV VDI-side bootstrap (Phase 3).
#
# Wires the in-VDI Chrome up to the CAC card the user has plugged into
# their LAPTOP. The chain on this side is:
#
#   Chrome <-NSS-> p11-kit-client.so <-stdio-> socat <-TCP-> 127.0.0.1:7888
#                                                              │
#                                                              ▼
#                                                      pw ssh -R tunnel
#                                                              │
#                                                       laptop pcsc/agent.sh
#                                                              │
#                                                              ▼
#                                                       OpenSC PKCS#11
#                                                              │
#                                                              ▼
#                                                         CAC card (USB)
#
# What this script does:
#   1. Locate p11-kit-client.so (ships with the p11-kit package).
#   2. Drop a p11-kit module config at
#      ~/.config/p11-kit/modules/pwrelay-cac.module that uses socat to
#      reach 127.0.0.1:$PORT.
#   3. Register the module with NSS (~/.pki/nssdb) via modutil so
#      Chrome/Firefox find the CAC certs through it.
#
# Prereqs on the VDI host:
#   - p11-kit (typically pre-installed on RHEL/SLES/Ubuntu)
#   - socat
#   - nss tools (modutil, certutil) — typically in `nss-tools` / `libnss3-tools`
#
# Idempotent. Re-run any time. Doesn't touch any system-wide config;
# everything lives under $HOME.
#
# Usage:
#   bash pcsc/bootstrap.sh
#   PW_CAC_PORT=7900 bash pcsc/bootstrap.sh

set -euo pipefail

PORT="${PW_CAC_PORT:-7888}"
NSS_DB="${HOME}/.pki/nssdb"
MOD_NAME="pwrelay-cac"

err() { printf '%s\n' "[pcsc-bootstrap error] $*" >&2; }
say() { printf '%s\n' "[pcsc-bootstrap] $*"; }

# ---- prereq checks --------------------------------------------------------
#
# We need TWO things on the VDI side:
#   1. modutil + certutil for NSS registration (libnss3-tools / nss-tools).
#   2. A stdio<->TCP bridge tool that p11-kit's `remote:` field can invoke.
#      socat is the typical pick; on HPC images without it (NOAA Ursa
#      etc.) we fall back to ncat or nc — both can do the bridge with the
#      same effective semantics.

for cmd in modutil certutil; do
  command -v "$cmd" >/dev/null 2>&1 || {
    err "$cmd not on PATH (install libnss3-tools / nss-tools)."
    exit 1
  }
done

BRIDGE_CMD=""
PY=""
for cand in python3 python; do
  if command -v "$cand" >/dev/null 2>&1; then
    PY=$(command -v "$cand"); break
  fi
done

if command -v socat >/dev/null 2>&1; then
  # `socat - TCP:host:port` — stdin/stdout bridged to a TCP socket.
  BRIDGE_CMD="socat - TCP:127.0.0.1:${PORT}"
elif [[ -n "$PY" ]]; then
  # Python bridge — most reliable across platforms. Empirically ncat's
  # --no-shutdown semantics don't always let p11-kit-client complete a
  # slot enumeration on Rocky 9.6 even with TCP connectivity intact.
  # The Python bridge gives us explicit control of half-close behavior.
  HERE="$(cd "$(dirname "$0")" && pwd)"
  BRIDGE_CMD="$PY $HERE/stdio_bridge.py 127.0.0.1 ${PORT}"
elif command -v ncat >/dev/null 2>&1; then
  # Fallback only — keep as a last resort. ncat is Nmap's improved
  # netcat; --no-shutdown keeps stdin open after the remote half closes.
  BRIDGE_CMD="ncat --no-shutdown 127.0.0.1 ${PORT}"
elif command -v nc >/dev/null 2>&1; then
  BRIDGE_CMD="nc 127.0.0.1 ${PORT}"
else
  err "no stdio<->TCP bridge tool found. Need socat, python3, ncat, or nc."
  exit 1
fi
say "using bridge: $BRIDGE_CMD"

# ---- find p11-kit-client.so ----------------------------------------------

P11_KIT_CLIENT=""
for cand in \
    /usr/lib64/pkcs11/p11-kit-client.so \
    /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so \
    /usr/lib/pkcs11/p11-kit-client.so \
    /opt/homebrew/lib/pkcs11/p11-kit-client.so \
    /usr/local/lib/pkcs11/p11-kit-client.so; do
  if [[ -f "$cand" ]]; then
    P11_KIT_CLIENT="$cand"
    break
  fi
done
if [[ -z "$P11_KIT_CLIENT" ]]; then
  err "p11-kit-client.so not found. Install p11-kit:"
  err "  sudo apt install p11-kit-modules    (Debian/Ubuntu)"
  err "  sudo dnf install p11-kit            (RHEL/Rocky)"
  exit 1
fi
say "found p11-kit-client.so at $P11_KIT_CLIENT"

# ---- write p11-kit module config -----------------------------------------
#
# Two valid forms exist in pkcs11.conf:
#   module: <path>     — load this local .so as a module
#   remote: |<cmd>     — spawn <cmd>, treat its stdio as the PKCS#11 RPC
#
# We use *only* `remote:`. p11-kit-proxy.so (already registered with NSS
# on RHEL/Fedora/Rocky/Ubuntu) reads ~/.config/p11-kit/modules/*.module,
# finds this entry, spawns the bridge command, and surfaces the laptop's
# CAC slots through its own slot list. Chrome -> NSS -> p11-kit-proxy ->
# our bridge command -> TCP tunnel -> laptop p11-kit-server -> OpenSC.
#
# Earlier iterations also did `module: p11-kit-client.so` and
# `modutil -add pwrelay-cac -libfile p11-kit-client.so`, which loaded
# p11-kit-client.so directly via NSS. That code path does NOT read the
# pkcs11.conf `remote:` field — p11-kit-client.so only honors
# P11_KIT_SERVER_ADDRESS env. End result: module loaded, zero slots.

mkdir -p ~/.config/p11-kit/modules
cat > ~/.config/p11-kit/modules/${MOD_NAME}.module <<EOF
# Auto-generated by auth-relay/pcsc/bootstrap.sh
# Bridges the in-VDI PKCS#11 stack to the laptop's CAC via the
# auth-relay pw ssh -R tunnel (TCP on 127.0.0.1:${PORT}).
# p11-kit-proxy.so reads this file and spawns the remote command.
remote: |${BRIDGE_CMD}
EOF
chmod 600 ~/.config/p11-kit/modules/${MOD_NAME}.module
say "wrote module config: ~/.config/p11-kit/modules/${MOD_NAME}.module"

# ---- ensure NSS has p11-kit-proxy and clean up any old direct module -----

mkdir -p "$NSS_DB"
# Initialize the NSS db if it doesn't exist (Chrome will create one too,
# but we may run before Chrome has).
if [[ ! -f "$NSS_DB/cert9.db" ]]; then
  certutil -d "sql:$NSS_DB" -N --empty-password >/dev/null
  say "initialized NSS db at sql:$NSS_DB (empty password)"
fi

# Drop any prior direct registration of pwrelay-cac with NSS. The slots
# now flow through p11-kit-proxy, which NSS auto-loads.
modutil -dbdir "sql:$NSS_DB" -delete "$MOD_NAME" -force >/dev/null 2>&1 \
  && say "removed prior pwrelay-cac registration from NSS (now via p11-kit-proxy)" \
  || true

# Sanity check: p11-kit-proxy should already be in the NSS db. If not,
# the user needs nss-tools and a basic NSS setup.
if ! modutil -dbdir "sql:$NSS_DB" -list 2>/dev/null | grep -qiE "p11-kit-proxy|p11kit"; then
  err "p11-kit-proxy is NOT registered with NSS — the relay won't surface."
  err "On most RHEL/Fedora/Ubuntu systems p11-kit-proxy is registered"
  err "automatically. If Chrome doesn't see it either, run:"
  err "  modutil -dbdir sql:\$HOME/.pki/nssdb -add p11-kit-proxy \\"
  err "    -libfile \$(p11-kit list-modules | head -1) -force"
  exit 1
fi
say "p11-kit-proxy is registered with NSS — the laptop CAC will surface through it"

# ---- summary --------------------------------------------------------------

cat <<EOF

==============================================================================
 PW CAC relay — VDI side ready
==============================================================================

Module          : ${MOD_NAME}
Backend         : ${P11_KIT_CLIENT}
Remote socket   : 127.0.0.1:${PORT}  (must be tunneled in by pwrelay)
NSS database    : ${NSS_DB}

To verify the module loads (with the laptop side running and pwrelay up
with the CAC tunnel):

    pkcs11-tool --module ${P11_KIT_CLIENT} --list-slots
    modutil -dbdir sql:${NSS_DB} -list

To exercise the chain end-to-end:

    openssl s_client -connect sso.noaa.gov:443 -showcerts < /dev/null

…or just navigate Chrome to https://sso.noaa.gov and pick your CAC
cert in the certificate-selection dialog. Touch the card / enter the
PIN as you would for a local CAC.

To remove this registration later:

    modutil -dbdir sql:${NSS_DB} -delete ${MOD_NAME} -force
    rm ~/.config/p11-kit/modules/${MOD_NAME}.module

==============================================================================
EOF
