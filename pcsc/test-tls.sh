#!/usr/bin/env bash
# Smoke test for the CAC relay (Phase 3).
#
# Exercises the full chain end-to-end:
#
#   in-VDI openssl s_client
#     -> NSS (via -engine, optional)
#     -> p11-kit-client.so
#     -> pw ssh -R tunnel
#     -> laptop pcsc/agent.sh
#     -> OpenSC -> CAC
#
# Without -engine, this is just a TLS reachability check + cert
# negotiation dump (no client-cert sign). With pkcs11-tool checks first,
# we confirm the laptop card is visible through the relay.
#
# Usage:
#   bash pcsc/test-tls.sh                       # defaults to sso.noaa.gov:443
#   bash pcsc/test-tls.sh login.gov 443
#
# Run AFTER:
#   1. laptop:  bash pcsc/agent.sh
#   2. laptop:  ./pwrelay up               # (once CAC tunnel is folded into pwrelay)
#   3. VDI:     bash pcsc/bootstrap.sh

set -euo pipefail

HOST="${1:-sso.noaa.gov}"
PORT="${2:-443}"
PW_CAC_PORT="${PW_CAC_PORT:-7888}"

say() { printf '%s\n' "[pcsc-test] $*"; }
err() { printf '%s\n' "[pcsc-test error] $*" >&2; }

# ---- 1. Is the tunnel up? -------------------------------------------------

if command -v ss >/dev/null 2>&1; then
  if ! ss -ltn 2>/dev/null | grep -q ":${PW_CAC_PORT}\b"; then
    err "no listener on 127.0.0.1:${PW_CAC_PORT}"
    err "  -> the CAC tunnel isn't established. On your laptop, run:"
    err "       bash pcsc/agent.sh"
    err "     and ensure pwrelay forwards ${PW_CAC_PORT} (currently a TODO — Phase 4)."
    exit 1
  fi
  say "tunnel listener on 127.0.0.1:${PW_CAC_PORT}: ok"
fi

# ---- 2. Does the PKCS#11 module see the card? -----------------------------

P11_KIT_CLIENT=""
for cand in \
    /usr/lib64/pkcs11/p11-kit-client.so \
    /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so \
    /usr/lib/pkcs11/p11-kit-client.so; do
  [[ -f "$cand" ]] && P11_KIT_CLIENT="$cand" && break
done
if [[ -z "$P11_KIT_CLIENT" ]]; then
  err "p11-kit-client.so not found; run bash pcsc/bootstrap.sh first."
  exit 1
fi

if command -v pkcs11-tool >/dev/null 2>&1; then
  say "listing slots through ${P11_KIT_CLIENT}..."
  if ! pkcs11-tool --module "$P11_KIT_CLIENT" --list-slots 2>&1; then
    err "pkcs11-tool failed — the laptop side may not be running."
    exit 1
  fi
  say "listing objects (no PIN — only public objects will show)..."
  pkcs11-tool --module "$P11_KIT_CLIENT" --list-objects 2>&1 | head -40 || true
else
  say "skipping pkcs11-tool checks (not installed; sudo apt install opensc to get it)"
fi

# ---- 3. TLS reachability --------------------------------------------------

say "openssl s_client -> ${HOST}:${PORT} (server cert dump only)"
echo | openssl s_client \
    -connect "${HOST}:${PORT}" \
    -servername "${HOST}" \
    -showcerts \
    -brief 2>&1 | head -20 || true

say ""
say "If the slot listing above shows your CAC and a TLS handshake completed,"
say "open Chrome in the VDI, navigate to https://${HOST}, and you should see"
say "your CAC cert in the certificate-selection dialog."
