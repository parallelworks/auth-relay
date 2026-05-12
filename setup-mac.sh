#!/usr/bin/env bash
# Bootstrap the YubiKey relay laptop-side agent on macOS.
# Idempotent; safe to re-run.

set -euo pipefail

echo "==> checking Homebrew"
if ! command -v brew >/dev/null 2>&1; then
  echo "Homebrew not found. Install from https://brew.sh and re-run." >&2
  exit 1
fi

echo "==> installing libfido2 (provides FIDO/CTAP support that python-fido2 uses)"
brew list libfido2 >/dev/null 2>&1 || brew install libfido2

echo "==> verifying Python 3"
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not on PATH. brew install python or use system Python." >&2
  exit 1
fi
python3 --version

echo "==> installing python-fido2 (Yubico's library; needed for iteration 2)"
python3 -m pip install --user --upgrade fido2

echo "==> checking pw CLI"
if ! command -v pw >/dev/null 2>&1; then
  echo "pw CLI not found. Install per Parallel Works docs, then run: pw auth login" >&2
  exit 1
fi
pw version-update --help >/dev/null 2>&1 || true
pw --version

echo "==> checking SSH key the pw flow expects"
if [ ! -f ~/.ssh/pwcli ]; then
  echo "WARNING: ~/.ssh/pwcli not found. Run 'pw auth login' to provision it." >&2
fi

echo "==> done. Smoke test the loopback path:"
echo "    python3 laptop/agent.py --port 17777 &"
echo "    python3 workspace/client.py --port 17777"
echo "    kill %1"
