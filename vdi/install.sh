#!/usr/bin/env bash
# Install the iter-3 components into the user's Chrome profile on the
# VDI host (typically the cluster mgmt node where the KasmVNC container
# runs, sharing the host network namespace).
#
# What this does:
#   1. Writes the native messaging host manifest into Chrome's per-user
#      NativeMessagingHosts directory, pointing at this repo's relay.py.
#   2. Prints the extension load instructions (Chrome Stable blocks
#      --load-extension; you load it via the UI once).
#
# Re-run after editing the extension to update the registered ID.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
EXT_DIR="${HERE}/extension"
NMH_DIR="${HERE}/nmh"
NMH_NAME="com.parallelworks.yubikey_relay"

# Detect Chrome NMH directory (Linux for VDI; macOS-style fallback for dev).
case "$(uname -s)" in
  Linux)
    CHROME_NMH="${HOME}/.config/google-chrome/NativeMessagingHosts"
    CHROMIUM_NMH="${HOME}/.config/chromium/NativeMessagingHosts"
    ;;
  Darwin)
    CHROME_NMH="${HOME}/Library/Application Support/Google/Chrome/NativeMessagingHosts"
    CHROMIUM_NMH="${HOME}/Library/Application Support/Chromium/NativeMessagingHosts"
    ;;
  *)
    echo "unsupported OS: $(uname -s)" >&2
    exit 1
    ;;
esac

# Pick a python3 capable of `from __future__ import annotations` (3.7+).
PYTHON_BIN=""
for cand in python3.12 python3.11 python3.10 python3.9 python3.8 python3.7 python3; do
  if command -v "$cand" >/dev/null 2>&1; then
    if "$cand" -c 'from __future__ import annotations' >/dev/null 2>&1; then
      PYTHON_BIN="$(command -v "$cand")"
      break
    fi
  fi
done
if [[ -z "$PYTHON_BIN" ]]; then
  echo "no python3.7+ found on PATH" >&2
  exit 1
fi
echo "using python: $PYTHON_BIN"

EXT_ID="${PW_EXT_ID:-}"
if [[ -z "$EXT_ID" ]]; then
  cat >&2 <<EOF

NOTE: The native messaging manifest will be written with a wildcard
"allowed_origins" for now. After loading the extension in Chrome you can
re-run this script with PW_EXT_ID=<your-extension-id> to tighten it.

EOF
fi

mkdir -p "$CHROME_NMH" "$CHROMIUM_NMH"

write_manifest() {
  local target="$1"
  local file="${target}/${NMH_NAME}.json"
  local origin_line
  if [[ -n "$EXT_ID" ]]; then
    origin_line="\"chrome-extension://${EXT_ID}/\""
  else
    # No wildcard support in NMH manifests; placeholder gets replaced once you know the ID.
    origin_line="\"chrome-extension://REPLACE_WITH_YOUR_EXTENSION_ID/\""
  fi
  cat > "$file" <<EOF
{
  "name": "${NMH_NAME}",
  "description": "PW YubiKey relay native messaging host",
  "path": "${NMH_DIR}/relay-wrapper.sh",
  "type": "stdio",
  "allowed_origins": [${origin_line}]
}
EOF
  echo "wrote ${file}"
}

# relay.py needs the venv's python OR a system python with no extra deps
# (the NMH itself imports only stdlib). Write a thin wrapper so we control
# the python binary used by Chrome when it spawns the NMH.
cat > "${NMH_DIR}/relay-wrapper.sh" <<EOF
#!/usr/bin/env bash
exec ${PYTHON_BIN} ${NMH_DIR}/relay.py "\$@"
EOF
chmod +x "${NMH_DIR}/relay-wrapper.sh"
echo "wrote ${NMH_DIR}/relay-wrapper.sh"

write_manifest "$CHROME_NMH"
write_manifest "$CHROMIUM_NMH"

echo
echo "Next steps:"
echo "  1. Make sure the relay agent is running on your LAPTOP:"
echo "       source .venv/bin/activate && python3 laptop/agent.py --port 7777 &"
echo
echo "  2. Open an SSH reverse tunnel from your LAPTOP to this host:"
echo "       ssh -i ~/.ssh/pwcli \\"
echo "           -o ProxyCommand=\"pw ssh --proxy-command %h\" \\"
echo "           -R 7777:127.0.0.1:7777 \\"
echo "           Matthew.Shaxted@gclusternoaav3 sleep 86400"
echo
echo "  3. In your VDI Chrome:"
echo "       open chrome://extensions"
echo "       toggle 'Developer mode' ON"
echo "       click 'Load unpacked' and select: ${EXT_DIR}"
echo "       note the assigned extension id"
echo
echo "  4. Re-run this script with that id baked in:"
echo "       PW_EXT_ID=<your-id> bash ${HERE}/install.sh"
echo "       then reload the extension in chrome://extensions"
echo
echo "  5. Open the test page: file://${HERE}/test.html"
echo "     Click 'Make credential' — your laptop YubiKey will blink."
echo
