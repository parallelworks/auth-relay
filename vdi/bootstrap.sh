#!/usr/bin/env bash
# Bootstrap the YubiKey relay on the VDI side (PW workspace, cluster mgmt
# node, login node, or anywhere Chrome runs and can reach 127.0.0.1:7777).
#
# What it does:
#   1. Writes the native-messaging-host manifest for both Chrome and
#      Chromium, hardcoding our deterministic extension ID.
#   2. Starts a tiny local-only HTTP server on 127.0.0.1:8080 to serve
#      the test page (so navigator.credentials doesn't run from file://
#      where it'd be a non-secure context).
#   3. Prints the exact Chrome steps for loading the extension and the
#      test URL.
#
# Idempotent. Re-run any time. Survives ssh session disconnect.

set -euo pipefail

# Deterministic extension ID derived from the committed RSA pubkey in
# vdi/extension/manifest.json. Regenerate via vdi/extension/regen-key.sh
# if you fork this project.
EXT_ID_DEFAULT="ifmfpjglkeipojipfiolefflhopdflgf"
EXT_ID="${PW_EXT_ID:-$EXT_ID_DEFAULT}"

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
EXT_DIR="${HERE}/extension"
NMH_DIR="${HERE}/nmh"
NMH_NAME="com.parallelworks.yubikey_relay"
HTTP_PORT="${PW_HTTP_PORT:-8080}"

# Locate Chrome. Same priority list as vdi/bin/chrome.
find_chrome() {
  if [[ -n "${PW_CHROME_BIN:-}" && -x "${PW_CHROME_BIN}" ]]; then
    printf '%s' "$PW_CHROME_BIN"; return 0
  fi
  local cands=(
    "$REPO_ROOT/chrome-portable/opt/google/chrome/google-chrome"
    "/usr/bin/google-chrome"
    "/usr/bin/google-chrome-stable"
  )
  for c in "${cands[@]}"; do [[ -x "$c" ]] && { printf '%s' "$c"; return 0; }; done
  for c in chromium chromium-browser; do
    command -v "$c" >/dev/null 2>&1 && { command -v "$c"; return 0; }
  done
  return 1
}
CHROME_BIN_FOUND="$(find_chrome || true)"

case "$(uname -s)" in
  Linux)
    CHROME_NMH="${HOME}/.config/google-chrome/NativeMessagingHosts"
    CHROMIUM_NMH="${HOME}/.config/chromium/NativeMessagingHosts"
    ;;
  Darwin)
    CHROME_NMH="${HOME}/Library/Application Support/Google/Chrome/NativeMessagingHosts"
    CHROMIUM_NMH="${HOME}/Library/Application Support/Chromium/NativeMessagingHosts"
    ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac

# Pick a python3 (NMH needs 3.7+ for `from __future__ import annotations`).
PYTHON_BIN=""
for cand in python3.12 python3.11 python3.10 python3.9 python3.8 python3.7 python3; do
  if command -v "$cand" >/dev/null 2>&1 && "$cand" -c 'from __future__ import annotations' >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v "$cand")"
    break
  fi
done
[[ -n "$PYTHON_BIN" ]] || { echo "no python 3.7+ on PATH" >&2; exit 1; }

# Wrapper so Chrome spawns the NMH with the python we picked.
cat > "${NMH_DIR}/relay-wrapper.sh" <<EOF
#!/usr/bin/env bash
exec ${PYTHON_BIN} ${NMH_DIR}/relay.py "\$@"
EOF
chmod +x "${NMH_DIR}/relay-wrapper.sh"

mkdir -p "$CHROME_NMH" "$CHROMIUM_NMH"
for target in "$CHROME_NMH" "$CHROMIUM_NMH"; do
  cat > "${target}/${NMH_NAME}.json" <<EOF
{
  "name": "${NMH_NAME}",
  "description": "PW YubiKey relay native messaging host",
  "path": "${NMH_DIR}/relay-wrapper.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://${EXT_ID}/"]
}
EOF
done

# Background a local HTTP server for the test page (Singularity netns share
# means the VDI Chromium can reach localhost:$HTTP_PORT directly).
# setsid + nohup + redirected FDs detaches fully so that when this script
# was invoked over pw ssh, the http.server survives the ssh session ending.
if ! ss -tlnp 2>/dev/null | grep -q ":${HTTP_PORT}\b"; then
  setsid nohup "$PYTHON_BIN" -m http.server "$HTTP_PORT" --bind 127.0.0.1 \
    --directory "$HERE" </dev/null >/tmp/pw-relay-http.log 2>&1 &
  disown || true
  sleep 0.5
fi

if [[ -n "$CHROME_BIN_FOUND" ]]; then
  CHROME_STATUS="${CHROME_BIN_FOUND}"
else
  CHROME_STATUS="NOT FOUND — run \`bash ${HERE}/install-chrome.sh [<install-prefix>]\` or set PW_CHROME_BIN"
fi

cat <<EOF

==============================================================================
 PW YubiKey Relay — VDI side ready
==============================================================================

Extension ID    : ${EXT_ID}
NMH manifest    : ${CHROME_NMH}/${NMH_NAME}.json
                  ${CHROMIUM_NMH}/${NMH_NAME}.json
Test page       : http://localhost:${HTTP_PORT}/test.html
Extension path  : ${EXT_DIR}
Chrome binary   : ${CHROME_STATUS}

Steps in your VDI Chrome (one time per browser profile):

  1. Launch Chrome via the wrapper (no --user-data-dir flag; that breaks
     native-messaging-host lookup on Chrome 148+):
        ${REPO_ROOT}/vdi/bin/chrome &

  2. Open chrome://extensions
  3. Toggle "Developer mode" ON  (top-right)
  4. Click "Load unpacked" and select:
        ${EXT_DIR}
     → it should appear with ID ${EXT_ID}

  5. Click "Inspect views: service worker" on the extension card; in the
     DevTools console you should see:
        [pw-relay] attach() succeeded — proxy is active

After the laptop side is up (run \`./pwrelay up <pw-resource>\` on your
laptop), open http://localhost:${HTTP_PORT}/test.html and click
"Make credential" — your laptop YubiKey will blink.

To re-run this script idempotently, just \`bash ${HERE}/bootstrap.sh\`.

EOF
