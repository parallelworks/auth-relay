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

# Dedicated user-data-dir for the relay's Chrome. We need this because
# Chrome 148+ disables --remote-debugging-port unless --user-data-dir
# is also set (the install-extension.py CDP install depends on the
# debug port), AND when --user-data-dir is set Chrome only looks for
# NMH manifests under <user-data-dir>/NativeMessagingHosts/. So this
# dir is where the manifest, the seeded Preferences, and the seeded
# Bookmarks all go.
PW_CHROME_USER_DATA_DIR="${PW_CHROME_USER_DATA_DIR:-$HOME/.config/google-chrome-pwrelay}"
PW_CHROME_NMH="${PW_CHROME_USER_DATA_DIR}/NativeMessagingHosts"

# Pick a python3 (NMH needs 3.7+ for `from __future__ import annotations`).
PYTHON_BIN=""
for cand in python3.12 python3.11 python3.10 python3.9 python3.8 python3.7 python3; do
  if command -v "$cand" >/dev/null 2>&1 && "$cand" -c 'from __future__ import annotations' >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v "$cand")"
    break
  fi
done
[[ -n "$PYTHON_BIN" ]] || { echo "no python 3.7+ on PATH" >&2; exit 1; }

# Wrapper so Chrome spawns the NMH with the python we picked. The wrapper
# also reads /tmp/pw-relay-port-<user> (written by `pwrelay up` on the
# laptop side) so a fresh NMH always connects to the currently-live port
# even if `pwrelay up` had to fall back to 7778/7779/etc.
cat > "${NMH_DIR}/relay-wrapper.sh" <<EOF
#!/usr/bin/env bash
PORT_HINT="/tmp/pw-relay-port-\${USER}"
if [[ -r "\$PORT_HINT" ]]; then
  export PW_RELAY_PORT="\$(cat "\$PORT_HINT")"
fi
exec ${PYTHON_BIN} ${NMH_DIR}/relay.py "\$@"
EOF
chmod +x "${NMH_DIR}/relay-wrapper.sh"

mkdir -p "$CHROME_NMH" "$CHROMIUM_NMH" "$PW_CHROME_NMH"
for target in "$CHROME_NMH" "$CHROMIUM_NMH" "$PW_CHROME_NMH"; do
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

# Drop a Desktop launcher icon so users can double-click to open Chrome
# via the wrapper (which fixes stack ulimit, redirects logs, finds the
# right binary, and auto-detects the VDI display).
DESKTOP_FILE="${HOME}/Desktop/pw-chrome.desktop"
if [[ -d "${HOME}/Desktop" ]] || mkdir -p "${HOME}/Desktop"; then
  cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=PW Chrome (YubiKey Relay)
GenericName=Web Browser
Comment=Chrome with the PW YubiKey relay extension preloaded
Exec=${REPO_ROOT}/vdi/bin/chrome %U
Icon=google-chrome
Terminal=false
StartupNotify=true
Categories=Network;WebBrowser;
MimeType=text/html;text/xml;application/xhtml+xml;x-scheme-handler/http;x-scheme-handler/https;
EOF
  chmod +x "$DESKTOP_FILE"
  # XFCE 4.18+ requires the executable bit AND a trust-mark via gio (or the
  # "Allow this file to run" right-click menu). Mark it trusted preemptively
  # if the tool exists; otherwise the user can right-click → Properties →
  # Permissions → "Allow this file to run as a program" once.
  if command -v gio >/dev/null 2>&1; then
    gio set "$DESKTOP_FILE" "metadata::xfce-exe-checksum" \
      "$(sha256sum "$DESKTOP_FILE" | cut -d' ' -f1)" 2>/dev/null || true
    gio set "$DESKTOP_FILE" "metadata::trusted" true 2>/dev/null || true
  fi
  # touch the Desktop dir so XFCE / nautilus re-scans and the new
  # icon appears without the user having to right-click → Refresh.
  touch "${HOME}/Desktop" 2>/dev/null || true
fi

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

# Pre-seed Chrome's developer_mode pref so the user does not have to click the
# toggle in chrome://extensions, and turn on the bookmarks bar so the seeded
# bookmarks (next block) are visible immediately. Only writes the keys we care
# about; never destroys other prefs. Seeded into the dedicated user-data-dir
# Chrome will actually use (see comment near PW_CHROME_USER_DATA_DIR above).
PREF_DIR="${PW_CHROME_USER_DATA_DIR}/Default"
PREF_FILE="${PREF_DIR}/Preferences"
mkdir -p "$PREF_DIR"
"$PYTHON_BIN" - "$PREF_FILE" <<'PYSEED'
import json, os, sys
path = sys.argv[1]
try:
    prefs = json.load(open(path)) if os.path.exists(path) else {}
except Exception:
    prefs = {}
prefs.setdefault("extensions", {}).setdefault("ui", {})["developer_mode"] = True
prefs.setdefault("bookmark_bar", {})["show_on_all_tabs"] = True
with open(path, "w") as f:
    json.dump(prefs, f, indent=2)
print(f"[bootstrap] developer_mode + bookmark_bar seeded in {path}")
PYSEED

# Pre-seed bookmarks bar with a useful starting set. We only write the file
# if it doesn't already exist — never overwrite a user's curated bookmarks.
# Source of truth is vdi/bookmarks.json; edit that to customize for your org.
BOOKMARKS_SRC="${HERE}/bookmarks.json"
BOOKMARKS_DEST="${PREF_DIR}/Bookmarks"
if [[ -f "$BOOKMARKS_SRC" && ! -f "$BOOKMARKS_DEST" ]]; then
  "$PYTHON_BIN" - "$BOOKMARKS_SRC" "$BOOKMARKS_DEST" <<'PYBM'
import json, sys, time
src, dst = sys.argv[1], sys.argv[2]
entries = json.load(open(src))
# Chrome's date_added is microseconds since 1601-01-01.
WEBKIT_EPOCH = 11644473600
now = str(int((time.time() + WEBKIT_EPOCH) * 1_000_000))
children = [
    {
        "id": str(i + 100),
        "name": e["name"],
        "type": "url",
        "url": e["url"],
        "date_added": now,
        "date_last_used": "0",
    }
    for i, e in enumerate(entries)
]
data = {
    "roots": {
        "bookmark_bar": {
            "children": children,
            "date_added": now,
            "date_modified": now,
            "id": "1",
            "name": "Bookmarks bar",
            "type": "folder",
        },
        "other": {
            "children": [], "date_added": now, "date_modified": now,
            "id": "2", "name": "Other bookmarks", "type": "folder",
        },
        "synced": {
            "children": [], "date_added": now, "date_modified": now,
            "id": "3", "name": "Mobile bookmarks", "type": "folder",
        },
    },
    "version": 1,
}
with open(dst, "w") as f:
    json.dump(data, f, indent=2)
print(f"[bootstrap] seeded {len(entries)} bookmarks into {dst}")
PYBM
elif [[ -f "$BOOKMARKS_DEST" ]]; then
  echo "[bootstrap] Chrome already has bookmarks; not overwriting"
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

Two ways to load the extension into Chrome:

  -- A. Auto-install (recommended; one command, no UI clicks): --

       Make sure Chrome is NOT already running, then:
           python3 ${HERE}/install-extension.py

       It launches Chrome with a debug port, asks it to load the unpacked
       extension via CDP, then leaves Chrome running for you. Developer mode
       is already on (we just seeded it).

  -- B. Manual (if A is blocked or you want to inspect): --

       Launch Chrome via the wrapper (NEVER pass --user-data-dir — Chrome 148+
       won't find the NMH manifest if you do):
           ${REPO_ROOT}/vdi/bin/chrome &
       Open chrome://extensions, click "Load unpacked", select:
           ${EXT_DIR}
       Verify the assigned ID is ${EXT_ID}.

Either way, click "Inspect views: service worker" on the extension card; the
DevTools console should print:
    [pw-relay] attach() succeeded — proxy is active

After the laptop side is up (run \`./pwrelay up <pw-resource>\` on your
laptop), open http://localhost:${HTTP_PORT}/test.html and click
"Make credential" — your laptop YubiKey will blink.

To re-run this script idempotently, just \`bash ${HERE}/bootstrap.sh\`.

EOF
