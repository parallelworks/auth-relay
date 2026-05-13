#!/usr/bin/env bash
# Install a portable Google Chrome under a user-chosen prefix. No root,
# no rpm install — just rpm2cpio + cpio.
#
# Suggested install pattern on HPC clusters with tight per-user $HOME quotas:
#
#   # Once, by a project admin, into the shared contrib filesystem so
#   # users don't burn their personal $HOME quota:
#   bash vdi/install-chrome.sh /contrib/<your-project>/auth-relay
#
# Idempotent: re-running just refreshes the binary to the latest stable.
#
# Prereqs (typically present on RHEL/SLES login nodes):
#   curl, rpm2cpio, cpio, glibc >= 2.28

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

# Target prefix: either the first arg, or the repo root for laptop dev / quick try.
TARGET="${1:-$REPO_ROOT}"

# Make sure the path is absolute so the wrapper can reference it without
# depending on the user's CWD.
mkdir -p "$TARGET"
TARGET="$(cd "$TARGET" && pwd)"
INSTALL_DIR="$TARGET/chrome-portable"
CHROME_BIN="$INSTALL_DIR/opt/google/chrome/google-chrome"

echo "==> installing Chrome under: $INSTALL_DIR"

for tool in curl rpm2cpio cpio; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing prereq: $tool" >&2; exit 1; }
done

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"
rm -rf opt usr etc CHROME_VERSION_EXTRA

echo "==> downloading Chrome RPM (~130 MB)"
curl -sL -o chrome.rpm https://dl.google.com/linux/direct/google-chrome-stable_current_x86_64.rpm

echo "==> extracting"
rpm2cpio chrome.rpm | cpio -idm 2>&1 | tail -1
rm -f chrome.rpm
# Drop man pages and other artifacts that aren't needed and may have failed
# to extract due to quota on cramped home filesystems.
rm -rf usr/share etc

[[ -x "$CHROME_BIN" ]] || { echo "extraction failed: $CHROME_BIN not present" >&2; exit 1; }

echo "==> installed: $($CHROME_BIN --version)"
echo "==> size: $(du -sh "$INSTALL_DIR" | cut -f1)"

# Wire-up hint that the bootstrap script and the chrome wrapper both honor.
cat <<EOF

Chrome binary    : $CHROME_BIN

To make bootstrap.sh and the chrome wrapper find it automatically, export:

    export PW_CHROME_BIN=$CHROME_BIN

(Add that line to your ~/.bashrc on the cluster login node so it sticks
across sessions.)
EOF
