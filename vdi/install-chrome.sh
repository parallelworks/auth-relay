#!/usr/bin/env bash
# Install a portable Google Chrome under a user-chosen prefix. No root,
# no rpm install — just stream-extracts the upstream RPM.
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
#   curl, rpm2cpio, glibc >= 2.28
#   plus ONE of: cpio, bsdtar, or python3 (for cpio extraction)

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

# Hard prereqs (no fallback — needed to download + crack the RPM envelope).
for tool in curl rpm2cpio; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing prereq: $tool" >&2; exit 1; }
done

# Pick a cpio extractor. Some HPC login nodes (e.g. Gaea) don't ship `cpio`,
# but they do have python3 (always) or bsdtar (common via libarchive). We
# prefer cpio when available because it's fastest; bsdtar handles cpio
# archives natively via libarchive; python is the universal last-resort.
CPIO_BACKEND=""
if command -v cpio >/dev/null 2>&1; then
  CPIO_BACKEND="cpio"
elif command -v bsdtar >/dev/null 2>&1; then
  CPIO_BACKEND="bsdtar"
elif command -v python3 >/dev/null 2>&1; then
  CPIO_BACKEND="python3"
else
  echo "missing prereq: need ONE of cpio / bsdtar / python3 to extract the RPM" >&2
  exit 1
fi
echo "==> cpio backend: $CPIO_BACKEND"

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"
rm -rf opt usr etc CHROME_VERSION_EXTRA

echo "==> downloading Chrome RPM (~130 MB)"
curl -sL -o chrome.rpm https://dl.google.com/linux/direct/google-chrome-stable_current_x86_64.rpm

echo "==> extracting via $CPIO_BACKEND"
case "$CPIO_BACKEND" in
  cpio)
    rpm2cpio chrome.rpm | cpio -idm 2>&1 | tail -1
    ;;
  bsdtar)
    # libarchive's bsdtar reads cpio archives natively; -f - reads stdin.
    rpm2cpio chrome.rpm | bsdtar -xf -
    ;;
  python3)
    # Pure-Python newc-cpio extractor (RPM payloads are cpio "newc", magic
    # 070701). Reads cpio from stdin and writes files relative to cwd.
    # Handles regular files, dirs, and symlinks (everything Chrome ships).
    rpm2cpio chrome.rpm | python3 -c '
import os, sys, errno
r = sys.stdin.buffer
def pad4(n): return (4 - (n & 3)) & 3
def read_exact(n):
    b = b""
    while len(b) < n:
        chunk = r.read(n - len(b))
        if not chunk: break
        b += chunk
    return b
while True:
    hdr = read_exact(110)
    if len(hdr) < 110: break
    if hdr[:6] != b"070701":
        sys.exit("bad cpio magic: %r (need newc archive)" % hdr[:6])
    f = lambda o: int(hdr[o:o+8], 16)
    mode, fsize, namesize = f(14), f(54), f(94)
    name = read_exact(namesize)
    r.read(pad4(110 + namesize))
    name = name.rstrip(b"\\0").decode("utf-8", "replace")
    if name == "TRAILER!!!": break
    if name.startswith("./"): name = name[2:]
    if not name:
        r.read(fsize + pad4(fsize)); continue
    ftype = mode & 0o170000
    if ftype == 0o040000:                         # dir
        os.makedirs(name, exist_ok=True)
        r.read(fsize + pad4(fsize))
    elif ftype == 0o120000:                       # symlink
        target = read_exact(fsize).decode("utf-8", "replace")
        r.read(pad4(fsize))
        os.makedirs(os.path.dirname(name) or ".", exist_ok=True)
        try: os.remove(name)
        except OSError as e:
            if e.errno != errno.ENOENT: raise
        os.symlink(target, name)
    else:                                          # regular file (and others)
        os.makedirs(os.path.dirname(name) or ".", exist_ok=True)
        with open(name, "wb") as out:
            remaining = fsize
            while remaining:
                chunk = r.read(min(65536, remaining))
                if not chunk: sys.exit("short read in %s" % name)
                out.write(chunk); remaining -= len(chunk)
        os.chmod(name, mode & 0o7777)
        r.read(pad4(fsize))
'
    ;;
esac
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
