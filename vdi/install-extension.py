#!/usr/bin/env python3
"""Auto-install the PW YubiKey relay extension into Chrome.

Chrome stable refuses to honor --load-extension (the warning shows up
as "--load-extension is not allowed in Google Chrome, ignoring."), so
we instead drive Chrome via the DevTools Protocol and call
Extensions.loadUnpacked. That method is documented for Chrome 124+ and
behaves the same as the chrome://extensions "Load unpacked" button —
just without the user clicking.

This script:
  1. Pre-seeds ~/.config/google-chrome/Default/Preferences so the
     "Developer mode" toggle in chrome://extensions is on. (Required
     for unpacked installs even via CDP.)
  2. Launches Chrome with --remote-debugging-port and a random port,
     wired up to the user's normal profile (no --user-data-dir; we
     learned that breaks the native-messaging-host lookup).
  3. HTTP GETs /json/version to discover the browser-level WebSocket
     debugger URL.
  4. Opens that WebSocket (hand-rolled minimal client; no pip deps)
     and POSTs Extensions.loadUnpacked.
  5. Prints success and exits, leaving Chrome running in the user's
     VDI as if they'd just opened it normally.

Usage:
    python3 vdi/install-extension.py
    python3 vdi/install-extension.py --ext-dir /path/to/extension
    PW_CHROME_BIN=/contrib/.../google-chrome python3 vdi/install-extension.py

If Chrome is already running with the user's normal profile, this
script will refuse to start a competing instance (one --user-data-dir
gets exclusive access). Close that Chrome window first.
"""

# Re-exec under a newer Python if /usr/bin/python3 is too old (RHEL 8/9
# typically ships 3.6 as system /usr/bin/python3, but has python3.12 in
# /usr/bin too). This block uses only stdlib that exists since Python 2,
# so it parses successfully regardless of which Python ran us.
import os
import sys
if sys.version_info < (3, 7):
    for _cand in ("python3.12", "python3.11", "python3.10",
                  "python3.9", "python3.8", "python3.7"):
        for _d in os.environ.get("PATH", "").split(os.pathsep):
            _p = os.path.join(_d, _cand)
            if os.access(_p, os.X_OK):
                os.execv(_p, [_p] + sys.argv)
    sys.stderr.write(
        "install-extension.py needs Python 3.7+; the python3 you invoked "
        "is %s and no python3.7-3.12 was on PATH. Re-run as e.g.\n"
        "    python3.12 %s\n" % (sys.version.split()[0], " ".join(sys.argv))
    )
    sys.exit(2)

# NOTE: no `from __future__ import annotations` here. Future imports must
# be the first statement in a file (after the docstring), but we run a
# Python-version-check + re-exec block before any imports — that block
# can't follow a future import. So this script is written to be
# annotation-compatible with Python 3.7+ without futures (Optional from
# typing instead of X | None, etc.).
import argparse
import base64
import json
import secrets
import shlex
import shutil
import socket
import struct
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional


def find_chrome() -> str:
    env = os.environ.get("PW_CHROME_BIN")
    if env and os.access(env, os.X_OK):
        return env
    repo_root = Path(__file__).resolve().parent.parent
    candidates = [
        repo_root / "chrome-portable/opt/google/chrome/google-chrome",
        Path("/usr/bin/google-chrome"),
        Path("/usr/bin/google-chrome-stable"),
    ]
    for c in candidates:
        if os.access(c, os.X_OK):
            return str(c)
    for c in ("chromium", "chromium-browser"):
        p = shutil.which(c)
        if p:
            return p
    raise SystemExit(
        "no Chrome found. Set PW_CHROME_BIN or run vdi/install-chrome.sh."
    )


def seed_dev_mode(profile_dir: Path) -> None:
    pref_path = profile_dir / "Default" / "Preferences"
    pref_path.parent.mkdir(parents=True, exist_ok=True)
    if pref_path.exists():
        try:
            prefs = json.loads(pref_path.read_text())
        except Exception:
            prefs = {}
    else:
        prefs = {}
    prefs.setdefault("extensions", {}).setdefault("ui", {})["developer_mode"] = True
    pref_path.write_text(json.dumps(prefs, indent=2))
    print(f"[install] developer_mode=true seeded in {pref_path}")


def autodetect_vnc() -> "Optional[tuple]":
    """Find the user's running VNC server and return (DISPLAY, XAUTHORITY).

    This lets `pw ssh resource 'python3 install-extension.py'` from a
    laptop terminal pop Chrome into the user's already-running VDI
    desktop, instead of failing because DISPLAY isn't set in the ssh
    shell. Matches Xvnc / Xkasmvnc / Xtigervnc (TigerVNC uses 'Xvnc',
    KasmVNC uses 'Xkasmvnc'; both put the display number and the auth
    file path in argv).
    """
    import re
    import subprocess
    try:
        user = os.environ.get("USER") or subprocess.check_output(["id", "-un"]).decode().strip()
        out = subprocess.check_output(
            ["ps", "-u", user, "-o", "args="], text=True, timeout=5
        )
    except Exception:
        return None
    for line in out.splitlines():
        argv = line.strip()
        # Match the Xvnc-family server's full argv line.
        if not re.search(r"/(Xvnc|Xkasmvnc|Xtigervnc|Xvfb)\b", argv):
            continue
        # Display number: a `:N` token surrounded by spaces or end-of-line.
        m = re.search(r"(?:^|\s)(:\d+)(?:\s|$)", argv)
        if not m:
            continue
        display = m.group(1)
        a = re.search(r"-auth\s+(\S+)", argv)
        xauthority = a.group(1) if a else ""
        return (display, xauthority)
    return None


def pick_unused_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ---------- minimal CDP WebSocket client (stdlib only) ---------------------

def ws_connect(url: str) -> socket.socket:
    p = urllib.parse.urlparse(url)
    host = p.hostname or "127.0.0.1"
    port = p.port or 80
    sock = socket.create_connection((host, port), timeout=10)
    key = base64.b64encode(os.urandom(16)).decode()
    request = (
        f"GET {p.path or '/'} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    sock.sendall(request.encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("ws handshake: peer closed")
        buf += chunk
    if b"101" not in buf.split(b"\r\n", 1)[0]:
        raise RuntimeError("ws handshake failed: " + buf[:200].decode(errors="replace"))
    # Leftover bytes after headers belong to the WS stream.
    head, _, leftover = buf.partition(b"\r\n\r\n")
    sock.setblocking(True)
    return _WSConn(sock, leftover)


class _WSConn:
    def __init__(self, sock: socket.socket, initial: bytes):
        self._sock = sock
        self._buf = initial

    def _recv(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self._sock.recv(max(n - len(self._buf), 4096))
            if not chunk:
                raise ConnectionError("ws closed mid-frame")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def send_text(self, text: str) -> None:
        payload = text.encode()
        mask = secrets.token_bytes(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        first = bytes([0x81])  # FIN + text opcode
        length = len(payload)
        if length < 126:
            second = bytes([0x80 | length])
        elif length < 65536:
            second = bytes([0x80 | 126]) + struct.pack(">H", length)
        else:
            second = bytes([0x80 | 127]) + struct.pack(">Q", length)
        self._sock.sendall(first + second + mask + masked)

    def recv_text(self) -> str:
        # Reassemble fragments if any; for CDP, server uses single text frames.
        while True:
            hdr = self._recv(2)
            fin = hdr[0] & 0x80
            opcode = hdr[0] & 0x0F
            masked = hdr[1] & 0x80
            length = hdr[1] & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._recv(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._recv(8))[0]
            mask = self._recv(4) if masked else None
            data = self._recv(length)
            if mask:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            if opcode == 0x9:  # ping → pong
                self._sock.sendall(bytes([0x8A, len(data)]) + data)
                continue
            if opcode == 0x8:  # close
                raise ConnectionError("server closed ws")
            if opcode in (0x1, 0x0):  # text or continuation
                if fin:
                    return data.decode("utf-8", errors="replace")
                # Continuation: very rare for CDP; bail.
                raise NotImplementedError("ws fragmentation not supported")
            # Binary or other — ignore quietly.

    def close(self) -> None:
        try:
            self._sock.sendall(bytes([0x88, 0x00]))
        except Exception:
            pass
        self._sock.close()


# ---------- main -----------------------------------------------------------

def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser()
    ap.add_argument("--ext-dir", default=str(repo_root / "vdi" / "extension"))
    ap.add_argument(
        "--profile",
        default=os.environ.get(
            "PW_CHROME_USER_DATA_DIR",
            str(Path.home() / ".config" / "google-chrome-pwrelay"),
        ),
        help=(
            "Chrome --user-data-dir to seed and use. Default is the "
            "auth-relay-dedicated profile (~/.config/google-chrome-pwrelay). "
            "Chrome 148+ requires a non-default user-data-dir to enable the "
            "remote debugging port we use for Extensions.loadUnpacked."
        ),
    )
    ap.add_argument("--port", type=int, default=0, help="0 = pick a free one")
    ap.add_argument(
        "--keep-running",
        action="store_true",
        default=True,
        help="Leave Chrome running after install (default). Pass --no-keep-running to exit Chrome.",
    )
    ap.add_argument("--no-keep-running", action="store_false", dest="keep_running")
    args = ap.parse_args()

    ext_dir = Path(args.ext_dir).resolve()
    if not (ext_dir / "manifest.json").exists():
        print(f"[install] {ext_dir}/manifest.json not found", file=sys.stderr)
        return 1

    profile = Path(args.profile)
    chrome_bin = find_chrome()
    debug_port = args.port or pick_unused_port()

    print(f"[install] Chrome   : {chrome_bin}")
    print(f"[install] Extension: {ext_dir}")
    print(f"[install] Profile  : {profile}")
    print(f"[install] CDP port : {debug_port}")

    seed_dev_mode(profile)

    # Launch Chrome with the debug port. We deliberately do NOT pass
    # --user-data-dir — that would break NMH manifest lookup on Chrome 148+
    # (see vdi/bin/chrome). The default profile dir is the one we just seeded.
    # We also clamp the stack ulimit on HPC nodes (see comment in vdi/bin/chrome).
    env = os.environ.copy()
    # If DISPLAY isn't already set (e.g., we were invoked from a pw ssh
    # shell with no X forwarding), find the user's running VNC server
    # and use its display + auth. Lets `pw ssh resource 'python3
    # install-extension.py'` Just Work from a laptop terminal.
    if not env.get("DISPLAY"):
        detected = autodetect_vnc()
        if detected:
            disp, xauth = detected
            env["DISPLAY"] = disp
            if xauth:
                env["XAUTHORITY"] = xauth
            print(f"[install] auto-detected VDI session: DISPLAY={disp}"
                  + (f" XAUTHORITY={xauth}" if xauth else ""))
        else:
            print("[install] WARNING: no DISPLAY in env and no running VNC found; "
                  "Chrome will likely fail to open a window", file=sys.stderr)
    log_path = f"/tmp/pw-chrome-{os.environ.get('USER', 'user')}.log"
    log = open(log_path, "ab")
    # We use pipe-based CDP (--remote-debugging-pipe) instead of the
    # WebSocket-based port. The Extensions domain (specifically the
    # Extensions.loadUnpacked method we depend on) is only exposed when
    # Chrome speaks CDP over its inherited fd 3/4 pipes, not over a TCP
    # socket. Chrome 148 returns 'Method not available' otherwise.
    in_r, in_w = os.pipe()    # parent writes to in_w  -> Chrome reads from in_r as fd 3
    out_r, out_w = os.pipe()  # parent reads from out_r <- Chrome writes to out_w as fd 4
    # Python 3.4+ sets FD_CLOEXEC on os.pipe() fds by default — they
    # would be auto-closed on exec, leaving Chrome with nothing to read
    # from. Mark the ones the child needs as inheritable.
    os.set_inheritable(in_r, True)
    os.set_inheritable(out_w, True)

    cmd = [
        chrome_bin,
        # Required: a non-default data dir or Chrome silently ignores
        # debugging flags. The same dir holds the NMH manifest that
        # bootstrap.sh writes.
        f"--user-data-dir={profile}",
        # Suppress first-run UI gates that block automation on a fresh
        # profile: default-browser prompt, welcome screen, the
        # search-engine-choice modal (Chrome 122+), and the
        # gnome-keyring/kwallet 'create password' modal (Rocky Linux 9
        # VDI on the google cluster).
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-default-apps",
        "--disable-search-engine-choice-screen",
        "--password-store=basic",
        # Pipe-based CDP (stdio rather than WebSocket). The Extensions
        # domain is only available over this transport. Combined with
        # --enable-unsafe-extension-debugging to unlock the method.
        "--remote-debugging-pipe",
        "--enable-unsafe-extension-debugging",
        # Initial tab so the user sees the extension show up right
        # after install-extension.py completes.
        "chrome://extensions",
    ]
    # ulimit -Ss is shell-level; set RLIMIT_STACK in this process before exec.
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_STACK)
        target = 8 * 1024 * 1024  # 8 MiB
        if soft > target:
            resource.setrlimit(resource.RLIMIT_STACK, (target, hard))
    except Exception as e:
        print(f"[install] could not clamp stack rlimit: {e}", file=sys.stderr)
    # Chrome's pipe-based CDP expects fd 3 = stdin, fd 4 = stdout, with
    # CLOEXEC clear so they survive exec. We tried doing this in a
    # subprocess preexec_fn dup2 — Chrome kept reporting "Remote
    # debugging pipe file descriptors are not open", strongly suggesting
    # either CPython's pre-exec fd plumbing was closing them or the
    # CLOEXEC flag was being set somewhere we couldn't see.
    #
    # The robust workaround is a tiny bash wrapper. We give bash stdin
    # = our in_r and stdout = our out_w via subprocess.Popen (which
    # subprocess sets up reliably), then the shell redirects fd 0->3,
    # fd 1->4 before exec'ing Chrome. Both POSIX redirection (3<&0,
    # 4>&1) and the chmod-style F_DUPFD it implies clear CLOEXEC by
    # spec, so Chrome gets clean fd 3/4.
    chrome_argv = shlex.join(cmd)
    shell_cmd = (
        "exec 3<&0 4>&1 "        # alias stdin -> fd 3, stdout -> fd 4
        "0</dev/null 1>&2; "     # detach stdin/stdout from the original pipes
        "exec " + chrome_argv    # replace bash with chrome
    )

    proc = subprocess.Popen(
        ["bash", "-c", shell_cmd],
        stdin=in_r,
        stdout=out_w,
        stderr=log,
        start_new_session=True,
        env=env,
    )
    # subprocess closes in_r and out_w in the parent automatically after
    # dup'ing them into the child as fd 0 / fd 1. Don't close them again
    # (Errno 9, Bad file descriptor). We only keep in_w (for writing to
    # Chrome) and out_r (for reading from Chrome).
    # Parent only keeps the two ends it talks to Chrome through.
    os.close(in_r)
    os.close(out_w)
    print(f"[install] Chrome pid: {proc.pid} (log: {log_path})")

    # Pipe-based CDP: JSON messages separated by NUL (\0) bytes.
    # Send Extensions.loadUnpacked and wait for its reply.
    request = json.dumps({
        "id": 1,
        "method": "Extensions.loadUnpacked",
        "params": {"path": str(ext_dir)},
    }).encode() + b"\x00"
    os.write(in_w, request)

    # Read replies until we see one with id=1 or hit a timeout.
    deadline = time.monotonic() + 60.0
    buf = b""
    installed_id = None
    cdp_error = None
    while time.monotonic() < deadline:
        try:
            chunk = os.read(out_r, 65536)
        except OSError as e:
            cdp_error = f"pipe read failed: {e}"
            break
        if not chunk:
            cdp_error = "Chrome closed CDP pipe before replying"
            break
        buf += chunk
        while True:
            idx = buf.find(b"\x00")
            if idx < 0:
                break
            line, buf = buf[:idx], buf[idx + 1:]
            try:
                msg = json.loads(line.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue
            if msg.get("id") != 1:
                continue
            if "error" in msg:
                cdp_error = str(msg["error"])
            else:
                installed_id = msg.get("result", {}).get("id", "(no id returned)")
            break
        if installed_id is not None or cdp_error is not None:
            break
    if cdp_error is not None:
        print(f"[install] CDP error: {cdp_error}", file=sys.stderr)
        os.close(in_w); os.close(out_r)
        return 3
    if installed_id is None:
        print("[install] CDP install timed out (no id=1 reply in 60s)", file=sys.stderr)
        os.close(in_w); os.close(out_r)
        return 4
    print(f"[install] installed extension id: {installed_id}")
    os.close(in_w)
    os.close(out_r)

    if not args.keep_running:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("[install] Chrome closed (per --no-keep-running)")
    else:
        print(
            "[install] Chrome left running; the extension is now loaded and the\n"
            "          NMH manifest is wired up. Open https://localhost:8080/test.html\n"
            "          or https://accounts.google.com to exercise the relay."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
