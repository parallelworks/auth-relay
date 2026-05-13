#!/usr/bin/env python3
"""pwrelay — laptop-side CLI for the Parallel Works Auth Relay.

Cross-platform (macOS, Linux, Windows). Replaces the bash version so
Windows users can run natively without WSL or Cygwin.

Subcommands
-----------
    setup                       one-time: deps + venv + key check
    up <pw-resource>            start agent + tunnel; foreground
    down                        stop agent/tunnel
    status                      show state
    doctor [<resource>]         dump local + remote diag info
    reset  [<resource>]         clean up everything *we own* both ends
                                (never touches pw agent on the cluster)

Examples
--------
    python3 pwrelay.py setup
    python3 pwrelay.py up gaeac5
    python3 pwrelay.py up workspace

On Mac/Linux you can also use the `pwrelay` bash wrapper that just
exec's this file. On Windows, invoke directly:
    python pwrelay.py up <resource>
"""

from __future__ import annotations

import argparse
import os
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

IS_WIN = platform.system() == "Windows"
HOME = Path.home()
REPO_ROOT = Path(__file__).resolve().parent

STATE_DIR = Path(tempfile.gettempdir())
PID_AGENT = STATE_DIR / "pwrelay-agent.pid"
PID_TUNNEL = STATE_DIR / "pwrelay-tunnel.pid"
PID_PORT = STATE_DIR / "pwrelay-port"
PID_SESSION = STATE_DIR / "pwrelay-session"
PID_RESOURCE = STATE_DIR / "pwrelay-resource"
LOG_AGENT = STATE_DIR / "pwrelay-agent.log"
LOG_TUNNEL = STATE_DIR / "pwrelay-tunnel.log"

DEFAULT_PORT = int(os.environ.get("PW_RELAY_PORT", "7777"))
PORT_FALLBACK_RANGE = 8  # try 7777, 7778, ..., 7784


# ---------- helpers --------------------------------------------------------


def _color(code: int) -> str:
    if not sys.stdout.isatty():
        return ""
    return f"\033[{code}m"


def say(msg: str) -> None:
    print(f"{_color(36)}[pwrelay]{_color(0)} {msg}")


def err(msg: str) -> None:
    print(f"{_color(31)}[pwrelay error]{_color(0)} {msg}", file=sys.stderr)


def ok(msg: str) -> None:
    print(f"{_color(32)}[pwrelay ok]{_color(0)} {msg}")


def _venv_python() -> Path:
    venv = REPO_ROOT / ".venv"
    if IS_WIN:
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python3"


def _require_cmd(cmd: str) -> str:
    p = shutil.which(cmd)
    if not p:
        err(f"{cmd} not on PATH")
        sys.exit(1)
    return p


def _read_pid(path: Path) -> int | None:
    try:
        return int(path.read_text().strip())
    except Exception:
        return None


def _is_running(pid_file: Path) -> bool:
    pid = _read_pid(pid_file)
    if pid is None:
        return False
    try:
        if IS_WIN:
            # On Windows, signal 0 isn't supported via os.kill. Use tasklist.
            r = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}"],
                capture_output=True, text=True, check=False,
            )
            return str(pid) in r.stdout
        else:
            os.kill(pid, 0)
            return True
    except (OSError, ProcessLookupError):
        return False


def _stop_pid(pid_file: Path, name: str) -> None:
    pid = _read_pid(pid_file)
    if pid is None:
        return
    if not _is_running(pid_file):
        try: pid_file.unlink()
        except FileNotFoundError: pass
        return
    say(f"stopping {name} (pid {pid})")
    # Try to also catch children (the ssh inside the supervisor loop)
    kids: list[int] = []
    if not IS_WIN:
        try:
            r = subprocess.run(
                ["pgrep", "-P", str(pid)], capture_output=True, text=True, check=False,
            )
            kids = [int(x) for x in r.stdout.split() if x.strip()]
        except Exception:
            pass
    targets = [pid] + kids
    for p in targets:
        try:
            if IS_WIN:
                subprocess.run(["taskkill", "/PID", str(p), "/F"], check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                os.kill(p, signal.SIGTERM)
        except (OSError, ProcessLookupError):
            pass
    # Give it a moment to exit, then SIGKILL on POSIX
    for _ in range(8):
        if not _is_running(pid_file):
            break
        time.sleep(0.25)
    if not IS_WIN:
        for p in targets:
            try: os.kill(p, signal.SIGKILL)
            except (OSError, ProcessLookupError): pass
    try: pid_file.unlink()
    except FileNotFoundError: pass


def _detach_kwargs() -> dict:
    """subprocess kwargs that detach the child from the current console."""
    if IS_WIN:
        # CREATE_NEW_PROCESS_GROUP lets Ctrl+C in the parent NOT propagate.
        # DETACHED_PROCESS detaches from the parent console.
        DETACHED_PROCESS = 0x00000008
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        return {
            "creationflags": DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
            "close_fds": True,
        }
    return {"start_new_session": True, "close_fds": True}


# ---------- subcommands ----------------------------------------------------


def cmd_setup(args: argparse.Namespace) -> None:
    _require_cmd("pw")
    _require_cmd("ssh")
    py = _require_cmd("python3" if not IS_WIN else "python")

    # Verify pw is authenticated.
    try:
        subprocess.run(["pw", "auth", "whoami"], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        err("pw CLI not authenticated. Run: pw auth login")
        sys.exit(1)

    pwcli_key = HOME / ".ssh" / "pwcli"
    if not pwcli_key.exists():
        err(f"{pwcli_key} missing. Run: pw auth login")
        sys.exit(1)

    venv = REPO_ROOT / ".venv"
    if not venv.exists():
        say(f"creating venv at {venv}")
        subprocess.run([py, "-m", "venv", str(venv)], check=True)

    vp = _venv_python()
    if not vp.exists():
        err(f"venv python missing at {vp}")
        sys.exit(1)

    # python-fido2 install if not present.
    has_fido2 = subprocess.run(
        [str(vp), "-c", "import fido2"],
        capture_output=True, check=False,
    ).returncode == 0
    if not has_fido2:
        say("installing python-fido2 into venv")
        subprocess.run([str(vp), "-m", "pip", "install", "--upgrade", "pip"],
                       check=True, capture_output=True)
        subprocess.run([str(vp), "-m", "pip", "install", "fido2"],
                       check=True)

    # Non-fatal: probe for a FIDO2 key.
    probe = subprocess.run(
        [str(vp), "-c", "from fido2.hid import CtapHidDevice; assert list(CtapHidDevice.list_devices())"],
        capture_output=True, check=False,
    )
    if probe.returncode == 0:
        ok("YubiKey detected")
    else:
        err("no FIDO2 USB device found right now "
            "(plug it in before `pwrelay up`)")

    ok("setup complete")


def _resolve_resource(arg: str | None) -> str:
    return arg or "workspace"


def _resource_user() -> str:
    override = os.environ.get("PW_RESOURCE_USER")
    if override:
        return override
    r = subprocess.run(["pw", "auth", "whoami"], capture_output=True, text=True, check=True)
    return r.stdout.strip()


def _probe_remote_port(resource: str, port: int) -> bool:
    """Return True if `port` is currently free on the remote resource."""
    cmd = ["pw", "ssh", resource,
           f"ss -tlnp 2>/dev/null | grep -q ':{port} ' && echo BUSY || echo FREE"]
    r = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return "FREE" in r.stdout


def _spawn_tunnel_supervisor(resource: str, rs_user: str, port: int,
                              session_id: str) -> int:
    """Spawn a Python child process that runs ssh -R in a retry loop.

    Returns the supervisor process PID. The supervisor writes activity to
    LOG_TUNNEL; the parent can grep for the 'tunnel-up on' line to confirm
    the tunnel is live before continuing.
    """
    LOG_TUNNEL.write_text("")  # truncate

    # Spawn a Python subprocess that runs the supervisor loop. Doing this
    # in Python rather than a shell `while true` keeps Windows happy.
    supervisor_script = f"""
import os, subprocess, sys, time

LOG = open({str(LOG_TUNNEL)!r}, 'a', buffering=1)
def log(msg):
    LOG.write(msg + '\\n')

while True:
    rc = subprocess.run(
        ['ssh',
         '-i', os.path.expanduser('~/.ssh/pwcli'),
         '-o', 'ProxyCommand=pw ssh --proxy-command %h',
         '-o', 'StrictHostKeyChecking=no',
         '-o', 'UserKnownHostsFile=' + ({0!r} if {1} else '/dev/null'),
         '-o', 'ServerAliveInterval=30',
         '-o', 'ServerAliveCountMax=3',
         '-o', 'TCPKeepAlive=yes',
         '-o', 'ExitOnForwardFailure=yes',
         '-R', '{port}:127.0.0.1:{port}',
         '{rs_user}@{resource}',
         'echo \"[remote] tunnel-up on $(hostname); pid=$$ marker={session_id}\"; '
         'exec -a \"{session_id}\" sleep 86400'],
        stdout=LOG, stderr=LOG,
    ).returncode

    # Tail the log to look for terminal failures.
    LOG.flush()
    try:
        tail = open({str(LOG_TUNNEL)!r}).read()
    except Exception:
        tail = ''
    if 'Permission denied' in tail or 'remote port forwarding failed' in tail:
        log(f'[supervisor] terminal failure rc={{rc}}; not retrying')
        sys.exit(rc)
    log(f'[supervisor] ssh exited rc={{rc}} — reconnecting in 3s')
    time.sleep(3)
""".format("nul", IS_WIN)

    proc = subprocess.Popen(
        [sys.executable, "-c", supervisor_script],
        stdout=open(LOG_TUNNEL, "ab"),
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        **_detach_kwargs(),
    )
    PID_TUNNEL.write_text(str(proc.pid))
    return proc.pid


def _wait_for_tunnel_up(timeout: float = 20.0) -> str | None:
    """Block until LOG_TUNNEL shows 'tunnel-up on ...'; return the host."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            text = LOG_TUNNEL.read_text()
        except FileNotFoundError:
            text = ""
        m = re.search(r"\[remote\] tunnel-up on ([^;\s]+)", text)
        if m:
            return m.group(1)
        # Terminal failures — bail early.
        if "Permission denied" in text:
            err("ssh public-key auth refused. `pw auth login` to refresh and retry.")
            return None
        if "remote port forwarding failed" in text:
            err("remote port still busy on the cluster (pw-agent may be caching it).")
            err("Try `./pwrelay reset <resource>` and re-run.")
            return None
        if not _is_running(PID_TUNNEL):
            return None
        time.sleep(0.5)
    return None


def cmd_up(args: argparse.Namespace) -> None:
    resource = _resolve_resource(args.resource)

    if _is_running(PID_AGENT):
        say(f"agent already running (pid {_read_pid(PID_AGENT)}). Use `pwrelay down` to stop.")
        sys.exit(1)

    vp = _venv_python()
    if not vp.exists():
        err("venv not found. Run: pwrelay setup")
        sys.exit(1)

    # Port fallback: pw-agent on some clusters caches forward state and
    # holds 7777 even with no client. Walk to next port if so.
    say(f"checking which port is free on remote {resource} ...")
    chosen_port: int | None = None
    for cand in range(DEFAULT_PORT, DEFAULT_PORT + PORT_FALLBACK_RANGE):
        if _probe_remote_port(resource, cand):
            chosen_port = cand
            break
    if chosen_port is None:
        err(f"no free port in {DEFAULT_PORT}..{DEFAULT_PORT + PORT_FALLBACK_RANGE - 1} on {resource}.")
        err("try `pwrelay reset <resource>` and re-run.")
        sys.exit(1)
    if chosen_port != DEFAULT_PORT:
        say(f"port {DEFAULT_PORT} on remote is busy; using {chosen_port}")
    PID_PORT.write_text(str(chosen_port))
    PID_RESOURCE.write_text(resource)

    rs_user = _resource_user()
    session_id = f"pwrelay-{int(time.time())}-{os.getpid()}"
    PID_SESSION.write_text(session_id)

    # Push chosen port to a hint file on the remote so the NMH wrapper
    # picks it up on its next spawn.
    try:
        subprocess.run(
            ["pw", "ssh", resource,
             f"echo {chosen_port} > /tmp/pw-relay-port-{rs_user}"],
            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass

    # Start the agent.
    say(f"starting agent on 127.0.0.1:{chosen_port}")
    agent_log = open(LOG_AGENT, "ab")
    agent_proc = subprocess.Popen(
        [str(vp), str(REPO_ROOT / "laptop" / "agent.py"), "--port", str(chosen_port)],
        stdout=agent_log, stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        **_detach_kwargs(),
    )
    PID_AGENT.write_text(str(agent_proc.pid))
    time.sleep(0.6)
    if not _is_running(PID_AGENT):
        err(f"agent failed to start; tail {LOG_AGENT}")
        try: sys.stderr.write(LOG_AGENT.read_text()[-2000:])
        except Exception: pass
        sys.exit(1)
    ok(f"agent listening on 127.0.0.1:{chosen_port}")

    # Tunnel supervisor.
    say(f"opening reverse tunnel via pw ssh to {resource} ({rs_user}@{resource}) [auto-reconnect, port {chosen_port}]")
    _spawn_tunnel_supervisor(resource, rs_user, chosen_port, session_id)

    rhost = _wait_for_tunnel_up()
    if not rhost:
        err("tunnel didn't come up; tail of " + str(LOG_TUNNEL))
        try: sys.stderr.write(LOG_TUNNEL.read_text()[-2000:])
        except Exception: pass
        cmd_down(args)
        sys.exit(1)
    ok(f"tunnel up to {rhost} — port {chosen_port} on remote -> agent on this laptop")

    print("""
────────────────────────────────────────────────────────────────────
 Relay live. On the VDI side:
   - The ACTIVATE auth_relay workflow should already be running
   - Or run manually: bash <repo>/vdi/bootstrap.sh; python3 install-extension.py
 Then open accounts.google.com / your SSO portal in the VDI Chrome.
 Ctrl+C here tears down the agent and tunnel cleanly.
────────────────────────────────────────────────────────────────────
""")

    # Foreground: tail the agent log until Ctrl+C.
    def _on_sigint(*_a) -> None:
        print()
        cmd_down(args)
        sys.exit(0)
    signal.signal(signal.SIGINT, _on_sigint)
    if hasattr(signal, "SIGTERM"):
        try: signal.signal(signal.SIGTERM, _on_sigint)
        except (ValueError, OSError): pass

    _tail_file(LOG_AGENT)


def _tail_file(path: Path) -> None:
    """Equivalent of `tail -F path` — block forever, print new lines."""
    last_size = 0
    while True:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(last_size)
                chunk = f.read()
                if chunk:
                    sys.stdout.write(chunk)
                    sys.stdout.flush()
                last_size = f.tell()
        except FileNotFoundError:
            pass
        time.sleep(0.5)


def cmd_down(args: argparse.Namespace) -> None:
    # Best-effort: tell the remote to kill our tagged sleep so the pw
    # agent releases the port faster. Never touch the agent itself.
    sid_path = PID_SESSION
    res_path = PID_RESOURCE
    if sid_path.exists() and res_path.exists():
        sid = sid_path.read_text().strip()
        res = res_path.read_text().strip()
        if sid and res:
            say(f"asking remote ({res}) to release our session marker '{sid}'")
            subprocess.run(
                ["pw", "ssh", res,
                 f"pkill -u $(whoami) -f \"{sid}\" 2>/dev/null; true"],
                check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
    _stop_pid(PID_TUNNEL, "ssh tunnel")
    _stop_pid(PID_AGENT, "agent")
    for p in (PID_PORT, PID_SESSION, PID_RESOURCE):
        try: p.unlink()
        except FileNotFoundError: pass
    ok("relay stopped")


def cmd_status(args: argparse.Namespace) -> None:
    if _is_running(PID_AGENT):
        ok(f"agent: running (pid {_read_pid(PID_AGENT)})")
    else:
        say("agent: not running")
    if _is_running(PID_TUNNEL):
        ok(f"tunnel: running (pid {_read_pid(PID_TUNNEL)})")
        try:
            lines = LOG_TUNNEL.read_text().splitlines()
            up = [l for l in lines if "tunnel-up on" in l]
            if up:
                print(" ", up[-1])
        except FileNotFoundError:
            pass
    else:
        say("tunnel: not running")


def cmd_doctor(args: argparse.Namespace) -> None:
    resource = _resolve_resource(args.resource)
    say("=== local (this laptop) ===")
    cmd_status(args)
    print(f"  port file : {PID_PORT.read_text().strip() if PID_PORT.exists() else '(none)'}")
    print(f"  session   : {PID_SESSION.read_text().strip() if PID_SESSION.exists() else '(none)'}")
    print(f"  resource  : {PID_RESOURCE.read_text().strip() if PID_RESOURCE.exists() else '(none)'}")
    print("  agent log tail:")
    _print_tail(LOG_AGENT, 3)
    print("  tunnel log tail:")
    _print_tail(LOG_TUNNEL, 5)
    print()
    say(f"=== remote ({resource}) ===")
    subprocess.run(
        ["pw", "ssh", resource,
         """
echo "  hostname  : $(hostname)"
echo "  whoami    : $(whoami)"
echo "  ports 7777..7785 (listening):"
ss -tlnp 2>/dev/null | awk '/:777[0-9] /{ printf "    %s  %s\\n", $4, $6 }'
echo "  my pwrelay-tagged sleeps (safe to kill via pwrelay reset):"
ps -u "$(whoami)" -o pid,comm 2>/dev/null | awk '/pwrelay-/{ printf "    pid=%s argv0=%s\\n", $1, $2 }'
echo "  pw agent (DO NOT KILL):"
pgrep -afu "$(whoami)" "pw agent" 2>/dev/null | sed 's/^/    /'
echo "  port hint file:"
cat "/tmp/pw-relay-port-$(whoami)" 2>/dev/null | sed 's/^/    /'
"""],
        check=False,
    )


def cmd_reset(args: argparse.Namespace) -> None:
    resource = (PID_RESOURCE.read_text().strip() if PID_RESOURCE.exists()
                else _resolve_resource(args.resource))
    say("resetting local pwrelay state (does NOT touch any pw agent)")
    try: cmd_down(args)
    except SystemExit: pass
    # Also catch any leaked agent processes
    if not IS_WIN:
        subprocess.run(["pkill", "-f", str(REPO_ROOT / "laptop" / "agent.py")],
                       check=False)
    if resource:
        say(f"asking {resource} to kill ALL pwrelay-tagged sleeps for this user")
        subprocess.run(
            ["pw", "ssh", resource,
             'pkill -u $(whoami) -f "pwrelay-" 2>/dev/null; rm -f /tmp/pw-relay-port-$(whoami); true'],
            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    ok("reset complete")


def _print_tail(path: Path, n: int) -> None:
    try:
        lines = path.read_text().splitlines()
        for l in lines[-n:]:
            print("    " + l)
    except FileNotFoundError:
        pass


# ---------- entrypoint -----------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="pwrelay", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("setup")
    p_up = sub.add_parser("up")
    p_up.add_argument("resource", nargs="?", default=None)
    sub.add_parser("down")
    sub.add_parser("stop")
    sub.add_parser("status")
    p_doc = sub.add_parser("doctor")
    p_doc.add_argument("resource", nargs="?", default=None)
    p_res = sub.add_parser("reset")
    p_res.add_argument("resource", nargs="?", default=None)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler = {
        "setup": cmd_setup,
        "up": cmd_up,
        "down": cmd_down,
        "stop": cmd_down,
        "status": cmd_status,
        "doctor": cmd_doctor,
        "reset": cmd_reset,
    }[args.cmd]
    handler(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
