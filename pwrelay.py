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
# FIDO2 (YubiKey, etc.) — port 7777, agent.py, tunnel
PID_AGENT = STATE_DIR / "pwrelay-agent.pid"
PID_TUNNEL = STATE_DIR / "pwrelay-tunnel.pid"
PID_PORT = STATE_DIR / "pwrelay-port"
LOG_AGENT = STATE_DIR / "pwrelay-agent.log"
LOG_TUNNEL = STATE_DIR / "pwrelay-tunnel.log"

# CAC / PIV smartcard — port 7888, pcsc/agent.sh, tunnel
PID_CAC_AGENT = STATE_DIR / "pwrelay-cac-agent.pid"
PID_CAC_TUNNEL = STATE_DIR / "pwrelay-cac-tunnel.pid"
PID_CAC_PORT = STATE_DIR / "pwrelay-cac-port"
LOG_CAC_AGENT = STATE_DIR / "pwrelay-cac-agent.log"
LOG_CAC_TUNNEL = STATE_DIR / "pwrelay-cac-tunnel.log"

# Per-session bookkeeping (shared across FIDO + CAC).
PID_SESSION = STATE_DIR / "pwrelay-session"
PID_RESOURCE = STATE_DIR / "pwrelay-resource"

DEFAULT_PORT = int(os.environ.get("PW_RELAY_PORT", "7777"))
DEFAULT_CAC_PORT = int(os.environ.get("PW_CAC_PORT", "7888"))
PORT_FALLBACK_RANGE = 8  # try N, N+1, ..., N+7


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
                              session_id: str, log_path: Path,
                              pid_path: Path, label: str = "fido") -> int:
    """Spawn a Python child process that runs ssh -R in a retry loop.

    Used identically for the FIDO (7777) and CAC (7888) tunnels — the
    log/pid paths and a `label` (just for the session marker) are the
    only differences.

    Returns the supervisor process PID. The supervisor writes activity
    to ``log_path``; the parent can grep for the 'tunnel-up on' line to
    confirm the tunnel is live before continuing.
    """
    log_path.write_text("")  # truncate

    # Each tunnel gets a distinct marker so `pkill -f marker` on the
    # remote at teardown only touches our own sleep, not the other relay.
    tunnel_marker = f"{session_id}-{label}"
    known_hosts_file = "nul" if IS_WIN else "/dev/null"

    # Render the supervisor script via str.format, NOT an f-string, so the
    # `{rc}` placeholders inside the inner `f'...{{rc}}...'` strings reach
    # the child process literally. We only substitute the named fields
    # explicitly listed below.
    supervisor_script = """\
import os, subprocess, sys, time

LOG = open({log_path!r}, 'a', buffering=1)
def log(msg):
    LOG.write(msg + '\\n')

while True:
    rc = subprocess.run(
        ['ssh',
         '-i', os.path.expanduser('~/.ssh/pwcli'),
         '-o', 'ProxyCommand=pw ssh --proxy-command %h',
         '-o', 'StrictHostKeyChecking=no',
         '-o', 'UserKnownHostsFile=' + {known_hosts!r},
         '-o', 'ServerAliveInterval=30',
         '-o', 'ServerAliveCountMax=3',
         '-o', 'TCPKeepAlive=yes',
         '-o', 'ExitOnForwardFailure=yes',
         '-R', '{port}:127.0.0.1:{port}',
         '{rs_user}@{resource}',
         'echo \"[remote] tunnel-up on $(hostname); pid=$$ marker={tunnel_marker}\"; '
         'exec -a \"{tunnel_marker}\" sleep 86400'],
        stdout=LOG, stderr=LOG,
    ).returncode

    # Tail the log to look for terminal failures.
    LOG.flush()
    try:
        tail = open({log_path!r}).read()
    except Exception:
        tail = ''
    if 'Permission denied' in tail or 'remote port forwarding failed' in tail:
        log(f'[supervisor] terminal failure rc={{rc}}; not retrying')
        sys.exit(rc)
    log(f'[supervisor] ssh exited rc={{rc}} — reconnecting in 3s')
    time.sleep(3)
""".format(
        log_path=str(log_path),
        known_hosts=known_hosts_file,
        port=port,
        rs_user=rs_user,
        resource=resource,
        tunnel_marker=tunnel_marker,
    )

    proc = subprocess.Popen(
        [sys.executable, "-c", supervisor_script],
        stdout=open(log_path, "ab"),
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        **_detach_kwargs(),
    )
    pid_path.write_text(str(proc.pid))
    return proc.pid


def _wait_for_tunnel_up(log_path: Path, pid_path: Path,
                         timeout: float = 20.0) -> str | None:
    """Block until ``log_path`` shows 'tunnel-up on ...'; return the host."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            text = log_path.read_text()
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
        if not _is_running(pid_path):
            return None
        time.sleep(0.5)
    return None


def _spawn_cac_agent(port: int) -> int:
    """Spawn pcsc/agent.sh as a detached background process.

    Returns the agent's PID. The agent listens on 127.0.0.1:``port`` and
    serves the local CAC card via p11-kit + socat.
    """
    if IS_WIN:
        err("--cac is not supported on Windows yet (pcsc/agent.sh is bash-only).")
        err("Track the Windows agent.py rewrite in docs/cac-relay-design.md.")
        sys.exit(1)

    agent_sh = REPO_ROOT / "pcsc" / "agent.sh"
    if not agent_sh.exists():
        err(f"missing CAC agent script at {agent_sh}")
        sys.exit(1)

    bash = shutil.which("bash")
    if not bash:
        err("--cac needs bash on PATH (couldn't find one).")
        sys.exit(1)

    LOG_CAC_AGENT.write_text("")  # truncate
    env = os.environ.copy()
    env["PW_CAC_PORT"] = str(port)
    proc = subprocess.Popen(
        [bash, str(agent_sh)],
        env=env,
        stdout=open(LOG_CAC_AGENT, "ab"),
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        **_detach_kwargs(),
    )
    PID_CAC_AGENT.write_text(str(proc.pid))
    return proc.pid


def _wait_for_cac_agent_up(timeout: float = 8.0) -> bool:
    """Probe the CAC agent's listening port until it accepts a TCP conn."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _is_running(PID_CAC_AGENT):
            return False
        try:
            port = int(PID_CAC_PORT.read_text().strip())
        except Exception:
            time.sleep(0.2); continue
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.4)
    return False


def _pick_remote_port(resource: str, default: int, label: str) -> int:
    """Walk default..default+RANGE looking for a free port on the remote."""
    say(f"[{label}] checking which port is free on remote {resource} ...")
    for cand in range(default, default + PORT_FALLBACK_RANGE):
        if _probe_remote_port(resource, cand):
            if cand != default:
                say(f"[{label}] port {default} on remote is busy; using {cand}")
            return cand
    err(f"[{label}] no free port in {default}..{default + PORT_FALLBACK_RANGE - 1} on {resource}.")
    err("try `pwrelay reset <resource>` and re-run.")
    sys.exit(1)


def cmd_up(args: argparse.Namespace) -> None:
    resource = _resolve_resource(args.resource)

    fido_enabled = not args.no_fido
    cac_enabled = bool(args.cac)
    if not fido_enabled and not cac_enabled:
        err("nothing to do — both FIDO and CAC are disabled.")
        err("drop --no-fido, or add --cac, or both.")
        sys.exit(1)

    if fido_enabled and _is_running(PID_AGENT):
        say(f"FIDO agent already running (pid {_read_pid(PID_AGENT)}). Use `pwrelay down` first.")
        sys.exit(1)
    if cac_enabled and _is_running(PID_CAC_AGENT):
        say(f"CAC agent already running (pid {_read_pid(PID_CAC_AGENT)}). Use `pwrelay down` first.")
        sys.exit(1)

    vp = _venv_python()
    if fido_enabled and not vp.exists():
        err("venv not found. Run: pwrelay setup")
        sys.exit(1)

    rs_user = _resource_user()
    session_id = f"pwrelay-{int(time.time())}-{os.getpid()}"
    PID_SESSION.write_text(session_id)
    PID_RESOURCE.write_text(resource)

    # ---- FIDO2 side --------------------------------------------------------
    chosen_port: int | None = None
    if fido_enabled:
        chosen_port = _pick_remote_port(resource, DEFAULT_PORT, "fido")
        PID_PORT.write_text(str(chosen_port))

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

        say(f"starting FIDO agent on 127.0.0.1:{chosen_port}")
        agent_proc = subprocess.Popen(
            [str(vp), str(REPO_ROOT / "laptop" / "agent.py"), "--port", str(chosen_port)],
            stdout=open(LOG_AGENT, "ab"), stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            **_detach_kwargs(),
        )
        PID_AGENT.write_text(str(agent_proc.pid))
        time.sleep(0.6)
        if not _is_running(PID_AGENT):
            err(f"FIDO agent failed to start; tail {LOG_AGENT}")
            try: sys.stderr.write(LOG_AGENT.read_text()[-2000:])
            except Exception: pass
            sys.exit(1)
        ok(f"FIDO agent listening on 127.0.0.1:{chosen_port}")

        say(f"opening FIDO reverse tunnel to {rs_user}@{resource} [auto-reconnect, port {chosen_port}]")
        _spawn_tunnel_supervisor(resource, rs_user, chosen_port, session_id,
                                  LOG_TUNNEL, PID_TUNNEL, label="fido")
        rhost = _wait_for_tunnel_up(LOG_TUNNEL, PID_TUNNEL)
        if not rhost:
            err("FIDO tunnel didn't come up; tail of " + str(LOG_TUNNEL))
            try: sys.stderr.write(LOG_TUNNEL.read_text()[-2000:])
            except Exception: pass
            cmd_down(args)
            sys.exit(1)
        ok(f"FIDO tunnel up to {rhost} — port {chosen_port} on remote -> agent on this laptop")

    # ---- CAC / PIV side ----------------------------------------------------
    cac_port: int | None = None
    if cac_enabled:
        cac_port = _pick_remote_port(resource, DEFAULT_CAC_PORT, "cac")
        PID_CAC_PORT.write_text(str(cac_port))

        say(f"starting CAC agent on 127.0.0.1:{cac_port}")
        _spawn_cac_agent(cac_port)
        if not _wait_for_cac_agent_up():
            err("CAC agent failed to start. Output:")
            try:
                sys.stderr.write("\n")
                sys.stderr.write(LOG_CAC_AGENT.read_text()[-4000:])
                sys.stderr.write("\n")
            except Exception:
                pass
            err(f"(full log: {LOG_CAC_AGENT})")
            cmd_down(args)
            sys.exit(1)
        ok(f"CAC agent listening on 127.0.0.1:{cac_port}")

        say(f"opening CAC reverse tunnel to {rs_user}@{resource} [auto-reconnect, port {cac_port}]")
        _spawn_tunnel_supervisor(resource, rs_user, cac_port, session_id,
                                  LOG_CAC_TUNNEL, PID_CAC_TUNNEL, label="cac")
        rhost = _wait_for_tunnel_up(LOG_CAC_TUNNEL, PID_CAC_TUNNEL)
        if not rhost:
            err("CAC tunnel didn't come up; tail of " + str(LOG_CAC_TUNNEL))
            try: sys.stderr.write(LOG_CAC_TUNNEL.read_text()[-2000:])
            except Exception: pass
            cmd_down(args)
            sys.exit(1)
        ok(f"CAC tunnel up to {rhost} — port {cac_port} on remote -> CAC agent on this laptop")

    # ---- summary -----------------------------------------------------------
    enabled_bits = []
    if fido_enabled: enabled_bits.append(f"FIDO2 :{chosen_port}")
    if cac_enabled:  enabled_bits.append(f"CAC/PIV :{cac_port}")
    summary = " + ".join(enabled_bits)
    print(f"""
────────────────────────────────────────────────────────────────────
 Relay live ({summary}). On the VDI side:
   - Run the ACTIVATE workflow (parallel.works > Workflows > auth-relay)
   - Or manually:  bash <repo>/vdi/bootstrap.sh
                  python3 <repo>/vdi/install-extension.py
                  bash <repo>/pcsc/bootstrap.sh   # if you enabled --cac
 Sign in to anywhere that uses WebAuthn or CAC TLS auth.
 Ctrl+C here tears down everything cleanly.
────────────────────────────────────────────────────────────────────
""")

    # Foreground: tail whichever log is most useful. FIDO is chatty, CAC
    # is mostly silent — prefer FIDO if it's running.
    def _on_sigint(*_a) -> None:
        print()
        cmd_down(args)
        sys.exit(0)
    signal.signal(signal.SIGINT, _on_sigint)
    if hasattr(signal, "SIGTERM"):
        try: signal.signal(signal.SIGTERM, _on_sigint)
        except (ValueError, OSError): pass

    tail_target = LOG_AGENT if fido_enabled else LOG_CAC_AGENT
    _tail_file(tail_target)


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
    # Best-effort: tell the remote to kill our tagged sleeps so the pw
    # agent releases the ports faster. Never touch the pw agent itself.
    sid_path = PID_SESSION
    res_path = PID_RESOURCE
    if sid_path.exists() and res_path.exists():
        sid = sid_path.read_text().strip()
        res = res_path.read_text().strip()
        if sid and res:
            say(f"asking remote ({res}) to release our session marker '{sid}'")
            # Match all sleeps tagged with this session (both -fido and -cac).
            subprocess.run(
                ["pw", "ssh", res,
                 f"pkill -u $(whoami) -f \"{sid}\" 2>/dev/null; true"],
                check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
    _stop_pid(PID_TUNNEL, "FIDO ssh tunnel")
    _stop_pid(PID_AGENT, "FIDO agent")
    _stop_pid(PID_CAC_TUNNEL, "CAC ssh tunnel")
    _stop_pid(PID_CAC_AGENT, "CAC agent")
    for p in (PID_PORT, PID_CAC_PORT, PID_SESSION, PID_RESOURCE):
        try: p.unlink()
        except FileNotFoundError: pass
    ok("relay stopped")


def _status_line(name: str, pid_path: Path, log_path: Path | None = None) -> None:
    if _is_running(pid_path):
        ok(f"{name}: running (pid {_read_pid(pid_path)})")
        if log_path is not None:
            try:
                lines = log_path.read_text().splitlines()
                up = [l for l in lines if "tunnel-up on" in l]
                if up:
                    print(" ", up[-1])
            except FileNotFoundError:
                pass
    else:
        say(f"{name}: not running")


def cmd_status(args: argparse.Namespace) -> None:
    _status_line("FIDO agent",  PID_AGENT)
    _status_line("FIDO tunnel", PID_TUNNEL, LOG_TUNNEL)
    _status_line("CAC agent",   PID_CAC_AGENT)
    _status_line("CAC tunnel",  PID_CAC_TUNNEL, LOG_CAC_TUNNEL)


def cmd_doctor(args: argparse.Namespace) -> None:
    resource = _resolve_resource(args.resource)
    say("=== local (this laptop) ===")
    cmd_status(args)
    print(f"  fido port  : {PID_PORT.read_text().strip() if PID_PORT.exists() else '(none)'}")
    print(f"  cac port   : {PID_CAC_PORT.read_text().strip() if PID_CAC_PORT.exists() else '(none)'}")
    print(f"  session    : {PID_SESSION.read_text().strip() if PID_SESSION.exists() else '(none)'}")
    print(f"  resource   : {PID_RESOURCE.read_text().strip() if PID_RESOURCE.exists() else '(none)'}")
    print("  fido agent log tail:")
    _print_tail(LOG_AGENT, 3)
    print("  fido tunnel log tail:")
    _print_tail(LOG_TUNNEL, 5)
    print("  cac agent log tail:")
    _print_tail(LOG_CAC_AGENT, 3)
    print("  cac tunnel log tail:")
    _print_tail(LOG_CAC_TUNNEL, 5)
    print()
    say(f"=== remote ({resource}) ===")
    # Grep for relay ports (777x and 788x) on the remote.
    subprocess.run(
        ["pw", "ssh", resource,
         """
echo "  hostname  : $(hostname)"
echo "  whoami    : $(whoami)"
echo "  relay ports (listening, 777x for FIDO + 788x for CAC):"
ss -tlnp 2>/dev/null | awk '/:(777[0-9]|788[0-9]) /{ printf "    %s  %s\\n", $4, $6 }'
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
        subprocess.run(["pkill", "-f", str(REPO_ROOT / "pcsc" / "agent.sh")],
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
    p_up.add_argument(
        "--cac", action="store_true",
        help="also expose the laptop CAC/PIV smartcard to the VDI (port 7888). "
             "Requires pcsc/agent.sh prereqs (opensc + p11-kit + socat). "
             "Not supported on Windows yet — see docs/cac-relay-design.md.")
    p_up.add_argument(
        "--no-fido", action="store_true",
        help="skip the FIDO2 (YubiKey) tunnel entirely. Pair with --cac for "
             "CAC-only operation.")
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
