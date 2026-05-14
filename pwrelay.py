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
    """Stop a process group (not just the leader).

    Every pwrelay-spawned process is launched with start_new_session=True
    (see _detach_kwargs), so each one is the leader of its own process
    group. Killing the group via os.killpg() catches not only the leader
    but ALL children, grandchildren, etc., including ones reparented to
    init after the leader died. This is what fixes the
    'p11-kit-server / socat survives after agent.sh dies' family of bugs
    we hit repeatedly: agent.sh's children would orphan and continue
    running, since killing only the agent.sh pid didn't touch them.
    """
    pid = _read_pid(pid_file)
    if pid is None:
        return
    if not _is_running(pid_file):
        try: pid_file.unlink()
        except FileNotFoundError: pass
        return
    say(f"stopping {name} (pid {pid})")

    if IS_WIN:
        # No process-group equivalent; kill the tree via taskkill /T.
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                       check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        # Resolve the process group ID. For start_new_session=True spawns
        # this equals the pid itself; fall back to pid if getpgid fails.
        try:
            pgid = os.getpgid(pid)
        except ProcessLookupError:
            pgid = pid
        try: os.killpg(pgid, signal.SIGTERM)
        except (OSError, ProcessLookupError): pass
        # Wait for graceful exit
        for _ in range(8):
            if not _is_running(pid_file):
                break
            time.sleep(0.25)
        # SIGKILL stragglers
        try: os.killpg(pgid, signal.SIGKILL)
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


def _find_desktop_session(resource: str) -> "dict | None":
    """Return the JSON dict for the user's running desktop on ``resource``,
    or None if no matching session exists."""
    import json as _json
    pw = shutil.which("pw")
    if not pw:
        return None
    try:
        r = subprocess.run(
            [pw, "sessions", "ls", "-o", "json"],
            capture_output=True, text=True, check=False, timeout=15,
        )
        sessions = _json.loads(r.stdout) if r.stdout.strip() else []
    except Exception:
        return None
    for s in sessions:
        if s.get("type") == "desktop" and s.get("status") == "running":
            target = (s.get("targetName") or "").rsplit("/", 1)[-1]
            if target == resource:
                return s
    return None


def _ensure_desktop_session(resource: str) -> "dict | None":
    """Make sure a running VDI desktop session exists on ``resource``.

    Returns the session JSON dict on success (existing or newly created),
    or None on failure.
    """
    pw = shutil.which("pw")
    if not pw:
        err("pw CLI not on PATH — can't manage VDI desktop sessions.")
        sys.exit(1)

    existing = _find_desktop_session(resource)
    if existing:
        ok(f"existing desktop session '{existing.get('name')}' on {resource} — skipping create")
        return existing

    say(f"no running desktop on {resource}; creating one (this typically "
        "takes 30–60s as the cluster spins up the VNC server) ...")
    rc = subprocess.run(
        [pw, "sessions", "create", "--type", "desktop", "--wait", resource],
        check=False,
    ).returncode
    if rc != 0:
        err(f"desktop create failed (rc={rc}). Continuing — pwrelay will still "
            "open the tunnels, but Chrome won't have a display to render into "
            "until you spin a desktop manually.")
        return None
    ok(f"desktop session up on {resource}")
    return _find_desktop_session(resource)


def _open_vnc_locally(session: dict) -> None:
    """Port-forward the desktop session and open it in the OS VNC viewer.

    Backgrounds `pw sessions connect <name> --port N` so it survives
    while pwrelay foregrounds the agent log. Once the proxy port is
    open, hands `vnc://127.0.0.1:N` to the OS via `open` (macOS),
    `xdg-open` (Linux), or `start` (Windows).
    """
    pw = shutil.which("pw")
    if not pw:
        err("pw CLI not on PATH — can't open VNC.")
        return

    name = session.get("name") or ""
    namespace = session.get("namespace") or ""
    full_name = f"{namespace}/{name}" if namespace else name
    if not full_name:
        err("desktop session has no name — can't connect.")
        return

    # Pick a free local port to forward into.
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    local_port = s.getsockname()[1]
    s.close()

    say(f"port-forwarding desktop session '{full_name}' to 127.0.0.1:{local_port}")
    connect_log = STATE_DIR / "pwrelay-vnc-connect.log"
    connect_log.write_text("")
    proc = subprocess.Popen(
        [pw, "sessions", "connect", "--port", str(local_port), full_name],
        stdout=open(connect_log, "ab"), stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        **_detach_kwargs(),
    )
    (STATE_DIR / "pwrelay-vnc-connect.pid").write_text(str(proc.pid))

    # Wait briefly for the listener to come up.
    deadline = time.monotonic() + 12.0
    listening = False
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", local_port), timeout=0.5):
                listening = True
                break
        except OSError:
            time.sleep(0.4)
    if not listening:
        err(f"local VNC proxy didn't come up on port {local_port}. "
            f"See {connect_log} for `pw sessions connect` output.")
        return
    ok(f"local VNC listener ready on 127.0.0.1:{local_port}")

    url = f"vnc://127.0.0.1:{local_port}"
    say(f"handing {url} to your OS VNC viewer")
    plat = platform.system()
    try:
        if plat == "Darwin":
            subprocess.Popen(["open", url], close_fds=True)
        elif plat == "Windows":
            os.startfile(url)  # type: ignore[attr-defined]
        else:
            subprocess.Popen(["xdg-open", url], close_fds=True)
    except Exception as e:
        err(f"couldn't auto-open VNC client: {e}")
        err(f"Open manually: {url}")


MARKETPLACE_SLUG = "marketplace/auth_relay"
SAVED_NAME_CANDIDATES = ("auth_relay", "auth-relay", "pw-auth-relay", "authrelay")


def _run_bootstrap_workflow(resource: str, cac_enabled: bool) -> None:
    """Run the bootstrap workflow on ACTIVATE.

    Invocation priority:
      1. ``marketplace/auth_relay`` — the canonical published workflow
         (https://noaa.parallel.works/market/i/auth_relay). Works for
         every user without first importing into their own account.
      2. A saved workflow in the user's own account whose name matches
         one of SAVED_NAME_CANDIDATES — useful if the user has a forked
         or hand-edited version.
      3. The in-repo workflow.yaml as an ad-hoc upload. This path hits
         a 409 slug conflict if the YAML has been uploaded before, so
         it's the last resort.
    """
    import json as _json
    pw = shutil.which("pw")
    if not pw:
        err("pw CLI not on PATH — can't run the bootstrap workflow.")
        sys.exit(1)

    inputs = {
        "resource": resource,
        "install_location": "home",
        "custom_relay_dir": "",
        "branch": "main",
        "seed_bookmarks": True,
        "auto_launch_chrome": True,
        "enable_cac": bool(cac_enabled),
    }
    inputs_json = _json.dumps(inputs)

    def _try_run(target: str, label: str) -> int:
        say(f"running workflow '{label}' on {resource}"
            + (" (with --cac)" if cac_enabled else ""))
        say(f"  inputs: {inputs_json}")
        return subprocess.run(
            [pw, "workflows", "run", target,
             "-i", inputs_json,
             "--name", f"pwrelay-bootstrap-{int(time.time())}",
             "-o", "text"],
            check=False,
        ).returncode

    # Tier 1: marketplace
    rc = _try_run(MARKETPLACE_SLUG, MARKETPLACE_SLUG)
    if rc == 0:
        ok("bootstrap workflow complete (marketplace)")
        return
    say(f"marketplace workflow run failed (rc={rc}); trying user-account-saved versions...")

    # Tier 2: user's saved workflow
    saved_name = ""
    try:
        ls = subprocess.run(
            [pw, "workflows", "ls", "-o", "list"],
            capture_output=True, text=True, check=False, timeout=10,
        )
        for line in ls.stdout.splitlines():
            n = line.strip()
            if n in SAVED_NAME_CANDIDATES:
                saved_name = n
                break
    except Exception:
        pass
    if saved_name:
        rc = _try_run(saved_name, saved_name)
        if rc == 0:
            ok(f"bootstrap workflow '{saved_name}' complete")
            return

    # Tier 3: local YAML upload
    workflow_yaml = REPO_ROOT / "workflow.yaml"
    if workflow_yaml.exists():
        rc = _try_run(str(workflow_yaml), "in-repo workflow.yaml")
        if rc == 0:
            ok("bootstrap workflow complete (local upload)")
            return

    err(f"all bootstrap workflow paths failed (last rc={rc}).")
    err(f"Inspect via: pw workflows runs ls")
    err("Continuing anyway; drop --workflow next time to skip this step.")


def _clear_stale_local_state() -> None:
    """Remove state files whose PID is no longer alive.

    Without this, a kill -9 of a previous pwrelay leaves the PID files
    behind, and `_is_running` returns False (process gone) but the file
    still exists — confusing later code paths. Cleaning lets a fresh
    `up` proceed cleanly even after an unclean exit.
    """
    for pid_path in (PID_AGENT, PID_TUNNEL, PID_CAC_AGENT, PID_CAC_TUNNEL):
        if pid_path.exists() and not _is_running(pid_path):
            try: pid_path.unlink()
            except FileNotFoundError: pass


def _clean_phantom_sleeps_on_remote(resource: str) -> None:
    """Kill ALL pwrelay-tagged sleeps on the remote for this user.

    Phantom accumulation: each `pwrelay up` opens reverse tunnels whose
    remote endpoint is a tagged `sleep`. If a previous run died unclean
    (laptop SIGKILL, network drop, etc.), the remote `sleep` plus its
    parent ssh peer can linger — pw agent then caches the port forward
    indefinitely, port-fallback bumps the new session to a higher port,
    and over time the cluster fills with phantom processes.

    Hard-clean every time we start: SSH in and kill any process under
    this user named `pwrelay-*`. NEVER touches the pw agent itself.
    Safe because the sleeps are ours by construction (we set argv[0] to
    `pwrelay-<session>-<role>` via bash's `exec -a`).
    """
    say(f"clearing any phantom pwrelay sleeps on {resource} from prior sessions")
    subprocess.run(
        ["pw", "ssh", resource,
         'pkill -u "$(id -un)" -f "pwrelay-" 2>/dev/null; '
         'rm -f /tmp/pw-relay-port-$(id -un) 2>/dev/null; true'],
        check=False,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=20,
    )


def cmd_up(args: argparse.Namespace) -> None:
    resource = _resolve_resource(args.resource)

    fido_enabled = not args.no_fido
    cac_enabled = bool(args.cac)
    if not fido_enabled and not cac_enabled:
        err("nothing to do — both FIDO and CAC are disabled.")
        err("drop --no-fido, or add --cac, or both.")
        sys.exit(1)

    # Sweep dead PID files so a kill -9'd previous run doesn't block us.
    _clear_stale_local_state()

    if fido_enabled and _is_running(PID_AGENT):
        say(f"FIDO agent already running (pid {_read_pid(PID_AGENT)}). Use `pwrelay down` first.")
        sys.exit(1)
    if cac_enabled and _is_running(PID_CAC_AGENT):
        say(f"CAC agent already running (pid {_read_pid(PID_CAC_AGENT)}). Use `pwrelay down` first.")
        sys.exit(1)

    # Clean the remote BEFORE picking ports. Otherwise pw-agent's cached
    # port reservations from phantom sessions push us to ever-higher
    # ports (7777 -> 7778 -> 7779 -> ... and 7888 -> 7889 -> ...).
    _clean_phantom_sleeps_on_remote(resource)

    vp = _venv_python()
    if fido_enabled and not vp.exists():
        err("venv not found. Run: pwrelay setup")
        sys.exit(1)

    # Optional: ensure a VDI desktop exists on the resource. Opt-in
    # (--desktop) because creating a desktop is a relatively heavy
    # action and most users start with a desktop already running.
    # --open implies --desktop.
    desktop_session: "dict | None" = None
    if args.desktop or args.open_vnc:
        desktop_session = _ensure_desktop_session(resource)
    if args.open_vnc and desktop_session:
        _open_vnc_locally(desktop_session)

    # Optional: run the bootstrap workflow on the remote BEFORE we open
    # tunnels. Opt-in (--workflow) because the remote side is typically
    # set up once per cluster; subsequent `pwrelay up`s should be fast.
    if args.workflow:
        _run_bootstrap_workflow(resource, cac_enabled)

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


def cmd_nuke(args: argparse.Namespace) -> None:
    """Wipe every pwrelay-adjacent process on the laptop, ignoring state files.

    Use when `down` and `reset` aren't clearing things (stale state files,
    orphaned p11-kit-server / socat that survived their parent agent.sh,
    leaked tunnel supervisors from kill -9'd previous runs). Walks
    /proc-equivalent for every user-owned process and kills any whose
    executable path or argv matches our binaries.

    Does NOT touch any pw agent — never matches on patterns containing
    'pw agent' or 'pw ssh'. Optionally cleans the remote too if a
    resource argument is given (or if PID_RESOURCE is set).
    """
    if IS_WIN:
        err("`pwrelay nuke` isn't implemented on Windows yet — use Task Manager.")
        sys.exit(1)

    say("nuking pwrelay procs on this laptop (does NOT touch pw agent)")

    # Patterns that uniquely identify our procs in argv. Conservative —
    # each one is specific enough that no real user process should match.
    OUR_ARGV_PATTERNS = (
        str(REPO_ROOT / "laptop" / "agent.py"),
        str(REPO_ROOT / "pcsc" / "agent.sh"),
        str(REPO_ROOT / "pcsc" / "stdio_bridge.py"),
        str(REPO_ROOT / "pwrelay.py"),
        "name pwrelay-cac --provider",        # p11-kit-server
        "socat TCP-LISTEN:7777",
        "socat TCP-LISTEN:7778",
        "socat TCP-LISTEN:7888",
        "socat TCP-LISTEN:7889",
        "tail -F /tmp/pwrelay",
        "pwrelay-tunnel.log",                 # tunnel supervisor's open() arg
        "pwrelay-cac-tunnel.log",
    )
    # Patterns we MUST NEVER kill — defense in depth.
    FORBIDDEN = ("pw agent", "pw ssh", " pw-agent")

    me = os.getuid()
    killed = 0
    # Use ps to enumerate cmdline so we don't depend on /proc.
    r = subprocess.run(
        ["ps", "-ww", "-u", str(me), "-o", "pid=,command="],
        capture_output=True, text=True, check=False,
    )
    self_pid = os.getpid()
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            pid_str, cmd = line.split(None, 1)
            pid = int(pid_str)
        except ValueError:
            continue
        if pid == self_pid:
            continue
        # NEVER touch pw agent
        if any(f in cmd for f in FORBIDDEN):
            continue
        if not any(p in cmd for p in OUR_ARGV_PATTERNS):
            continue
        # Kill the whole process group so children orphaned by an earlier
        # kill -9 of the leader also go.
        try:
            pgid = os.getpgid(pid)
        except ProcessLookupError:
            pgid = pid
        try:
            os.killpg(pgid, signal.SIGKILL)
            killed += 1
        except (OSError, ProcessLookupError):
            try:
                os.kill(pid, signal.SIGKILL)
                killed += 1
            except (OSError, ProcessLookupError):
                pass
    say(f"laptop kill count: {killed}")

    # State files
    state_removed = 0
    for f in STATE_DIR.glob("pwrelay-*"):
        try:
            if f.is_dir():
                shutil.rmtree(f, ignore_errors=True)
            else:
                f.unlink()
            state_removed += 1
        except OSError:
            pass
    say(f"laptop state files removed: {state_removed}")

    # Remote cleanup (optional)
    resource = (PID_RESOURCE.read_text().strip() if PID_RESOURCE.exists()
                else _resolve_resource(args.resource))
    if resource:
        say(f"asking {resource} to kill ALL pwrelay-tagged sleeps for this user (NOT pw agent)")
        subprocess.run(
            ["pw", "ssh", resource,
             'for p in $(ps -u "$(id -un)" -o pid,comm 2>/dev/null | awk "$2 == \\"sleep\\" {print $1}"); do '
             '  cmd=$(tr "\\0" " " < /proc/$p/cmdline 2>/dev/null); '
             '  echo "$cmd" | grep -q "pwrelay-" && kill -9 "$p" 2>/dev/null; '
             'done; '
             'rm -f /tmp/pw-relay-port-$(id -un) 2>/dev/null; '
             'rm -f $HOME/.config/google-chrome-pwrelay/SingletonLock $HOME/.config/google-chrome-pwrelay/SingletonCookie $HOME/.config/google-chrome-pwrelay/SingletonSocket 2>/dev/null; '
             'true'],
            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=20,
        )
    ok("nuke complete")


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
    p_up.add_argument(
        "--workflow", action="store_true",
        help="ALSO submit the in-repo workflow.yaml via `pw workflows run` "
             "to provision the remote (chrome install, extension, optionally "
             "the CAC module). Typically a one-time-per-cluster step; once "
             "the remote side is set up you don't need this flag again. The "
             "--cac flag is propagated to the workflow's enable_cac input.")
    p_up.add_argument(
        "--desktop", action="store_true",
        help="ensure a VDI desktop session exists on the resource. If "
             "`pw sessions ls` doesn't already show a running desktop on "
             "this resource, create one via `pw sessions create --type "
             "desktop`. Use when starting from a clean cluster — saves you "
             "the trip to the ACTIVATE web UI to spin up a desktop.")
    p_up.add_argument(
        "--open", action="store_true", dest="open_vnc",
        help="after ensuring a desktop session, port-forward it to a local "
             "VNC port and hand the URL to your OS's default VNC handler "
             "(macOS Screen Sharing, TightVNC, RealVNC, etc.). Implies "
             "--desktop. Background-runs `pw sessions connect`; closing "
             "pwrelay closes the VNC connection too.")
    sub.add_parser("down")
    sub.add_parser("stop")
    sub.add_parser("status")
    p_doc = sub.add_parser("doctor")
    p_doc.add_argument("resource", nargs="?", default=None)
    p_res = sub.add_parser("reset")
    p_res.add_argument("resource", nargs="?", default=None)
    p_nuke = sub.add_parser(
        "nuke",
        help="wipe every pwrelay-adjacent process on this laptop "
             "(ignoring state files) and clean the remote too. Use when "
             "`down` and `reset` leave stragglers behind. Never touches pw agent.")
    p_nuke.add_argument("resource", nargs="?", default=None)
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
        "nuke": cmd_nuke,
    }[args.cmd]
    handler(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
