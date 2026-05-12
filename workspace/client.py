"""Workspace-side test client for the YubiKey relay (iteration 1).

Connects to 127.0.0.1:<port> on the workspace, which (via the pw ssh -R
reverse tunnel started on the laptop) reaches the laptop's agent.py.
Runs a small scripted scenario and prints timing.

Run on the workspace:

    python3 workspace/client.py
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.protocol import recv_message, send_message


def call(sock: socket.socket, msg: dict) -> tuple[dict, float]:
    t0 = time.perf_counter()
    send_message(sock, msg)
    reply = recv_message(sock)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    if reply is None:
        raise ConnectionError("agent closed before replying")
    return reply, elapsed_ms


def run(host: str, port: int) -> int:
    print(f"connecting to {host}:{port} ...", flush=True)
    with socket.create_connection((host, port), timeout=5) as sock:
        print(f"connected (local={sock.getsockname()} peer={sock.getpeername()})")

        reply, dt = call(sock, {"op": "ping", "payload": "hello-from-workspace"})
        print(f"[ping] {dt:6.1f} ms  -> {reply}")
        assert reply.get("ok") and reply.get("echo") == "hello-from-workspace", reply

        reply, dt = call(sock, {"op": "info"})
        print(f"[info] {dt:6.1f} ms  -> versions={reply['info']['versions']}")
        assert reply.get("ok"), reply

        reply, dt = call(sock, {"op": "make_credential", "rp_id": "google.com"})
        print(f"[make_credential] {dt:6.1f} ms  -> credential_id={reply.get('credential_id')}")
        assert reply.get("ok"), reply

        reply, dt = call(sock, {"op": "get_assertion", "rp_id": "google.com"})
        print(f"[get_assertion]   {dt:6.1f} ms  -> sig={reply.get('signature')[:16]}...")
        assert reply.get("ok"), reply

        # Latency probe: 10 rapid pings to characterize the tunnel.
        timings: list[float] = []
        for i in range(10):
            _, dt = call(sock, {"op": "ping", "payload": f"probe-{i}"})
            timings.append(dt)
        timings.sort()
        median = timings[len(timings) // 2]
        print(f"[ping x10] min={timings[0]:.1f}ms  median={median:.1f}ms  max={timings[-1]:.1f}ms")

    print("OK — relay pipe is end-to-end functional")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="workspace-side relay test client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7777)
    args = parser.parse_args(argv)
    return run(args.host, args.port)


if __name__ == "__main__":
    raise SystemExit(main())
