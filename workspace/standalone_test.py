"""Self-contained workspace-side test (no imports from this repo).

Bundled so it can be scp'd or piped to the workspace as a single file.
Mirrors workspace/client.py but inlines the framing helpers.
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
import time

MAX_MESSAGE_BYTES = 1 << 20


def send_message(sock: socket.socket, msg: dict) -> None:
    payload = json.dumps(msg, separators=(",", ":")).encode("utf-8")
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            if not chunks:
                return None
            raise ConnectionError("peer closed mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_message(sock: socket.socket) -> dict | None:
    header = _recv_exact(sock, 4)
    if header is None:
        return None
    (length,) = struct.unpack(">I", header)
    if length == 0 or length > MAX_MESSAGE_BYTES:
        raise ValueError(f"invalid message length: {length}")
    body = _recv_exact(sock, length)
    if body is None:
        raise ConnectionError("peer closed mid-message")
    return json.loads(body.decode("utf-8"))


def call(sock: socket.socket, msg: dict) -> tuple[dict, float]:
    t0 = time.perf_counter()
    send_message(sock, msg)
    reply = recv_message(sock)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    if reply is None:
        raise ConnectionError("agent closed before replying")
    return reply, elapsed_ms


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=7777)
    args = ap.parse_args()

    print(f"[workspace] hostname={socket.gethostname()} connecting to {args.host}:{args.port}")
    with socket.create_connection((args.host, args.port), timeout=10) as sock:
        print(f"[workspace] connected (local={sock.getsockname()} peer={sock.getpeername()})")

        reply, dt = call(sock, {"op": "ping", "payload": "hello-from-workspace"})
        print(f"[ping]             {dt:7.2f} ms  echo={reply.get('echo')!r}")
        assert reply.get("ok") and reply.get("echo") == "hello-from-workspace", reply

        reply, dt = call(sock, {"op": "info"})
        print(f"[info]             {dt:7.2f} ms  vendor={reply['info']['vendor']}")
        assert reply.get("ok"), reply

        reply, dt = call(sock, {"op": "make_credential", "rp_id": "accounts.google.com"})
        print(f"[make_credential]  {dt:7.2f} ms  cred_id={reply.get('credential_id')}")
        assert reply.get("ok"), reply

        reply, dt = call(sock, {"op": "get_assertion", "rp_id": "accounts.google.com"})
        print(f"[get_assertion]    {dt:7.2f} ms  sig={reply.get('signature', '')[:24]}...")
        assert reply.get("ok"), reply

        timings = []
        for i in range(20):
            _, dt = call(sock, {"op": "ping", "payload": f"probe-{i}"})
            timings.append(dt)
        timings.sort()
        median = timings[len(timings) // 2]
        p95 = timings[int(len(timings) * 0.95)]
        print(f"[ping x20]         min={timings[0]:.1f}  median={median:.1f}  p95={p95:.1f}  max={timings[-1]:.1f}  ms")

    print("[workspace] OK — relay traversed pw ssh -R tunnel end-to-end")
    return 0


if __name__ == "__main__":
    sys.exit(main())
