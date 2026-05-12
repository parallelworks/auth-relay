"""Laptop-side YubiKey relay agent (iteration 1: synthetic backend).

Listens on 127.0.0.1:7777 for the pw-ssh-reverse-tunnel peer (the workspace
stub) and answers a tiny set of ops. Once we prove the pipe carries traffic
cleanly, the synthetic backend gets swapped for libfido2 calls to the real
YubiKey.

Run on the laptop:

    python3 laptop/agent.py

Then in another terminal, hold a reverse tunnel open:

    pw ssh -R 7777:127.0.0.1:7777 workspace -- sleep 86400
"""

from __future__ import annotations

import argparse
import logging
import os
import secrets
import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.protocol import recv_message, send_message

LOG = logging.getLogger("agent")

LOOPBACK_HOST = "127.0.0.1"

SYNTHETIC_INFO = {
    "aaguid": "00000000-0000-0000-0000-000000000000",
    "versions": ["U2F_V2", "FIDO_2_0", "FIDO_2_1"],
    "extensions": ["credProtect", "hmac-secret"],
    "options": {"rk": True, "up": True, "uv": False, "plat": False},
    "transports": ["usb"],
    "vendor": "ParallelWorks-Synthetic",
    "product": "pw-fido-agent v0",
}


def handle_op(msg: dict) -> dict:
    op = msg.get("op")
    if op == "ping":
        return {"ok": True, "op": "ping", "echo": msg.get("payload"), "t_agent": time.time()}
    if op == "info":
        return {"ok": True, "op": "info", "info": SYNTHETIC_INFO}
    if op == "make_credential":
        return {
            "ok": True,
            "op": "make_credential",
            "synthetic": True,
            "credential_id": secrets.token_hex(16),
            "rp_id": msg.get("rp_id"),
            "note": "iteration-1 synthetic; real YubiKey integration is iteration-2",
        }
    if op == "get_assertion":
        return {
            "ok": True,
            "op": "get_assertion",
            "synthetic": True,
            "signature": secrets.token_hex(32),
            "rp_id": msg.get("rp_id"),
            "note": "iteration-1 synthetic; real YubiKey integration is iteration-2",
        }
    return {"ok": False, "error": f"unknown op: {op!r}"}


def serve_one(client: socket.socket, addr: tuple) -> None:
    peer = f"{addr[0]}:{addr[1]}"
    LOG.info("connection from %s", peer)
    try:
        with client:
            while True:
                msg = recv_message(client)
                if msg is None:
                    LOG.info("%s closed", peer)
                    return
                LOG.info("%s -> %s", peer, msg)
                reply = handle_op(msg)
                LOG.info("%s <- %s", peer, reply)
                send_message(client, reply)
    except (ConnectionError, OSError) as exc:
        LOG.warning("%s aborted: %s", peer, exc)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="laptop-side YubiKey relay agent (loopback-only; reach it via pw ssh -R)",
    )
    parser.add_argument("--port", type=int, default=7777)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

    # Intentionally loopback-only. The only sanctioned path from a remote PW
    # session to this agent is the pw ssh -R reverse tunnel, which terminates
    # on 127.0.0.1 here. Binding to a routable interface is a footgun we don't
    # want available.
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LOOPBACK_HOST, args.port))
    srv.listen(8)
    LOG.info("agent listening on %s:%d (loopback only; pid=%d)", LOOPBACK_HOST, args.port, os.getpid())
    try:
        while True:
            client, addr = srv.accept()
            threading.Thread(target=serve_one, args=(client, addr), daemon=True).start()
    except KeyboardInterrupt:
        LOG.info("shutting down")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
