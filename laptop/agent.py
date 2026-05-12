"""Laptop-side YubiKey relay agent (iter 2: real CTAP2 pass-through).

Listens on 127.0.0.1:7777 for a peer that arrives via `pw ssh -R`, and pipes
each incoming length-prefixed frame to a USB YubiKey as a CTAPHID CBOR call.
The device's response bytes are sent back as the next frame.

Wire payload semantics (opaque to this module's framing, defined by python-fido2):

    request_frame  = <CTAP2 cmd byte> || <CBOR-encoded arguments>
    response_frame = <CTAP2 status byte> || <CBOR-encoded response>

Touch-required operations (make_credential, get_assertion) block the per-client
thread until the user physically touches the key. python-fido2 absorbs CTAPHID
keepalive frames internally during that wait.

Run on the laptop:

    python3 laptop/agent.py

Then have a peer reach it through the tunnel:

    ssh -i ~/.ssh/pwcli -o ProxyCommand="pw ssh --proxy-command %h" \\
        -R 7777:127.0.0.1:7777 Matthew.Shaxted@<resource> '<run client>'
"""

from __future__ import annotations

import argparse
import logging
import os
import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.protocol import recv_frame, send_frame

from fido2.hid import CTAPHID, CtapHidDevice

LOG = logging.getLogger("agent")

LOOPBACK_HOST = "127.0.0.1"


def discover_yubikey() -> CtapHidDevice:
    devs = list(CtapHidDevice.list_devices())
    if not devs:
        raise SystemExit("no FIDO HID device found; plug in your YubiKey and retry")
    if len(devs) > 1:
        raise SystemExit(f"multiple FIDO HID devices found ({len(devs)}); refusing to guess")
    return devs[0]


def serve_one(client: socket.socket, addr: tuple, device: CtapHidDevice, device_lock: threading.Lock) -> None:
    peer = f"{addr[0]}:{addr[1]}"
    LOG.info("connection from %s", peer)
    try:
        with client:
            while True:
                frame = recv_frame(client)
                if frame is None:
                    LOG.info("%s closed", peer)
                    return
                if not frame:
                    LOG.warning("%s sent empty frame; ignoring", peer)
                    continue
                ctap2_cmd = frame[0]
                t0 = time.perf_counter()
                # Serialize device access; the YubiKey can only handle one
                # ceremony at a time, and CTAPHID is not multi-channel safe
                # for our purposes.
                with device_lock:
                    LOG.info("%s -> ctap2_cmd=0x%02x len=%d", peer, ctap2_cmd, len(frame))
                    try:
                        response = device.call(CTAPHID.CBOR, frame)
                    except Exception as exc:
                        LOG.error("%s device.call failed: %r", peer, exc)
                        # Send a CTAP error frame back: status 0x7F (CTAP1_ERR_OTHER)
                        # so the peer gets a parseable response rather than a dead socket.
                        response = b"\x7f"
                dt_ms = (time.perf_counter() - t0) * 1000.0
                status = response[0] if response else 0xFF
                LOG.info("%s <- status=0x%02x len=%d dt=%.1fms", peer, status, len(response), dt_ms)
                send_frame(client, response)
    except (ConnectionError, OSError) as exc:
        LOG.warning("%s aborted: %s", peer, exc)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="laptop-side YubiKey relay agent (loopback-only; reach it via pw ssh -R)",
    )
    parser.add_argument("--port", type=int, default=7777)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

    device = discover_yubikey()
    LOG.info("YubiKey discovered: %s", device.descriptor)
    device_lock = threading.Lock()

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
            threading.Thread(
                target=serve_one, args=(client, addr, device, device_lock), daemon=True
            ).start()
    except KeyboardInterrupt:
        LOG.info("shutting down")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
