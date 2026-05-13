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
        -R 7777:127.0.0.1:7777 <user>@<resource> '<run client>'
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

from fido2.ctap import CtapError
from fido2.hid import CTAPHID, CtapHidDevice

LOG = logging.getLogger("agent")

LOOPBACK_HOST = "127.0.0.1"

# CTAP1_ERR_OTHER — when the failure isn't from the authenticator itself
# (e.g., HID transport went sideways), we return this generic status so the
# peer gets a parseable CTAP error byte rather than a dead socket.
CTAP_ERR_OTHER = 0x7F


def discover_yubikey() -> CtapHidDevice:
    devs = list(CtapHidDevice.list_devices())
    if not devs:
        raise SystemExit("no FIDO HID device found; plug in your YubiKey and retry")
    if len(devs) > 1:
        raise SystemExit(f"multiple FIDO HID devices found ({len(devs)}); refusing to guess")
    return devs[0]


class DeviceManager:
    """Wraps a CtapHidDevice and transparently re-opens it on transport
    failures (HID stale channel, USB blip, etc.). Concurrent callers
    serialize via the same lock; only one ceremony can be in flight at a
    time on a YubiKey.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._device: CtapHidDevice | None = None

    def _ensure_open(self) -> CtapHidDevice:
        if self._device is None:
            self._device = discover_yubikey()
            LOG.info("device opened: %s", self._device.descriptor)
        return self._device

    def _force_reopen(self) -> None:
        if self._device is not None:
            try:
                self._device.close()
            except Exception:
                pass
            self._device = None
        # Brief pause lets the OS release the HID handle before we re-open.
        time.sleep(0.2)

    def call_cbor(self, frame: bytes) -> bytes:
        """Send a CTAPHID CBOR frame, return the response bytes.

        On transport-level failures (typically `ConnectionFailure: Wrong
        channel` after the key has been touched-while-idle, replugged, or
        used by another app), re-open the HID device and retry once.
        Authenticator-level errors (`CtapError`, non-zero CBOR status) are
        propagated unchanged so the wire carries the real status byte.
        """
        with self._lock:
            dev = self._ensure_open()
            try:
                return dev.call(CTAPHID.CBOR, frame)
            except CtapError:
                # Authenticator returned a non-zero status; that's a real
                # CTAP-level error, not a transport problem. Re-raise so the
                # caller forwards the actual code.
                raise
            except Exception as exc:
                LOG.warning("device.call transport failure (%r); re-opening", exc)
                self._force_reopen()
                dev = self._ensure_open()
                return dev.call(CTAPHID.CBOR, frame)


def serve_one(client: socket.socket, addr: tuple, devices: DeviceManager) -> None:
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
                LOG.info("%s -> ctap2_cmd=0x%02x len=%d", peer, ctap2_cmd, len(frame))
                try:
                    response = devices.call_cbor(frame)
                except CtapError as exc:
                    # Authenticator-level error — forward the real status
                    # byte so the extension/RP sees what the device said
                    # (e.g., 0x2E = NO_CREDENTIALS, 0x36 = USER_ACTION_TIMEOUT).
                    response = bytes([exc.code])
                    LOG.warning("%s ctap error 0x%02x: %s", peer, exc.code, exc)
                except Exception as exc:
                    LOG.error("%s device.call hard failure: %r", peer, exc)
                    response = bytes([CTAP_ERR_OTHER])
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

    devices = DeviceManager()
    # Open eagerly so the user sees the YubiKey is detected at startup.
    devices._ensure_open()  # noqa: SLF001 — internal use, fine here

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
                target=serve_one, args=(client, addr, devices), daemon=True
            ).start()
    except KeyboardInterrupt:
        LOG.info("shutting down")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
