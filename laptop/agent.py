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
import platform
import socket
import sys
import threading
import time
from pathlib import Path

# Make laptop/windows_backend importable when this script is invoked directly.
sys.path.insert(0, str(Path(__file__).resolve().parent))

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


IS_WIN = platform.system() == "Windows"


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

                # Dispatch by first byte: '{' (0x7B) -> JSON envelope (used
                # by the Windows non-admin path, which needs WebAuthn-level
                # options not just a CTAP2 frame). Anything else -> raw
                # CTAP2 (Linux/macOS, the existing path).
                if frame[0] == 0x7B:  # '{'
                    response = _serve_json(frame, peer, devices)
                else:
                    response = _serve_raw(frame, devices, peer)
                send_frame(client, response)
    except (ConnectionError, OSError) as exc:
        LOG.warning("%s aborted: %s", peer, exc)


def _serve_raw(frame: bytes, devices: DeviceManager, peer: str) -> bytes:
    """Existing path: forward a CTAP2 CBOR frame to a local HID YubiKey."""
    ctap2_cmd = frame[0]
    t0 = time.perf_counter()
    LOG.info("%s -> ctap2_cmd=0x%02x len=%d", peer, ctap2_cmd, len(frame))
    try:
        response = devices.call_cbor(frame)
    except CtapError as exc:
        response = bytes([exc.code])
        LOG.warning("%s ctap error 0x%02x: %s", peer, exc.code, exc)
    except Exception as exc:
        LOG.error("%s device.call hard failure: %r", peer, exc)
        response = bytes([CTAP_ERR_OTHER])
    dt_ms = (time.perf_counter() - t0) * 1000.0
    status = response[0] if response else 0xFF
    LOG.info("%s <- status=0x%02x len=%d dt=%.1fms", peer, status, len(response), dt_ms)
    return response


def _serve_json(frame: bytes, peer: str, devices: DeviceManager) -> bytes:
    """Handle a JSON envelope.

    The extension always sends both an embedded CTAP2 'frame' (used on
    Linux/macOS where we forward to a HID YubiKey) AND a 'webauthn'
    block of WebAuthn-level options (used on Windows where webauthn.dll
    has the HID reserved). The agent picks based on its own platform.

    Response wire is also JSON. Linux/macOS returns
        {ok, frame: "<b64 ctap2 response>"}
    Windows returns
        {ok, webauthn: <PublicKeyCredential JSON>}
    The NMH forwards the response verbatim to the extension, which knows
    how to consume either shape.
    """
    import base64 as _b64
    import json as _json
    t0 = time.perf_counter()
    try:
        req = _json.loads(frame.decode("utf-8"))
    except Exception as exc:
        LOG.error("%s bad JSON envelope: %r", peer, exc)
        return _json.dumps({"ok": False, "error": f"bad JSON: {exc}"}).encode()

    req_id = req.get("id")

    if IS_WIN:
        op = (req.get("webauthn") or {}).get("op", "?")
        LOG.info("%s -> webauthn op=%s (Windows path)", peer, op)
        from windows_backend import handle_webauthn
        out = handle_webauthn(req)
        dt_ms = (time.perf_counter() - t0) * 1000.0
        LOG.info("%s <- webauthn ok=%s dt=%.1fms", peer, out.get("ok"), dt_ms)
        return _json.dumps(out).encode()

    # Linux/macOS: pull the embedded CTAP2 frame and forward to HID.
    frame_b64 = req.get("frame")
    if not frame_b64:
        return _json.dumps({"id": req_id, "ok": False,
            "error": "envelope has no 'frame' field; agent is not Windows"}).encode()
    padded = frame_b64 + "=" * (-len(frame_b64) % 4)
    ctap2 = _b64.urlsafe_b64decode(padded.replace("-", "+").replace("_", "/"))
    resp = _serve_raw(ctap2, devices, peer)
    return _json.dumps({
        "id": req_id, "ok": True,
        "frame": _b64.b64encode(resp).decode("ascii"),
    }).encode()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="laptop-side YubiKey relay agent (loopback-only; reach it via pw ssh -R)",
    )
    parser.add_argument("--port", type=int, default=7777)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

    devices = DeviceManager()
    # On Linux/macOS, open eagerly so the user sees the YubiKey is
    # detected at startup. On Windows we deliberately skip this — the
    # raw HID open requires admin (webauthn.dll has the device
    # reserved), and we serve everything via the JSON-envelope path
    # which calls fido2.client.WindowsClient instead.
    if not IS_WIN:
        devices._ensure_open()  # noqa: SLF001 — internal use, fine here
    else:
        LOG.info("Windows detected — skipping HID open; using WindowsClient backend")

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
