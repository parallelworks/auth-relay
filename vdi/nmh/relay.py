"""Thin native-messaging host: Chrome extension ↔ YubiKey relay agent (iter 3).

Chrome's native messaging protocol:
  - stdin/stdout, length-prefixed messages
  - 4-byte length in native byte order (little-endian on x86)
  - body is UTF-8 JSON
  - max 1 MB per message

Wire to relay agent:
  - 4-byte big-endian length
  - body is raw CTAPHID CBOR frame (ctap2_cmd + CBOR), same as iter 2

This NMH base64-decodes a `frame` field from the extension's JSON, sends
it as a single relay frame, reads one response frame, base64-encodes,
returns. One TCP connection per NMH lifetime (Chrome respawns the NMH
process per connectNative() call from the extension, so the lifetime
matches the extension session).

Errors are surfaced as {"error": "...", "context": "..."} JSON.

Log lines go to stderr (visible in `chrome://extensions/?id=<id>` developer
tools after enabling "Collect errors", or via tail -f on a log file if
the NMH is started by the launcher with stderr redirected).
"""

from __future__ import annotations

import base64
import json
import os
import socket
import struct
import sys
import traceback
from typing import Any

RELAY_HOST = os.environ.get("PW_RELAY_HOST", "127.0.0.1")
RELAY_FRAME_MAX = 1 << 20

# A pwrelay session may end up on a non-default port if 7777 was taken by
# leftover pw-agent forward state from a prior session (see iter-6 notes
# in README). Pwrelay drops the chosen port into this file when it brings
# the tunnel up. NMH reads it on each frame so reconnects always pick
# the live port, even if it changed between Chrome's NMH spawns.
_PORT_HINT_FILE = f"/tmp/pw-relay-port-{os.environ.get('USER', 'user')}"


def _read_port_hint() -> int:
    try:
        with open(_PORT_HINT_FILE) as f:
            return int(f.read().strip())
    except Exception:
        return int(os.environ.get("PW_RELAY_PORT", "7777"))


# Read-deadline for relay socket. Touch ceremonies can legitimately take
# 30+ seconds (user has to physically touch the key), so we set this
# above that bound. If we hit it, the tunnel is almost certainly broken;
# we surface a clean error to Chrome instead of hanging the WebAuthn
# request forever (today's "request already pending" trap).
RECV_TIMEOUT_S = float(os.environ.get("PW_RELAY_RECV_TIMEOUT", "90"))


def log(msg: str) -> None:
    sys.stderr.write(f"[pw-nmh] {msg}\n")
    sys.stderr.flush()


def read_chrome_message() -> dict[str, Any] | None:
    raw_len = sys.stdin.buffer.read(4)
    if len(raw_len) == 0:
        return None
    if len(raw_len) != 4:
        raise IOError(f"truncated length header: {len(raw_len)} bytes")
    (n,) = struct.unpack("=I", raw_len)
    if n > 1_000_000:
        raise ValueError(f"chrome message too large: {n}")
    body = sys.stdin.buffer.read(n)
    if len(body) != n:
        raise IOError(f"truncated chrome body: {len(body)}/{n}")
    return json.loads(body.decode("utf-8"))


def write_chrome_message(obj: dict[str, Any]) -> None:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("=I", len(body)))
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("relay socket closed mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def relay_call(sock: socket.socket, frame: bytes) -> bytes:
    if len(frame) > RELAY_FRAME_MAX:
        raise ValueError(f"frame too large: {len(frame)}")
    sock.sendall(struct.pack(">I", len(frame)) + frame)
    (resp_len,) = struct.unpack(">I", _recv_exact(sock, 4))
    if resp_len > RELAY_FRAME_MAX:
        raise ValueError(f"oversized response: {resp_len}")
    return _recv_exact(sock, resp_len) if resp_len > 0 else b""


def main() -> int:
    port = _read_port_hint()
    log(f"starting; relay={RELAY_HOST}:{port}  recv_timeout={RECV_TIMEOUT_S:.0f}s")
    sock: socket.socket | None = None
    try:
        while True:
            try:
                req = read_chrome_message()
            except Exception as e:
                log(f"failed to read chrome message: {e!r}")
                return 1
            if req is None:
                log("stdin closed; exiting")
                return 0

            req_id = req.get("id")
            kind = req.get("type", "frame")
            try:
                if kind == "ping":
                    # Cheap health check the extension can fire on connect.
                    write_chrome_message({"id": req_id, "ok": True, "type": "pong"})
                    continue
                if kind != "frame":
                    raise ValueError(f"unknown type: {kind!r}")

                # If the extension included a 'webauthn' field, we forward
                # the WHOLE request as a JSON envelope so the laptop agent
                # (on Windows) can hand the high-level options to
                # WindowsClient instead of doing raw HID. Linux/macOS
                # agents will respond with an error if they receive a JSON
                # envelope; on those platforms the extension's CTAP2
                # frame is sufficient and the agent uses that path.
                webauthn = req.get("webauthn")
                if webauthn:
                    # Pass through as JSON bytes; the agent's first-byte
                    # dispatch ('{' == 0x7B) routes to its JSON handler.
                    envelope = json.dumps({
                        "id": req_id,
                        "type": "frame",
                        "webauthn": webauthn,
                    }).encode("utf-8")
                    if sock is None:
                        port = _read_port_hint()
                        sock = socket.create_connection((RELAY_HOST, port), timeout=10)
                        sock.settimeout(RECV_TIMEOUT_S)
                        log(f"connected to relay (local={sock.getsockname()} port={port})")
                    resp_bytes = relay_call(sock, envelope)
                    # Response is JSON bytes too.
                    try:
                        resp_obj = json.loads(resp_bytes.decode("utf-8"))
                    except Exception as e:
                        raise ValueError(f"bad JSON response from agent: {e}; raw={resp_bytes[:200]!r}")
                    # Forward verbatim — the extension knows how to
                    # consume {ok, webauthn} or {ok, error}.
                    resp_obj.setdefault("id", req_id)
                    write_chrome_message(resp_obj)
                    continue

                # Legacy CTAP2 path (Linux/macOS laptop):
                frame_b64 = req.get("frame")
                if not isinstance(frame_b64, str):
                    raise ValueError("frame must be a base64 string")
                # The JS side produces unpadded base64url; python's decoder
                # is strict about padding, so re-pad before decoding.
                padded = frame_b64 + "=" * (-len(frame_b64) % 4)
                frame = base64.urlsafe_b64decode(padded)
                if sock is None:
                    # Re-read the port hint on each (re)connect so a pwrelay
                    # session that switched ports mid-life is picked up
                    # transparently.
                    port = _read_port_hint()
                    sock = socket.create_connection((RELAY_HOST, port), timeout=10)
                    sock.settimeout(RECV_TIMEOUT_S)
                    log(f"connected to relay (local={sock.getsockname()} port={port})")
                resp = relay_call(sock, frame)
                write_chrome_message({"id": req_id, "ok": True, "frame": base64.b64encode(resp).decode("ascii")})
            except Exception as e:
                tb = traceback.format_exc()
                log(f"request {req_id} failed: {e!r}\n{tb}")
                write_chrome_message({"id": req_id, "ok": False, "error": str(e)})
                # Reset socket on failure so next request reconnects.
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass
                    sock = None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


if __name__ == "__main__":
    sys.exit(main())
