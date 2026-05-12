"""Length-prefixed JSON message framing for the YubiKey relay.

Wire format: 4-byte big-endian length, then UTF-8 JSON payload.
Iteration 1 carries simple {op, ...} messages; iteration 2 will swap the
payload for raw CTAP2 CBOR once the pipe is proven to work end-to-end.
"""

from __future__ import annotations

import json
import socket
import struct
from typing import Any

MAX_MESSAGE_BYTES = 1 << 20


def send_message(sock: socket.socket, msg: dict[str, Any]) -> None:
    payload = json.dumps(msg, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_MESSAGE_BYTES:
        raise ValueError(f"message too large: {len(payload)} bytes")
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def recv_message(sock: socket.socket) -> dict[str, Any] | None:
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
