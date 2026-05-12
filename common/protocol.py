"""Length-prefixed byte-frame framing for the YubiKey relay (iter 2).

Wire format: 4-byte big-endian length, then `length` bytes of payload.

The payload is opaque to the framing layer. In iter 2 the payload is a raw
CTAPHID CBOR frame body — i.e., a CTAP2 command byte followed by CBOR-encoded
arguments on the request side, and a CTAP2 status byte followed by a
CBOR-encoded response on the reply side. The relay agent pipes these bytes
straight through to the YubiKey's HID transport via python-fido2.
"""

from __future__ import annotations

import socket
import struct

MAX_FRAME_BYTES = 1 << 20


def send_frame(sock: socket.socket, payload: bytes) -> None:
    if len(payload) > MAX_FRAME_BYTES:
        raise ValueError(f"frame too large: {len(payload)} bytes")
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def recv_frame(sock: socket.socket) -> bytes | None:
    header = _recv_exact(sock, 4)
    if header is None:
        return None
    (length,) = struct.unpack(">I", header)
    if length > MAX_FRAME_BYTES:
        raise ValueError(f"invalid frame length: {length}")
    if length == 0:
        return b""
    body = _recv_exact(sock, length)
    if body is None:
        raise ConnectionError("peer closed mid-frame")
    return body


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
