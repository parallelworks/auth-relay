"""Workspace-side real-ceremony test (iter 2): make_credential + get_assertion.

Standalone (vendors the framing inline) so it can be scp'd or piped to the
workspace as a single file. Requires python-fido2 on the workspace
(pip install --user fido2).

What it does, end-to-end:

  1. Connect to the relay socket (which terminates at the laptop agent via
     pw ssh -R).
  2. authenticatorGetInfo — read real metadata from the laptop's YubiKey.
  3. authenticatorMakeCredential against rp_id=demo.parallel.works.
     -> The laptop YubiKey blinks. Touch it within ~30s.
  4. authenticatorGetAssertion using the credential just minted.
     -> Blinks again. Touch it.

The rp_id is intentionally a test value, not accounts.google.com — wiring a
real-RP ceremony to a browser is iter 3 (CDP virtual authenticator).
"""

from __future__ import annotations

import argparse
import os
import socket
import struct
import sys
import time

from fido2.ctap import CtapDevice
from fido2.ctap2 import Ctap2
from fido2.cose import ES256
from fido2.hid import CAPABILITY, CTAPHID

MAX_FRAME_BYTES = 1 << 20

DEMO_RP = {"id": "demo.parallel.works", "name": "PW YubiKey Relay Demo"}
DEMO_USER = {
    "id": b"\x01" * 16,
    "name": "demo@parallel.works",
    "displayName": "Demo User",
}
ES256_PARAM = {"type": "public-key", "alg": ES256.ALGORITHM}


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


class SocketCtapDevice(CtapDevice):
    def __init__(self, sock: socket.socket):
        self._sock = sock

    @property
    def capabilities(self) -> int:
        return CAPABILITY.CBOR

    def call(self, cmd: int, data: bytes = b"", event=None, on_keepalive=None) -> bytes:
        if cmd != CTAPHID.CBOR:
            raise NotImplementedError(f"relay only carries CTAPHID.CBOR; got 0x{cmd:02x}")
        send_frame(self._sock, data)
        resp = recv_frame(self._sock)
        if resp is None:
            raise ConnectionError("agent closed before replying")
        return resp

    def close(self) -> None:
        self._sock.close()

    @classmethod
    def list_devices(cls):
        return []


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=7777)
    args = ap.parse_args()

    print(f"[workspace] hostname={socket.gethostname()} connecting to {args.host}:{args.port}")
    # No socket timeout on read — make_credential blocks on the user's physical touch
    # at the laptop, which can take many seconds.
    with socket.create_connection((args.host, args.port), timeout=10) as sock:
        sock.settimeout(None)
        print(f"[workspace] connected (local={sock.getsockname()} peer={sock.getpeername()})")
        device = SocketCtapDevice(sock)
        ctap2 = Ctap2(device)

        info = ctap2.info
        print(f"[info]            aaguid={info.aaguid.hex()}")
        print(f"[info]            versions={info.versions}")

        client_data_hash_mc = os.urandom(32)
        print("[make_credential] sending request — TOUCH YOUR YUBIKEY on the laptop now")
        t0 = time.perf_counter()
        att = ctap2.make_credential(
            client_data_hash_mc,
            DEMO_RP,
            DEMO_USER,
            [ES256_PARAM],
        )
        dt = (time.perf_counter() - t0) * 1000.0
        cred_data = att.auth_data.credential_data
        cred_id = cred_data.credential_id
        print(f"[make_credential] {dt:7.1f} ms  (includes physical touch latency)")
        print(f"[make_credential] credential_id ({len(cred_id)} bytes): {cred_id.hex()}")
        print(f"[make_credential] aaguid: {cred_data.aaguid.hex()}")
        print(f"[make_credential] fmt: {att.fmt}")

        client_data_hash_ga = os.urandom(32)
        print("[get_assertion]   sending request — TOUCH YOUR YUBIKEY again")
        t0 = time.perf_counter()
        assertion = ctap2.get_assertion(
            DEMO_RP["id"],
            client_data_hash_ga,
            [{"type": "public-key", "id": cred_id}],
        )
        dt = (time.perf_counter() - t0) * 1000.0
        print(f"[get_assertion]   {dt:7.1f} ms")
        print(f"[get_assertion]   signature ({len(assertion.signature)} bytes): {assertion.signature.hex()[:64]}...")
        print(f"[get_assertion]   signCount: {assertion.auth_data.counter}")

    print("[workspace] OK — real CTAP2 ceremony completed through pw ssh -R relay")
    return 0


if __name__ == "__main__":
    sys.exit(main())
