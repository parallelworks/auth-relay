"""Workspace-side test client for the YubiKey relay (iter 2).

Wraps the relay socket in a python-fido2 CtapDevice so we can drive the
remote YubiKey through the same `Ctap2(...)` API used against a local USB
device. Runs only no-touch operations (authenticatorGetInfo) so the script
can be used for latency / routing validation without prompting the user.

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
from common.protocol import recv_frame, send_frame

from fido2.ctap import CtapDevice
from fido2.ctap2 import Ctap2
from fido2.hid import CAPABILITY, CTAPHID


class SocketCtapDevice(CtapDevice):
    """A CtapDevice that forwards CTAPHID CBOR calls over a TCP relay socket.

    The relay agent on the laptop terminates this socket and replays each
    incoming frame against a real YubiKey via libfido2's HID transport.
    Wire payload semantics match the agent's: <ctap2_cmd byte> || <CBOR>.
    """

    def __init__(self, sock: socket.socket):
        self._sock = sock

    @property
    def capabilities(self) -> int:
        return CAPABILITY.CBOR

    def call(self, cmd: int, data: bytes = b"", event=None, on_keepalive=None) -> bytes:
        if cmd != CTAPHID.CBOR:
            raise NotImplementedError(
                f"relay only carries CTAPHID.CBOR; refusing cmd=0x{cmd:02x}"
            )
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


def run(host: str, port: int) -> int:
    print(f"connecting to {host}:{port} ...", flush=True)
    with socket.create_connection((host, port), timeout=10) as sock:
        print(f"connected (local={sock.getsockname()} peer={sock.getpeername()})")
        device = SocketCtapDevice(sock)
        ctap2 = Ctap2(device)

        info = ctap2.info
        print(f"[info]            aaguid={info.aaguid.hex()}")
        print(f"[info]            versions={info.versions}")
        print(f"[info]            extensions={info.extensions}")
        print(f"[info]            transports={info.transports}")
        print(f"[info]            options={info.options}")

        timings: list[float] = []
        for i in range(20):
            t0 = time.perf_counter()
            ctap2.get_info()
            timings.append((time.perf_counter() - t0) * 1000.0)
        timings.sort()
        median = timings[len(timings) // 2]
        p95 = timings[int(len(timings) * 0.95)]
        print(
            f"[get_info x20]    min={timings[0]:.1f}  median={median:.1f}  "
            f"p95={p95:.1f}  max={timings[-1]:.1f}  ms"
        )

    print("OK — relay carries real CTAP2 end-to-end (no touch required)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="workspace-side relay test client (iter 2)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7777)
    args = parser.parse_args(argv)
    return run(args.host, args.port)


if __name__ == "__main__":
    raise SystemExit(main())
