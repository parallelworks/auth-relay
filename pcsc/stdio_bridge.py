#!/usr/bin/env python3
"""Minimal stdio<->TCP bridge for p11-kit-client's `remote:` field.

p11-kit-client.so spawns the configured `remote:` command and speaks its
binary PKCS#11 RPC protocol over the spawned process's stdin/stdout. The
laptop side ships a TCP listener (socat -> Unix socket -> p11-kit-server),
so the bridge command's job is just:

    stdin  -> TCP socket send
    socket -> stdout

Why not ncat? In practice ncat's --no-shutdown + binary stdio behavior
hasn't yielded a working p11-kit slot enumeration on Rocky 9.6 even
though raw TCP connectivity is fine. This bridge gives us full control
over buffering and half-close semantics: bytes flow as-is, both
directions, until either end closes.

Usage:
    python3 stdio_bridge.py <host> <port>

Exits with the socket's exit reason (peer EOF -> 0). Never line-buffers.
"""

from __future__ import annotations

import os
import select
import socket
import sys
import time


def _open_debug_log() -> "object | None":
    """Open a debug log file if PWRELAY_BRIDGE_DEBUG is set.

    The env var should point at a file path. Each chunk that flows
    through the bridge is logged with a timestamp, direction, byte
    count, and a hex preview of the first 32 bytes — enough to see
    which RPC message the p11-kit RPC dance is on and whether it was
    truncated. Multiple bridge spawns append to the same file
    (line-buffered) so a single chrome sign attempt's full byte flow
    is visible in one place.
    """
    path = os.environ.get("PWRELAY_BRIDGE_DEBUG")
    if not path:
        return None
    try:
        return open(path, "ab", buffering=0)
    except OSError as e:
        print(f"stdio_bridge: couldn't open debug log {path}: {e}",
              file=sys.stderr)
        return None


def _dlog(f: "object | None", direction: str, buf: bytes) -> None:
    if f is None:
        return
    head = buf[:32].hex()
    line = f"{time.time():.3f} pid={os.getpid()} {direction} bytes={len(buf)} head={head}\n"
    try:
        f.write(line.encode())
    except OSError:
        pass


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: stdio_bridge.py <host> <port>", file=sys.stderr)
        return 2
    host = sys.argv[1]
    port = int(sys.argv[2])

    sock = socket.create_connection((host, port))
    sock.setblocking(False)

    stdin_fd = sys.stdin.buffer.fileno()
    stdout_fd = sys.stdout.buffer.fileno()
    sock_fd = sock.fileno()

    os.set_blocking(stdin_fd, False)
    os.set_blocking(stdout_fd, False)

    dlog = _open_debug_log()
    _dlog(dlog, "open",
          f"connect_to={host}:{port}".encode())

    stdin_open = True
    sock_open = True

    while stdin_open or sock_open:
        rlist = []
        if stdin_open: rlist.append(stdin_fd)
        if sock_open:  rlist.append(sock_fd)
        if not rlist:
            break
        try:
            r, _, _ = select.select(rlist, [], [], 30.0)
        except InterruptedError:
            continue

        if stdin_fd in r:
            try:
                buf = os.read(stdin_fd, 65536)
            except (BlockingIOError, InterruptedError):
                # Spurious wakeup or interrupted syscall — NOT EOF.
                # Treating this as EOF was an iter46 bug that caused
                # the socket's send side to be half-closed mid-RPC,
                # truncating long signing responses and yielding
                # ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED in Chrome.
                buf = None
            if buf is None:
                pass  # retry on next select iteration
            elif buf == b"":
                # Real EOF on stdin — half-close the socket's send side.
                # Don't close recv; p11-kit-server may still drain.
                _dlog(dlog, "stdin_eof", b"")
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                stdin_open = False
            else:
                _dlog(dlog, "stdin->sock", buf)
                _write_all(sock_fd, buf, is_socket=True, sock=sock)

        if sock_fd in r:
            try:
                buf = sock.recv(65536)
            except (BlockingIOError, InterruptedError):
                buf = None
            if buf is None:
                pass  # retry on next select iteration
            elif buf == b"":
                _dlog(dlog, "sock_eof", b"")
                sock_open = False
            else:
                _dlog(dlog, "sock->stdout", buf)
                _write_all(stdout_fd, buf, is_socket=False)

    try: sock.close()
    except OSError: pass
    return 0


def _write_all(fd_or_none: int, data: bytes, is_socket: bool,
                sock: "socket.socket | None" = None) -> None:
    view = memoryview(data)
    while view:
        try:
            if is_socket and sock is not None:
                n = sock.send(view)
            else:
                n = os.write(fd_or_none, view)
        except BlockingIOError:
            # Spin-wait briefly; for our throughput a select+retry would
            # be cleaner but stdio writes are tiny and rarely block.
            continue
        except (BrokenPipeError, OSError):
            return
        view = view[n:]


if __name__ == "__main__":
    sys.exit(main())
