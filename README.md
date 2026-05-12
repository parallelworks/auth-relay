# NOAA YubiKey Relay — iteration 1

POC of a userspace relay that lets a YubiKey plugged into a user's laptop
service WebAuthn / FIDO2 requests originating on a remote PW ACTIVATE
session, without USB forwarding, kernel modules, or root anywhere.

This iteration proves the **pipe**: a TCP relay through a `pw ssh -R`
reverse tunnel between a "laptop" (gpu.parallel.works) and the PW
`workspace`, carrying a small JSON op protocol against a **synthetic**
authenticator backend. Real YubiKey integration is iteration 2.

## Layout

```
common/protocol.py         length-prefixed JSON framing (used by both ends)
laptop/agent.py            laptop-side TCP server, synthetic FIDO backend
workspace/client.py        workspace-side client (uses common/)
workspace/standalone_test.py   self-contained client for scp-less deploy
```

## Where each piece runs

| Component | Lives on | Why |
|---|---|---|
| `laptop/agent.py` | The user's actual laptop (Mac, Linux, or Windows) | This is where the YubiKey physically plugs in |
| `pw ssh -R` tunnel | Initiated from the laptop | The laptop is the side with the credentials and the auth context |
| `workspace/...` (or eventually login-node relay + compute-node browser) | PW workspace / NOAA login + compute node | The "remote" side that needs WebAuthn but lacks USB |

The `/home/mattshax/noaa-yubikey-auth/` copy on gpu.parallel.works is the development
mirror; the deployable copy of the agent lives on the user's Mac. See "macOS setup" below.

## macOS setup (run once on the Mac that will hold the YubiKey)

```bash
# 1. copy the project from gpu.parallel.works to the Mac
rsync -av --exclude='__pycache__' \
  mattshax@gpu.parallel.works:noaa-yubikey-auth/ \
  ~/noaa-yubikey-auth/

# 2. install prerequisites
cd ~/noaa-yubikey-auth
bash setup-mac.sh

# 3. ensure pw CLI is authenticated and the SSH key is there
pw auth login            # if not already logged in
ls -la ~/.ssh/pwcli      # should exist; if not, pw auth re-issues it
```

After setup, the Test B steps below run unchanged — just from the Mac instead of
gpu.parallel.works. The agent binds to `127.0.0.1` either way; only the originating side
of the `pw ssh -R` tunnel changes.

## Architectural invariant: the pw tunnel is the only path

The agent binds to **`127.0.0.1` only** — it is not reachable from any
network. The only sanctioned route from a PW ACTIVATE session to the
agent is the authenticated `pw ssh -R` reverse tunnel. This is enforced
in code (no `--host` flag), not by convention. Every test below — and
every iteration going forward — uses the tunnel, including when both
ends happen to live on the same physical box.

## Run it (single-host code-correctness check)

Both ends on the laptop. The "client" and "agent" still talk over
loopback, which is the same boundary the tunnel terminates on, so this
isn't a different deployment mode — just a way to validate the code
without involving the workspace.

```bash
python3 laptop/agent.py --port 17777 &
python3 workspace/client.py --port 17777
```

## Run it (end-to-end through pw ssh -R)

On the laptop:

```bash
python3 laptop/agent.py --host 127.0.0.1 --port 7777 &

# push standalone client to workspace (one-time):
B64=$(base64 -w0 workspace/standalone_test.py)
pw ssh workspace "mkdir -p ~/noaa-yubikey-auth && echo $B64 | base64 -d > ~/noaa-yubikey-auth/standalone_test.py"

# open reverse tunnel + run the workspace client:
ssh -i ~/.ssh/pwcli \
    -o ProxyCommand="pw ssh --proxy-command %h" \
    -R 7777:127.0.0.1:7777 \
    Matthew.Shaxted@workspace \
    'python3 ~/noaa-yubikey-auth/standalone_test.py'
```

## What iteration 1 demonstrated

- pw CLI's reverse port forwarding (via `pw ssh --proxy-command`) carries
  arbitrary TCP cleanly between a laptop and an ACTIVATE workspace.
- Median round-trip on the relay: **~41 ms** (min 38, p95 298, max 298).
  Plenty of headroom against the seconds-scale human button-press cost of
  any real WebAuthn ceremony.
- The agent/client pattern slots cleanly into the eventual production
  architecture: agent on the user's laptop, browser extension + native
  messaging host on the VNC compute node, login-node relay forwarding
  between them.

## Iteration 2 (next)

1. Swap `laptop/agent.py`'s synthetic handlers for **python-fido2**
   (Yubico, wraps libfido2). `make_credential` / `get_assertion` route
   to a real YubiKey on the laptop; user physically touches the key
   when prompted.
2. Replace the JSON op envelope with **CTAP2 CBOR** pass-through so the
   wire format matches what a browser extension / native messaging host
   actually wants to forward. JSON envelope is fine for debugging but
   real CTAP2 is binary CBOR.
3. Add a tiny Chrome/Firefox **WebAuthn-intercepting extension** plus a
   **native messaging host** on the workspace side that connects to the
   relay. End-to-end target: log into accounts.google.com from a browser
   on the workspace using the YubiKey that lives on the laptop.

## Iteration 3 (full topology)

Same architecture, but the relay terminates on a **login node** (RHEL,
same `libfido2` availability as the workspace) and the browser runs on
a **VNC compute node**. The compute node reaches the login-node relay
via an internal `ssh -L` from the desktop launcher script. This is the
target topology for NOAA HPC; nothing on compute nodes, one userspace
binary on login nodes (the install ask).

## Constraints honored

- No root on either end.
- No kernel modules, no `uinput`, no `pcscd`, no system daemons.
- Single TCP port forwarded through the PW platform's existing auth
  channel — no new firewall holes.
