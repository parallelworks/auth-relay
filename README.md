# NOAA YubiKey Relay — iteration 2

Userspace relay that lets a YubiKey plugged into a user's laptop service real
WebAuthn / FIDO2 (CTAP2) requests originating on a remote PW ACTIVATE session,
without USB forwarding, kernel modules, or root anywhere.

Iter 2 carries **real CTAP2 traffic** through a `pw ssh -R` reverse tunnel
between a laptop and a PW session. Wire payload is the raw CTAPHID CBOR frame
body (CTAP2 cmd byte + CBOR), piped straight through python-fido2 to the
physical key. Real `make_credential` / `get_assertion` ceremonies complete
end-to-end with a physical touch on the laptop.

A browser inside the VDI consuming this relay (via a CDP virtual authenticator
harness) is iteration 3.

## Layout

```
common/protocol.py         length-prefixed byte-frame framing
laptop/agent.py            laptop-side TCP server, python-fido2 backend
workspace/client.py        workspace-side client, no-touch get_info loop for timing
workspace/standalone_test.py   self-contained no-touch smoke test
workspace/test_real.py     self-contained real-ceremony test (make_credential + get_assertion)
```

## Where each piece runs

| Component | Lives on | Why |
|---|---|---|
| `laptop/agent.py` | The user's actual laptop (Mac, Linux, or Windows) | Where the YubiKey physically plugs in |
| `pw ssh -R` tunnel | Initiated from the laptop | The laptop holds the credentials and the auth context |
| `workspace/...` (login node / mgmt node / eventually compute node) | PW workspace, cluster mgmt node, or VDI compute node | The side that needs WebAuthn but lacks USB |

## macOS setup (run once on the Mac that will hold the YubiKey)

```bash
# 1. clone or rsync this repo onto the Mac
# 2. install prerequisites
cd ~/auth-relay
bash setup-mac.sh

# 3. set up a venv with python-fido2 (PEP 668 means you can't pip --user on Homebrew Python)
python3 -m venv .venv
source .venv/bin/activate
pip install fido2

# 4. ensure pw CLI is authenticated and the SSH key is there
pw auth login            # if not already logged in
ls -la ~/.ssh/pwcli      # should exist; if not, pw auth re-issues it
```

## Architectural invariant: the pw tunnel is the only path

The agent binds to **`127.0.0.1` only** — it is not reachable from any
network. The only sanctioned route from a PW session to the agent is the
authenticated `pw ssh -R` reverse tunnel. Enforced in code (no `--host` flag),
not by convention.

## Run it (single-host code-correctness check)

Both ends on the laptop, loopback. Validates code without involving any
remote side.

```bash
source .venv/bin/activate
python3 laptop/agent.py --port 17777 &
python3 workspace/client.py --port 17777        # no touch required
python3 workspace/test_real.py --port 17777     # touches the key TWICE
```

## Run it (end-to-end through pw ssh -R)

On the workspace / cluster mgmt node, install python-fido2 once:

```bash
pw ssh <resource> 'python3.12 -m ensurepip --user && python3.12 -m pip install --user --upgrade fido2'
```

Then on the laptop:

```bash
source .venv/bin/activate
python3 laptop/agent.py --port 7777 &

# push the standalone tests to the resource (one-time):
B64=$(base64 < workspace/standalone_test.py | tr -d '\n')
pw ssh <resource> "mkdir -p ~/noaa-yubikey-auth && echo $B64 | base64 -d > ~/noaa-yubikey-auth/standalone_test.py"
B64=$(base64 < workspace/test_real.py | tr -d '\n')
pw ssh <resource> "echo $B64 | base64 -d > ~/noaa-yubikey-auth/test_real.py"

# open reverse tunnel + run the no-touch test:
ssh -i ~/.ssh/pwcli \
    -o ProxyCommand="pw ssh --proxy-command %h" \
    -R 7777:127.0.0.1:7777 \
    Matthew.Shaxted@<resource> \
    'python3.12 ~/noaa-yubikey-auth/standalone_test.py'

# then the real ceremony (touch the key twice when prompted):
ssh -i ~/.ssh/pwcli \
    -o ProxyCommand="pw ssh --proxy-command %h" \
    -R 7777:127.0.0.1:7777 \
    Matthew.Shaxted@<resource> \
    'python3.12 -u ~/noaa-yubikey-auth/test_real.py'
```

`<resource>` can be `workspace`, a cluster URI like `gclusternoaav3`, or any
PW resource you have shell access to.

## What iteration 1 demonstrated

- `pw ssh -R` carries arbitrary TCP cleanly between a laptop and a PW
  workspace.
- Median round-trip on the synthetic JSON-op relay: **~41 ms**.
- The agent/client pattern slots into the production architecture: agent on
  the user's laptop, relay socket terminating on a remote node, eventual
  browser + CDP harness on a VDI compute node.

## What iteration 2 demonstrates (this iteration)

- Real CTAP2 over the wire — payload is raw `<ctap2_cmd>||<CBOR>` frames,
  no JSON envelope, no re-encoding. The relay is byte-transparent to
  python-fido2.
- Real `authenticatorMakeCredential` and `authenticatorGetAssertion`
  ceremonies complete end-to-end: laptop YubiKey blinks on demand from a
  remote PW resource, user touches, real ECDSA signature returns.
- Measured against the NOAA `gclusternoaav3` cluster mgmt node (which is
  also the host that runs KasmVNC inside a Singularity container, sharing
  the host network namespace — so the same loopback path is reachable
  from inside the VDI):
  - `get_info` round-trip: min 31.9, **median 35.9**, p95 60.6 ms
    (≈12 ms USB-HID + ≈24 ms cluster-to-laptop network).
  - `make_credential` wallclock: 4029.9 ms (≈3700 ms physical touch
    latency dominates; network overhead 21 ms).
  - `get_assertion` wallclock: 403.8 ms.
- Real attestation: 1054-byte CBOR, AAGUID `c1f9a0bc1dd2404ab27f8e29047a43fd`,
  fmt `packed`, signCount increments per ceremony.

## Iteration 3 (next)

Wire iter 2's relay to a real browser running in a NOAA ACTIVATE VDI
desktop. Recommended approach: **CDP virtual authenticator** on a
Chromium launched with `--remote-debugging-port`. A small Python harness
inside the VDI calls `WebAuthn.addVirtualAuthenticator` and forwards each
CTAP2 command into the relay socket on `127.0.0.1`. Because the KasmVNC
container shares the host network namespace, the relay socket established
by the user's `pw ssh -R` is already on the same loopback.

UX cost: users launch Google via a "PW-managed Chromium" wrapper, not
their normal browser icon. This is the price of doing this purely in
userspace (no `uinput` on compute nodes).

The alternative (`uinput` virtual HID) is cleaner UX but needs root on
compute nodes, which we don't have on NOAA HPC. Disqualified.

## Constraints honored

- No root on either end.
- No kernel modules, no `uinput`, no `pcscd`, no system daemons.
- Single TCP port forwarded through the PW platform's existing auth
  channel — no new firewall holes.
- The agent binds loopback-only; the pw tunnel is the only sanctioned
  network path.
