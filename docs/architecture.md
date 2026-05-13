# Architecture

## 60-second mental model

```
┌────────────────────────────┐                ┌─────────────────────────────┐
│ Your laptop                │                │ Cluster login / desktop node│
│                            │                │                             │
│   YubiKey (USB)            │                │   Chrome + this extension   │
│      │                     │                │      │                      │
│  pwrelay agent             │  pw ssh -R     │      │                      │
│  127.0.0.1:7777   ◀────────┼───tunnel───────┼─▶  127.0.0.1:7777           │
│                            │                │      │                      │
│                            │                │   Native messaging host     │
└────────────────────────────┘                └─────────────────────────────┘
```

The extension intercepts `navigator.credentials.create()` and `.get()`
calls in the in-VDI Chrome and forwards each CTAP2 ceremony as raw
bytes through the relay to your laptop's security key. You touch the
key on your desk; the assertion comes back; the page authenticates.

## What's on the wire

The reverse-tunnel payload is **length-prefixed raw CTAPHID CBOR frames**:

- Request: `<CTAP2 command byte> || <CBOR-encoded args>`
  - cmd 0x01 = `authenticatorMakeCredential`
  - cmd 0x02 = `authenticatorGetAssertion`
  - cmd 0x04 = `authenticatorGetInfo` (no-touch, used for routing checks)
- Response: `<status byte> || <CBOR-encoded response>`

The laptop agent forwards each frame straight to the USB device via
`fido2.hid.CtapHidDevice.call(CTAPHID.CBOR, ...)`. Touch latency on the
YubiKey (~3 s) dominates everything else; relay overhead is ≈25 ms median
on a cloud cluster, ≈100 ms on cross-WAN NOAA on-prem.

## Components

```
pwrelay                  laptop CLI: setup / up / down / status / doctor / reset
laptop/agent.py          laptop-side TCP server, python-fido2 backend
common/protocol.py       length-prefixed byte-frame framing
workspace/               iter-1/2 test scripts for routing/timing checks (no browser)
vdi/
  install-chrome.sh      portable Chrome installer (no root, extracts RPM)
  bootstrap.sh           VDI-side one-shot setup (NMH manifest, desktop icon,
                         bookmarks, http.server for the test page)
  install-extension.py   auto-installs the extension into Chrome via CDP
  bin/chrome             Chrome launcher; honors $PW_CHROME_BIN,
                         clamps stack ulimit, auto-detects VDI DISPLAY
  extension/             MV3 Chrome extension using chrome.webAuthenticationProxy
  nmh/relay.py           native-messaging host bridging Chrome ↔ relay socket
  test.html              local-RP test page (http://localhost:8080/test.html)
  bookmarks.json         default bookmark set seeded into Chrome on first launch
```

## Resilience

Behaviors that quietly keep things working without intervention:

- **Auto-reconnect tunnel.** Some clusters drop idle ssh sessions after
  about an hour. `pwrelay up` runs `ssh -R` in a supervisor loop that
  reconnects in 3 seconds.
- **Auto port-fallback.** If port 7777 on the cluster is held by a stale
  `pw-agent` forward cache, `pwrelay up` walks 7777 → 7784 until it finds
  a free one and drops the chosen port to a file the NMH reads.
- **NMH read timeout (90 s).** Long enough for a real touch ceremony;
  short enough that a dead tunnel surfaces in Chrome as a clean error
  rather than a wedged-forever request.
- **Session-marker shutdown.** Each `pwrelay up` tags its remote `sleep`
  keepalive with a unique session ID; `pwrelay down` asks the cluster to
  kill only that tag.
- **`pwrelay doctor`** / **`pwrelay reset`** for diagnostics + recovery.
  Never touches the `pw agent` itself.
- **HPC stack ulimit clamp.** Some clusters default `ulimit -s` to 1 GiB,
  which makes Chrome crash-loop. The wrapper clamps to 8 MiB.
- **VDI DISPLAY auto-detect.** `install-extension.py` and `vdi/bin/chrome`
  find the user's running `Xvnc`/`Xkasmvnc` via `ps` and set
  `DISPLAY`+`XAUTHORITY`. Lets `pw ssh resource '...'` from a laptop
  terminal pop Chrome into the user's existing VDI desktop.

## Constraints honored

- No root on either end.
- No kernel modules, no `uinput`, no `pcscd`, no system daemons.
- Single TCP port forwarded through PW's existing auth channel; no new
  firewall holes; agent binds loopback-only.
- Chrome extension is loaded from `$HOME` (or a shared install path) via
  the user's own session. No Web Store listing, no admin install, no
  enterprise policy required.

## Validated environments

| Where | Hostname | Latency (med) | WebAuthn ceremony |
|---|---|---|---|
| PW workspace | `pw-user-...-0` | 44 ms | ✓ |
| Google-cloud HPC cluster | `...-mgmt` | 26 ms | ✓ |
| NOAA on-prem `ursa` | `ufe02` | 85 ms | ✓ (no-touch path) |
| NOAA on-prem `gaeac5` | `gaea54` | 102 ms | ✓ — real Google sign-in |

## CAC / non-FIDO

Out of scope for what currently ships. The repo name `auth-relay` is
intentionally generic — a CAC/PIV (PKCS#11 + PC/SC) relay would slot in
as a peer module (e.g. `pcsc/` next to `vdi/`) sharing the same
`pwrelay` CLI and `pw ssh -R` tunnel pattern. See the bottom of
`HANDOFF.md` for the design sketch.
