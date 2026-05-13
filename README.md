# NOAA YubiKey Relay

Use the YubiKey plugged into your **laptop** to complete WebAuthn / FIDO2
prompts (Google MFA, GitHub, anything that uses `navigator.credentials`)
inside a Parallel Works ACTIVATE **remote desktop** session — without USB
forwarding, kernel modules, browser plugins from a store, or root anywhere.

No raw USB. No `uinput`. No `pcscd`. No system daemons. The whole thing is
$HOME-only on both sides and rides the existing `pw ssh -R` channel.

## Quickstart (5 minutes the first time, ~30 seconds per session after that)

### On your laptop

```bash
git clone <this-repo> auth-relay
cd auth-relay
./pwrelay setup                   # one time: deps, venv, key check
./pwrelay up gclusternoaav3       # each session: agent + tunnel, foreground
```

`up` takes any pw resource: `workspace`, `gclusternoaav3`, or a full
`pw://Matthew.Shaxted/gclusternoaav3` URI. Ctrl+C tears down cleanly.

### On the VDI (inside the ACTIVATE desktop session)

Open a terminal in your VDI desktop (XFCE menu → Terminal) and run **once**:

```bash
git clone <this-repo> ~/auth-relay
bash ~/auth-relay/vdi/install-chrome.sh   # portable Chrome under ~/auth-relay/chrome-portable
bash ~/auth-relay/vdi/bootstrap.sh
```

The bootstrap script prints the extension load instructions. In short:

1. Launch Chrome via the wrapper (do NOT pass `--user-data-dir` — Chrome
   148+ won't find the NMH manifest if you do):
   ```bash
   ~/auth-relay/vdi/bin/chrome &
   ```
2. Open `chrome://extensions`
3. Toggle **Developer mode** ON (top-right)
4. Click **Load unpacked**, select `~/auth-relay/vdi/extension`
5. The extension loads with ID `ifmfpjglkeipojipfiolefflhopdflgf` (deterministic, baked in)
6. Click **Inspect views: service worker** on the extension card; in the
   DevTools console you should see:

   ```
   [pw-relay] attach() succeeded — proxy is active
   ```

#### NOAA on-prem (Ursa, Gaea, Hera, …): install Chrome once into `/contrib`

On NOAA HPC, `$HOME` is small (10 GB on Ursa) and Chrome is ~340 MB. Avoid
the quota hit by installing Chrome **once, by an admin, into your project's
shared contrib filesystem**, then have users point `PW_CHROME_BIN` at it:

```bash
# Admin (once per cluster). Choose the contrib path your project uses.
git clone <this-repo> /contrib/<project>/auth-relay
bash /contrib/<project>/auth-relay/vdi/install-chrome.sh /contrib/<project>/auth-relay
```

```bash
# Users, in their shell rc (e.g. ~/.bashrc on the cluster login node):
export PW_CHROME_BIN=/contrib/<project>/auth-relay/chrome-portable/opt/google/chrome/google-chrome
```

`bootstrap.sh`, `vdi/bin/chrome`, and any future scripts honor that env var.

Also confirmed in testing: Chrome 148+ on NOAA RHEL/SLES (glibc ≥ 2.34) runs
cleanly from a portable extraction. Firefox is the only system browser on the
login nodes we've tested (Ursa `ufe02`, Gaea `gaea54`), so the portable Chrome
is required.

### Test it

In the VDI Chrome, open **<http://localhost:8080/test.html>** and click
**Make credential**. Your laptop YubiKey blinks; touch it; the page
shows a real attestation.

Then go to **<https://accounts.google.com>** in the same VDI Chrome and
sign in with your security key. Touch happens on your laptop.

## Architecture (one screen)

```
┌──────────────────────────────────────────┐         ┌─────────────────────────────────────────┐
│  Your laptop                              │         │  PW resource (cluster / workspace)       │
│                                           │         │                                          │
│  YubiKey on USB                           │         │  VDI browser (Chrome)                    │
│       │                                   │         │     │                                    │
│  laptop/agent.py                          │  pw ssh │     ├ chrome.webAuthenticationProxy      │
│  (python-fido2, CTAP2)                    │   -R    │     │   intercepts navigator.credentials│
│       │  127.0.0.1:7777    ◀──────────────┼─────────┼─▶   │                                    │
│       └─ pwrelay binds tunnel            7777      vdi/extension (MV3 service worker)         │
│                                           │         │     │  WebAuthn↔CTAP2 in JS              │
│                                           │         │     │                                    │
│                                           │         │  vdi/nmh/relay.py (native messaging)     │
│                                           │         │     stdio ↔ TCP                          │
└──────────────────────────────────────────┘         └─────────────────────────────────────────┘
                                                          (Singularity container with --net
                                                           sharing the host loopback)
```

Wire payload on the tunnel is **raw CTAPHID CBOR frames**: a one-byte
CTAP2 command (0x01 make_credential, 0x02 get_assertion, 0x04 get_info)
followed by CBOR-encoded arguments. Length-prefixed (4-byte big-endian).
The agent forwards each frame straight to the USB device via
`fido2.hid.CtapHidDevice.call(CTAPHID.CBOR, ...)`. Touch latency on the
laptop dominates everything else; relay overhead is ~25 ms median.

## Files at a glance

```
pwrelay                  laptop CLI: setup / up / down / status (auto-reconnects the tunnel)
laptop/agent.py          laptop-side TCP server, python-fido2 backend
common/protocol.py       length-prefixed byte-frame framing
workspace/               iter-1/2 test scripts (no browser; for routing/timing checks)
  client.py, standalone_test.py    no-touch (authenticatorGetInfo loop)
  test_real.py                     full ceremony (touches the key)
vdi/
  bootstrap.sh           VDI-side one-command setup (NMH manifest, http.server, etc.)
  install-chrome.sh      portable Chrome installer; pass a target dir to use /contrib
  bin/chrome             Chrome wrapper; honors $PW_CHROME_BIN, no --user-data-dir
  extension/             MV3 Chrome extension (webAuthenticationProxy proxy)
  nmh/relay.py           native messaging host bridging Chrome <-> relay socket
  test.html              self-contained local-RP test page
  dev/cdp_probe.py       development helper for service-worker inspection
HANDOFF.md               iteration-by-iteration log and design notes
```

## What's in each iteration

| Iter | Adds                                                                                                  | Validated against                       |
|------|-------------------------------------------------------------------------------------------------------|-----------------------------------------|
| 1    | length-prefixed JSON-op pipe through `pw ssh -R`, synthetic backend                                   | gpu.parallel.works → workspace          |
| 2    | real CTAP2 over the wire, python-fido2 backend, real make_credential / get_assertion ceremonies        | Mac laptop → gclusternoaav3 mgmt node   |
| 3    | Chrome extension + NMH so the in-VDI browser does real WebAuthn against the relay                     | Mac laptop YubiKey → accounts.google.com inside NOAA VDI Chrome |
| 4    | Deterministic extension ID, one-command CLI on both sides, this README                                 | gclusternoaav3 mgmt node                |
| 5    | On-prem packaging: portable Chrome installer + wrapper, `pw ssh -R` auto-reconnect, contrib install pattern | NOAA Ursa `ufe02`, Gaea-C5 `gaea54`     |

## Troubleshooting

**`pwrelay up` says "tunnel didn't come up in 15s"**
Check `pw auth whoami` and `~/.ssh/pwcli`. Re-run `pw auth login` if either
is stale. The `--ProxyCommand="pw ssh --proxy-command %h"` SSH chain
requires both.

**Tunnel disconnects mid-session (NOAA Gaea / Hera idle drops)**
`pwrelay` runs the `ssh -R` inside a supervisor loop that auto-reconnects
in 3 seconds on idle drops. You'll see `[supervisor] ssh exited rc=N —
reconnecting in 3s` in `/tmp/pwrelay-tunnel.log`. If the supervisor itself
ever exits (auth failure, or remote port held), that's terminal; check
the log.

**`pwrelay up` says "remote port 7777 is already bound by another process"**
A prior pwrelay session left an `ssh -R ... sleep 86400` running on the
cluster login node. The new pwrelay can't reuse the port. Recovery:
`pw ssh <resource> 'pgrep -u $USER -af "sleep 86400" | awk "{print \$1}" | xargs -r kill'`.
**Do not** kill any process named `pw agent` on the cluster — that's
your cluster's per-user daemon. Killing it makes `pw ssh <resource>` fail
auth, and you'll need PW support (or a web SSH into the login node) to
re-bootstrap your agent.

**Extension console says `attach() failed: webAuthenticationProxy is undefined`**
You need Chrome (or Chromium) 115 or newer. Check `chrome://version`.

**Extension console says `attach() failed: ...permission denied / enterprise policy`**
The `webAuthenticationProxy` API is documented as enterprise-policy-gated,
but in practice it works for unpacked extensions in developer mode on
Chrome stable. If you do hit the policy gate, set a per-user managed-policy
file on the VDI host: `~/.config/google-chrome/managed/pwrelay.json`
containing the `WebAuthenticationProxyExtensionAllowlist` policy with our
extension ID. (No root required if your Chrome reads per-user policies.)

**Test page says `SecurityError: This is an invalid domain`**
Use the URL `http://localhost:8080/test.html` (not `http://127.0.0.1:8080`).
WebAuthn doesn't accept IP addresses as RP IDs.

**Service worker idle / not picking up changes**
After editing the extension or NMH, click the **reload icon** on the
extension card in `chrome://extensions`. The NMH process respawns on next
extension request automatically.

**Google rejects the assertion**
You need a YubiKey that has already been registered with Google (under a
different machine is fine — the key itself holds the credential). This
relay forwards an existing key; it doesn't create a virtual one.

**The YubiKey blinks but Chrome shows a generic error**
Inspect the service worker console for an `Invalid responseJson` message;
it'll tell you which WebAuthn-Level-3 field Chrome rejected. We've handled
all the ones modern accounts.google.com exercises; new RPs may surface
new ones.

## Constraints honored

- No root on either end. No kernel modules.
- No `uinput`, no `pcscd`, no system daemons, no system services.
- Single TCP port forwarded through the PW platform's existing auth
  channel; no new firewall holes; agent binds loopback only.
- The Chrome extension is loaded by the user from $HOME (Developer Mode →
  Load Unpacked); no store listing, no admin install.

## Status and provenance

This is a working POC. Validated end-to-end on:

- Laptop: macOS, Python 3.14, YubiKey 5 OTP+FIDO+CCID, Chrome 148
- VDI: NOAA `gclusternoaav3` mgmt node, KasmVNC inside Singularity
  (--nv, no `--net`, $HOME bind-mount), Chrome 148

See `HANDOFF.md` for the iteration log, design decisions, what was
considered and discarded, and the open production-readiness questions.

## CAC / smartcard?

Not supported by this code. CAC uses PKCS#11 + PC/SC + TLS client cert
auth, which is a separate protocol stack from FIDO2. The same
architectural template (pw ssh -R + userspace agent on laptop + loopback
endpoint on the VDI) carries over; the cargo and the VDI hook do not.
That would be a sibling project alongside this one.
