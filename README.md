# Parallel Works Auth Relay

Use the YubiKey (or any FIDO2 security key) that's plugged into your
**laptop** to complete WebAuthn / FIDO2 prompts — Google Workspace MFA,
GitHub, Okta, your SSO portal, anything that uses `navigator.credentials` —
from inside a Parallel Works ACTIVATE **remote desktop** session running on
any cluster.

No USB forwarding. No kernel modules. No `uinput`. No `pcscd`. No system
daemons. No root on either side. `$HOME`-only on both ends, riding the
existing `pw ssh -R` reverse tunnel.

---

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

---

## Before you start

You need these on your **laptop** (one-time):

1. **`pw` CLI installed.** See <https://parallelworks.com/docs/cli> or
   `brew install parallelworks/pw/pw` on macOS.
2. **`pw` CLI authenticated.** Run `pw auth login` and complete the
   browser flow. Verify with `pw auth whoami`. This also writes
   `~/.ssh/pwcli` which the relay's `ssh -R` uses.
3. **Python 3.10+** on PATH (Mac stock; on Linux any modern distro).
4. **A FIDO2 security key** (YubiKey 5, anything CTAP2-capable)
   plugged into a USB port. The agent verifies it at `./pwrelay setup`.

On the **VDI** side: a desktop session via PW ACTIVATE. Nothing else;
the relay installs its own Chrome and Python deps under your `$HOME`.

## Quickstart

### On your **laptop** (Mac, Linux, or WSL on Windows)

```bash
git clone https://github.com/parallelworks/auth-relay
cd auth-relay
./pwrelay setup                  # one time
./pwrelay up <pw-resource>       # each session
```

Replace `<pw-resource>` with anything from `pw cluster ls` — e.g.
`workspace`, `gaeac5`, `mycluster`. `setup` installs Python + python-fido2
into a local venv and verifies your security key is detected. `up` starts
the agent and the `pw ssh -R` tunnel; Ctrl+C tears it all down cleanly.

### Inside the **VDI desktop** (one time per session)

Open a terminal in the desktop. First, pick where to install the relay:

```bash
# Where to put the relay + portable Chrome (~340 MB). Pick one:
#
#   $HOME/auth-relay              if your $HOME has ≥500 MB free
#   /tmp/$USER/auth-relay         if $HOME is tight; /tmp must be on the
#                                  SAME node as your VDI desktop (true on
#                                  most single-login-node clusters). Cleared
#                                  on reboot — reinstall once per uptime.
#   /contrib/<proj>/auth-relay    admin-installed once into shared project
#                                  storage; all users in <proj> share it.
#                                  See "Cluster with a small $HOME quota?"
#                                  below.
export RELAY_DIR="$HOME/auth-relay"
```

Then:

**First-time setup (each new VDI session):**

```bash
git clone https://github.com/parallelworks/auth-relay "$RELAY_DIR"
bash "$RELAY_DIR/vdi/install-chrome.sh" "$RELAY_DIR"   # ~5 min, one time, no root
bash "$RELAY_DIR/vdi/bootstrap.sh"                     # NMH manifest + http.server
python3 "$RELAY_DIR/vdi/install-extension.py"          # auto-loads extension into Chrome
```

The last command launches Chrome, loads the extension via Chrome's
DevTools Protocol (no UI clicks), and leaves Chrome running with the
relay wired up.

**Day-two and later — just open Chrome via the wrapper:**

```bash
"$RELAY_DIR/vdi/bin/chrome" &
```

The wrapper sets up the right stack ulimit, points at the portable
Chrome via `$PW_CHROME_BIN`, and redirects Chrome's noisy stderr to
`/tmp/pw-chrome-<user>.log` so your terminal stays usable. The
extension is persistently installed in your Chrome profile from the
first-time run; you don't need `install-extension.py` again unless you
wipe `~/.config/google-chrome/Default`.

In Chrome, go to your SSO portal or `https://accounts.google.com` and
sign in. Touch the security key on your laptop when prompted.

### Cluster with a small `$HOME` quota? Install Chrome once into a shared dir.

If user homes are tight (typical on HPC), an admin can install the relay
into a project's shared contrib filesystem once, then individual users
just point at the prebuilt Chrome:

```bash
# admin, once per cluster:
export RELAY_DIR=/contrib/<your-project>/auth-relay
git clone https://github.com/parallelworks/auth-relay "$RELAY_DIR"
bash "$RELAY_DIR/vdi/install-chrome.sh" "$RELAY_DIR"
```

```bash
# users, in their shell rc on the cluster:
echo 'export PW_CHROME_BIN=/contrib/<your-project>/auth-relay/chrome-portable/opt/google/chrome/google-chrome' >> ~/.bashrc
```

`bootstrap.sh`, the chrome wrapper, and `install-extension.py` all honor
that env var.

### Quick alternative: install Chrome in `/tmp`

If you can't write to `/contrib` and `$HOME` is tight, `/tmp` on the
login node is usually fine — it's local disk on most clusters and has
hundreds of GB free. Caveats: it's per-node (won't help on clusters
that move you between login nodes mid-session), and it's cleared on
node reboot.

```bash
export RELAY_DIR=/tmp/$USER/auth-relay
mkdir -p "$RELAY_DIR"
git clone https://github.com/parallelworks/auth-relay "$RELAY_DIR"
bash "$RELAY_DIR/vdi/install-chrome.sh" "$RELAY_DIR"
bash "$RELAY_DIR/vdi/bootstrap.sh"
python3 "$RELAY_DIR/vdi/install-extension.py"
```

---

## Troubleshooting

| Symptom | Try this |
|---|---|
| `pwrelay up` hangs at "tunnel didn't come up" | `pw auth login`, then retry |
| `pwrelay up` says "every port in 7777..7784 was rejected" | `./pwrelay reset <resource>` then `./pwrelay up <resource>` |
| Chrome shows `request already pending` and never finishes | The tunnel died mid-ceremony. `./pwrelay status` to verify, refresh the page. The NMH times out after 90 s and surfaces a clean error. |
| `attach() failed: webAuthenticationProxy is undefined` | Need Chrome ≥ 115. `chrome://version` to check. |
| `Specified native messaging host not found` | Don't launch Chrome with `--user-data-dir` — Chrome 148+ looks for NMH manifests inside the data dir if you do. Use `~/auth-relay/vdi/bin/chrome &` instead. |
| Chrome won't load any page; terminal shows `pthread_create: Resource temporarily unavailable` | The cluster's default `ulimit -s` is 1 GiB and Chrome blows up. The wrapper at `~/auth-relay/vdi/bin/chrome` clamps it to 8 MiB — use the wrapper. |
| Things look generally weird | `./pwrelay doctor <resource>` prints both ends' state. Paste output if you need help. |

**Do not** kill any process named `pw agent` on the cluster. It's your
per-user pw daemon and if it dies you'll need PW support (or web SSH)
to re-bootstrap it. `pwrelay reset` only touches things that are
provably ours (tagged with our session marker).

---

## What's inside

```
pwrelay                  laptop CLI: setup / up / down / status / doctor / reset
laptop/agent.py          laptop-side TCP server, python-fido2 backend
common/protocol.py       length-prefixed byte-frame framing
workspace/               iter-1/2 test scripts for routing/timing checks
vdi/
  install-chrome.sh      portable Chrome installer (no root)
  bootstrap.sh           VDI-side one-shot setup
  install-extension.py   auto-installs the extension into Chrome via CDP
  bin/chrome             Chrome launcher; honors $PW_CHROME_BIN, clamps stack ulimit
  extension/             MV3 Chrome extension using chrome.webAuthenticationProxy
  nmh/relay.py           native-messaging-host bridging Chrome ↔ relay socket
  test.html              local-RP test page (http://localhost:8080/test.html)
HANDOFF.md               iteration log + design notes
```

## Resilience features that matter to a normal user

These are the bits that quietly keep things working without intervention:

- **Auto-reconnect tunnel.** Some clusters drop idle ssh sessions after
  about an hour. `pwrelay up` runs the `ssh -R` inside a supervisor
  loop that reconnects in 3 seconds.
- **Auto port-fallback.** If port 7777 on the cluster is held by a prior
  forward in pw-agent's cache, `pwrelay up` walks through 7777 → 7784
  until it finds a free one, drops the chosen port to a file on the
  cluster, and the NMH reads it. You don't have to know.
- **NMH read timeout (90 s).** Long enough for a real security-key
  touch ceremony; short enough that a dead tunnel surfaces in Chrome
  as a clean error you can retry rather than a wedged-forever request.
- **Session marker for clean shutdown.** Every `pwrelay up` tags its
  remote `sleep` keepalive with a unique session ID. `pwrelay down`
  asks the cluster to kill that tag — and only that tag — so the next
  session gets a clean port instead of pw-agent caching state from us.
- **`pwrelay doctor`.** Dumps local + remote process and port state in
  one place. Paste it when something looks off.
- **`pwrelay reset`.** Kills everything *we own* on both ends. Never
  touches the pw agent.

---

## Validated environments

| Where | Hostname | Latency (med) | WebAuthn ceremony |
|---|---|---|---|
| PW workspace | `pw-user-...-0` | 44 ms | ✓ |
| Google-cloud HPC cluster | `...-mgmt` | 26 ms | ✓ |
| NOAA on-prem `ursa` | `ufe02` | 85 ms | ✓ (no-touch path) |
| NOAA on-prem `gaeac5` | `gaea54` | 102 ms | ✓ — real Google sign-in working |

Touch latency on the security key (~3 s) dominates relay overhead in
every case.

---

## Constraints honored

- No root on either end.
- No kernel modules, no `uinput`, no `pcscd`, no system daemons.
- Single TCP port forwarded through PW's existing auth channel; no new
  firewall holes; agent binds loopback-only.
- Chrome extension is loaded from `$HOME` (or a shared install path) via
  the user's own session. No Web Store listing, no admin install, no
  enterprise policy required.

## CAC / smartcard / non-FIDO?

Out of scope for what currently ships. The repo name (`auth-relay`) is
intentionally generic: a CAC/PIV (PKCS#11 + PC/SC) relay would slot in
as a peer module — e.g., `pcsc/` sibling to `vdi/` — sharing the same
`pwrelay` CLI and `pw ssh -R` tunnel pattern. The wire and the in-VDI
hook would be different, but the architectural template carries over.
See the bottom of `HANDOFF.md` for the design sketch.

## Iteration log

See `HANDOFF.md` for full design rationale and per-iteration log:

1. Synthetic JSON-op relay through `pw ssh -R`. Proves the pipe.
2. Real CTAP2 over the wire via python-fido2.
3. Chrome extension + native messaging host. Real WebAuthn in the
   in-VDI browser, including Google sign-in.
4. Packaging: deterministic extension ID, `pwrelay` CLI.
5. On-prem hardening: portable Chrome installer, contrib-path support,
   auto-reconnect tunnel.
6. Resilience: port fallback, NMH read timeout, session-marker
   shutdown, `pwrelay doctor` / `reset`.
