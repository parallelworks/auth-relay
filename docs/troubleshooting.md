# Troubleshooting

## Quick reference

| Symptom | Try this |
|---|---|
| `pwrelay up` hangs at "tunnel didn't come up" | `pw auth login`, then retry |
| `pwrelay up` says "every port in 7777..7784 was rejected" | `./pwrelay reset <resource>` then `./pwrelay up <resource>` |
| Chrome shows `request already pending` and never finishes | The tunnel died mid-ceremony. `./pwrelay status` to verify; refresh the page. The NMH times out after 90 s and surfaces a clean error. |
| `attach() failed: webAuthenticationProxy is undefined` | Need Chrome ≥ 115. `chrome://version` to check. |
| `Specified native messaging host not found` | Don't launch Chrome with `--user-data-dir` — Chrome 148+ looks for NMH manifests inside the data dir if you do. Use `$RELAY_DIR/vdi/bin/chrome &` or the desktop icon. |
| Chrome won't load any page; `pthread_create: Resource temporarily unavailable` | The cluster's default `ulimit -s` is 1 GiB and Chrome blows up. The wrapper at `$RELAY_DIR/vdi/bin/chrome` clamps it to 8 MiB — use the wrapper. |
| `install-extension.py` fails with `SyntaxError: future feature annotations is not defined` | Your `python3` is < 3.7. The script now self-detects and re-execs under `python3.12`/`python3.11`/... if available. If you see this, you're on an older copy — `git pull` and retry. |
| Bookmarks bar doesn't show | Press `Ctrl+Shift+B` to toggle. The bootstrap turns it on, but Chrome can hide it later. |
| Things look generally weird | `./pwrelay doctor <resource>` dumps both ends' state. Paste output if asking for help. |

## Diagnostic commands

```bash
./pwrelay status                  # local agent + tunnel state
./pwrelay doctor <resource>       # both ends; safe to share
./pwrelay reset <resource>        # kill everything we own, both sides
```

`doctor` and `reset` never touch any process named `pw agent` on the
remote — that's your per-user pw daemon, and if it dies you'll need PW
support (or web SSH) to re-bootstrap it.

## Common log locations

| File | What's in it |
|---|---|
| `/tmp/pwrelay-agent.log` | laptop-side `agent.py` activity (one line per CTAP frame) |
| `/tmp/pwrelay-tunnel.log` | `ssh -R` supervisor stdout + reconnect attempts |
| `/tmp/pw-chrome-<user>.log` | Chrome's stderr/stdout (chatty by default) |
| `/tmp/pw-relay-port-<user>` | The remote-side port pwrelay landed on this session |

## Service-worker console

In the in-VDI Chrome: `chrome://extensions` → "PW YubiKey Relay" card →
**Inspect views: service worker**. Useful console lines:

- `[pw-relay] attach() succeeded — proxy is active` — extension is ready
- `[pw-relay] onCreateRequest` / `onGetRequest` — a WebAuthn ceremony fired
- `[pw-relay] nmh disconnected: <reason>` — Chrome can't keep the NMH alive
- `[pw-relay] get failed: CtapError: CTAP error 0x<hex>` — see CTAP code below

## CTAP error codes seen in practice

| Hex | Name | Likely cause |
|---|---|---|
| `0x00` | success | (no error) |
| `0x2e` | NO_CREDENTIALS | Your YubiKey has no credential registered for this RP. Register first via the site's "Add security key" UI. |
| `0x36` | USER_ACTION_TIMEOUT | YubiKey waited 30 s for a touch and gave up. Run the ceremony again, touch promptly. |
| `0x3a` | OPERATION_DENIED / ACTION_TIMEOUT | Same as 0x36 in older firmware. |
| `0x7f` | OTHER | Transport-layer failure (HID disconnect, USB blip). `pwrelay` re-opens the device automatically and retries once. |

## What NOT to do

- **Don't `kill` any process named `pw agent` on the cluster.** It's
  your per-user pw daemon. If it dies, `pw ssh <resource>` will fail
  auth until support (or web SSH) re-bootstraps it. Use
  `pwrelay reset` for cleanup instead — it's targeted via session
  markers and never touches the agent.
- **Don't launch Chrome with `--user-data-dir`.** Chrome 148+ looks
  for the NMH manifest *inside* the custom data dir, which breaks the
  whole chain. The wrapper at `vdi/bin/chrome` deliberately omits it.
