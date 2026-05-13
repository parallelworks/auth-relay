# Parallel Works Auth Relay

Use the **FIDO2 security key** (YubiKey, etc.) and/or **CAC / PIV smartcard**
plugged into your **laptop** to complete authentication prompts from inside a
Parallel Works ACTIVATE **remote desktop**. No root, no USB forwarding, no
admin install on the cluster.

| Auth method     | Status      | Use cases                                       |
|-----------------|-------------|-------------------------------------------------|
| **FIDO2 / WebAuthn**  | ✅ stable | Gmail, Google MFA, NOAA SSO, GitHub, anywhere WebAuthn is used |
| **CAC / PIV (TLS client-cert)** | 🚧 beta — opt-in via `--cac` | NOAA / DoD / federal sites that require a CAC |

## Before you start

On your **laptop**:
- `pw` CLI installed + authenticated (`pw auth login`)
- Python 3.10+
- For **FIDO2**: a YubiKey (or compatible) plugged into USB.
- For **CAC** (optional): an inserted CAC + a CCID-class USB reader, plus
  `opensc`, `p11-kit`, and `socat` available
  (`brew install opensc p11-kit socat` on macOS; package manager on Linux).
  Windows CAC support is on the roadmap, not yet shipped.

## Laptop

```bash
git clone https://github.com/parallelworks/auth-relay
cd auth-relay
./pwrelay setup                  # one time

# pick what you want exposed to the VDI:
./pwrelay up <resource>          # FIDO2 only (default)
./pwrelay up <resource> --cac    # FIDO2 + CAC
./pwrelay up <resource> --cac --no-fido   # CAC only
```

`<resource>` is anything from `pw cluster ls` (e.g. `workspace`, `gaeac5`).
Ctrl+C tears the relay(s) down.

> **Windows**: use `pwrelay.cmd` instead of `./pwrelay`. CAC support
> (`--cac`) is bash-only today — track the Python rewrite in
> [`docs/cac-relay-design.md`](docs/cac-relay-design.md).

## VDI desktop — option A (easy): the ACTIVATE workflow

On https://noaa.parallel.works (or your ACTIVATE deployment), run the
**`auth-relay`** workflow against the same resource you ran `pwrelay up`
against. It does everything the manual steps below do — clone the repo,
install portable Chrome, register the extension, drop a desktop launcher.

The workflow lives at `workflow.yaml` in this repo; you can add it via
**Workflows → Add Workflow → Custom (GitHub)** pointing at
`parallelworks/auth-relay`.

## VDI desktop — option B (manual)

```bash
export RELAY_DIR="$HOME/auth-relay"
git clone https://github.com/parallelworks/auth-relay "$RELAY_DIR"
bash "$RELAY_DIR/vdi/install-chrome.sh" "$RELAY_DIR"
bash "$RELAY_DIR/vdi/bootstrap.sh"
python3.12 "$RELAY_DIR/vdi/install-extension.py"

# If you also passed --cac on the laptop, register the smartcard module:
bash "$RELAY_DIR/pcsc/bootstrap.sh"
```

Chrome opens with the extension already loaded and a **PW Chrome** icon on
your VDI desktop. Sign in to Gmail, your SSO portal, or any
CAC-protected site — touch your laptop YubiKey or enter your CAC PIN when
prompted.

**Day two and later** — just `$RELAY_DIR/vdi/bin/chrome &`, or double-click
the desktop icon.

## Docs

| | |
|---|---|
| [Architecture](docs/architecture.md) | How the relay is wired |
| [Troubleshooting](docs/troubleshooting.md) | When something doesn't work |
| [HPC deployment](docs/hpc.md) | Shared install for clusters with tight `$HOME` quota |
| [Customization](docs/customization.md) | Bookmarks, extension key, per-org branding |
| [CAC / PIV relay (design)](docs/cac-relay-design.md) | The smartcard relay design + Windows roadmap |
| [HANDOFF.md](HANDOFF.md) | Design log + per-iteration history |
