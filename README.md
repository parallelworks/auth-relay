# Parallel Works Auth Relay

Use the FIDO2 security key on your **laptop** to complete WebAuthn prompts
from inside a Parallel Works ACTIVATE **remote desktop**. No root, no USB
forwarding, no admin install.

## Before you start

On your **laptop**:
- `pw` CLI installed + authenticated (`pw auth login`)
- Python 3.10+
- A FIDO2 key (YubiKey or compatible) plugged into USB

## Laptop

```bash
git clone https://github.com/parallelworks/auth-relay
cd auth-relay
./pwrelay setup            # one time
./pwrelay up <resource>    # each session (workspace, gaeac5, ...)
```

`<resource>` is anything from `pw cluster ls`. Ctrl+C tears the relay down.

## VDI desktop

```bash
export RELAY_DIR="$HOME/auth-relay"
git clone https://github.com/parallelworks/auth-relay "$RELAY_DIR"
bash "$RELAY_DIR/vdi/install-chrome.sh" "$RELAY_DIR"
bash "$RELAY_DIR/vdi/bootstrap.sh"
python3.12 "$RELAY_DIR/vdi/install-extension.py"
```

Chrome opens with the extension already loaded and a **PW Chrome** icon on your
desktop. Sign in to Gmail, your SSO portal, or anywhere that uses WebAuthn —
touch your laptop YubiKey when prompted.

**Day two and later** — just `$RELAY_DIR/vdi/bin/chrome &`, or double-click the
desktop icon.

## Docs

| | |
|---|---|
| [Architecture](docs/architecture.md) | How the relay is wired |
| [Troubleshooting](docs/troubleshooting.md) | When something doesn't work |
| [HPC deployment](docs/hpc.md) | Shared install for clusters with tight `$HOME` quota |
| [Customization](docs/customization.md) | Bookmarks, extension key, per-org branding |
| [CAC / PIV relay (design)](docs/cac-relay-design.md) | Planned smartcard relay alongside FIDO2 |
| [HANDOFF.md](HANDOFF.md) | Design log + per-iteration history |
