# HPC deployment

Patterns for clusters where individual `$HOME` quotas are tight and one
install should serve a whole project (typical NOAA on-prem situation).

## TL;DR

If your `$HOME` has < 1 GB free, install the relay (~340 MB for the
portable Chrome plus a few MB for the code) into a shared project
directory once, then point users at it via an env var.

## Pattern 1 — shared `/contrib` install

```bash
# Admin, once per cluster:
export SHARED_DIR=/contrib/<your-project>/auth-relay
git clone https://github.com/parallelworks/auth-relay "$SHARED_DIR"
bash "$SHARED_DIR/vdi/install-chrome.sh" "$SHARED_DIR"
```

```bash
# Users, in their shell rc on the cluster (.bashrc / .zshrc):
export PW_CHROME_BIN=/contrib/<your-project>/auth-relay/chrome-portable/opt/google/chrome/google-chrome
```

`bootstrap.sh`, `vdi/bin/chrome`, and `install-extension.py` all honor
`$PW_CHROME_BIN`. Each user still runs `bootstrap.sh` + `install-extension.py`
once per VDI session to register the NMH manifest in *their* Chrome
profile and seed bookmarks, but they no longer need to install Chrome.

## Pattern 2 — `/tmp` install (per-user, no shared dir needed)

For clusters where you can't write to `/contrib` and `$HOME` is tight,
the login node's `/tmp` is usually local disk with plenty of room:

```bash
export RELAY_DIR=/tmp/$USER/auth-relay
mkdir -p "$RELAY_DIR"
git clone https://github.com/parallelworks/auth-relay "$RELAY_DIR"
bash "$RELAY_DIR/vdi/install-chrome.sh" "$RELAY_DIR"
bash "$RELAY_DIR/vdi/bootstrap.sh"
python3.12 "$RELAY_DIR/vdi/install-extension.py"
```

Caveats:

- `/tmp` is **per-node** on most clusters. If your VDI desktop runs on
  a different node than where you installed (e.g. the cluster moved
  you between login nodes mid-session), Chrome won't be visible. On
  single-login-node setups (NOAA Gaea-C5) this is fine.
- `/tmp` is **cleared on reboot**. You'll re-install ~340 MB after each
  cluster maintenance window. Cheap, just be aware.
- Some HPC `/tmp` is `tmpfs` (RAM-backed) or quota-limited. Run
  `df -h /tmp` before assuming free space.

## Pattern 3 — `$HOME` install (simplest, default)

What the main README documents. Use this when `$HOME` has plenty of
room (>1 GB free). Survives reboots, follows you across login nodes.

```bash
export RELAY_DIR="$HOME/auth-relay"
git clone ... "$RELAY_DIR"
# ... rest of the standard quickstart
```

## Confirming which Chrome `bootstrap.sh` will use

```bash
bash $RELAY_DIR/vdi/bootstrap.sh
# Look for: "Chrome binary   : <path>"
```

If the path is `NOT FOUND`, either run `vdi/install-chrome.sh` or set
`PW_CHROME_BIN`.

## Validated HPC environments

| Cluster | Login node | Notes |
|---|---|---|
| NOAA Ursa | `ufe02` / `ufe03` | 10 GB `$HOME` quota — recommend `/contrib` or `/tmp` install. `/tmp` is per-node. |
| NOAA Gaea-C5 | `gaea54` | Single login node, VDI runs on same node — `$HOME` or `/tmp` both fine. |
