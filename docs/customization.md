# Customization

For deployers forking this repo for a specific organization.

## Bookmarks

The default bookmark set seeded into each user's Chrome on first launch
lives in **`vdi/bookmarks.json`**. Edit that one file, push, done.

```json
[
  { "name": "Test page (relay)", "url": "http://localhost:8080/test.html" },
  { "name": "Gmail",             "url": "https://mail.google.com/" },
  { "name": "Our wiki",          "url": "https://internal.example.com/wiki" }
]
```

`bootstrap.sh` only writes the Bookmarks file if Chrome doesn't already
have one — it never overwrites a user's curated set.

## Desktop launcher icon

`bootstrap.sh` drops `~/Desktop/pw-chrome.desktop` with a "PW Chrome
(YubiKey Relay)" label. To rebrand: edit the `Name=`/`Comment=` lines
in `vdi/bootstrap.sh` (search for `Desktop Entry`). Icon comes from
the system's `google-chrome` theme icon by default; swap to a path
under your repo for a custom logo.

## Extension ID / packing key

The extension ID is **deterministic** — derived from an RSA public key
baked into `vdi/extension/manifest.json`. The committed key gives ID
`ifmfpjglkeipojipfiolefflhopdflgf`. The NMH manifest hard-codes that
ID as its only allowed origin, so a re-pack is needed if you fork.

```bash
bash vdi/extension/regen-key.sh
```

This generates a fresh RSA-2048 keypair, updates `manifest.json` with
the new public key, and updates `install.sh`/`bootstrap.sh` with the
new derived ID. The private key lands at
`vdi/extension/.private-key.pem` (gitignored).

Re-run `bash vdi/extension/regen-key.sh` only when forking a new
deployment; never on a working install (every user's currently-loaded
extension would orphan).

## Chrome binary location

Three places look for Chrome, in order:

1. `$PW_CHROME_BIN` env var
2. `<RELAY_DIR>/chrome-portable/opt/google/chrome/google-chrome`
3. `/usr/bin/google-chrome` (system install)
4. `chromium` / `chromium-browser` on PATH

Set `PW_CHROME_BIN` in users' shell rc for the shared-install pattern
described in [hpc.md](hpc.md).

## CTAP timeout for touch ceremonies

`vdi/nmh/relay.py` waits up to **90 seconds** for the YubiKey to
respond once a CTAP frame has been forwarded. Override with the
`PW_RELAY_RECV_TIMEOUT` env var (seconds). Lower it for noisier
"is the tunnel alive" feedback; raise it for very long-ceremony tests.

Set via the NMH wrapper that `bootstrap.sh` generates — edit
`vdi/nmh/relay-wrapper.sh` after running bootstrap, or change the
`cat > relay-wrapper.sh` block in `bootstrap.sh` for a permanent
override.

## Local-RP test page

`vdi/test.html` is a self-contained `navigator.credentials` exerciser
served on `http://localhost:8080/test.html` by `bootstrap.sh`. Edit
to change the demo RP ID, default user, or button copy.

## Branch protection / commits

The `parallelworks` org applies a ruleset to `main`: PR required,
squash merge only, linear history, **commit messages cannot contain
`claude[bot]` / `anthropic.com` / `175728472`**. Fork-and-PR
workflow is the supported path.
