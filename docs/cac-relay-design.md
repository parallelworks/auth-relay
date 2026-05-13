# CAC / PIV smartcard relay — design

> **Status: design only.** Nothing under `pcsc/` is wired up yet. This doc
> is the plan; the `pcsc/` directory has stubs you can grow into.

NOAA services accept both YubiKey (FIDO2 / WebAuthn) and CAC/PIV
smartcard for sign-in. The FIDO side is done (`vdi/` directory, fully
working). This document specifies the same trick for CAC: physical card
stays on the user's laptop, the VDI Chrome authenticates via TLS client
cert against `sso.noaa.gov` (and similar) using that card.

## Why we can't reuse the FIDO2 relay

FIDO2 and CAC are different stacks all the way down:

| Layer | FIDO2 (current relay) | CAC / PIV (this design) |
|---|---|---|
| USB class | HID (CTAPHID) | CCID (ISO 7816 smartcard) |
| OS service | none — Chrome talks HID directly | `pcsc-lite` / `pcscd` + OpenSC + NSS |
| App-level API | `navigator.credentials` → CTAP2 CBOR | PKCS#11 / TLS client cert |
| Browser hook | `chrome.webAuthenticationProxy` extension API | NSS module discovery (no JS hook) |
| Key shape | per-credential keys, derived in HW per RP | long-lived X.509 certs + private keys on card |
| Auth pattern | per-ceremony "touch", no persistent secret | one PIN unlocks the card for the session |

The browser-extension trick we used for FIDO2 has **no equivalent** for
CAC. TLS client-cert selection happens beneath the browser's JS layer
— Chrome consults NSS, NSS consults its registered PKCS#11 modules,
the OS provides certs and signing. The only injection point we have is
**adding a custom PKCS#11 module** that forwards calls over the relay.

## Architecture

```
┌────────────────────────────────────┐         ┌──────────────────────────────────────┐
│ Your laptop                         │         │ Cluster login / desktop node          │
│                                     │         │                                       │
│  CAC card in USB CCID reader        │         │   Chrome (NSS-backed TLS)             │
│       │                             │         │      │                                │
│  OpenSC PKCS#11 (system or bundled) │         │      ▼                                │
│       │                             │         │   NSS reads ~/.pki/nssdb              │
│  p11-kit server / pcsc/agent.sh     │ pw ssh  │      │ (registered: pwrelay-cac.so)   │
│  exposes the PKCS#11 module ◀───────┼── -R ───┼─▶  pwrelay-cac.so (p11-kit-client)    │
│  on 127.0.0.1:7888                  │ tunnel  │      forwards every PKCS#11 call      │
│                                     │         │      to 127.0.0.1:7888                │
└────────────────────────────────────┘         └──────────────────────────────────────┘
```

The wire protocol is **p11-kit's RPC** — p11-kit (the standard PKCS#11
discovery service shipped in every modern Linux distro) supports
remote modules out of the box. We do not have to invent a protocol.

## Components

### Laptop side — `pcsc/agent.sh`

Wraps `p11-kit server --provider <opensc-pkcs11.so>` so the laptop's
real PKCS#11 module (OpenSC, which reads the CAC) is exposed on a
Unix socket. A tiny socat-style bridge re-publishes that socket on
`127.0.0.1:7888` so the existing `pw ssh -R` machinery can carry it.

Reuses `pwrelay`'s tunnel — one `pwrelay up <resource>` could open
both the FIDO port (7777) and the PKCS#11 port (7888). Or a separate
`pwrelay up <resource> --pcsc` flag.

### Wire — `pw ssh -R 7888:127.0.0.1:7888`

Same tunnel mechanism. p11-kit's RPC is binary but well-defined; the
existing `common/protocol.py`-style framing is **not** reused —
p11-kit carries its own framing.

### VDI side — `pcsc/bootstrap.sh`

Installs `p11-kit-client.so` if not present (most distros ship it via
the `p11-kit` package). Drops a config file at
`~/.config/p11-kit/modules/pwrelay-cac.module`:

```
module: p11-kit-client.so
remote: |tcp 127.0.0.1 7888
```

Registers the module with the user's NSS database:

```
modutil -dbdir sql:$HOME/.pki/nssdb -add pwrelay-cac \
        -libfile $(p11-kit list-modules --info=p11-kit-client.so | ...) \
        -mechanisms RSA -force
```

Chrome on next launch sees the new PKCS#11 module, queries it for
client certs, gets the CAC's certs back via the relay.

### TLS client cert flow

1. User in VDI Chrome navigates to `https://sso.noaa.gov`
2. Server's `Certificate Request` includes acceptable issuers
3. Chrome asks NSS for client certs; NSS queries every registered
   PKCS#11 module, including `pwrelay-cac`
4. `pwrelay-cac.so` forwards `C_GetSlotList` / `C_FindObjects` over the
   relay to laptop → OpenSC → physical CAC
5. Chrome shows "Select a certificate" dialog with the CAC certs
6. User picks the right cert
7. Chrome's TLS layer asks NSS to sign the handshake-hash with the
   selected key; NSS calls `C_Sign` on `pwrelay-cac.so`
8. Forwarded to laptop; OpenSC asks the card to sign; **the CAC PIN
   dialog appears on the laptop side** (pcsc-lite default) — or in
   Chrome if we configure the module to forward PIN prompts
9. Signed handshake comes back; TLS continues; user is logged in

## Security model

- **PIN handling**: the cleanest model is **PIN entered on the
  laptop** via `pinentry` or pcsc-lite's default UI. The PIN never
  traverses the wire. Some PKCS#11 stacks force PIN-on-application
  (Chrome's "Enter smart card PIN" dialog) — in that case the PIN
  goes laptop-bound through the encrypted pw ssh -R tunnel. Both are
  acceptable in our threat model (single-tenant relay over a tunnel
  the user themselves opened).
- **Cert exposure**: only certs on the user's plugged-in CAC are
  exposed. Nothing fundamentally new compared to local CAC use.
- **Card removal mid-session**: when CAC is unplugged, the PKCS#11
  module reports an empty slot list. Chrome's open TLS sessions
  remain; new TLS handshakes fail until re-insertion. Same UX as a
  local card unplug.

## Constraints honored (same as the FIDO relay)

- No root on either end.
- No kernel modules. No system daemons modified.
- Standard Linux PKCS#11 infrastructure (p11-kit, NSS, OpenSC) only —
  all already present on RHEL/Rocky/SLES.
- `pw ssh -R` is the only network path.

## Open questions to resolve before implementation

1. **Is OpenSC PKCS#11 on macOS sufficient for NOAA's CAC certs?** Many
   CACs use NIST PIV plus DoD-specific PKI. OpenSC's PIV module
   handles standard PIV; NOAA "CAC" may be NIST PIV in practice.
2. **Does NOAA's CAC reader work over the macOS PC/SC stack?** Most
   commodity CCID readers do; check the user's specific reader.
3. **Does p11-kit-client.so support raw TCP, or only Unix sockets?**
   Recent versions support `|tcp <host> <port>` in module files
   (verified in p11-kit 0.24+). RHEL 9 ships 0.25; Rocky 9.7 should
   too.
4. **Does the VDI's Chrome use the user's NSS db (`~/.pki/nssdb`)
   or a separate one?** Chrome 148 on Linux uses `~/.pki/nssdb` by
   default. Our portable Chrome wrapper uses
   `--user-data-dir=~/.config/google-chrome-pwrelay` — need to verify
   that doesn't isolate the NSS db too. If it does, we'd point Chrome
   at the standard NSS path explicitly via env vars.
5. **Will Chrome 148 honor a freshly-added NSS module without a
   restart?** Almost certainly no — bootstrap.sh would need to
   restart Chrome (or install before the user opens any TLS sites).

## File layout (after implementation)

```
pcsc/
  README.md                    one-page user doc
  agent.sh                     laptop-side wrapper around p11-kit server
  bootstrap.sh                 VDI-side: install p11-kit-client module, NSS register
  test-tls.sh                  smoke test: openssl s_client against an NOAA endpoint
docs/cac-relay-design.md       this file
pwrelay                        grows a --pcsc flag that opens 7888 alongside 7777
```

## Phasing

1. **Now (this PR)**: design doc + skeleton `pcsc/` directory + this
   doc landed. No actual relay yet.
2. **Phase 2**: laptop-side `pcsc/agent.sh` working — verify a local
   p11-kit-client can talk to it and see the CAC certs.
3. **Phase 3**: VDI-side bootstrap.sh that registers the module with
   NSS and a smoke test against `https://sso.noaa.gov`.
4. **Phase 4**: bundle the laptop side into `pwrelay` so a single
   `pwrelay up <resource>` brings up both relays.

This will be a multi-day undertaking; the design here is the contract
each phase must hit.
