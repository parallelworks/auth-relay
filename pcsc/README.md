# CAC / PIV smartcard relay (early scaffolding)

Sibling to `vdi/` for FIDO2 — forwards the user's CAC / PIV smartcard
from the laptop's USB CCID reader to the in-VDI Chrome so TLS
client-cert sign-in works against `sso.noaa.gov` and similar services.

**Status:** Phase 3 in progress. `agent.sh` (laptop) and `bootstrap.sh`
(VDI) both ship a first draft. Still TODO: fold the CAC tunnel into
`pwrelay` so the user only runs one command (Phase 4), and write a
Windows-native `agent.py` equivalent.
See [`../docs/cac-relay-design.md`](../docs/cac-relay-design.md).

## Architecture (one line)

`Laptop CAC → OpenSC PKCS#11 → p11-kit server → pw ssh -R → p11-kit-client.so → NSS → VDI Chrome`

## Why it's separate from `vdi/`

The FIDO2 relay hooks `chrome.webAuthenticationProxy` (a JS-level API)
to forward CTAPHID CBOR frames. CAC/PIV is **TLS-client-cert auth** —
intercepted at the NSS / PKCS#11 layer, below the browser. Completely
different code, even though the `pw ssh -R` tunnel pattern is the same.

## Files

```
agent.sh         laptop-side: p11-kit server wrapping OpenSC, bridged to TCP
                 via socat. [DONE — first draft]
bootstrap.sh     VDI-side: installs p11-kit-client module + registers
                 with NSS. [DONE — first draft]
test-tls.sh      smoke test: tunnel listener check + pkcs11-tool slot
                 dump + openssl s_client against an NOAA endpoint.
                 [DONE — first draft]
```

## Try the VDI side

After the laptop side is up and `pwrelay` forwards port 7888 (Phase 4
TODO — for now, manually `pw ssh -R 7888:127.0.0.1:7888 <vdi-host>`):

```bash
# in the VDI shell:
bash pcsc/bootstrap.sh        # registers pwrelay-cac with NSS
bash pcsc/test-tls.sh         # sanity check the chain
```

## Try the laptop side standalone (Mac/Linux)

```bash
brew install opensc p11-kit socat        # Mac, one time
bash pcsc/agent.sh                       # exposes CAC on 127.0.0.1:7888
```

In another terminal:

```bash
pkcs11-tool --module $(brew --prefix)/lib/p11-kit-client.so --list-slots \
    --slot-index 0
```

You should see the CAC's slots / certs. From here the missing piece
is wiring the VDI side to use `p11-kit-client.so` via NSS so Chrome
in the VDI picks the cert up.

## Windows laptop note

The current `agent.sh` is Bash + `p11-kit server` + `socat`. On
Windows the equivalent stack doesn't exist out of the box. We'll need
to write a parallel `agent.py` (similar to `laptop/agent.py` for FIDO)
that talks PKCS#11 directly via a Python binding and forwards to a TCP
socket. See the design doc's "Open questions" section.

## See also

- [`docs/cac-relay-design.md`](../docs/cac-relay-design.md) — full design
- [vsmartcard](https://frankmorgner.github.io/vsmartcard/) — alternative
  approach (virtual PC/SC reader); we chose PKCS#11 forwarding instead
- [p11-kit](https://p11-glue.github.io/p11-glue/p11-kit.html) — the
  upstream tooling we'll lean on
