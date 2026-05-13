# CAC / PIV smartcard relay (planned)

Sibling to `vdi/` for FIDO2 — forwards the user's CAC / PIV smartcard
from the laptop's USB CCID reader to the in-VDI Chrome so TLS
client-cert sign-in works against `sso.noaa.gov` and similar services.

**Status: design only.** See [`docs/cac-relay-design.md`](../docs/cac-relay-design.md)
for the architecture and the path forward.

## Architecture (one line)

`Laptop CAC → OpenSC PKCS#11 → p11-kit server → pw ssh -R → p11-kit-client.so → NSS → VDI Chrome`

## Why it's separate from `vdi/`

The FIDO2 relay hooks `chrome.webAuthenticationProxy` (a JS-level API)
to forward CTAPHID CBOR frames. CAC/PIV is **TLS-client-cert auth** —
intercepted at the NSS / PKCS#11 layer, below the browser. Completely
different code, even though the `pw ssh -R` tunnel pattern is the same.

## Files (when this is built)

```
agent.sh         laptop-side: p11-kit server wrapping OpenSC, listening on a
                 local TCP port the pw ssh -R tunnel reaches
bootstrap.sh     VDI-side: installs p11-kit-client module + registers with NSS
test-tls.sh      smoke test: openssl s_client against an NOAA endpoint
```

None of these exist yet. The current placeholder is so a future
implementer has the directory structure ready and the design doc
right next door.

## See also

- [`docs/cac-relay-design.md`](../docs/cac-relay-design.md) — full design
- [vsmartcard](https://frankmorgner.github.io/vsmartcard/) — alternative
  approach (virtual PC/SC reader); we chose PKCS#11 forwarding instead
- [p11-kit](https://p11-glue.github.io/p11-glue/p11-kit.html) — the
  upstream tooling we'll lean on
