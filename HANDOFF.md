# Handoff — NOAA YubiKey Relay POC

**Date:** 2026-05-12 · **Authored on:** gpu.parallel.works (PW dev box)
**Origin:** Matthew Shaxted + Claude Code session
**Status:** Iteration 1 complete and validated. Ready to continue on the
agent author's Mac for iteration 2.

---

## 1. The problem we're solving

NOAA customers use Parallel Works ACTIVATE remote desktops (VNC-based) on
HPC compute nodes. They need to complete Google MFA inside the remote
browser using their YubiKey, but VNC does not forward USB HID devices —
so the YubiKey plugged into the user's laptop is invisible to the remote
browser. Google MFA is currently blocked from inside any ACTIVATE
session.

NOAA on-prem HPC systems run **without root**, which disqualifies most
off-the-shelf USB-redirection solutions (USB/IP, xrdp+FreeRDP USB
channels, NoMachine, NICE DCV) because they require kernel modules,
`uinput`, or system daemon installs. Cloud-side PW clusters (GCP, AWS,
Azure) do have root and are usable for prototyping, but the production
target is the no-root HPC environment.

## 2. The chosen architecture

A purely **userspace** CTAP relay. Three components, in three places:

```
USER'S LAPTOP (Mac)              LOGIN NODE (RHEL)         COMPUTE NODE (VNC)
─────────────────────            ─────────────────          ──────────────────
YubiKey (USB)                    pw-fido-relay              Browser in VNC
   │                             (userspace, $HOME-only)    │
   ▼                                  │                     │
laptop/agent.py    ──pw ssh -R──▶     │   ──ssh -L──▶  WebAuthn extension
(libfido2 via python-fido2)      forwards relay socket     + native messaging host
                                                            (per-user, $HOME)
```

Key properties:

- No root anywhere. No kernel modules, no `uinput`, no `pcscd`, no
  system daemons. The login-node footprint (`pw-fido-relay` + the
  `libfido2` shared library) is the *only* install ask we make of NOAA
  sysadmins, and it runs as the invoking user.
- The pw CLI tunnel is the **only sanctioned network path** from any
  remote PW session back to the laptop-side agent. The agent binds to
  `127.0.0.1` only — enforced in code (no `--host` flag), not by
  convention.
- Latency is dominated by the user's physical touch on the YubiKey
  (seconds); relay overhead measured at 38 ms median, 44 ms p95.

## 3. What iteration 1 proved

A length-prefixed JSON op protocol over a `pw ssh -R` reverse tunnel
between gpu.parallel.works (standing in for "laptop") and the PW
workspace `pw-user-matthewshaxted-0` (standing in for "remote"). Four
synthetic ops: `ping`, `info`, `make_credential`, `get_assertion`. All
four return correctly, latency tight, agent log shows the workspace
arriving on loopback (the tunneled side, not via an open port).

What is **not yet real**:
- The agent's responses are synthesized — no `libfido2`, no real
  YubiKey. (Iteration 2.)
- The wire format is invented JSON, not CTAP2 CBOR. (Iteration 2.)
- No browser. Nothing on the workspace side speaks WebAuthn yet.
  (Iteration 3.)

So iteration 1 is "the pipe works." It does *not* yet let a real Chrome
in a real VNC desktop do Google MFA — that requires iterations 2 and 3.

## 4. How to run what exists

Once the project is on your Mac (see §6), see `README.md`. Two tests:

- **Test A** — both halves run on your Mac on a loopback port. Validates
  code correctness in isolation. Sub-millisecond round-trip.
- **Test B** — agent on your Mac, client runs on the PW workspace
  through a `pw ssh -R` tunnel. Validates the full relay path. ~40 ms
  median round-trip. The README has copy-paste invocations.

## 5. Iteration 2 (next, ~1 day of work)

**Goal:** real YubiKey, real CTAP2 wire format. After this, the agent
log shows a YubiKey touch happening when the workspace asks for a
credential.

1. `pip install fido2` (Yubico's library, wraps libfido2). Plug a
   YubiKey into the Mac.
2. In `laptop/agent.py`, replace `handle_op()`'s synthetic branches
   with `python-fido2` calls. Discover the device via
   `fido2.hid.CtapHidDevice.list_devices()`, perform `MakeCredential`
   or `GetAssertion` against it, return the real CBOR.
3. Replace the JSON envelope in `common/protocol.py` with raw CTAP2
   CBOR pass-through (still length-prefixed). Update `workspace/`
   clients accordingly.
4. Write a `workspace/test_real.py` that calls a real
   `make_credential` and prints the credential ID, AAGUID, and
   attestation. Expect a physical touch on the YubiKey when this runs.

Acceptance: run the test from the workspace, see the YubiKey LED blink,
touch it, get a valid credential back.

## 6. Iteration 3 (after 2)

**Goal:** a real browser in a VNC desktop on a PW cluster uses the
YubiKey end-to-end against `accounts.google.com`.

Recommended approach: **CDP virtual authenticator.**
- Launch Chromium on the workspace with `--remote-debugging-port=PORT`.
- A small Python harness connects via the Chrome DevTools Protocol and
  calls `WebAuthn.addVirtualAuthenticator` to register a virtual FIDO2
  authenticator. The harness backs that authenticator by forwarding all
  CTAP2 commands to the relay (which forwards them to the real
  YubiKey on the Mac).
- The user opens `accounts.google.com` in this Chromium and signs in
  normally. WebAuthn sees the virtual authenticator; the virtual
  authenticator's responses come from the laptop's real YubiKey.

UX cost: users launch Google via a "PW-managed Chromium" wrapper, not
their normal browser icon. This is the price of doing this purely in
userspace.

The alternative (`uinput` virtual HID) is cleaner UX but needs root on
compute nodes, which we don't have on NOAA HPC. Disqualified.

## 7. Iteration 4 (the NOAA install request)

Once iteration 3 works on a PW cloud cluster, the artifact for NOAA is:

- A short proof-of-path doc (this file plus the README, plus latency
  numbers and the security boundary argument).
- Install request: `libfido2` shared library + a signed
  `pw-fido-relay` binary on **login nodes only** (not compute nodes).
- The launcher script change that adds the internal `ssh -L` from
  compute → login node when starting a VNC session.

## 8. Open questions / decisions still owed

- **Relay binary vs `pw fido-relay` subcommand.** Shipping the
  login-node relay as a subcommand of the existing `pw` CLI would
  reduce the install ask to "the pw CLI on login nodes" rather than
  two artifacts. Probably preferable.
- **Browser scope.** Chrome/Chromium only initially? Firefox support is
  doable but adds work. CDP virtual authenticator is Chromium-only.
- **Multi-compute-node session routing.** When the user's VNC session
  lands on a different compute node mid-relay (rare but possible), how
  do we re-rendezvous? Probably the launcher script reissues the
  internal `ssh -L`; needs a small reconnect loop in the workspace-side
  client.
- **Audit logging.** Should every WebAuthn ceremony route through the
  relay produce a log line that NOAA can audit? Probably yes; cheap to
  add in iteration 2.

## 9. Layout

```
common/protocol.py             length-prefixed JSON framing (iteration 1)
laptop/agent.py                laptop-side TCP server, synthetic backend (iteration 1)
                               → real libfido2 backend in iteration 2
workspace/client.py            workspace-side relay client (uses common/)
workspace/standalone_test.py   self-contained scp-friendly variant
setup-mac.sh                   one-time prereq install for the Mac
README.md                      user-facing usage
HANDOFF.md                     this document
```

## 10. Contact

Matthew Shaxted — author of iteration 1, current owner.
PW context used: `noaa.parallel.works`, user `Matthew.Shaxted`,
workspace `pw-user-matthewshaxted-0`.
