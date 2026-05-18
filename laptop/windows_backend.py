"""Windows native WebAuthn backend.

Used when the agent runs on Windows. Win10+ reserves the FIDO HID
interface for ``webauthn.dll`` (the same DLL Chrome and Edge use
locally), so userspace python-fido2 ``CtapHidDevice`` enumeration fails
to find the YubiKey unless the agent is running elevated. Instead of
forwarding raw CTAP2 CBOR frames to a HID device, we accept the
higher-level WebAuthn options from the extension, call
``fido2.client.WindowsClient`` (which goes through webauthn.dll), and
return a pre-built ``PublicKeyCredential`` JSON.

Why this works without admin: ``webauthn.dll`` runs as a user-mode COM
server and arbitrates HID access on the caller's behalf. The OS shows
its own "Use this passkey" dialog, the user touches the YubiKey, and
the DLL hands the response back. The relay's job is just to feed the
options in and ship the response back over the tunnel.

Wire-format note: the extension still sends the legacy CTAP2 ``frame``
field for Linux/macOS compatibility. On Windows we ignore ``frame``
and use the ``webauthn`` payload (rp, user, challenge, origin, etc.).
Response shape on Windows is a complete ``PublicKeyCredential`` JSON,
not a CTAP2 frame — the extension uses it verbatim. See
``laptop/agent.py`` for the dispatch + protocol details.
"""

from __future__ import annotations

import base64
import logging
from typing import Any

LOG = logging.getLogger("agent.windows")


# ---------- b64url helpers --------------------------------------------------

def _b64url_decode(s: str) -> bytes:
    s = s + "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s.replace("-", "+").replace("_", "/"))


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


# ---------- top-level entry -------------------------------------------------

def handle_webauthn(req: dict) -> dict:
    """Dispatch a webauthn request from the wire to WindowsClient.

    ``req`` is a parsed JSON message with shape:
        {"id": N, "type": "frame",
         "webauthn": {"op": "create"|"get", <options...>}}

    Returns a dict to be sent back on the wire:
        {"id": N, "ok": True, "webauthn": <PublicKeyCredential JSON>}
      | {"id": N, "ok": False, "error": "..."}
    """
    wa = req.get("webauthn")
    if not wa:
        return {"id": req.get("id"), "ok": False,
                "error": "Windows backend requires the 'webauthn' field "
                         "in the request — extension version too old?"}
    try:
        op = wa.get("op")
        if op == "create":
            cred = _make_credential(wa)
        elif op == "get":
            cred = _get_assertion(wa)
        else:
            return {"id": req.get("id"), "ok": False,
                    "error": f"unknown op {op!r}"}
        return {"id": req.get("id"), "ok": True, "webauthn": cred}
    except Exception as e:
        LOG.exception("Windows WebAuthn op failed")
        return {"id": req.get("id"), "ok": False, "error": f"{type(e).__name__}: {e}"}


# ---------- make_credential -------------------------------------------------

def _cose_to_spki(cose) -> bytes:
    """Convert a COSE_Key (python-fido2 CoseKey or dict-like) to SPKI DER.

    Chrome 148+ requires the SPKI bytes in the WebAuthn proxy response's
    `publicKey` field. python-fido2 has a few API paths to get there;
    fall back to manual SPKI construction for ES256 (P-256), which is
    what almost every YubiKey ships out of the box.
    """
    # Path 1: CoseKey.public_bytes() helper (some versions)
    if hasattr(cose, "public_bytes"):
        try:
            b = cose.public_bytes()
            if b:
                return b
        except Exception:
            pass
    # Path 2: CoseKey -> cryptography public_key -> SPKI DER
    try:
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat,
        )
        pk_attr = getattr(cose, "public_key", None)
        pk = pk_attr() if callable(pk_attr) else pk_attr
        if pk is not None and hasattr(pk, "public_bytes"):
            return pk.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    except Exception:
        pass
    # Path 3: Manual SPKI assembly for ES256 / P-256 (RFC 5480).
    # COSE_Key fields per RFC 8152: 1=kty, 3=alg, -1=crv, -2=x, -3=y
    try:
        getf = (lambda k: cose.get(k)) if hasattr(cose, "get") else (lambda k: cose[k])
        kty = getf(1)
        alg = getf(3)
        if kty == 2 and alg == -7:  # EC2, ES256
            crv = getf(-1)
            x = getf(-2)
            y = getf(-3)
            if crv == 1 and isinstance(x, (bytes, bytearray)) and isinstance(y, (bytes, bytearray)):
                if len(x) == 32 and len(y) == 32:
                    # SPKI prefix for P-256 + uncompressed point (0x04 || x || y)
                    spki_prefix = bytes.fromhex(
                        "3059301306072a8648ce3d020106082a8648ce3d030107034200"
                    )
                    return spki_prefix + b"\x04" + bytes(x) + bytes(y)
    except Exception:
        pass
    return b""


def _unwrap_registration_response(r):
    """Return the inner AuthenticatorAttestationResponse-like object.

    python-fido2 1.1+ returns a RegistrationResponse that wraps the
    AuthenticatorAttestationResponse in a .response attribute. Older
    versions return the inner directly. Walk one level if needed.
    """
    if hasattr(r, "attestation_object"):
        return r
    if hasattr(r, "response") and hasattr(r.response, "attestation_object"):
        return r.response
    raise AttributeError(
        f"make_credential returned an unrecognized shape: {type(r).__name__}; "
        f"attrs={[a for a in dir(r) if not a.startswith('_')]}"
    )


def _find_credential_id(r) -> "bytes | None":
    """Walk a python-fido2 assertion result and return the credentialId bytes.

    On 1.1+ the AuthenticationResponse wrapper carries raw_id; on
    AssertionSelection the wrapper's get_response(0) reaches it. Walk
    the wrappers and check any attribute named raw_id / credential_id /
    credential along the way.
    """
    seen = set()
    while r is not None and id(r) not in seen:
        seen.add(id(r))
        for attr in ("raw_id", "credential_id", "credential"):
            v = getattr(r, attr, None)
            if isinstance(v, (bytes, bytearray)) and v:
                return bytes(v)
            # PublicKeyCredentialDescriptor with .id
            if v is not None and hasattr(v, "id"):
                vid = getattr(v, "id", None)
                if isinstance(vid, (bytes, bytearray)) and vid:
                    return bytes(vid)
        # Walk one more level.
        if hasattr(r, "get_response"):
            try:
                r = r.get_response(0)
                continue
            except Exception:
                pass
        r = getattr(r, "response", None)
    return None


def _unwrap_assertion_response(r):
    """Walk through wrapper layers to find an object that has both
    ``authenticator_data`` and ``client_data`` directly.

    python-fido2's API has TWO layers of wrappers as of 1.1:
        AssertionSelection.get_response(0) -> AuthenticationResponse
        AuthenticationResponse.response   -> AuthenticatorAssertionResponse
    We need to peel both off. Walk iteratively until the attributes we
    need are directly present (or give up with a clear error).
    """
    seen = set()
    while True:
        if id(r) in seen:
            break
        seen.add(id(r))
        # The shape we want — used directly by the caller.
        if hasattr(r, "authenticator_data") and hasattr(r, "client_data"):
            return r
        # AssertionSelection-style: pick the first choice.
        if hasattr(r, "get_response"):
            try:
                r = r.get_response(0)
                continue
            except Exception:
                pass
        # Generic wrapper: peel `.response`.
        inner = getattr(r, "response", None)
        if inner is not None and inner is not r:
            r = inner
            continue
        break
    raise AttributeError(
        f"get_assertion returned an unrecognized shape: {type(r).__name__}; "
        f"attrs={[a for a in dir(r) if not a.startswith('_')]}"
    )


def _force_hwnd(client) -> None:
    """Ensure the WindowsClient instance has a non-zero HWND attribute.

    Even if our constructor call passed handle=hwnd, some python-fido2
    versions ignore it (or initialize hwnd internally to 0). After
    construction, inspect the client for any attribute that looks like
    an HWND slot and overwrite it if it's falsy.

    Also logs the relevant attributes so the user can see what
    python-fido2 actually stored.
    """
    hwnd = _get_foreground_hwnd()
    LOG.info("_force_hwnd: resolved hwnd=%s; will force into client", hwnd)
    if not hwnd:
        LOG.error("_force_hwnd: HWND is 0; webauthn.dll WILL reject with E_ACCESSDENIED")
        return
    candidates = ("handle", "hwnd", "_handle", "_hwnd", "window_handle", "_window_handle")
    found = []
    for attr in candidates:
        if hasattr(client, attr):
            current = getattr(client, attr, None)
            found.append(f"{attr}={current}")
            try:
                setattr(client, attr, hwnd)
            except Exception as e:
                LOG.warning("could not set %s on client: %r", attr, e)
    LOG.info("_force_hwnd: existing attrs %s; all set to %s", found, hwnd)
    # Also list any other attributes that might be related (helps diagnose
    # which attribute python-fido2 actually consults inside make_credential).
    related = [a for a in dir(client)
               if not a.startswith("__")
               and ("h" == a[0].lower() or "wnd" in a.lower() or "window" in a.lower())]
    if related:
        LOG.info("_force_hwnd: other client attrs that may be relevant: %s", related)


def _get_foreground_hwnd():
    """Resolve a usable HWND for webauthn.dll's UI parent.

    WebAuthNAuthenticatorMakeCredential refuses to operate on
    HWND = NULL (returns E_ACCESSDENIED, WinError -2147417829). We
    need to hand it a window handle to be the parent of its dialog.

    Pwrelay launches the agent as a detached subprocess (no controlling
    console), so GetConsoleWindow() returns 0 here. GetForegroundWindow()
    is racy — may return 0 if no window is focused on the user's
    session at that instant. GetDesktopWindow() always returns a valid
    HWND; webauthn.dll accepts it as a parent even though the dialog
    visually attaches to whatever has focus.

    Try in order, log each result. The first non-zero HWND wins.
    """
    import ctypes
    candidates = [
        ("GetForegroundWindow", lambda: ctypes.windll.user32.GetForegroundWindow()),
        ("GetConsoleWindow",    lambda: ctypes.windll.kernel32.GetConsoleWindow()),
        ("GetDesktopWindow",    lambda: ctypes.windll.user32.GetDesktopWindow()),
        ("GetShellWindow",      lambda: ctypes.windll.user32.GetShellWindow()),
    ]
    for name, fn in candidates:
        try:
            hwnd = fn()
        except Exception as e:
            LOG.warning("HWND probe %s raised: %r", name, e)
            continue
        LOG.info("HWND probe %s = %s", name, hwnd)
        if hwnd:
            return hwnd
    LOG.error("could not resolve any HWND; webauthn.dll will likely refuse with E_ACCESSDENIED")
    return 0


def _make_windows_client(WindowsClient, origin: str):
    """Instantiate WindowsClient across python-fido2 versions.

    python-fido2 reshuffled this API across releases:
      0.9/1.0:  WindowsClient(origin: str, handle=None)
      1.1+:     WindowsClient(client_data_collector, handle=None, ...)

    Crucially we MUST pass a non-NULL window handle (HWND), or
    WebAuthNAuthenticatorMakeCredential returns E_ACCESSDENIED.
    Some python-fido2 builds default to GetForegroundWindow but
    others pass NULL — pass explicitly to be safe.
    """
    import inspect
    hwnd = _get_foreground_hwnd()
    LOG.info("instantiating WindowsClient with hwnd=%s origin=%s", hwnd, origin)

    Collector = _import_client_data_collector()

    # NEW API: WindowsClient(DefaultClientDataCollector(origin), handle=hwnd)
    if Collector is not None:
        for attempt in (
            lambda: WindowsClient(Collector(origin), handle=hwnd),
            lambda: WindowsClient(Collector(origin), hwnd),
            lambda: WindowsClient(Collector(origin)),
            lambda: WindowsClient(client_data_collector=Collector(origin), handle=hwnd),
            lambda: WindowsClient(collector=Collector(origin), handle=hwnd),
        ):
            try:
                return attempt()
            except TypeError:
                continue

    # OLD API: WindowsClient(origin, handle=hwnd)
    for attempt in (
        lambda: WindowsClient(origin, handle=hwnd),
        lambda: WindowsClient(origin, hwnd),
        lambda: WindowsClient(origin),
    ):
        try:
            return attempt()
        except TypeError:
            continue
    for kw in ("origin", "verify_origin", "rp_id"):
        try:
            return WindowsClient(**{kw: origin}, handle=hwnd)
        except TypeError:
            try:
                return WindowsClient(**{kw: origin})
            except TypeError:
                continue

    try:
        sig = inspect.signature(WindowsClient)
    except Exception:
        sig = "<unknown>"
    raise TypeError(
        f"can't instantiate WindowsClient. Tried new-API "
        f"(DefaultClientDataCollector wrapper) and old-API (str origin), "
        f"with and without handle=hwnd. Signature: {sig}. "
        f"Send this back to extend the fallbacks."
    )


def _import_client_data_collector():
    """Return DefaultClientDataCollector class, or None if not available."""
    for path in (
        ("fido2.client", "DefaultClientDataCollector"),
        ("fido2.client._client_data_collector", "DefaultClientDataCollector"),
        ("fido2.client.client_data_collector", "DefaultClientDataCollector"),
    ):
        try:
            mod = __import__(path[0], fromlist=[path[1]])
            return getattr(mod, path[1])
        except (ImportError, AttributeError):
            continue
    return None


def _import_windows_client():
    """Locate the WindowsClient class across python-fido2 versions.

    python-fido2 has moved WindowsClient's export location more than once:
      0.x/1.0: fido2.client.WindowsClient
      1.1+:    fido2.client.windows.WindowsClient (submodule, sometimes
               not re-exported from the parent)
      future:  unclear
    Try in priority order.
    """
    last_err = None
    for path in (
        ("fido2.client", "WindowsClient"),
        ("fido2.client.windows", "WindowsClient"),
        ("fido2.win_api", "WindowsClient"),    # very old name
    ):
        try:
            mod = __import__(path[0], fromlist=[path[1]])
            return getattr(mod, path[1])
        except (ImportError, AttributeError) as e:
            last_err = e
            continue
    raise ImportError(
        f"could not locate WindowsClient in python-fido2; "
        f"tried fido2.client, fido2.client.windows, fido2.win_api. "
        f"`pip install --upgrade fido2` may help. Last error: {last_err}"
    )


def _make_credential(wa: dict) -> dict:
    """Call WindowsClient.make_credential and return a PublicKeyCredential dict."""
    WindowsClient = _import_windows_client()
    from fido2.webauthn import (
        PublicKeyCredentialCreationOptions,
        PublicKeyCredentialRpEntity,
        PublicKeyCredentialUserEntity,
        PublicKeyCredentialParameters,
        PublicKeyCredentialType,
        PublicKeyCredentialDescriptor,
        AuthenticatorSelectionCriteria,
        UserVerificationRequirement,
        ResidentKeyRequirement,
        AttestationConveyancePreference,
        AuthenticatorAttachment,
    )

    rp = wa["rp"]
    user = wa["user"]
    options = PublicKeyCredentialCreationOptions(
        rp=PublicKeyCredentialRpEntity(name=rp["name"], id=rp.get("id")),
        user=PublicKeyCredentialUserEntity(
            id=_b64url_decode(user["id"]),
            name=user["name"],
            display_name=user.get("displayName", user["name"]),
        ),
        challenge=_b64url_decode(wa["challenge"]),
        pub_key_cred_params=[
            PublicKeyCredentialParameters(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                alg=int(p["alg"]),
            )
            for p in wa.get("pubKeyCredParams", [])
        ],
        timeout=wa.get("timeout"),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                id=_b64url_decode(c["id"]),
                transports=c.get("transports"),
            )
            for c in wa.get("excludeCredentials", [])
        ] or None,
        authenticator_selection=_authn_selection(wa.get("authenticatorSelection")),
        attestation=_attestation_pref(wa.get("attestation", "none")),
    )

    client = _make_windows_client(WindowsClient, wa["origin"])
    _force_hwnd(client)
    LOG.info("WindowsClient.make_credential: rp=%s user=%s", rp.get("id"), user.get("name"))
    raw_response = client.make_credential(options)

    # python-fido2 response shapes vary by version:
    #   1.0:    AuthenticatorAttestationResponse (has .attestation_object, .client_data)
    #   1.1+:   RegistrationResponse (wraps: .response.attestation_object, .response.client_data)
    # Unwrap the outer container if present.
    response = _unwrap_registration_response(raw_response)

    attestation_obj = bytes(response.attestation_object)
    client_data = bytes(response.client_data)
    auth_data = response.attestation_object.auth_data
    auth_data_bytes = bytes(auth_data)
    credential_id = auth_data.credential_data.credential_id

    # WebAuthn-Level-3 additions Chrome 148+ requires in proxy responses.
    pub_key_spki = b""
    pub_key_alg = 0
    try:
        cose = auth_data.credential_data.public_key
        pub_key_alg = int(cose.get(3) if hasattr(cose, "get") else cose[3])
        pub_key_spki = _cose_to_spki(cose)
    except Exception as e:
        LOG.warning("could not derive publicKey SPKI from COSE key: %r", e)

    return {
        "id": _b64url_encode(credential_id),
        "rawId": _b64url_encode(credential_id),
        "type": "public-key",
        "authenticatorAttachment": "cross-platform",
        "response": {
            "clientDataJSON": _b64url_encode(client_data),
            "attestationObject": _b64url_encode(attestation_obj),
            "transports": ["usb"],
            "authenticatorData": _b64url_encode(auth_data_bytes),
            "publicKey": _b64url_encode(pub_key_spki) if pub_key_spki else "",
            "publicKeyAlgorithm": pub_key_alg,
        },
        "clientExtensionResults": {},
    }


# ---------- get_assertion ---------------------------------------------------

def _get_assertion(wa: dict) -> dict:
    """Call WindowsClient.get_assertion and return a PublicKeyCredential dict."""
    WindowsClient = _import_windows_client()
    from fido2.webauthn import (
        PublicKeyCredentialRequestOptions,
        PublicKeyCredentialDescriptor,
        PublicKeyCredentialType,
        UserVerificationRequirement,
    )

    options = PublicKeyCredentialRequestOptions(
        challenge=_b64url_decode(wa["challenge"]),
        timeout=wa.get("timeout"),
        rp_id=wa.get("rpId"),
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                id=_b64url_decode(c["id"]),
                transports=c.get("transports"),
            )
            for c in wa.get("allowCredentials", [])
        ] or None,
        user_verification=_uv_requirement(wa.get("userVerification")),
    )

    client = _make_windows_client(WindowsClient, wa["origin"])
    _force_hwnd(client)
    LOG.info("WindowsClient.get_assertion: rpId=%s", wa.get("rpId"))
    raw_response = client.get_assertion(options)

    # python-fido2 response shapes vary (1.1+ has two nested wrappers):
    #   AssertionSelection.get_response(0) -> AuthenticationResponse
    #   AuthenticationResponse.response    -> AuthenticatorAssertionResponse
    inner = _unwrap_assertion_response(raw_response)

    client_data = bytes(inner.client_data)
    auth_data = bytes(inner.authenticator_data)
    sig = bytes(inner.signature)

    # credential_id may live on any of: the inner, the intermediate
    # AuthenticationResponse (as raw_id / id), or the AssertionSelection.
    # Try all of them.
    cred_id = (
        getattr(inner, "credential_id", None)
        or getattr(inner, "credential", None)
        or _find_credential_id(raw_response)
    )

    out = {
        "id": _b64url_encode(cred_id) if cred_id else None,
        "rawId": _b64url_encode(cred_id) if cred_id else None,
        "type": "public-key",
        "authenticatorAttachment": "cross-platform",
        "response": {
            "clientDataJSON": _b64url_encode(client_data),
            "authenticatorData": _b64url_encode(auth_data),
            "signature": _b64url_encode(sig),
        },
        "clientExtensionResults": {},
    }
    user_handle = getattr(inner, "user_handle", None)
    if user_handle:
        out["response"]["userHandle"] = _b64url_encode(bytes(user_handle))
    return out


# ---------- option mapping helpers ------------------------------------------

def _authn_selection(d):
    if not d:
        return None
    from fido2.webauthn import (
        AuthenticatorSelectionCriteria,
        AuthenticatorAttachment,
        UserVerificationRequirement,
        ResidentKeyRequirement,
    )
    kw: dict[str, Any] = {}
    if d.get("authenticatorAttachment"):
        kw["authenticator_attachment"] = AuthenticatorAttachment(d["authenticatorAttachment"])
    if d.get("requireResidentKey") is not None:
        kw["require_resident_key"] = bool(d["requireResidentKey"])
    if d.get("residentKey"):
        kw["resident_key"] = ResidentKeyRequirement(d["residentKey"])
    if d.get("userVerification"):
        kw["user_verification"] = UserVerificationRequirement(d["userVerification"])
    return AuthenticatorSelectionCriteria(**kw)


def _attestation_pref(s):
    from fido2.webauthn import AttestationConveyancePreference
    if not s:
        return None
    try:
        return AttestationConveyancePreference(s)
    except ValueError:
        return None


def _uv_requirement(s):
    from fido2.webauthn import UserVerificationRequirement
    if not s:
        return None
    try:
        return UserVerificationRequirement(s)
    except ValueError:
        return None
