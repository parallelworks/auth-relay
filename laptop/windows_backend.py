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

    client = WindowsClient(origin=wa["origin"])
    LOG.info("WindowsClient.make_credential: rp=%s user=%s", rp.get("id"), user.get("name"))
    response = client.make_credential(options)

    # response is an AuthenticatorAttestationResponse-like object.
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
        pub_key_alg = int(cose.ALGORITHM) if hasattr(cose, "ALGORITHM") else int(cose[3])
        # CoseKey has a .public_bytes() helper on newer python-fido2; older
        # versions: convert via cryptography.
        if hasattr(cose, "public_bytes"):
            pub_key_spki = cose.public_bytes()
        else:
            from cryptography.hazmat.primitives.serialization import (
                Encoding, PublicFormat,
            )
            crypto_pub = cose.public_key() if hasattr(cose, "public_key") else None
            if crypto_pub is not None:
                pub_key_spki = crypto_pub.public_bytes(
                    Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    except Exception as e:
        LOG.warning("could not derive publicKey SPKI: %r", e)

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

    client = WindowsClient(origin=wa["origin"])
    LOG.info("WindowsClient.get_assertion: rpId=%s", wa.get("rpId"))
    response = client.get_assertion(options)

    # AuthenticatorAssertionResponse-like; some python-fido2 versions
    # return a list of assertion choices — we take the first.
    if hasattr(response, "get_response"):
        # Newer python-fido2: AssertionSelection.get_response(0)
        first = response.get_response(0)
    else:
        first = response

    client_data = bytes(first.client_data)
    auth_data = bytes(first.authenticator_data)
    sig = bytes(first.signature)
    cred_id = first.credential_id

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
    user_handle = getattr(first, "user_handle", None)
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
