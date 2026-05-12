// PW YubiKey Relay — service worker.
//
// Intercepts WebAuthn navigator.credentials.create() / .get() in the
// containing browser via chrome.webAuthenticationProxy, translates each
// request to a CTAP2 ceremony, forwards the raw CBOR frame over a native
// messaging host that pipes it to the laptop relay agent's TCP socket,
// then translates the CTAP2 response back into a WebAuthn JSON response.
//
// Wire shape (extension <-> NMH):
//   request:  {id: int, type: "frame", frame: <base64url of ctap2_cmd||cbor>}
//   response: {id: int, ok: true,  frame: <base64url of status||cbor>}
//          | {id: int, ok: false, error: "..."}

const NMH_NAME = "com.parallelworks.yubikey_relay";

// ----------------------------------------------------------------------------
// base64url helpers
// ----------------------------------------------------------------------------

function bytesToB64Url(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = "";
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64UrlToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function concatBytes(...arrs) {
  let total = 0;
  for (const a of arrs) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

// ----------------------------------------------------------------------------
// Minimal CBOR encoder/decoder (CTAP2 subset).
// Supports: positive int (0..2^53), negative int, byte string, text string,
// array, map (with int or string keys), bool, null. No floats, no tags.
// ----------------------------------------------------------------------------

function cborEncodeUint(major, n) {
  if (n < 24) return new Uint8Array([(major << 5) | n]);
  if (n < 0x100) return new Uint8Array([(major << 5) | 24, n]);
  if (n < 0x10000) return new Uint8Array([(major << 5) | 25, n >> 8, n & 0xff]);
  if (n < 0x100000000) {
    return new Uint8Array([
      (major << 5) | 26,
      (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff,
    ]);
  }
  // 64-bit: split via BigInt
  const big = BigInt(n);
  const buf = new Uint8Array(9);
  buf[0] = (major << 5) | 27;
  for (let i = 0; i < 8; i++) buf[8 - i] = Number((big >> BigInt(8 * i)) & 0xffn);
  return buf;
}

function cborEncode(v) {
  if (v === null) return new Uint8Array([0xf6]);
  if (v === undefined) return new Uint8Array([0xf7]);
  if (typeof v === "boolean") return new Uint8Array([v ? 0xf5 : 0xf4]);
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new Error("non-integer numbers not supported");
    if (v >= 0) return cborEncodeUint(0, v);
    return cborEncodeUint(1, -v - 1);
  }
  if (typeof v === "string") {
    const u = new TextEncoder().encode(v);
    return concatBytes(cborEncodeUint(3, u.length), u);
  }
  if (v instanceof Uint8Array) return concatBytes(cborEncodeUint(2, v.length), v);
  if (v instanceof ArrayBuffer) {
    const u = new Uint8Array(v);
    return concatBytes(cborEncodeUint(2, u.length), u);
  }
  if (Array.isArray(v)) {
    const parts = [cborEncodeUint(4, v.length)];
    for (const el of v) parts.push(cborEncode(el));
    return concatBytes(...parts);
  }
  if (v instanceof Map) {
    // Encode keys in their natural insertion order. CTAP2 demands canonical
    // ordering on some paths (e.g., authenticatorClientPin), but for the
    // make_credential / get_assertion params we send, the YubiKey accepts
    // any ordering. Keep things simple here.
    const parts = [cborEncodeUint(5, v.size)];
    for (const [k, val] of v) {
      parts.push(cborEncode(k));
      parts.push(cborEncode(val));
    }
    return concatBytes(...parts);
  }
  if (typeof v === "object") {
    // Plain object => text-keyed map
    const keys = Object.keys(v);
    const parts = [cborEncodeUint(5, keys.length)];
    for (const k of keys) {
      parts.push(cborEncode(k));
      parts.push(cborEncode(v[k]));
    }
    return concatBytes(...parts);
  }
  throw new Error("cannot encode value of type " + typeof v);
}

function cborDecode(bytes) {
  let off = 0;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  function readInt(info) {
    if (info < 24) return info;
    if (info === 24) { const v = view.getUint8(off); off += 1; return v; }
    if (info === 25) { const v = view.getUint16(off, false); off += 2; return v; }
    if (info === 26) { const v = view.getUint32(off, false); off += 4; return v; }
    if (info === 27) {
      const hi = view.getUint32(off, false), lo = view.getUint32(off + 4, false);
      off += 8;
      // Most CTAP2 lengths fit in 53 bits; bail if not.
      const big = (BigInt(hi) << 32n) | BigInt(lo);
      if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("cbor uint too large");
      return Number(big);
    }
    throw new Error("indefinite length not supported");
  }

  function readItem() {
    const first = view.getUint8(off++);
    const major = first >> 5;
    const info = first & 0x1f;
    switch (major) {
      case 0: return readInt(info);                  // positive int
      case 1: return -1 - readInt(info);             // negative int
      case 2: {                                      // byte string
        const n = readInt(info);
        const v = new Uint8Array(bytes.buffer, bytes.byteOffset + off, n);
        off += n;
        return v.slice();
      }
      case 3: {                                      // text string
        const n = readInt(info);
        const v = new Uint8Array(bytes.buffer, bytes.byteOffset + off, n);
        off += n;
        return new TextDecoder().decode(v);
      }
      case 4: {                                      // array
        const n = readInt(info);
        const out = [];
        for (let i = 0; i < n; i++) out.push(readItem());
        return out;
      }
      case 5: {                                      // map
        const n = readInt(info);
        const out = new Map();
        for (let i = 0; i < n; i++) {
          const k = readItem();
          const v = readItem();
          out.set(k, v);
        }
        return out;
      }
      case 7: {
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22) return null;
        if (info === 23) return undefined;
        throw new Error("unsupported simple value: " + info);
      }
      default:
        throw new Error("unsupported cbor major type: " + major);
    }
  }

  const item = readItem();
  return { value: item, consumed: off };
}

// ----------------------------------------------------------------------------
// Native messaging port to the local NMH (relay.py).
// ----------------------------------------------------------------------------

let nmhPort = null;
let nextNmhId = 1;
const pendingNmh = new Map(); // id -> {resolve, reject}

function ensureNmh() {
  if (nmhPort) return nmhPort;
  const port = chrome.runtime.connectNative(NMH_NAME);
  port.onMessage.addListener((msg) => {
    const id = msg.id;
    const p = pendingNmh.get(id);
    if (!p) {
      console.warn("[pw-relay] unmatched nmh response id=", id, msg);
      return;
    }
    pendingNmh.delete(id);
    if (msg.ok) p.resolve(msg);
    else p.reject(new Error(msg.error || "NMH error"));
  });
  port.onDisconnect.addListener(() => {
    const err = chrome.runtime.lastError;
    console.error("[pw-relay] nmh disconnected:", err && err.message);
    for (const [, p] of pendingNmh) p.reject(new Error("NMH disconnected"));
    pendingNmh.clear();
    nmhPort = null;
  });
  nmhPort = port;
  return port;
}

function nmhCall(req) {
  return new Promise((resolve, reject) => {
    const port = ensureNmh();
    const id = nextNmhId++;
    pendingNmh.set(id, { resolve, reject });
    port.postMessage({ id, ...req });
  });
}

async function relayFrame(ctapCmd, cborBody) {
  const frame = concatBytes(new Uint8Array([ctapCmd]), cborBody);
  const resp = await nmhCall({ type: "frame", frame: bytesToB64Url(frame) });
  const respBytes = b64UrlToBytes(resp.frame);
  if (respBytes.length === 0) throw new Error("empty relay response");
  const status = respBytes[0];
  const body = respBytes.subarray(1);
  if (status !== 0x00) {
    throw new CtapError(status);
  }
  return body;
}

class CtapError extends Error {
  constructor(status) {
    super(`CTAP error 0x${status.toString(16).padStart(2, "0")}`);
    this.name = "CtapError";
    this.status = status;
  }
}

// ----------------------------------------------------------------------------
// WebAuthn ↔ CTAP2 translation.
// ----------------------------------------------------------------------------

const CTAP2_CMD_MAKE_CREDENTIAL = 0x01;
const CTAP2_CMD_GET_ASSERTION = 0x02;

async function sha256(bytes) {
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(hash);
}

async function buildClientDataJSON(type, challengeBytes, origin, crossOrigin = false) {
  // The exact field order matches what browsers produce so RP-side
  // hash-recomputation matches in case the RP recomputes from individual
  // fields (some do, most just verify the hash).
  const obj = {
    type,
    challenge: bytesToB64Url(challengeBytes),
    origin,
    crossOrigin,
  };
  const json = JSON.stringify(obj);
  return new TextEncoder().encode(json);
}

async function getActiveOrigin() {
  // The webAuthenticationProxy onCreateRequest event does not carry the tab
  // origin, so we have to find it ourselves. Best-effort: the active tab in
  // the focused window.
  const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  if (tabs.length === 0 || !tabs[0].url) return null;
  return new URL(tabs[0].url).origin;
}

// makeCredential ------------------------------------------------------------

async function handleCreate(options, origin) {
  const challenge = b64UrlToBytes(options.challenge);
  const clientDataJSON = await buildClientDataJSON("webauthn.create", challenge, origin);
  const clientDataHash = await sha256(clientDataJSON);

  const rp = options.rp;
  const user = { ...options.user, id: b64UrlToBytes(options.user.id) };
  const pubKeyCredParams = options.pubKeyCredParams;
  const excludeList = (options.excludeCredentials || []).map(d => ({
    type: d.type,
    id: b64UrlToBytes(d.id),
    ...(d.transports ? { transports: d.transports } : {}),
  }));

  // CTAP2 makeCredential request CBOR map (integer keys per CTAP2 spec).
  const req = new Map();
  req.set(1, clientDataHash);
  req.set(2, rp);
  req.set(3, user);
  req.set(4, pubKeyCredParams);
  if (excludeList.length > 0) req.set(5, excludeList);

  const reqBytes = cborEncode(req);
  const respBytes = await relayFrame(CTAP2_CMD_MAKE_CREDENTIAL, reqBytes);
  const { value: respMap } = cborDecode(respBytes);
  if (!(respMap instanceof Map)) throw new Error("expected CBOR map in response");

  const fmt = respMap.get(1);
  const authData = respMap.get(2);
  const attStmt = respMap.get(3);
  console.log("[pw-relay] ctap make_credential response: fmt=", fmt, " authData.len=", authData && authData.length, " attStmt is Map?", attStmt instanceof Map);
  if (!fmt || !authData) throw new Error("incomplete make_credential response");

  // Parse authData to extract credentialId and COSE public key.
  // Layout: rpIdHash(32) flags(1) signCount(4) [AAGUID(16) credIdLen(2) credId(N) cosePubKey(...)]
  if (authData.length < 37) throw new Error("authData too short");
  const flags = authData[32];
  if ((flags & 0x40) === 0) throw new Error("AT flag not set in authData");
  const aaguidStart = 37;
  const credIdLen = (authData[aaguidStart + 16] << 8) | authData[aaguidStart + 17];
  const credIdStart = aaguidStart + 18;
  const credId = authData.subarray(credIdStart, credIdStart + credIdLen);
  const coseKeyBytes = authData.subarray(credIdStart + credIdLen);

  const { value: coseKey, consumed: coseKeyLen } = cborDecode(coseKeyBytes);
  if (!(coseKey instanceof Map)) throw new Error("COSE key not a Map");
  // COSE_Key fields (per RFC 8152): 1=kty, 3=alg, -1=crv, -2=x, -3=y
  const alg = coseKey.get(3);
  const publicKeyBytes = cosePublicKeyToSpki(coseKey);
  console.log("[pw-relay] cose alg=", alg, " spki.len=", publicKeyBytes ? publicKeyBytes.length : null);

  // Reconstruct attestationObject as WebAuthn-format CBOR map with text keys.
  // Order: fmt, attStmt, authData (canonical CBOR length-first then lexical).
  const attObj = new Map();
  attObj.set("fmt", fmt);
  attObj.set("attStmt", attStmt instanceof Map ? attStmt : new Map());
  attObj.set("authData", authData);
  const attestationObject = cborEncode(attObj);
  console.log("[pw-relay] attestationObject len=", attestationObject.length);

  return {
    id: bytesToB64Url(credId),
    rawId: bytesToB64Url(credId),
    type: "public-key",
    authenticatorAttachment: "cross-platform",
    response: {
      clientDataJSON: bytesToB64Url(clientDataJSON),
      attestationObject: bytesToB64Url(attestationObject),
      transports: ["usb"],
      // WebAuthn-Level-3 additions (Chrome 148+ requires these in the
      // proxy responseJson for create()):
      authenticatorData: bytesToB64Url(authData),
      publicKey: publicKeyBytes ? bytesToB64Url(publicKeyBytes) : "",
      publicKeyAlgorithm: alg,
    },
    clientExtensionResults: {},
  };
}

// Convert a COSE_Key (CBOR Map, per RFC 8152) to its SubjectPublicKeyInfo
// (SPKI) DER encoding. Supports only EC2 P-256 (alg=-7) for iter 3 — RS256
// would need RSA SPKI which is more involved.
function cosePublicKeyToSpki(coseKey) {
  const kty = coseKey.get(1);
  const alg = coseKey.get(3);
  if (kty === 2 && alg === -7) {
    // EC2 / ES256 / P-256
    const x = coseKey.get(-2);
    const y = coseKey.get(-3);
    if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array)) return null;
    if (x.length !== 32 || y.length !== 32) return null;
    // SPKI prefix for P-256 (27 bytes): SEQUENCE { AlgorithmIdentifier, BIT STRING }
    const prefix = new Uint8Array([
      0x30, 0x59,
        0x30, 0x13,
          0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,           // id-ecPublicKey
          0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,     // prime256v1
        0x03, 0x42, 0x00,                                                  // BIT STRING (66 bytes, 0 unused)
          0x04,                                                            // uncompressed point marker
    ]);
    return concatBytes(prefix, x, y);
  }
  // Fallback: skip SPKI for unsupported algs; Chrome accepts publicKey="" but
  // publicKeyAlgorithm must still be the real alg.
  return null;
}

// getAssertion --------------------------------------------------------------

async function handleGet(options, origin) {
  const challenge = b64UrlToBytes(options.challenge);
  const clientDataJSON = await buildClientDataJSON("webauthn.get", challenge, origin);
  const clientDataHash = await sha256(clientDataJSON);

  const rpId = options.rpId;
  const allowList = (options.allowCredentials || []).map(d => ({
    type: d.type,
    id: b64UrlToBytes(d.id),
    ...(d.transports ? { transports: d.transports } : {}),
  }));

  const req = new Map();
  req.set(1, rpId);
  req.set(2, clientDataHash);
  if (allowList.length > 0) req.set(3, allowList);

  const reqBytes = cborEncode(req);
  const respBytes = await relayFrame(CTAP2_CMD_GET_ASSERTION, reqBytes);
  const { value: respMap } = cborDecode(respBytes);
  if (!(respMap instanceof Map)) throw new Error("expected CBOR map in assertion response");

  // Per CTAP2: 1 = credential (PublicKeyCredentialDescriptor), 2 = authData,
  // 3 = signature, 4 = user, 5 = numberOfCredentials.
  // For single-credential allow lists, 1 may be omitted by the authenticator;
  // we then use the credential the caller already provided.
  const credentialDesc = respMap.get(1);
  const authData = respMap.get(2);
  const signature = respMap.get(3);
  const user = respMap.get(4);
  console.log("[pw-relay] ctap get_assertion response: authData.len=", authData && authData.length,
              " sig.len=", signature && signature.length, " user?", !!user, " credentialDesc?", !!credentialDesc);
  if (!authData || !signature) throw new Error("incomplete get_assertion response");

  let credIdBytes;
  if (credentialDesc instanceof Map) {
    credIdBytes = credentialDesc.get("id");
  } else if (allowList.length === 1) {
    credIdBytes = allowList[0].id;
  } else {
    throw new Error("cannot determine credential id from assertion response");
  }

  const responseFields = {
    clientDataJSON: bytesToB64Url(clientDataJSON),
    authenticatorData: bytesToB64Url(authData),
    signature: bytesToB64Url(signature),
  };
  // userHandle is optional in WebAuthn-Level-3 JSON. For non-discoverable
  // credentials the authenticator returns no user, and Chrome rejects
  // `userHandle: null` — so omit the field entirely in that case.
  if (user instanceof Map && user.get("id") instanceof Uint8Array) {
    responseFields.userHandle = bytesToB64Url(user.get("id"));
  }

  return {
    id: bytesToB64Url(credIdBytes),
    rawId: bytesToB64Url(credIdBytes),
    type: "public-key",
    authenticatorAttachment: "cross-platform",
    response: responseFields,
    clientExtensionResults: {},
  };
}

// ----------------------------------------------------------------------------
// Service worker bootstrap.
// ----------------------------------------------------------------------------

async function attachProxy() {
  if (!chrome.webAuthenticationProxy) {
    console.error("[pw-relay] chrome.webAuthenticationProxy is undefined; need Chrome 115+ and webAuthenticationProxy permission");
    return;
  }
  try {
    await chrome.webAuthenticationProxy.attach();
    console.log("[pw-relay] attach() succeeded — proxy is active");
  } catch (err) {
    console.error("[pw-relay] attach() failed:", err && err.message ? err.message : err);
  }
}

function setupListeners() {
  if (!chrome.webAuthenticationProxy) return;
  chrome.webAuthenticationProxy.onCreateRequest.addListener(async (req) => {
    console.log("[pw-relay] onCreateRequest id=", req.requestId);
    try {
      const options = JSON.parse(req.requestDetailsJson);
      const origin = (await getActiveOrigin()) || `https://${options.rp.id}`;
      console.log("[pw-relay] create origin=", origin, " rp=", options.rp);
      const response = await handleCreate(options, origin);
      const json = JSON.stringify(response);
      console.log("[pw-relay] responseJson length=", json.length);
      console.log("[pw-relay] responseJson =", json);
      await chrome.webAuthenticationProxy.completeCreateRequest({
        requestId: req.requestId,
        responseJson: json,
      });
      console.log("[pw-relay] completeCreateRequest sent");
    } catch (err) {
      console.error("[pw-relay] create failed:", err);
      await chrome.webAuthenticationProxy.completeCreateRequest({
        requestId: req.requestId,
        error: {
          name: err && err.name === "CtapError" ? "NotAllowedError" : "UnknownError",
          message: String(err && err.message ? err.message : err),
        },
      });
    }
  });

  chrome.webAuthenticationProxy.onGetRequest.addListener(async (req) => {
    console.log("[pw-relay] onGetRequest id=", req.requestId);
    try {
      const options = JSON.parse(req.requestDetailsJson);
      const origin = (await getActiveOrigin()) || `https://${options.rpId}`;
      console.log("[pw-relay] get origin=", origin, " rpId=", options.rpId);
      const response = await handleGet(options, origin);
      const json = JSON.stringify(response);
      console.log("[pw-relay] get responseJson length=", json.length);
      console.log("[pw-relay] get responseJson =", json);
      await chrome.webAuthenticationProxy.completeGetRequest({
        requestId: req.requestId,
        responseJson: json,
      });
      console.log("[pw-relay] completeGetRequest sent");
    } catch (err) {
      console.error("[pw-relay] get failed:", err);
      await chrome.webAuthenticationProxy.completeGetRequest({
        requestId: req.requestId,
        error: {
          name: err && err.name === "CtapError" ? "NotAllowedError" : "UnknownError",
          message: String(err && err.message ? err.message : err),
        },
      });
    }
  });

  chrome.webAuthenticationProxy.onRequestCanceled.addListener((requestId) => {
    console.log("[pw-relay] onRequestCanceled id=", requestId);
    // Best-effort: nothing to actively cancel on the laptop side without a
    // distinct cancellation channel. The user can also press the key to
    // abort the touch wait.
  });
}

console.log("[pw-relay] service worker booting");
setupListeners();
attachProxy();

chrome.runtime.onInstalled.addListener(() => attachProxy());
chrome.runtime.onStartup.addListener(() => attachProxy());
