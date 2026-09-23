"""
vaultwarden.py — mirror every locator-managed secret into Vaultwarden.

OpenBao is the operational source of truth (machines resolve from it). This
module keeps a second, human-readable copy in the `locator-service@` Vaultwarden
account as encrypted secure notes — one note per secret set, one hidden custom
field per key. Purpose: recovery and audit, not serving traffic. If you can
read OpenBao you can read the vault and vice versa.

How it works, concretely:

- Credentials for the service account live at secret/locator/vaultwarden
  (provisioned by provision_vw.py; never in compose or env files).
- Login is the standard Bitwarden password grant: PBKDF2-SHA256(password,
  email, 600k) -> master key -> PBKDF2(master key, password, 1) -> mph.
  The token response carries the user symkey as an encstring, decrypted
  with the HKDF-expanded stretched master key.
- Every cipher field we send is an encstring type 2 (AES-256-CBC + HMAC),
  encrypted with the user symkey — the vault DB only ever holds ciphertext.
- mirror() is idempotent: it lists ciphers, decrypts names client-side,
  and PUTs the existing note or POSTs a new one.

Everything here fails soft: a Vaultwarden outage must never break ingest,
quarantine, or renewal. Callers get False and a logged line, not an exception.
"""

import base64
import hashlib
import hmac as hmac_mod
import json
import os
import threading
import time
import urllib.parse
import urllib.request
import uuid

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import bao

ENABLED = os.environ.get("VW_MIRROR_ENABLED", "true").lower() in ("1", "true", "yes")
BAO_CREDS_PATH = os.environ.get("VW_BAO_PATH", "locator/vaultwarden")
NAME_PREFIX = "locator/"
CLIENT_KDF_ITER = 600000
HTTP_TIMEOUT = 15

_lock = threading.Lock()
_state = {
    "access_token": None,
    "token_exp": 0.0,
    "symkey": None,          # 64B user symmetric key
    "device_id": str(uuid.uuid4()),
    "ciphers": None,         # {plain_name: cipher_id}
    "ciphers_at": 0.0,
}


def _pbkdf2(pw: bytes, salt: bytes, iters: int, n: int = 32) -> bytes:
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=n, salt=salt,
                      iterations=iters).derive(pw)


def _hkdf(prk: bytes, info: bytes, n: int = 32) -> bytes:
    return HKDFExpand(algorithm=hashes.SHA256(), length=n, info=info).derive(prk)


def _enc(key64: bytes, data) -> str:
    if isinstance(data, str):
        data = data.encode()
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    enc = Cipher(algorithms.AES(key64[:32]), modes.CBC(iv)).encryptor()
    ct = enc.update(padder.update(data) + padder.finalize()) + enc.finalize()
    mac = hmac_mod.new(key64[32:], iv + ct, hashlib.sha256).digest()
    b = base64.b64encode
    return f"2.{b(iv).decode()}|{b(ct).decode()}|{b(mac).decode()}"


def _dec(key64: bytes, encstr: str) -> bytes:
    t, rest = encstr.split(".", 1)
    if t != "2":
        raise ValueError(f"unsupported encstring type {t}")
    iv_b64, ct_b64, mac_b64 = rest.split("|")
    iv, ct = base64.b64decode(iv_b64), base64.b64decode(ct_b64)
    expect = hmac_mod.new(key64[32:], iv + ct, hashlib.sha256).digest()
    if not hmac_mod.compare_digest(expect, base64.b64decode(mac_b64)):
        raise ValueError("encstring MAC mismatch")
    d = Cipher(algorithms.AES(key64[:32]), modes.CBC(iv)).decryptor()
    padded = d.update(ct) + d.finalize()
    unpad = padding.PKCS7(128).unpadder()
    return unpad.update(padded) + unpad.finalize()


def _creds():
    c = bao.read_secret("secret", BAO_CREDS_PATH, use_cache=False)
    return c["email"], c["password"], c["url"].rstrip("/")


def _login() -> bool:
    """Password grant + symkey decrypt. Returns False rather than raising."""
    email, password, url = _creds()
    master_key = _pbkdf2(password.encode(), email.lower().encode(), CLIENT_KDF_ITER)
    mph = _pbkdf2(master_key, password.encode(), 1)
    form = urllib.parse.urlencode({
        "grant_type": "password",
        "username": email,
        "password": base64.b64encode(mph).decode(),
        "scope": "api offline_access",
        "client_id": "web",
        "deviceType": "9",
        "deviceIdentifier": _state["device_id"],
        "deviceName": "locator",
    }).encode()
    req = urllib.request.Request(
        url + "/identity/connect/token", data=form,
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    resp = json.load(urllib.request.urlopen(req, timeout=HTTP_TIMEOUT))
    _state["access_token"] = resp["access_token"]
    _state["token_exp"] = time.time() + resp.get("expires_in", 3600) - 60
    enc_key = _hkdf(master_key, b"enc")
    mac_key = _hkdf(master_key, b"mac")
    _state["symkey"] = _dec(enc_key + mac_key, resp["Key"])
    _state["vw_url"] = url
    _state["ciphers"] = None
    return True


def _api(path, method="GET", body=None):
    if not ENABLED:
        raise RuntimeError("vaultwarden mirror disabled")
    if (_state["access_token"] is None
            or time.time() > _state["token_exp"]):
        _login()
    url = _state["vw_url"] + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": "Bearer " + _state["access_token"],
        "Content-Type": "application/json"})
    try:
        return json.load(urllib.request.urlopen(req, timeout=HTTP_TIMEOUT))
    except urllib.error.HTTPError as e:
        if e.code == 401:  # token died early — one relogin retry
            _login()
            req = urllib.request.Request(url, data=data, method=method, headers={
                "Authorization": "Bearer " + _state["access_token"],
                "Content-Type": "application/json"})
            return json.load(urllib.request.urlopen(req, timeout=HTTP_TIMEOUT))
        raise


def _cipher_map() -> dict:
    """{decrypted name: cipher id}, cached 5 min."""
    now = time.time()
    if _state["ciphers"] is not None and now - _state["ciphers_at"] < 300:
        return _state["ciphers"]
    resp = _api("/api/ciphers")
    out = {}
    for c in resp.get("data", []):
        try:
            name = _dec(_state["symkey"], c["name"]).decode()
            out[name] = c["id"]
        except Exception:
            continue
    _state["ciphers"] = out
    _state["ciphers_at"] = now
    return out


def mirror(name: str, fields: dict, notes: str = "") -> bool:
    """Upsert a secure note named `locator/<name>` with one hidden field per
    key in `fields`. `fields` values are secret — they cross the wire only as
    encstrings. Returns True on success, False (logged) on any failure."""
    if not ENABLED:
        return False
    try:
        with _lock:
            full_name = NAME_PREFIX + name.lstrip("/")
            existing = _cipher_map().get(full_name)  # triggers login on first use
            fields_js = [
                {"type": 1,  # hidden — masked in every vault client
                 "name": _enc(_state["symkey"], k),
                 "value": _enc(_state["symkey"], str(v)),
                 "linkedId": None}
                for k, v in sorted(fields.items())
            ]
            cipher = {
                "type": 2,  # secure note
                "name": _enc(_state["symkey"], full_name),
                "notes": _enc(_state["symkey"], notes or
                              f"mirrored by locator {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}"),
                "favorite": False,
                "folderId": None,
                "organizationId": None,
                "secureNote": {"type": 0},
                "fields": fields_js,
                "reprompt": 0,
            }
            if existing:
                cipher["id"] = existing
                _api(f"/api/ciphers/{existing}", method="PUT", body=cipher)
            else:
                resp = _api("/api/ciphers", method="POST", body=cipher)
                cid = resp.get("id") or resp.get("data", {}).get("id")
                if cid:
                    _state["ciphers"][full_name] = cid
        return True
    except Exception as e:
        print(f"[vaultwarden] mirror {name} failed: {e}", flush=True)
        return False
