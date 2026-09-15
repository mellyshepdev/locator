"""Per-unit ingest keys: how a lokey proves which unit it is to the locator.

These are LOCATOR credentials, never OpenBao ones. Only the locator holds an
OpenBao token; a unit key lets that unit's lokey do exactly two things through
the locator:

  * file its own .env credentials into OpenBao  (/api/secrets/ingest)
  * read back the secrets filed under its own name (/api/secrets/unit-resolve)

It cannot read another unit's secrets, and it is not the admin key, so a
compromised unit exposes its own services' credentials and nothing else.

Only a SHA-256 of each key is kept. Keys are 256 bits of randomness, so a plain
hash is enough — there is nothing to brute-force the way there is with a
password. A lost key is replaced by minting a new one, which also revokes the
old one.
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
from datetime import datetime, timezone

KEYS_FILE = os.environ.get(
    "UNIT_KEYS_FILE",
    os.path.join(os.environ.get("DATA_DIR", "/app/data"), "unit_ingest_keys.json"))

# A unit name becomes an OpenBao path segment (compose/units/<unit>/...), so it
# gets the same charset discipline as any other path segment.
UNIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

_lock = threading.Lock()


def _hash(key):
    return hashlib.sha256(key.encode()).hexdigest()


def _load():
    try:
        with open(KEYS_FILE) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, ValueError):
        return {}


def _save(data):
    tmp = KEYS_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, KEYS_FILE)


def valid_unit(unit):
    return bool(unit) and bool(UNIT_RE.match(unit))


def mint(unit):
    """Create (or rotate) a unit's key. Returns the key — the only time it exists
    in clear anywhere on this side."""
    if not valid_unit(unit):
        raise ValueError(f"invalid unit name {unit!r}")
    key = "lk_" + secrets.token_urlsafe(32)
    with _lock:
        data = _load()
        data[unit] = {"sha256": _hash(key),
                      "created": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        _save(data)
    return key


def verify(unit, key):
    if not (valid_unit(unit) and key):
        return False
    rec = _load().get(unit) or {}
    stored = rec.get("sha256", "")
    return bool(stored) and hmac.compare_digest(_hash(key), stored)


def listing():
    """Which units hold a key, and since when. Never the hashes."""
    return {u: {"created": r.get("created")} for u, r in sorted(_load().items())}


def secret_prefix(base, unit):
    """OpenBao path prefix a unit may write to and read from: <base>/units/<unit>"""
    return f"{base}/units/{unit}"


def path_in_scope(path, base, unit):
    """True when an OpenBao path sits under the unit's own prefix — and cannot
    climb out of it."""
    if not valid_unit(unit) or not isinstance(path, str):
        return False
    parts = path.split("/")
    if any(p in ("", ".", "..") for p in parts):
        return False
    return path.startswith(secret_prefix(base, unit) + "/")
